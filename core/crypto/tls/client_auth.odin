package tls

import "core:crypto"
import "core:crypto/x509"
import "core:mem"
import "core:time"
import credential_store "credentials/store"

Client_Auth_Mode :: enum {
	Disabled,
	Request,
	Require,
}

// Borrow roots and policy until the handshake finishes. Request accepts an
// empty certificate, but any supplied identity must authenticate fully.
Client_Auth_Config :: struct {
	mode:         Client_Auth_Mode,
	roots:        []^x509.Certificate,
	current_time: time.Time,
}

Peer_Identity :: struct {
	authenticated:      bool,
	certificate_sha256: [32]u8,
}

client_auth_config_valid :: proc(config: ^Client_Auth_Config) -> bool {
	if config == nil || config.mode == .Disabled {
		return true
	}
	if config.mode != .Request && config.mode != .Require || len(config.roots) == 0 {
		return false
	}
	for root in config.roots {
		if root == nil {
			return false
		}
	}
	return true
}

@(private)
Client_Certificate_Request :: struct {
	schemes: [32]u16,
	count:   int,
}

client_certificate_request_schemes :: proc(message: []u8) -> (Client_Certificate_Request, Handshake_Error) {
	request: Client_Certificate_Request
	if len(message) < 11 || message[0] != 13 || handshake_body_size(message) + 4 != len(message) || message[4] != 0 {
		return {}, {kind = .Malformed_Message}
	}
	if int(authentication_u16(message, 5)) != len(message) - 7 {
		return {}, {kind = .Malformed_Message}
	}
	at := 7
	have := false
	seen: [64]u16
	seen_n := 0
	for at < len(message) {
		if len(message) - at < 4 || seen_n == len(seen) {
			return {}, {kind = .Malformed_Message}
		}
		typ := authentication_u16(message, at)
		n := int(authentication_u16(message, at + 2))
		at += 4
		if n > len(message) - at {
			return {}, {kind = .Malformed_Message}
		}
		for prior in seen[:seen_n] {
			if prior == typ {
				return {}, {kind = .Malformed_Message}
			}
		}
		seen[seen_n] = typ
		seen_n += 1
		if typ == 13 {
			if n < 4 ||
			   n & 1 != 0 ||
			   int(authentication_u16(message, at)) != n - 2 ||
			   (n - 2) / 2 > len(request.schemes) {
				return {}, {kind = .Malformed_Message}
			}
			request.count = (n - 2) / 2
			for i in 0 ..< request.count {request.schemes[i] = authentication_u16(message, at + 2 + 2 * i)}
			have = true
		}
		at += n
	}
	if !have {
		return {}, {kind = .Malformed_Message}
	}
	return request, {}
}

@(private)
client_auth_request_decode :: proc(conn: ^Conn, message: []u8) -> Handshake_Error {
	request, e := client_certificate_request_schemes(message)
	if e.kind != .None {
		return e
	}
	conn.client_auth_schemes = request.schemes
	conn.client_auth_scheme_count = request.count
	conn.client_auth_requested = true
	return {}
}

// Produce the client's Certificate and CertificateVerify flight, excluding
// Finished. The transcript already includes the authenticated server Finished.
// The result is owned by allocator. Store generations are pinned only while
// copying/signing; the resulting flight has no borrowed key or DER references.
client_authentication_flight :: proc(
	store: ^credential_store.Store,
	schemes: []u16,
	transcript: ^Handshake_Transcript,
	allocator: mem.Allocator,
	identity_lease: ^credential_store.Lease = nil,
) -> (
	[]u8,
	Handshake_Error,
) {
	lease: credential_store.Lease
	leased := false
	defer if leased {
		_ = credential_store.release(store, &lease)
	}
	count, total := 0, 0
	scheme: u16
	if store != nil {
		if identity_lease != nil {
			lease = identity_lease^
		} else {
			l, e := credential_store.acquire(store)
			if e.kind != .None {
				return nil, {kind = .Authentication_Failed}
			}
			lease = l
			leased = true
		}
		if credential_store.check_client_leaf(store, lease, time.now()).kind != .None {
			return nil, {kind = .Authentication_Failed, authentication = {kind = .Invalid_Certificate_Usage}}
		}
		selected, se := credential_store.signature_scheme(store, lease)
		if se.kind != .None {
			return nil, {kind = .Authentication_Failed}
		}
		for offered in schemes {
			if offered == u16(selected) {
				scheme = offered
				break
			}
		}
		if scheme != 0 {
			n, e := credential_store.certificate_count(store, lease)
			if e.kind != .None {
				return nil, {kind = .Authentication_Failed}
			}
			count = n
			for i in 0 ..< count {
				der, der_error := credential_store.certificate_der(store, lease, i)
				if der_error.kind != .None || len(der) > MAX_CERTIFICATE_MESSAGE_SIZE - total - 5 {
					return nil, {kind = .Server_Flight_Oversized}
				}
				total += 5 + len(der)
			}
		}
	}
	size := 8 + total
	if count > 0 {
		size += 520
	}
	flight, ae := make([]u8, size, allocator)
	if ae != nil {
		return nil, {kind = .Allocation_Failed, allocation = ae}
	}
	success := false
	defer if !success {
		crypto.zero_explicit(raw_data(flight), len(flight))
		delete(flight, allocator)
	}
	flight[0] = 11
	server_flight_put24(flight[1:4], 4 + total)
	server_flight_put24(flight[5:8], total)
	at := 8
	for i in 0 ..< count {
		der, e := credential_store.certificate_der(store, lease, i)
		if e.kind != .None {
			return nil, {kind = .Authentication_Failed}
		}
		server_flight_put24(flight[at:at + 3], len(der))
		at += 3
		at += copy(flight[at:], der)
		at += 2
	}
	transcript_update(transcript, flight[:at])
	if count > 0 {
		digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
		signed_storage: [MAX_CERTIFICATE_VERIFY_INPUT_SIZE]u8
		signed := certificate_verify_content(signed_storage[:], transcript_hash(transcript, digest_storage[:]), false)
		selected, _ := credential_store.signature_scheme(store, lease)
		n, e := credential_store.sign_sha256(store, lease, selected, signed, flight[at + 8:])
		if e.kind != .None {
			return nil, {kind = .Authentication_Failed}
		}
		flight[at] = 15
		server_flight_put24(flight[at + 1:at + 4], 4 + n)
		flight[at + 4], flight[at + 5], flight[at + 6], flight[at + 7] = u8(scheme >> 8), u8(scheme), u8(n >> 8), u8(n)
		transcript_update(transcript, flight[at:at + 8 + n])
		at += 8 + n
	}
	// Preserve the full allocation extent for correct custom allocator release.
	out, copy_error := make([]u8, at, allocator)
	if copy_error != nil {
		return nil, {kind = .Allocation_Failed, allocation = copy_error}
	}
	copy(out, flight[:at])
	crypto.zero_explicit(raw_data(flight), len(flight))
	delete(flight, allocator)
	success = true
	return out, {}
}

@(private)
client_auth_prepare :: proc(conn: ^Conn, allocator: mem.Allocator) -> Handshake_Error {
	if !conn.client_auth_requested {
		return {}
	}
	conn.client_auth_used = true
	if raw_data(conn.client_auth_flight) != nil {
		return {}
	}
	flight, e := client_authentication_flight(
		conn.config.client_credentials,
		conn.client_auth_schemes[:conn.client_auth_scheme_count],
		&conn.server_finished_transcript,
		allocator,
		conn.config.client_credential_lease,
	)
	if e.kind != .None {
		return e
	}
	if len(flight) > 13 && flight[0] == 11 {
		n := authentication_u24(flight, 8)
		if n > 0 && n <= len(flight) - 11 {
			conn.session_identity = ticket_hash(flight[11:11 + n])
			conn.session_identity_present = true
			conn.session_identity_valid = true
		}
	}
	conn.client_auth_flight = flight
	conn.client_auth_allocator = allocator
	return {}
}

@(private)
client_auth_clear :: proc(conn: ^Conn) {
	if raw_data(conn.client_auth_flight) != nil {
		crypto.zero_explicit(raw_data(conn.client_auth_flight), len(conn.client_auth_flight))
		delete(conn.client_auth_flight, conn.client_auth_allocator)
	}
	conn.client_auth_flight = nil
	conn.client_auth_offset = 0
	conn.client_auth_allocator = {}
	conn.client_auth_requested = false
	conn.client_auth_scheme_count = 0
	crypto.zero_explicit(&conn.client_auth_schemes, size_of(conn.client_auth_schemes))
}
