package tls

import "core:crypto/sha2"
import "core:crypto/x509"
import "core:time"
import "core:mem"

Server_Client_Auth_Stage :: enum {
	Certificate,
	Verify,
	Finished,
}

Server_Client_Auth :: struct {
	stage:       Server_Client_Auth_Stage,
	certificate: []u8,
	certs:       Server_Certificates,
}

server_handshake_peer_identity :: proc(owner: ^Server_Handshake) -> Peer_Identity {
	if !server_handshake_valid(owner) || owner._phase != .Complete {
		return {}
	}
	return owner._peer_identity
}

server_client_auth_clear :: proc(owner: ^Server_Handshake) {
	if owner._client_auth == nil {
		return
	}
	state := owner._client_auth
	previous := context.allocator
	context.allocator = owner._allocator
	server_certificates_destroy(&state.certs)
	context.allocator = previous
	if raw_data(state.certificate) != nil {
		owner._stats.live_bytes -= len(state.certificate)
		server_handshake_wipe_free(owner, state.certificate)
	}
	owner._stats.live_bytes -= size_of(Server_Client_Auth)
	server_handshake_wipe_free(owner, mem.byte_slice(state, size_of(Server_Client_Auth)), align_of(Server_Client_Auth))
	owner._client_auth = nil
}

server_client_auth_verify_chain :: proc(owner: ^Server_Handshake, message: []u8) -> bool {
	auth := owner._client_auth
	previous := context.allocator
	context.allocator = owner._allocator
	defer context.allocator = previous
	certs, e := server_certificates_parse(message)
	if e.kind != .None {
		return false
	}
	auth.certs = certs
	leaf := &auth.certs.chain[0]
	owner._peer_expires = time.to_unix_seconds(leaf.not_after)
	if leaf.has_key_usage && .Digital_Signature not_in leaf.key_usage {
		return false
	}
	inter: [MAX_SERVER_CERTIFICATES - 1]^x509.Certificate
	for i in 1 ..< certs.count {inter[i - 1] = &auth.certs.chain[i]}
	now := owner._config.client_auth.current_time
	if now == (time.Time{}) {
		now = time.now()
	}
	for i in 1 ..< auth.certs.count {owner._peer_expires = min(owner._peer_expires, time.to_unix_seconds(auth.certs.chain[i].not_after))}
	chain, ce := x509.verify_chain(
		leaf,
		{
			roots = owner._config.client_auth.roots,
			intermediates = inter[:certs.count - 1],
			current_time = now,
			required_eku = x509.EKU_Bit.Client_Auth,
		},
	)
	if ce != .None {
		return false
	}
	delete(chain)
	return true
}

server_client_auth_verify_signature :: proc(owner: ^Server_Handshake, message: []u8) -> bool {
	if len(message) < 8 || message[0] != 15 || handshake_body_size(message) + 4 != len(message) {
		return false
	}
	n := int(authentication_u16(message, 6))
	if n == 0 || n != len(message) - 8 {
		return false
	}
	scheme := Signature_Scheme(authentication_u16(message, 4))
	if scheme != .Rsa_Pss_Rsae_Sha256 && scheme != .Ecdsa_Secp256r1_Sha256 && scheme != .Ed25519 {
		return false
	}
	digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
	signed_storage: [MAX_CERTIFICATE_VERIFY_INPUT_SIZE]u8
	signed := certificate_verify_content(
		signed_storage[:],
		transcript_hash(&owner._transcript, digest_storage[:]),
		false,
	)
	valid, e := authentication_signature_check(&owner._client_auth.certs.chain[0], scheme, signed, message[8:])
	return valid && e.kind == .None
}

server_client_auth_feed :: proc(
	owner: ^Server_Handshake,
	level: Server_Handshake_Level,
	input: []u8,
) -> (
	consumed: int,
	status: Server_Handshake_Status,
	error: Server_Handshake_Error,
) {
	if level != .Handshake {
		server_handshake_fail(owner, .Wrong_Level)
		return 0, .Terminal, .Wrong_Level
	}
	if owner._client_auth == nil {
		grant, ok := server_handshake_allocate(owner, size_of(Server_Client_Auth), align_of(Server_Client_Auth))
		if !ok {
			server_handshake_fail(owner, .Allocation_Failed)
			return 0, .Terminal, .Allocation_Failed
		}
		owner._client_auth = cast(^Server_Client_Auth)raw_data(grant)
	}
	auth := owner._client_auth
	for {
		if auth.stage == .Finished {
			n, s, e := server_handshake_finished_feed(owner, level, input[consumed:])
			return consumed + n, s, e
		}
		expected := u8(11) if auth.stage == .Certificate else u8(15)
		for owner._received < 4 && consumed < len(input) {
			owner._header[owner._received] = input[consumed]
			owner._received += 1
			consumed += 1
			if owner._header[0] != expected {
				server_handshake_fail(owner, .Client_Authentication_Failed)
				return consumed, .Terminal, .Client_Authentication_Failed
			}
		}
		if owner._received < 4 {
			return consumed, .Need_Input, .None
		}
		if owner._message_size == 0 {
			size := 4 + authentication_u24(owner._header[:], 1)
			cap := MAX_CERTIFICATE_MESSAGE_SIZE if auth.stage == .Certificate else SERVER_HANDSHAKE_OUTPUT_CAP
			if size < 8 || size > cap {
				server_handshake_fail(owner, .Limit)
				return consumed, .Terminal, .Limit
			}
			if auth.stage == .Certificate {
				grant, ok := server_handshake_allocate(owner, size)
				if !ok {
					server_handshake_fail(owner, .Allocation_Failed)
					return consumed, .Terminal, .Allocation_Failed
				}
				auth.certificate = grant
			}
			owner._message_size = size
			target := auth.certificate if auth.stage == .Certificate else owner._output
			copy(target[:4], owner._header[:])
		}
		target := auth.certificate if auth.stage == .Certificate else owner._output
		n := min(len(input) - consumed, owner._message_size - owner._received)
		copy(target[owner._received:], input[consumed:consumed + n])
		owner._received += n
		consumed += n
		if owner._received < owner._message_size {
			return consumed, .Need_Input, .None
		}
		message := target[:owner._message_size]
		if auth.stage == .Certificate {
			empty := len(message) == 8 && message[4] == 0 && authentication_u24(message, 5) == 0
			if empty {
				if owner._config.client_auth.mode == .Require {
					server_handshake_fail(owner, .Client_Authentication_Failed)
					return consumed, .Terminal, .Client_Authentication_Failed
				}
				auth.stage = .Finished
			} else {
				if !server_client_auth_verify_chain(owner, message) {
					server_handshake_fail(owner, .Client_Authentication_Failed)
					return consumed, .Terminal, .Client_Authentication_Failed
				}
				auth.stage = .Verify
			}
		} else {
			if !server_client_auth_verify_signature(owner, message) {
				server_handshake_fail(owner, .Client_Authentication_Failed)
				return consumed, .Terminal, .Client_Authentication_Failed
			}
			digest: sha2.Context_256
			sha2.init_256(&digest)
			sha2.update(&digest, auth.certs.chain[0].raw)
			sha2.final(&digest, owner._peer_identity.certificate_sha256[:])
			owner._peer_identity.authenticated = true
			auth.stage = .Finished
		}
		transcript_update(&owner._transcript, message)
		owner._header = {}
		owner._received = 0
		owner._message_size = 0
		if consumed == len(input) {
			return consumed, .Need_Input, .None
		}
	}
}
