package tls

import "core:crypto"
import "core:crypto/ecdh"
import "core:crypto/x509"
import "core:time"
import credential_store "credentials/store"

@(private)
Server_Flight_Stage :: enum {
	None,
	Retry_Wait,
	Hello,
	Handshake_Write,
	Handshake_Read,
	Extensions,
	Certificate_Header,
	Certificate_Entry,
	Certificate_DER,
	Certificate_Extensions,
	Verify,
	Finished,
	Application_Write,
	Application_Read,
	End,
}
@(private)
Server_Flight :: struct {
	stage:                                   Server_Flight_Stage,
	store:                                   ^credential_store.Store,
	lease:                                   credential_store.Lease,
	count, index, offset, certificate_bytes: int,
	handshake:                               Handshake_Secrets,
	using transient: struct #raw_union {
		application: Application_Secrets,
		retry: Server_Retry,
	},
	client_finished_secret:                  [32]u8,
}

// Explicit admission, after accepting tentative Peer_Parameters. The host keeps
// Store alive until destroy/abort. Pins one generation even across rotation/close.
// Parameters are explicitly selected, or default to optional TCP/no ALPN.
server_handshake_start_flight :: proc(
	owner: ^Server_Handshake,
	store: ^credential_store.Store,
	now: time.Time,
) -> Server_Handshake_Error {
	if !server_handshake_valid(owner) {
		return .Invalid_Owner
	}
	if owner._phase != .Await_Flight ||
	   owner._event.kind != .None ||
	   owner._flight.stage != .None {
		return .Invalid_State
	}
	if !owner._parameters.selected {
		e := server_parameters_select(owner, {})
		if e != .None {server_handshake_fail(owner, e); return e}
	}
	lease, error := credential_store.acquire(store)
	if error.kind != .None {
		server_handshake_fail(owner, .Credential_Failed); return .Credential_Failed
	}
	owner._flight.store, owner._flight.lease = store, lease
	if credential_store.check_server_leaf(store, lease, now).kind != .None {
		server_handshake_fail(owner, .Credential_Failed); return .Credential_Failed
	}
	offers := owner._hello.signature_algorithms_cert
	if len(offers) == 0 {
		offers = owner._hello.signature_algorithms
	}
	count, ce := credential_store.certificate_count(store, lease)
	if ce.kind != .None || count < 1 || count > 16 {
		server_handshake_fail(owner, .Credential_Failed); return .Credential_Failed
	}
	total := 0
	for index in 0 ..< count {
		der, de := credential_store.certificate_der(store, lease, index)
		metadata, me := credential_store.certificate_algorithms(store, lease, index)
		if de.kind != .None || me.kind != .None {
			server_handshake_fail(owner, .Credential_Failed); return .Credential_Failed
		}
		// Conservative chain profile: RSA PKCS1 SHA256/384/512 signatures.
		// Other parsed algorithms require issuer-key/parameter policy, not
		// inference from a leaf's RSA signing key. Even roots must match here.
		scheme := server_flight_certificate_scheme(metadata.signature)
		if scheme == 0 || !server_hello_offer_contains(offers, scheme) {
			server_handshake_fail(owner, .Unsupported); return .Unsupported
		}
		if len(der) == 0 || len(der) > 0xffffff - 5 || total > 0xffffff - 4 - 5 - len(der) {
			server_handshake_fail(owner, .Limit); return .Limit
		}
		total += 5 + len(der)
	}
	owner._flight.count, owner._flight.certificate_bytes = count, total
	owner._flight.stage = .Hello
	return .None
}
@(private)
server_flight_certificate_scheme :: proc(algorithm: x509.Signature_Algorithm) -> u16 {
	#partial switch algorithm {
	case .RSA_SHA256:
		return 0x0401
	case .RSA_SHA384:
		return 0x0501
	case .RSA_SHA512:
		return 0x0601
	case:
		return 0
	}
}
@(private)
server_flight_cleanup :: proc(owner: ^Server_Handshake) {
	if server_retry_active(owner) {server_retry_clear(owner)}
	if owner._flight.store != nil {
		_ = credential_store.release(owner._flight.store, &owner._flight.lease)
	}
	crypto.zero_explicit(&owner._flight, size_of(owner._flight))
}
@(private)
server_flight_put24 :: proc(dst: []u8, value: int) {
	dst[0], dst[1], dst[2] = u8(value >> 16), u8(value >> 8), u8(value)
}
@(private)
server_flight_bytes :: proc(
	owner: ^Server_Handshake,
	bytes: []u8,
	initial := false,
) -> Server_Handshake_Error {
	return server_handshake_publish(
		owner,
		{kind = .Handshake_Bytes, level = .Initial if initial else .Handshake, bytes = bytes},
	)
}
@(private)
server_flight_secret :: proc(
	owner: ^Server_Handshake,
	secret: []u8,
	direction: Server_Handshake_Direction,
	application := false,
) -> Server_Handshake_Error {
	return server_handshake_publish(
		owner,
		{
			kind = .Traffic_Secret,
			level = .Application if application else .Handshake,
			direction = direction,
			cipher = .AES_128_GCM_SHA256,
			secret = secret,
		},
	)
}

// Called only with no outstanding borrow. State advances when publishing; the
// next stage cannot execute until that entire event was accepted. Hashing occurs
// exactly once in accept, so SH/CV/Finished snapshots include accepted bytes only.
@(private)
server_flight_next :: proc(owner: ^Server_Handshake) -> Server_Handshake_Error {
	f := &owner._flight
	switch f.stage {
	case .None, .Retry_Wait:
		return .None
	case .Hello:
		if !crypto.HAS_RAND_BYTES {
			return .Entropy_Unavailable
		}
		private: ecdh.Private_Key
		defer ecdh.private_key_clear(&private)
		curve := ecdh.Curve.X25519 if owner._selection.group == .X25519 else .SECP256R1
		if !ecdh.private_key_generate(&private, curve) {return .Entropy_Unavailable}
		random: [32]u8; crypto.rand_bytes(random[:])
		return server_flight_prepare_ecdh(owner, &private, random)
	case .Handshake_Write:
		f.stage = .Handshake_Read
		return server_flight_secret(owner, f.handshake.server_traffic_secret[:], .Write)
	case .Handshake_Read:
		f.stage = .Extensions
		return server_flight_secret(owner, f.handshake.client_traffic_secret[:], .Read)
	case .Extensions:
		f.stage = .Certificate_Header
		return server_parameters_extensions(owner)
	case .Certificate_Header:
		header: [8]u8; header[0] = 11
		server_flight_put24(header[1:4], 4 + f.certificate_bytes)
		server_flight_put24(header[5:8], f.certificate_bytes)
		f.stage = .Certificate_Entry
		return server_flight_bytes(owner, transmute([]u8)header[:])
	case .Certificate_Entry:
		der, e := credential_store.certificate_der(f.store, f.lease, f.index)
		if e.kind != .None {
			return .Credential_Failed
		}
		header: [3]u8; server_flight_put24(header[:], len(der))
		f.offset = 0; f.stage = .Certificate_DER
		return server_flight_bytes(owner, transmute([]u8)header[:])
	case .Certificate_DER:
		der, e := credential_store.certificate_der(f.store, f.lease, f.index)
		if e.kind != .None {
			return .Credential_Failed
		}
		end := min(len(der), f.offset + SERVER_HANDSHAKE_OUTPUT_CAP)
		chunk := der[f.offset:end]; f.offset = end
		if end == len(der) {
			f.stage = .Certificate_Extensions
		}
		return server_handshake_publish(
			owner,
			{kind = .Handshake_Bytes, level = .Handshake, bytes = chunk},
			true,
		)
	case .Certificate_Extensions:
		f.index += 1
		f.stage = .Verify if f.index == f.count else .Certificate_Entry
		wire: [2]u8
		return server_flight_bytes(owner, transmute([]u8)wire[:])
	case .Verify:
		wire: [520]u8; defer crypto.zero_explicit(&wire, size_of(wire))
		digest := certificate_verify_digest(transcript_snapshot(&owner._transcript), true)
		n, e := credential_store.sign_digest_pss_sha256(f.store, f.lease, digest, wire[8:])
		if e.kind != .None {
			return .Signing_Failed
		}
		wire[0] = 15; server_flight_put24(wire[1:4], 4 + n)
		wire[4], wire[5], wire[6], wire[7] = 8, 4, u8(n >> 8), u8(n)
		f.stage = .Finished
		return server_flight_bytes(owner, transmute([]u8)wire[:8 + n])
	case .Finished:
		wire: [36]u8; defer crypto.zero_explicit(&wire, size_of(wire))
		n, e := finished_encode(
			wire[:],
			f.handshake.server_traffic_secret,
			transcript_snapshot(&owner._transcript),
		)
		if e != .None {
			return .Invalid_State
		}
		f.stage = .Application_Write
		return server_flight_bytes(owner, transmute([]u8)wire[:n])
	case .Application_Write:
		f.application = application_secrets_derive(
			f.handshake.handshake_secret,
			transcript_snapshot(&owner._transcript),
		)
		f.client_finished_secret = f.handshake.client_traffic_secret
		crypto.zero_explicit(&f.handshake, size_of(f.handshake))
		f.stage = .Application_Read
		return server_flight_secret(owner, f.application.server_traffic_secret[:], .Write, true)
	case .Application_Read:
		f.stage = .End
		return server_flight_secret(owner, f.application.client_traffic_secret[:], .Read, true)
	case .End:
		_ = credential_store.release(f.store, &f.lease); f.store = nil
		crypto.zero_explicit(&f.application, size_of(f.application))
		f.stage = .None; owner._phase = .Await_Client_Finished
		return .None
	}
	unreachable()
}
// Keep the X25519 wrapper used by deterministic fixtures.
@(private)
server_flight_hello :: proc(dst: []u8, session: []u8, public, random: [32]u8) -> int {
	pub:=public
	return server_flight_group_hello(dst, session, .X25519, pub[:], random)
}
@(private)
server_flight_group_hello :: proc(dst: []u8, session: []u8, group: Named_Group, public: []u8, random: [32]u8) -> int {
	at := 4
	hello_put_u16(dst, &at, 0x0303)
	for b,i in random {dst[at+i]=b}; at += 32
	dst[at] = u8(len(session)); at += 1; copy(dst[at:], session); at += len(session)
	hello_put_u16(dst, &at, 0x1301); dst[at] = 0; at += 1
	hello_put_u16(dst, &at, u16(14+len(public)))
	hello_put_u16(dst, &at, 43); hello_put_u16(dst, &at, 2); hello_put_u16(dst, &at, 0x0304)
	hello_put_u16(dst, &at, 51); hello_put_u16(dst, &at, u16(4+len(public))); hello_put_u16(dst, &at, u16(group))
	hello_put_u16(dst, &at, u16(len(public)))
	copy(dst[at:],public); at += len(public)
	dst[0] = 2; server_flight_put24(dst[1:4], at - 4)
	return at
}

// Private deterministic seam; production uses OS-generated keys through the
// pointer API, never a by-value ECDH union or a persistent per-owner key.
@(private)
server_flight_prepare_hello :: proc(owner: ^Server_Handshake, private_key, random: [32]u8) -> Server_Handshake_Error {
	private: ecdh.Private_Key; defer ecdh.private_key_clear(&private)
	curve := ecdh.Curve.X25519 if owner._selection.group == .X25519 else .SECP256R1
	key:=private_key; defer crypto.zero_explicit(&key,size_of(key))
	if !ecdh.private_key_set_bytes(&private,curve,key[:]) {return .Malformed}
	return server_flight_prepare_ecdh(owner,&private,random)
}
@(private)
server_flight_prepare_ecdh :: proc(owner: ^Server_Handshake, private: ^ecdh.Private_Key, random: [32]u8) -> Server_Handshake_Error {
	f := &owner._flight
	shared: [32]u8; public: [65]u8
	defer crypto.zero_explicit(&shared,size_of(shared))
	peer: ecdh.Public_Key; defer ecdh.public_key_clear(&peer)
	curve := ecdh.Curve.X25519 if owner._selection.group == .X25519 else .SECP256R1
	if !ecdh.public_key_set_bytes(&peer,curve,owner._selection.peer_key_share) ||
	   !ecdh.ecdh(private,&peer,shared[:]) {return .Malformed}
	size := 32 if curve == .X25519 else 65
	ecdh.private_key_public_bytes(private,public[:size])
	wire: [155]u8
	n := server_flight_group_hello(wire[:],owner._hello.session_id,owner._selection.group,public[:size],random)
	staged := owner._transcript; transcript_update(&staged,wire[:n])
	secrets,e := handshake_secrets_derive_from_hash(shared,transcript_snapshot(&staged))
	defer crypto.zero_explicit(&secrets,size_of(secrets))
	if e != .None {return .Malformed}
	f.handshake=secrets
	e2:=server_flight_bytes(owner,transmute([]u8)wire[:n],true)
	if e2 != .None {return e2}
	server_handshake_release_input(owner)
	f.stage=.Handshake_Write
	return .None
}
