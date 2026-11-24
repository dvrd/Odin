package tls

import "core:mem"

import "core:crypto"
import "core:crypto/ecdh"
import "core:crypto/hash"
import "core:crypto/mlkem"
import "core:crypto/x509"
import "core:time"
import credential_store "credentials/store"

Server_Flight_Stage :: enum {
	None,
	Retry_Wait,
	Hello,
	Handshake_Write,
	Handshake_Read,
	Extensions,
	Certificate_Request,
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

Server_Flight :: struct {
	stage:                                   Server_Flight_Stage,
	store:                                   ^credential_store.Store,
	lease:                                   credential_store.Lease,
	count, index, offset, certificate_bytes: int,
	// The negotiated suite; the hello views are released after ServerHello.
	cipher:                                  Cipher_Suite,
	// Upstream's schedule stage: handshake secret, then master secret.
	keys:                                    Handshake_Keys,
	// Sized by the suite's hash. The client secret stays through its Finished.
	client_handshake_secret:                 [MAX_TRANSCRIPT_HASH_SIZE]u8,
	server_handshake_secret:                 [MAX_TRANSCRIPT_HASH_SIZE]u8,
	using transient:                         struct #raw_union {
		application: Server_Application_Secrets,
		retry:       Server_Retry,
	},
}

Server_Application_Secrets :: struct {
	client_traffic_secret: [MAX_TRANSCRIPT_HASH_SIZE]u8,
	server_traffic_secret: [MAX_TRANSCRIPT_HASH_SIZE]u8,
}

// Bytes of one traffic secret of the flight's suite.
@(private)
server_flight_secret_size :: proc(f: ^Server_Flight) -> int {
	return hash.DIGEST_SIZES[CIPHER_SUITE_HASH[f.cipher]]
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
	if owner._phase != .Await_Flight || owner._event.kind != .None || owner._flight.stage != .None {
		return .Invalid_State
	}
	if !owner._parameters.selected {
		e := server_parameters_select(owner, {})
		if e != .None {
			server_handshake_fail(owner, e)
			return e
		}
	}
	lease, error := credential_store.acquire(store)
	if error.kind != .None {
		server_handshake_fail(owner, .Credential_Failed)
		return .Credential_Failed
	}
	owner._flight.store, owner._flight.lease = store, lease
	if credential_store.check_server_leaf(store, lease, now).kind != .None {
		server_handshake_fail(owner, .Credential_Failed)
		return .Credential_Failed
	}
	if re := server_resumption_prepare(owner, now); re != .None {
		server_handshake_fail(owner, re)
		return re
	}
	if owner._resumed {
		owner._flight.stage = .Hello
		return .None
	}
	scheme, se := credential_store.signature_scheme(store, lease)
	if se.kind != .None || scheme == .None {
		server_handshake_fail(owner, .Credential_Failed)
		return .Credential_Failed
	}
	if !server_hello_offer_contains(owner._hello.signature_algorithms, u16(scheme)) {
		server_handshake_fail(owner, .Unsupported)
		return .Unsupported
	}
	owner._selection.signature = cast(Signature_Scheme)u16(scheme)
	offers := owner._hello.signature_algorithms_cert
	if len(offers) == 0 {
		offers = owner._hello.signature_algorithms
	}
	count, ce := credential_store.certificate_count(store, lease)
	if ce.kind != .None || count < 1 || count > 16 {
		server_handshake_fail(owner, .Credential_Failed)
		return .Credential_Failed
	}
	total := 0
	for index in 0 ..< count {
		der, de := credential_store.certificate_der(store, lease, index)
		metadata, me := credential_store.certificate_algorithms(store, lease, index)
		if de.kind != .None || me.kind != .None {
			server_handshake_fail(owner, .Credential_Failed)
			return .Credential_Failed
		}
		// Conservative chain profile: RSA PKCS1 SHA256/384/512, PSS SHA256
		// with an RSAE issuer, or ECDSA SHA256/P-256. Signature policy is separate
		// from the leaf's CertificateVerify key. Even roots must match here.
		scheme := server_flight_certificate_scheme(metadata.signature)
		if metadata.signature == .ECDSA_SHA256 || metadata.signature == .RSA_PSS {
			issuer_index := min(index + 1, count - 1)
			issuer, ie := credential_store.certificate_algorithms(store, lease, issuer_index)
			if ie.kind != .None {
				server_handshake_fail(owner, .Credential_Failed)
				return .Credential_Failed
			}
			if metadata.signature == .ECDSA_SHA256 {
				if issuer.subject_key != .ECDSA_P256 {
					server_handshake_fail(owner, .Unsupported)
					return .Unsupported
				}
			} else {
				parameters, pe := credential_store.certificate_pss_parameters(store, lease, index)
				if pe.kind != .None {
					server_handshake_fail(owner, .Credential_Failed)
					return .Credential_Failed
				}
				if issuer.subject_key != .RSA ||
				   parameters.digest != .SHA256 ||
				   parameters.mgf_digest != .SHA256 ||
				   parameters.salt_length != 32 {
					server_handshake_fail(owner, .Unsupported)
					return .Unsupported
				}
				scheme = 0x0804
			}
		}
		if scheme == 0 || !server_hello_offer_contains(offers, scheme) {
			server_handshake_fail(owner, .Unsupported)
			return .Unsupported
		}
		if len(der) == 0 || len(der) > 0xffffff - 5 || total > 0xffffff - 4 - 5 - len(der) {
			server_handshake_fail(owner, .Limit)
			return .Limit
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
	case .ECDSA_SHA256:
		return 0x0403
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
	if server_retry_active(owner) {
		server_retry_clear(owner)
	}
	if owner._flight.store != nil {
		_ = credential_store.release(owner._flight.store, &owner._flight.lease)
	}
	crypto.zero_explicit(&owner._flight, size_of(owner._flight))
}

@(private)
server_flight_put24 :: proc(dst: []u8, value: int) {
	dst[0], dst[1], dst[2] = u8(value >> 16), u8(value >> 8), u8(value)
}

// Explicit pointer views at stack-backed call sites preserve the copy contract:
// publish uses borrow_bytes=false and copies bytes before returning.
@(private)
server_flight_bytes :: proc(owner: ^Server_Handshake, bytes: []u8, initial := false) -> Server_Handshake_Error {
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
			cipher = owner._flight.cipher,
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
	if owner._resumption != nil && owner._resumption.early_accepted && !owner._resumption.early_event_sent {
		state := owner._resumption
		if !server_handshake_id(owner) {
			return .Identity_Exhausted
		}
		state.early_event_sent = true
		owner._event = {
			id        = owner._next_id,
			kind      = .Early_Traffic_Secret,
			level     = .Application,
			direction = .Read,
			cipher    = .TLS_AES_128_GCM_SHA256,
			secret    = state.early_secret[:],
		}
		return .None
	}
	switch f.stage {
	case .None, .Retry_Wait:
		return .None
	case .Hello:
		if !crypto.HAS_RAND_BYTES {
			return .Entropy_Unavailable
		}
		private: ecdh.Private_Key
		defer ecdh.private_key_clear(&private)

		if !ecdh.private_key_generate(&private, server_flight_curve(owner._selection.group)) {
			return .Entropy_Unavailable
		}

		random: [32]u8
		crypto.rand_bytes(random[:])
		return server_flight_prepare_ecdh(owner, &private, random)
	case .Handshake_Write:
		f.stage = .Handshake_Read
		return server_flight_secret(owner, f.server_handshake_secret[:server_flight_secret_size(f)], .Write)
	case .Handshake_Read:
		f.stage = .Extensions
		return server_flight_secret(owner, f.client_handshake_secret[:server_flight_secret_size(f)], .Read)
	case .Extensions:
		f.stage = .Finished if owner._resumed else .Certificate_Request
		return server_parameters_extensions(owner)
	case .Certificate_Request:
		f.stage = .Certificate_Header
		if owner._config.client_auth == nil || owner._config.client_auth.mode == .Disabled {
			return server_flight_next(owner)
		}
		wire := [?]u8{13, 0, 0, 15, 0, 0, 12, 0, 13, 0, 8, 0, 6, 8, 4, 4, 3, 8, 7}
		return server_flight_bytes(owner, mem.slice_ptr(cast(^u8)(cast(rawptr)&wire), len(wire)))
	case .Certificate_Header:
		header: [8]u8
		header[0] = 11
		server_flight_put24(header[1:4], 4 + f.certificate_bytes)
		server_flight_put24(header[5:8], f.certificate_bytes)
		f.stage = .Certificate_Entry
		return server_flight_bytes(owner, mem.slice_ptr(cast(^u8)(cast(rawptr)&header), len(header)))
	case .Certificate_Entry:
		der, e := credential_store.certificate_der(f.store, f.lease, f.index)
		if e.kind != .None {
			return .Credential_Failed
		}
		header: [3]u8
		server_flight_put24(header[:], len(der))
		f.offset = 0
		f.stage = .Certificate_DER
		return server_flight_bytes(owner, mem.slice_ptr(cast(^u8)(cast(rawptr)&header), len(header)))
	case .Certificate_DER:
		der, e := credential_store.certificate_der(f.store, f.lease, f.index)
		if e.kind != .None {
			return .Credential_Failed
		}
		end := min(len(der), f.offset + SERVER_HANDSHAKE_OUTPUT_CAP)
		chunk := der[f.offset:end]
		f.offset = end
		if end == len(der) {
			f.stage = .Certificate_Extensions
		}
		return server_handshake_publish(owner, {kind = .Handshake_Bytes, level = .Handshake, bytes = chunk}, true)
	case .Certificate_Extensions:
		f.index += 1
		f.stage = .Verify if f.index == f.count else .Certificate_Entry
		wire: [2]u8
		return server_flight_bytes(owner, mem.slice_ptr(cast(^u8)(cast(rawptr)&wire), len(wire)))
	case .Verify:
		wire: [520]u8
		defer crypto.zero_explicit(&wire, size_of(wire))

		digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
		signed_storage: [MAX_CERTIFICATE_VERIFY_INPUT_SIZE]u8
		digest := transcript_hash(&owner._transcript, digest_storage[:])
		signed := certificate_verify_content(signed_storage[:], digest, true)
		// Hello views/selection were erased after ServerHello. The live lease
		// identifies the same admitted generation even after store rotation.
		scheme, se := credential_store.signature_scheme(f.store, f.lease)
		if se.kind != .None {
			return .Signing_Failed
		}
		n, e := credential_store.sign_sha256(f.store, f.lease, scheme, signed, wire[8:])
		if e.kind != .None {
			return .Signing_Failed
		}
		wire[0] = 15
		server_flight_put24(wire[1:4], 4 + n)
		wire[4], wire[5], wire[6], wire[7] = u8(u16(scheme) >> 8), u8(scheme), u8(n >> 8), u8(n)
		f.stage = .Finished
		return server_flight_bytes(owner, mem.slice_ptr(cast(^u8)(cast(rawptr)&wire), 8 + n))
	case .Finished:
		wire: [MAX_FINISHED_MESSAGE_SIZE]u8
		defer crypto.zero_explicit(&wire, size_of(wire))

		size := server_flight_secret_size(f)
		digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
		digest := transcript_hash(&owner._transcript, digest_storage[:])
		finished_header_encode(wire[:], size)
		schedule_finished_mac(f.keys.hash, f.server_handshake_secret[:size], digest, wire[4:4 + size])

		f.stage = .Application_Write
		return server_flight_bytes(owner, mem.slice_ptr(cast(^u8)(cast(rawptr)&wire), 4 + size))
	case .Application_Write:
		// Upstream's schedule step to the master secret (zero IKM), then the
		// application traffic secrets over the transcript through server Finished.
		size := server_flight_secret_size(f)
		zeroes: [MAX_TRANSCRIPT_HASH_SIZE]u8
		digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
		digest := transcript_hash(&owner._transcript, digest_storage[:])

		update_handshake_keys(&f.keys, zeroes[:size])
		schedule_derive_secret(&f.keys, "c ap traffic", digest, f.application.client_traffic_secret[:size])
		schedule_derive_secret(&f.keys, "s ap traffic", digest, f.application.server_traffic_secret[:size])
		if owner._resumption != nil {
			copy(owner._resumption.master[:], schedule_secret(&f.keys))
		}

		clear_handshake_keys(&f.keys)
		crypto.zero_explicit(&f.server_handshake_secret, size_of(f.server_handshake_secret))
		f.stage = .Application_Read
		return server_flight_secret(owner, f.application.server_traffic_secret[:size], .Write, true)
	case .Application_Read:
		f.stage = .End
		return server_flight_secret(
			owner,
			f.application.client_traffic_secret[:server_flight_secret_size(f)],
			.Read,
			true,
		)
	case .End:
		// Keep the admitted generation pinned through client Finished. Shared
		// cleanup releases it on verified completion or any terminal failure.
		crypto.zero_explicit(&f.application, size_of(f.application))
		f.stage = .None
		owner._phase = .Await_Client_Finished
		return .None
	}
	unreachable()
}

// Keep the X25519 wrapper used by deterministic fixtures.
@(private)
server_flight_hello :: proc(dst: []u8, session: []u8, public, random: [32]u8) -> int {
	pub := public
	return server_flight_group_hello(dst, session, .X25519, pub[:], random)
}

@(private)
server_flight_group_hello :: proc(
	dst: []u8,
	session: []u8,
	group: Named_Group,
	public: []u8,
	random: [32]u8,
	cipher: Cipher_Suite = .TLS_AES_128_GCM_SHA256,
) -> int {
	at := 4
	hello_put_u16(dst, &at, 0x0303)
	for b, i in random {dst[at + i] = b}; at += 32
	dst[at] = u8(len(session))
	at += 1
	copy(dst[at:], session)
	at += len(session)
	hello_put_u16(dst, &at, u16(cipher))
	dst[at] = 0
	at += 1
	hello_put_u16(dst, &at, u16(14 + len(public)))
	hello_put_u16(dst, &at, 43)
	hello_put_u16(dst, &at, 2)
	hello_put_u16(dst, &at, 0x0304)
	hello_put_u16(dst, &at, 51)
	hello_put_u16(dst, &at, u16(4 + len(public)))
	hello_put_u16(dst, &at, u16(group))
	hello_put_u16(dst, &at, u16(len(public)))
	copy(dst[at:], public)
	at += len(public)
	dst[0] = 2
	server_flight_put24(dst[1:4], at - 4)
	return at
}

@(private)
server_flight_curve :: proc(group: Named_Group) -> ecdh.Curve {
	#partial switch group {
	case .X448:
		return .X448
	case .Secp256r1:
		return .SECP256R1
	case .Secp384r1:
		return .SECP384R1
	}

	// X25519, and the classical half of X25519MLKEM768.
	return .X25519
}

// Private deterministic seam; production uses OS-generated keys through the
// pointer API, never a by-value ECDH union or a persistent per-owner key.
@(private)
server_flight_prepare_hello :: proc(owner: ^Server_Handshake, private_key, random: [32]u8) -> Server_Handshake_Error {
	private: ecdh.Private_Key
	defer ecdh.private_key_clear(&private)

	key := private_key
	defer crypto.zero_explicit(&key, size_of(key))

	if !ecdh.private_key_set_bytes(&private, server_flight_curve(owner._selection.group), key[:]) {
		return .Malformed
	}
	return server_flight_prepare_ecdh(owner, &private, random)
}

// The server's half of the key exchange for the selected group: its share
// into share_dst and the shared secret into secret_dst. X25519MLKEM768
// encapsulates to the client's ML-KEM key and adds X25519 with private
// (RFC 8446 section 4.2.8; the hybrid concatenates KEM then ECDH).
@(private)
server_flight_key_exchange :: proc(
	group: Named_Group,
	private: ^ecdh.Private_Key,
	peer_share: []u8,
	share_dst, secret_dst: []u8,
) -> (
	share: []u8,
	secret: []u8,
	ok: bool,
) {
	share = share_dst[:named_group_share_size(group, true)]
	curve := server_flight_curve(group)
	classical_peer, classical_share := peer_share, share
	classical_secret := secret_dst[:ecdh.SHARED_SECRET_SIZES[curve]]
	secret = classical_secret

	if group == .X25519MLKEM768 {
		kem_key_size := mlkem.ENCAPSULATION_KEY_SIZES[.ML_KEM_768]
		kem_ciphertext_size := mlkem.CIPHERTEXT_SIZES[.ML_KEM_768]
		secret = secret_dst[:mlkem.SHARED_SECRET_SIZE + len(classical_secret)]
		classical_secret = secret[mlkem.SHARED_SECRET_SIZE:]
		classical_peer = peer_share[kem_key_size:]
		classical_share = share[kem_ciphertext_size:]

		if !mlkem.encaps(
			.ML_KEM_768,
			peer_share[:kem_key_size],
			secret[:mlkem.SHARED_SECRET_SIZE],
			share[:kem_ciphertext_size],
		) {
			return nil, nil, false
		}
	}

	peer: ecdh.Public_Key
	defer ecdh.public_key_clear(&peer)

	if !ecdh.public_key_set_bytes(&peer, curve, classical_peer) || !ecdh.ecdh(private, &peer, classical_secret) {
		return nil, nil, false
	}

	ecdh.private_key_public_bytes(private, classical_share)
	return share, secret, true
}

// Emits ServerHello for the selected suite and group, then runs upstream's
// schedule to the handshake traffic secrets over the transcript through it.
@(private)
server_flight_prepare_ecdh :: proc(
	owner: ^Server_Handshake,
	private: ^ecdh.Private_Key,
	random: [32]u8,
) -> Server_Handshake_Error {
	f := &owner._flight
	group, cipher := owner._selection.group, owner._selection.cipher
	algorithm := CIPHER_SUITE_HASH[cipher]
	size := hash.DIGEST_SIZES[algorithm]

	shared_storage: [mlkem.SHARED_SECRET_SIZE + 56]u8
	defer crypto.zero_explicit(&shared_storage, size_of(shared_storage))

	share_storage: [MAX_KEY_SHARE_SIZE]u8
	share, shared, agreed := server_flight_key_exchange(
		group,
		private,
		owner._selection.peer_key_share,
		share_storage[:],
		shared_storage[:],
	)
	if !agreed {
		return .Malformed
	}

	// Header, version, random, session, suite, compression, extension length,
	// supported_versions, key_share and the optional pre_shared_key.
	wire: [44 + 32 + 6 + 8 + MAX_KEY_SHARE_SIZE + 6]u8
	n := server_flight_group_hello(wire[:], owner._hello.session_id, group, share, random, cipher)
	if owner._resumed {
		at := n
		hello_put_u16(wire[:], &at, 41)
		hello_put_u16(wire[:], &at, 2)
		hello_put_u16(wire[:], &at, owner._resumption.selected_index)
		ext_at := 42 + len(owner._hello.session_id)
		retry_put_u16(wire[:], ext_at, u16(at - ext_at - 2))
		n = at
		server_flight_put24(wire[1:4], n - 4)
	}

	staged := owner._transcript
	transcript_update(&staged, wire[:n])
	digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
	digest := transcript_hash(&staged, digest_storage[:])

	psk: []u8
	if owner._resumed {
		psk = owner._resumption.claims.psk[:]
	}

	schedule_init(&f.keys, algorithm, psk)
	update_handshake_keys(&f.keys, shared)
	schedule_derive_secret(&f.keys, "c hs traffic", digest, f.client_handshake_secret[:size])
	schedule_derive_secret(&f.keys, "s hs traffic", digest, f.server_handshake_secret[:size])
	f.cipher = cipher

	// Publishing copies the bytes into the owner before this frame returns.
	if e := server_flight_bytes(owner, mem.slice_ptr(cast(^u8)(cast(rawptr)&wire), n), true); e != .None {
		return e
	}

	server_handshake_release_input(owner)
	f.stage = .Handshake_Write
	return .None
}
