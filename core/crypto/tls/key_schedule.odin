package tls

import "core:crypto"
import "core:crypto/hash"
import "core:crypto/hkdf"
import "core:crypto/hmac"

// The handshake and connection key schedule is upstream's (tls_key_schedule.odin):
// Handshake_Keys carries the early, handshake and master secret, and
// Connection_Secrets the traffic secrets and AEAD state of the negotiated
// suite. This file adds what that schedule does not name: a PSK early secret,
// the secrets derived from a transcript digest (binder, early traffic,
// resumption), and the SHA-256 by-value forms the QUIC hooks and the pure
// codecs expose.

Key_Schedule_Error :: enum {
	None,
	Invalid_Shared_Secret,
	Invalid_Client_Hello,
	Invalid_Server_Hello,
	Invalid_Secret_Length,
	Invalid_Label_Length,
	Context_Oversized,
	Output_Oversized,
}

// TLS 1.3 HKDF-Expand-Label (RFC 8446 section 7.1) for the hash of the suite.
// Performs all validation before writing dst. Labels exclude the "tls13 "
// prefix and must be nonempty; output is bounded by the hash's HKDF limit.
hkdf_expand_label :: proc(
	secret: []u8,
	label: string,
	label_context: []u8,
	dst: []u8,
	algorithm: hash.Algorithm = .SHA256,
) -> Key_Schedule_Error {
	digest_size := hash.DIGEST_SIZES[algorithm]
	if digest_size == 0 || len(secret) != digest_size {
		return .Invalid_Secret_Length
	}

	if len(label) < 1 || len(label) > 249 {
		return .Invalid_Label_Length
	}

	if len(label_context) > 255 {
		return .Context_Oversized
	}

	if len(dst) > 255 * digest_size {
		return .Output_Oversized
	}

	info: [2 + 1 + 255 + 1 + 255]u8
	info[0] = u8(len(dst) >> 8)
	info[1] = u8(len(dst))
	info[2] = u8(6 + len(label))
	copy(info[3:9], "tls13 ")
	copy(info[9:][:len(label)], label)

	at := 9 + len(label)
	info[at] = u8(len(label_context))
	at += 1
	copy(info[at:][:len(label_context)], label_context)
	at += len(label_context)

	hkdf.expand(algorithm, secret, info[:at], dst)
	return .None
}

// Every internal call uses secrets sized by their hash and known TLS labels,
// so label validation cannot fail unless this code is changed.
schedule_expand :: proc(algorithm: hash.Algorithm, secret: []u8, label: string, context_bytes, dst: []u8) {
	err := hkdf_expand_label(secret, label, context_bytes, dst, algorithm)
	assert(err == .None, "invalid internal TLS HKDF parameters")
}

// The current stage secret of keys: early, handshake or master.
schedule_secret :: proc(keys: ^Handshake_Keys) -> []u8 {
	return keys.secret[:hash.DIGEST_SIZES[keys.hash]]
}

// Early secret of the schedule. An empty psk is the full handshake's zero
// IKM (upstream's init_handshake_keys); a resumption PSK replaces that IKM.
schedule_init :: proc(keys: ^Handshake_Keys, algorithm: hash.Algorithm, psk: []u8 = nil) {
	init_handshake_keys(keys, algorithm)
	if len(psk) == 0 {
		return
	}

	zeroes: [hash.MAX_DIGEST_SIZE]u8
	hkdf.extract(algorithm, zeroes[:hash.DIGEST_SIZES[algorithm]], psk, schedule_secret(keys))
}

// Derive-Secret(stage secret, label, transcript) for a transcript digest.
schedule_derive_secret :: proc(keys: ^Handshake_Keys, label: string, transcript_digest: []u8, dst: []u8) {
	schedule_expand(keys.hash, schedule_secret(keys), label, transcript_digest, dst)
}

// The Finished MAC over a transcript digest (RFC 8446 section 4.4.4), also the
// PSK binder when base_key is the binder key. dst holds one digest.
schedule_finished_mac :: proc(algorithm: hash.Algorithm, base_key, transcript_digest, dst: []u8) {
	finished_key_storage: [hash.MAX_DIGEST_SIZE]u8
	defer crypto.zero_explicit(&finished_key_storage, size_of(finished_key_storage))

	finished_key := finished_key_storage[:hash.DIGEST_SIZES[algorithm]]
	schedule_expand(algorithm, base_key, "finished", nil, finished_key)
	hmac.sum(algorithm, dst, transcript_digest, finished_key)
}

// Loads one traffic secret of suite into the role's slot of scratch secrets,
// so upstream's per-direction derivations can run on a secret that was
// exported, stored or received as an event.
schedule_load_secret :: proc(secrets: ^Connection_Secrets, suite: Cipher_Suite, traffic_secret: []u8, is_client: bool) {
	secrets.hash = CIPHER_SUITE_HASH[suite]
	secrets.aead = CIPHER_SUITE_AEAD[suite]
	secrets.is_client = is_client
	if is_client {
		copy(secrets.client_secret[:], traffic_secret)
	} else {
		copy(secrets.server_secret[:], traffic_secret)
	}
}

schedule_message_valid :: proc(wire: []u8, message_type: Handshake_Type) -> bool {
	if len(wire) < 4 || wire[0] != u8(message_type) {
		return false
	}

	body_size := int(wire[1]) << 16 | int(wire[2]) << 8 | int(wire[3])
	return body_size == len(wire) - 4
}

// SHA-256 by-value forms
//
// TLS_AES_128_GCM_SHA256 only: the secrets QUIC consumes and the pure codecs
// the tests and harnesses drive. They hold no schedule logic of their own
// beyond naming the labels for a transcript digest.

Handshake_Secrets :: struct {
	handshake_secret:      [32]u8,
	client_traffic_secret: [32]u8,
	server_traffic_secret: [32]u8,
	client_key:            [16]u8,
	server_key:            [16]u8,
	client_iv:             [12]u8,
	server_iv:             [12]u8,
}

// AES-128-GCM/SHA-256 handshake schedule (RFC 8446 sections 7.1, 7.3).
// psk is empty for a full handshake (zero IKM). A 32-byte resumption PSK
// selects psk_dhe_ke. This does not derive early traffic keys or a replay window.
// Hashes exact ClientHello || ServerHello handshake messages, including their
// four-byte headers and excluding record headers. Message semantics must have
// been checked by the handshake layer; this procedure checks framing only.
// The returned secrets remain unauthenticated until CertificateVerify and
// Finished verification complete. The caller owns and must clear the result.
handshake_secrets_derive :: proc(
	shared_secret: [32]u8,
	client_hello: []u8,
	server_hello: []u8,
	transcript_prefix: []u8 = nil,
	psk: []u8 = nil,
) -> (
	secrets: Handshake_Secrets,
	err: Key_Schedule_Error,
) {
	if !schedule_message_valid(client_hello, .Client_Hello) {
		return {}, .Invalid_Client_Hello
	}

	if !schedule_message_valid(server_hello, .Server_Hello) {
		return {}, .Invalid_Server_Hello
	}

	t: Handshake_Transcript
	transcript_init(&t)
	transcript_update(&t, transcript_prefix)
	transcript_update(&t, client_hello)
	transcript_update(&t, server_hello)
	return handshake_secrets_derive_from_hash(shared_secret, transcript_snapshot(&t), psk)
}

// The caller has validated message framing/order. Hash CH through SH inclusive,
// with the synthetic message_hash prefix when retry was accepted. Returned
// client/server directions are protocol roles, independent of the local role.
handshake_secrets_derive_from_hash :: proc(
	shared_secret: [32]u8,
	transcript_hash: [32]u8,
	psk: []u8 = nil,
) -> (secrets: Handshake_Secrets, err: Key_Schedule_Error) {
	shared := shared_secret
	defer crypto.zero_explicit(&shared, size_of(shared))

	if len(psk) != 0 && len(psk) != 32 {
		return {}, .Invalid_Secret_Length
	}

	if crypto.is_zero_constant_time(shared[:]) == 1 {
		return {}, .Invalid_Shared_Secret
	}

	keys: Handshake_Keys
	defer clear_handshake_keys(&keys)

	schedule_init(&keys, .SHA256, psk)
	update_handshake_keys(&keys, shared[:])
	copy(secrets.handshake_secret[:], schedule_secret(&keys))

	digest := transcript_hash
	schedule_derive_secret(&keys, "c hs traffic", digest[:], secrets.client_traffic_secret[:])
	schedule_derive_secret(&keys, "s hs traffic", digest[:], secrets.server_traffic_secret[:])
	secrets.client_key, secrets.client_iv = traffic_key_iv(secrets.client_traffic_secret)
	secrets.server_key, secrets.server_iv = traffic_key_iv(secrets.server_traffic_secret)
	return secrets, .None
}

// Finished verification and application key derivation

FINISHED_MESSAGE_SIZE :: 4 + 32
MAX_FINISHED_MESSAGE_SIZE :: 4 + MAX_TRANSCRIPT_HASH_SIZE

Finished_Error :: enum {
	None,
	Destination_Undersized,
	Invalid_Length,
	Unexpected_Handshake_Type,
	Verification_Failed,
}

Application_Secrets :: struct {
	master_secret:         [32]u8,
	client_traffic_secret: [32]u8,
	server_traffic_secret: [32]u8,
	client_key:            [16]u8,
	server_key:            [16]u8,
	client_iv:             [12]u8,
	server_iv:             [12]u8,
}

// RFC 8446 section 4.4.4. transcript_hash excludes the Finished being
// generated/verified, but includes all preceding handshake message headers.
finished_verify_data :: proc(traffic_secret: [32]u8, transcript_hash: [32]u8) -> (verify_data: [32]u8) {
	secret := traffic_secret
	defer crypto.zero_explicit(&secret, size_of(secret))

	digest := transcript_hash
	schedule_finished_mac(.SHA256, secret[:], digest[:], verify_data[:])
	return
}

// Takes exactly one complete SHA-256 Finished handshake message. MAC bytes
// are compared in constant time after checking the public framing fields.
finished_verify :: proc(
	message: []u8,
	traffic_secret: [32]u8,
	transcript_hash: [32]u8,
) -> Finished_Error {
	if len(message) != FINISHED_MESSAGE_SIZE {
		return .Invalid_Length
	}

	if message[0] != u8(Handshake_Type.Finished) {
		return .Unexpected_Handshake_Type
	}

	if message[1] != 0 || message[2] != 0 || message[3] != 32 {
		return .Invalid_Length
	}

	expected := finished_verify_data(traffic_secret, transcript_hash)
	defer crypto.zero_explicit(&expected, size_of(expected))

	if crypto.compare_constant_time(message[4:], expected[:]) != 1 {
		return .Verification_Failed
	}

	return .None
}

finished_encode :: proc(
	dst: []u8,
	traffic_secret: [32]u8,
	transcript_hash: [32]u8,
) -> (
	written: int,
	err: Finished_Error,
) {
	if len(dst) < FINISHED_MESSAGE_SIZE {
		return 0, .Destination_Undersized
	}

	verify_data := finished_verify_data(traffic_secret, transcript_hash)
	defer crypto.zero_explicit(&verify_data, size_of(verify_data))

	finished_header_encode(dst, 32)
	copy(dst[4:FINISHED_MESSAGE_SIZE], verify_data[:])
	return FINISHED_MESSAGE_SIZE, .None
}

finished_header_encode :: proc(dst: []u8, verify_data_size: int) {
	dst[0] = u8(Handshake_Type.Finished)
	dst[1] = 0
	dst[2] = 0
	dst[3] = u8(verify_data_size)
}

// RFC 8446 sections 7.1 and 7.3. The hash includes the server Finished but
// excludes client Finished. Only install/use these keys after authenticating
// the server and its Finished, and send client Finished under handshake keys.
// The caller owns the returned secrets and must erase them when no longer used.
application_secrets_derive :: proc(
	handshake_secret: [32]u8,
	server_finished_transcript_hash: [32]u8,
) -> (
	secrets: Application_Secrets,
) {
	keys: Handshake_Keys
	defer clear_handshake_keys(&keys)

	// Stage the handshake secret, then let upstream take it to the master secret.
	init_handshake_keys(&keys, .SHA256)
	local := handshake_secret
	defer crypto.zero_explicit(&local, size_of(local))
	copy(schedule_secret(&keys), local[:])

	zeroes: [32]u8
	update_handshake_keys(&keys, zeroes[:])
	copy(secrets.master_secret[:], schedule_secret(&keys))

	digest := server_finished_transcript_hash
	schedule_derive_secret(&keys, "c ap traffic", digest[:], secrets.client_traffic_secret[:])
	schedule_derive_secret(&keys, "s ap traffic", digest[:], secrets.server_traffic_secret[:])
	secrets.client_key, secrets.client_iv = traffic_key_iv(secrets.client_traffic_secret)
	secrets.server_key, secrets.server_iv = traffic_key_iv(secrets.server_traffic_secret)
	return secrets
}

// RFC 8446 section 7.2. Install the result only after sending/receiving the
// KeyUpdate record using the old key, and reset that direction's sequence.
traffic_secret_update :: proc(secret: [32]u8) -> (updated: [32]u8) {
	scratch: Connection_Secrets
	defer clear_connection_secrets(&scratch)

	local := secret
	defer crypto.zero_explicit(&local, size_of(local))

	schedule_load_secret(&scratch, .TLS_AES_128_GCM_SHA256, local[:], true)
	update_connection_secret(&scratch, true)
	copy(updated[:], scratch.client_secret[:32])
	return
}

traffic_key_iv :: proc(secret: [32]u8) -> (key: [16]u8, iv: [12]u8) {
	local := secret
	defer crypto.zero_explicit(&local, size_of(local))

	schedule_expand(.SHA256, local[:], "key", nil, key[:])
	schedule_expand(.SHA256, local[:], "iv", nil, iv[:])
	return key, iv
}
