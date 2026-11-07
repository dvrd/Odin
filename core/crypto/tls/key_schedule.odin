package tls

import "core:crypto"
import "core:crypto/hkdf"
import "core:crypto/hmac"

// Handshake key derivation

Handshake_Secrets :: struct {
	handshake_secret:      [32]u8,
	client_traffic_secret: [32]u8,
	server_traffic_secret: [32]u8,
	client_key:            [16]u8,
	server_key:            [16]u8,
	client_iv:             [12]u8,
	server_iv:             [12]u8,
}

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

// TLS 1.3 HKDF-Expand-Label for SHA-256 (RFC 8446 section 7.1).
// Performs all validation before writing dst. Labels exclude the "tls13 "
// prefix and must be nonempty; output is bounded by SHA-256's HKDF limit.
hkdf_expand_label :: proc(
	secret: []u8,
	label: string,
	label_context: []u8,
	dst: []u8,
) -> Key_Schedule_Error {
	if len(secret) != 32 do return .Invalid_Secret_Length

	if len(label) < 1 || len(label) > 249 {
		return .Invalid_Label_Length
	}

	if len(label_context) > 255 do return .Context_Oversized

	if len(dst) > 255 * 32 do return .Output_Oversized

	key_schedule_expand_label(secret, label, label_context, dst)
	return .None
}

// No-PSK AES-128-GCM/SHA-256 handshake schedule (RFC 8446 sections 7.1, 7.3).
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
) -> (
	secrets: Handshake_Secrets,
	err: Key_Schedule_Error,
) {
	if !key_schedule_message_valid(client_hello, .Client_Hello) {
		return {}, .Invalid_Client_Hello
	}

	if !key_schedule_message_valid(server_hello, .Server_Hello) {
		return {}, .Invalid_Server_Hello
	}

	t: Handshake_Transcript
	transcript_init(&t)
	transcript_update(&t, transcript_prefix)
	transcript_update(&t, client_hello)
	transcript_update(&t, server_hello)
	return handshake_secrets_derive_from_hash(shared_secret, transcript_snapshot(&t))
}

// The caller has validated message framing/order. Hash CH through SH inclusive,
// with the synthetic message_hash prefix when retry was accepted. Returned
// client/server directions are protocol roles, independent of the local role.
@(private)
handshake_secrets_derive_from_hash :: proc(
	shared_secret: [32]u8,
	transcript_hash: [32]u8,
) -> (secrets: Handshake_Secrets, err: Key_Schedule_Error) {
	shared := shared_secret
	defer crypto.zero_explicit(&shared, size_of(shared))
	if crypto.is_zero_constant_time(shared[:]) == 1 {
		return {}, .Invalid_Shared_Secret
	}

	zero: [32]u8
	early_secret, derived_secret: [32]u8
	defer crypto.zero_explicit(&early_secret, size_of(early_secret))
	defer crypto.zero_explicit(&derived_secret, size_of(derived_secret))
	// With no PSK the IKM is Hash.length zero bytes, not an empty string.
	hkdf.extract(.SHA256, zero[:], zero[:], early_secret[:])
	empty_hash := transcript_empty_hash()
	key_schedule_expand_label(early_secret[:], "derived", empty_hash[:], derived_secret[:])
	hkdf.extract(.SHA256, derived_secret[:], shared[:], secrets.handshake_secret[:])
	hash := transcript_hash
	handshake_traffic_secrets_derive(&secrets, hash[:])
	return secrets, .None
}

handshake_traffic_secrets_derive :: proc(secrets: ^Handshake_Secrets, transcript_hash: []u8) {
	key_schedule_expand_label(
		secrets.handshake_secret[:],
		"c hs traffic",
		transcript_hash,
		secrets.client_traffic_secret[:],
	)
	key_schedule_expand_label(
		secrets.handshake_secret[:],
		"s hs traffic",
		transcript_hash,
		secrets.server_traffic_secret[:],
	)
	key_schedule_expand_label(secrets.client_traffic_secret[:], "key", nil, secrets.client_key[:])
	key_schedule_expand_label(secrets.server_traffic_secret[:], "key", nil, secrets.server_key[:])
	key_schedule_expand_label(secrets.client_traffic_secret[:], "iv", nil, secrets.client_iv[:])
	key_schedule_expand_label(secrets.server_traffic_secret[:], "iv", nil, secrets.server_iv[:])
}

key_schedule_message_valid :: proc(wire: []u8, message_type: Handshake_Type) -> bool {
	if len(wire) < 4 || wire[0] != cast(u8)message_type {
		return false
	}

	body_size := cast(int)wire[1] << 16 | cast(int)wire[2] << 8 | cast(int)wire[3]
	return body_size == len(wire) - 4
}

// All lengths have been checked by the public wrapper, or are fixed constants
// of the handshake schedule. No allocation or attacker-sized stack buffer.
key_schedule_expand_label :: proc(secret: []u8, label: string, label_context, dst: []u8) {
	info: [2 + 1 + 255 + 1 + 255]u8
	info[0], info[1] = cast(u8)(len(dst) >> 8), cast(u8)len(dst)
	info[2] = cast(u8)(6 + len(label))
	copy(info[3:9], []u8{'t', 'l', 's', '1', '3', ' '})
	copy(info[9:][:len(label)], transmute([]u8)label)
	at := 9 + len(label)
	info[at] = cast(u8)len(label_context)
	at += 1
	copy(info[at:][:len(label_context)], label_context)
	at += len(label_context)
	hkdf.expand(.SHA256, secret, info[:at], dst)
}

// Finished verification and application key derivation

FINISHED_MESSAGE_SIZE :: 4 + 32

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
finished_verify_data :: proc(traffic_secret: [32]u8, transcript_hash: [32]u8) -> [32]u8 {
	secret := traffic_secret
	defer crypto.zero_explicit(&secret, size_of(secret))
	finished_key: [32]u8
	defer crypto.zero_explicit(&finished_key, size_of(finished_key))
	finished_expand(secret[:], "finished", nil, finished_key[:])
	hash := transcript_hash
	verify_data: [32]u8
	hmac.sum(.SHA256, verify_data[:], hash[:], finished_key[:])
	return verify_data
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

	if message[0] != cast(u8)Handshake_Type.Finished {
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
	dst[0], dst[1], dst[2], dst[3] = cast(u8)Handshake_Type.Finished, 0, 0, 32
	copy(dst[4:FINISHED_MESSAGE_SIZE], verify_data[:])
	return FINISHED_MESSAGE_SIZE, .None
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
	secret := handshake_secret
	defer crypto.zero_explicit(&secret, size_of(secret))
	derived: [32]u8
	defer crypto.zero_explicit(&derived, size_of(derived))
	zero: [32]u8
	empty_hash := transcript_empty_hash()
	finished_expand(secret[:], "derived", empty_hash[:], derived[:])
	hkdf.extract(.SHA256, derived[:], zero[:], secrets.master_secret[:])
	hash := server_finished_transcript_hash
	finished_expand(
		secrets.master_secret[:],
		"c ap traffic",
		hash[:],
		secrets.client_traffic_secret[:],
	)
	finished_expand(
		secrets.master_secret[:],
		"s ap traffic",
		hash[:],
		secrets.server_traffic_secret[:],
	)
	secrets.client_key, secrets.client_iv = traffic_key_iv(secrets.client_traffic_secret)
	secrets.server_key, secrets.server_iv = traffic_key_iv(secrets.server_traffic_secret)
	return secrets
}

// RFC 8446 section 7.2. Install the result only after sending/receiving the
// KeyUpdate record using the old key, and reset that direction's sequence.
traffic_secret_update :: proc(secret: [32]u8) -> [32]u8 {
	copy_secret := secret
	defer crypto.zero_explicit(&copy_secret, size_of(copy_secret))
	updated: [32]u8
	finished_expand(copy_secret[:], "traffic upd", nil, updated[:])
	return updated
}

traffic_key_iv :: proc(secret: [32]u8) -> (key: [16]u8, iv: [12]u8) {
	copy_secret := secret
	defer crypto.zero_explicit(&copy_secret, size_of(copy_secret))
	finished_expand(copy_secret[:], "key", nil, key[:])
	finished_expand(copy_secret[:], "iv", nil, iv[:])
	return key, iv
}

// Every call above uses fixed-size SHA-256 secrets/outputs and known TLS
// labels, so HKDF label validation cannot fail unless this code is changed.
finished_expand :: proc(secret: []u8, label: string, context_bytes, dst: []u8) {
	err := hkdf_expand_label(secret, label, context_bytes, dst)
	assert(err == .None, "invalid internal TLS HKDF parameters")
}
