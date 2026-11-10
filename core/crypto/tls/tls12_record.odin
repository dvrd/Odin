package tls

import "core:bytes"
import "core:crypto"
import "core:crypto/aes"

TLS12_GCM_EXPLICIT_NONCE_SIZE :: 8
TLS12_GCM_OVERHEAD :: TLS12_GCM_EXPLICIT_NONCE_SIZE + GCM_TAG_SIZE
TLS12_MAX_CIPHERTEXT_SIZE :: MAX_PLAINTEXT_SIZE + TLS12_GCM_OVERHEAD
// RFC9325 section4.4 recommends the TLS1.3 2^24.5 full-record ceiling also
// for TLS1.2 AESGCM. A conservative2^24 cap applies to each direction/key.
TLS12_MAX_RECORDS_PER_KEY :: u64(1 << 24)

// Separate type prevents accidentally treating TLS1.2 explicit-nonce/AAD records
// as TLS1.3 inner-content records. One owner/direction; never copy/reinitialize
// with the same key/salt or share between readers/writers. No renegotiation.
TLS12_Record_Protection :: struct {
	ctx: aes.Context_GCM,
	iv: [4]u8,
	sequence: u64,
	initialized: bool,
	failure: Record_Protection_Error,
}

tls12_record_protection_clear :: proc(state: ^TLS12_Record_Protection) {
	if state != nil {crypto.zero_explicit(state, size_of(state^))}
}

tls12_record_protection_init :: proc(state: ^TLS12_Record_Protection, key: [16]u8, iv: [4]u8) {
	if state == nil {return}
	tls12_record_protection_clear(state)
	secret := key
	defer crypto.zero_explicit(&secret, size_of(secret))
	aes.init_gcm(&state.ctx, secret[:])
	state.iv = iv
	state.initialized = true
}

// Complete TLS1.2 record, RFC5246 section6.2.3.3/RFC5288. The deterministic
// explicit nonce is sequence in network order (RFC9325 section4.2). Validation
// preserves all inputs/dst and consumes no sequence; body and dst cannot alias.
tls12_record_seal :: proc(
	state: ^TLS12_Record_Protection,
	dst: []u8,
	content_type: TLS_Content_Type,
	body: []u8,
) -> (written: int, error: Record_Protection_Error) {
	if validation_error := tls12_protection_validate(state); validation_error != .None {return 0, validation_error}
	if validation_error := tls12_content_validate(content_type, len(body)); validation_error != .None {return 0, validation_error}
	wire_size := RECORD_HEADER_SIZE + TLS12_GCM_OVERHEAD + len(body)
	if len(dst) < wire_size {return 0, .Destination_Undersized}
	if bytes.alias(dst[:wire_size], body) {return 0, .Overlapping_Buffers}
	header := record_header_encode({content_type, LEGACY_TLS_1_2, u16(len(body) + TLS12_GCM_OVERHEAD)})
	copy(dst[:RECORD_HEADER_SIZE], header[:])
	nonce: [12]u8
	copy(nonce[:4], state.iv[:])
	tls12_sequence_encode(nonce[4:], state.sequence)
	copy(dst[RECORD_HEADER_SIZE:][:8], nonce[4:])
	aad := tls12_aad(state.sequence, content_type, len(body))
	at := RECORD_HEADER_SIZE + TLS12_GCM_EXPLICIT_NONCE_SIZE
	aes.seal_gcm(&state.ctx, dst[at:][:len(body)], dst[at + len(body):wire_size], nonce[:], aad[:], body)
	state.sequence += 1
	return wire_size, .None
}

// Receiver uses the peer's explicit nonce, not an assumed sequence encoding;
// its own monotonically increasing sequence authenticates AAD. Local size/alias
// errors are retryable. Malformed/authenticated-content failures erase/poison
// the direction. Tag failure returns no plaintext and zeros the affected dst.
tls12_record_open :: proc(
	state: ^TLS12_Record_Protection,
	dst: []u8,
	wire: []u8,
) -> (content_type: TLS_Content_Type, body: []u8, error: Record_Protection_Error) {
	if validation_error := tls12_protection_validate(state); validation_error != .None {return {}, nil, validation_error}
	if len(wire) < RECORD_HEADER_SIZE {return {}, nil, tls12_protection_fail(state, .Header_Incomplete)}
	if wire[1] != 3 || wire[2] != 3 {return {}, nil, tls12_protection_fail(state, .Invalid_Legacy_Version)}
	content_type = TLS_Content_Type(wire[0])
	cipher_size := int(wire[3]) << 8 | int(wire[4])
	if cipher_size > TLS12_MAX_CIPHERTEXT_SIZE {return {}, nil, tls12_protection_fail(state, .Record_Oversized)}
	if len(wire) != RECORD_HEADER_SIZE + cipher_size {return {}, nil, tls12_protection_fail(state, .Record_Length_Mismatch)}
	if cipher_size < TLS12_GCM_OVERHEAD {return {}, nil, tls12_protection_fail(state, .Ciphertext_Too_Short)}
	plain_size := cipher_size - TLS12_GCM_OVERHEAD
	if validation_error := tls12_content_validate(content_type, plain_size); validation_error != .None {
		return {}, nil, tls12_protection_fail(state, validation_error)
	}
	if len(dst) < plain_size {return {}, nil, .Destination_Undersized}
	if bytes.alias(dst[:plain_size], wire) {return {}, nil, .Overlapping_Buffers}
	nonce: [12]u8
	copy(nonce[:4], state.iv[:]); copy(nonce[4:], wire[RECORD_HEADER_SIZE:][:8])
	aad := tls12_aad(state.sequence, content_type, plain_size)
	at := RECORD_HEADER_SIZE + TLS12_GCM_EXPLICIT_NONCE_SIZE
	if !aes.open_gcm(&state.ctx, dst[:plain_size], nonce[:], aad[:], wire[at:][:plain_size], wire[at + plain_size:]) {
		crypto.zero_explicit(raw_data(dst), plain_size)
		return {}, nil, tls12_protection_fail(state, .Authentication_Failed)
	}
	state.sequence += 1
	return content_type, dst[:plain_size], .None
}

@(private)
tls12_protection_validate :: proc(state: ^TLS12_Record_Protection) -> Record_Protection_Error {
	if state == nil {return .Invalid_State}
	if state.failure != .None {return state.failure}
	if !state.initialized {return .Invalid_State}
	if state.sequence >= TLS12_MAX_RECORDS_PER_KEY {return .Key_Usage_Limit}
	return .None
}

@(private)
tls12_protection_fail :: proc(state: ^TLS12_Record_Protection, error: Record_Protection_Error) -> Record_Protection_Error {
	tls12_record_protection_clear(state)
	state.failure = error
	return error
}

@(private)
tls12_content_validate :: proc(content_type: TLS_Content_Type, size: int) -> Record_Protection_Error {
	if size > MAX_PLAINTEXT_SIZE {return .Record_Oversized}
	#partial switch content_type {
	case .Application_Data: return .None
	case .Handshake:
		if size == 0 {return .Empty_Handshake}
		return .None
	case .Alert:
		// TLS1.2 permits same-type messages to span/coalesce across records.
		// The driver assembles bounded two-byte alerts; records only forbid0.
		if size == 0 {return .Invalid_Alert_Length}
		return .None
	}
	return .Unexpected_Outer_Content_Type
}

@(private)
tls12_sequence_encode :: proc(dst: []u8, sequence: u64) {
	for i in 0 ..< 8 {dst[i] = u8(sequence >> uint(8 * (7-i)))}
}

@(private)
tls12_aad :: proc(sequence: u64, content_type: TLS_Content_Type, size: int) -> (aad: [13]u8) {
	tls12_sequence_encode(aad[:8], sequence)
	aad[8], aad[9], aad[10] = u8(content_type), 3, 3
	aad[11], aad[12] = u8(size >> 8), u8(size)
	return
}
