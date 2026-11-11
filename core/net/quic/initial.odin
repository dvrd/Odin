package quic

import "core:bytes"
import "core:crypto"
import "core:crypto/aes"
import "core:crypto/hkdf"

Protection_Error :: enum {
	None,
	Invalid_Connection_ID,
	Invalid_Keys,
	Invalid_Packet_Number,
	Invalid_Header,
	Invalid_Length,
	Destination_Undersized,
	Overlapping_Buffers,
	Sample_Too_Short,
	Authentication_Failed,
	Invalid_Implementation,
	Zero_RTT_Disabled,
	Key_Update_Disabled,
	Header_Protection_Failed,
	Unauthenticated,
}

// Caller owns this key material. Copies create additional secrets that the
// caller must erase separately. Initial keys do not authenticate a peer.
Initial_Keys :: struct {
	secret:      [32]u8,
	key:         [16]u8,
	iv:          [12]u8,
	hp:          [16]u8,
	initialized: bool,
}
Initial_Key_Pair :: struct {
	client, server: Initial_Keys,
}

initial_keys_derive_v1 :: proc(
	client_destination_id: []u8,
) -> (
	Initial_Key_Pair,
	Protection_Error,
) {
	if len(client_destination_id) > 20 {
		return {}, .Invalid_Connection_ID
	}
	salt := [20]u8 {
		0x38,
		0x76,
		0x2c,
		0xf7,
		0xf5,
		0x59,
		0x34,
		0xb3,
		0x4d,
		0x17,
		0x9a,
		0xe6,
		0xa4,
		0xc8,
		0x0c,
		0xad,
		0xcc,
		0xbb,
		0x7f,
		0x0a,
	}
	initial_secret: [32]u8
	defer crypto.zero_explicit(&initial_secret, size_of(initial_secret))
	hkdf.extract(.SHA256, salt[:], client_destination_id, initial_secret[:])
	pair: Initial_Key_Pair
	// Explicit returns copy the value before deferred local erasure.
	defer initial_key_pair_clear(&pair)
	expand_initial_label(pair.client.secret[:], initial_secret[:], "client in")
	expand_initial_label(pair.server.secret[:], initial_secret[:], "server in")
	for keys in ([]^Initial_Keys{&pair.client, &pair.server}) {
		expand_initial_label(keys.key[:], keys.secret[:], "quic key")
		expand_initial_label(keys.iv[:], keys.secret[:], "quic iv")
		expand_initial_label(keys.hp[:], keys.secret[:], "quic hp")
		keys.initialized = true
	}
	return pair, .None
}

initial_keys_clear :: proc(keys: ^Initial_Keys) {
	if keys != nil {
		crypto.zero_explicit(keys, size_of(Initial_Keys))
	}
}
initial_key_pair_clear :: proc(keys: ^Initial_Key_Pair) {
	if keys != nil {
		crypto.zero_explicit(keys, size_of(Initial_Key_Pair))
	}
}

initial_nonce :: proc(keys: ^Initial_Keys, full_packet_number: u64) -> ([12]u8, Protection_Error) {
	if keys == nil || !keys.initialized {
		return {}, .Invalid_Keys
	}
	if full_packet_number > MAX_VARINT {
		return {}, .Invalid_Packet_Number
	}
	nonce := keys.iv
	for i in 0 ..< 8 {nonce[11 - i] ~= u8((full_packet_number >> uint(i * 8)) & 255)}
	return nonce, .None
}

// Encrypts payload+tag into dst. Header is the complete UNPROTECTED Initial
// header through PN. Its declared Length must agree with payload+tag+PN and its
// truncated PN must agree with full_packet_number. Caller enforces PN uniqueness.
// Input may alias dst exactly at plaintext start; other overlap is rejected.
// Bounds/header/alias failures leave dst unchanged. No allocation/retention.
initial_payload_seal :: proc(
	dst, header, plaintext: []u8,
	keys: ^Initial_Keys,
	full_packet_number: u64,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> (
	int,
	Protection_Error,
) {
	if implementation != .Portable && implementation != .Hardware {
		return 0, .Invalid_Implementation
	}
	nonce, e := initial_nonce(keys, full_packet_number)
	if e != .None {
		return 0, e
	}
	defer crypto.zero_explicit(&nonce, size_of(nonce))
	if u64(len(plaintext)) > INITIAL_GCM_TEXT_MAX || len(plaintext) > max(int) - 16 {
		return 0, .Invalid_Length
	}
	need := len(plaintext) + 16
	if header_error := initial_header_check(header, u64(need), full_packet_number, true); header_error != .None {
		return 0, header_error
	}
	if len(dst) < need {
		return 0, .Destination_Undersized
	}
	out := dst[:need]
	if bytes.alias(out, header) ||
	   bytes.alias(out, initial_key_storage(keys)) ||
	   bytes.alias_inexactly(out[:len(plaintext)], plaintext) ||
	   bytes.alias(out[len(plaintext):], plaintext) {
		return 0, .Overlapping_Buffers
	}
	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, keys.key[:], implementation)
	defer aes.reset_gcm(&ctx)
	aes.seal_gcm(&ctx, out[:len(plaintext)], out[len(plaintext):], nonce[:], header, plaintext)
	return need, .None
}

// Requires already unmasked header and caller-reconstructed full PN. Success
// verifies the GCM tag only, not peer identity, reserved bits or connection state.
// On authentication failure produced plaintext is zeroed and written=0. On
// preflight failure dst is unchanged. Exact ciphertext-start in-place open is
// supported and invalidates that ciphertext even on authentication failure.
initial_payload_open :: proc(
	dst, header, ciphertext_and_tag: []u8,
	keys: ^Initial_Keys,
	full_packet_number: u64,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> (
	int,
	Protection_Error,
) {
	if implementation != .Portable && implementation != .Hardware {
		return 0, .Invalid_Implementation
	}
	nonce, e := initial_nonce(keys, full_packet_number)
	if e != .None {
		return 0, e
	}
	defer crypto.zero_explicit(&nonce, size_of(nonce))
	if len(ciphertext_and_tag) < 16 || u64(len(ciphertext_and_tag) - 16) > INITIAL_GCM_TEXT_MAX {
		return 0, .Invalid_Length
	}
	need := len(ciphertext_and_tag) - 16
	if header_error := initial_header_check(header, u64(len(ciphertext_and_tag)), full_packet_number, false);
	   header_error != .None {
		return 0, header_error
	}
	if len(dst) < need {
		return 0, .Destination_Undersized
	}
	out := dst[:need]
	ciphertext := ciphertext_and_tag[:need]
	tag := ciphertext_and_tag[need:]
	if bytes.alias(out, header) ||
	   bytes.alias(out, tag) ||
	   bytes.alias(out, initial_key_storage(keys)) ||
	   bytes.alias_inexactly(out, ciphertext) {
		return 0, .Overlapping_Buffers
	}
	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, keys.key[:], implementation)
	defer aes.reset_gcm(&ctx)
	if !aes.open_gcm(&ctx, out, nonce[:], header, ciphertext, tag) {
		return 0, .Authentication_Failed
	}
	return need, .None
}

// Operates on exactly one Initial packet, after payload encryption. Packet must
// include the 16-byte sample at PN offset+4. Does not allocate or retain keys.
// Applying twice is not defined as an undo; use the explicit remove procedure.
initial_header_protection_apply :: proc(
	packet: []u8,
	keys: ^Initial_Keys,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> Protection_Error {
	return initial_header_protection(packet, keys, false, implementation)
}

// Removes HP in place; resulting header/PN remain unauthenticated until payload
// open succeeds. Validate all structural/sample bounds before changing packet.
initial_header_protection_remove :: proc(
	packet: []u8,
	keys: ^Initial_Keys,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> Protection_Error {
	return initial_header_protection(packet, keys, true, implementation)
}

@(private)
INITIAL_GCM_TEXT_MAX :: u64(0xfffffffe0)
@(private)
initial_key_storage :: proc(keys: ^Initial_Keys) -> []u8 {
	return (cast([^]u8)keys)[:size_of(Initial_Keys)]
}

@(private)
expand_initial_label :: proc(dst, secret: []u8, label: string) {
	// All call sites use fixed labels of at most9 ASCII bytes, with empty context.
	info: [20]u8
	info[0] = u8(len(dst) >> 8)
	info[1] = u8(len(dst) & 255)
	info[2] = u8(6 + len(label))
	copy(info[3:], "tls13 ")
	copy(info[9:], label)
	info[9 + len(label)] = 0
	hkdf.expand(.SHA256, secret, info[:10 + len(label)], dst)
}

@(private)
initial_header_check :: proc(
	header: []u8,
	ciphertext_length: u64,
	pn: u64,
	sending: bool,
) -> Protection_Error {
	if u64(len(header)) > max(u64) / 8 {
		return .Invalid_Length
	}
	inv, e := invariant_decode(header)
	if e != .None ||
	   !inv.long_header ||
	   inv.version != 1 ||
	   inv.first_byte & 0xf0 != 0xc0 ||
	   len(inv.destination_id) > 20 ||
	   len(inv.source_id) > 20 {
		return .Invalid_Header
	}
	if sending && inv.first_byte & 0x0c != 0 {
		return .Invalid_Header
	}
	p := inv.prefix_length
	token, w, ve := varint_decode(header[p:])
	if ve != .None {
		return .Invalid_Header
	}
	p += w
	if token > u64(len(header) - p) {
		return .Invalid_Header
	}
	p += int(token)
	declared, lw, le := varint_decode(header[p:])
	if le != .None {
		return .Invalid_Header
	}
	p += lw
	pn_length := int(inv.first_byte & 3) + 1
	if len(header) - p != pn_length {
		return .Invalid_Header
	}
	if ciphertext_length > MAX_VARINT - u64(pn_length) ||
	   declared != ciphertext_length + u64(pn_length) {
		return .Invalid_Length
	}
	for i in 0 ..< pn_length {
		if header[p + i] != u8((pn >> uint((pn_length - 1 - i) * 8)) & 255) {
			return .Invalid_Packet_Number
		}
	}
	return .None
}

@(private)
initial_header_protection :: proc(
	packet: []u8,
	keys: ^Initial_Keys,
	remove: bool,
	implementation: aes.Implementation,
) -> Protection_Error {
	if keys == nil || !keys.initialized {
		return .Invalid_Keys
	}
	if implementation != .Portable && implementation != .Hardware {
		return .Invalid_Implementation
	}
	view, consumed, e := packet_decode_v1(packet)
	if e != .None || view.kind != .Initial || consumed != len(packet) {
		return .Invalid_Header
	}
	p := view.packet_number_offset
	if len(packet) - p < 20 {
		return .Sample_Too_Short
	}
	if bytes.alias(packet, initial_key_storage(keys)) {
		return .Overlapping_Buffers
	}
	ctx: aes.Context_ECB
	aes.init_ecb(&ctx, keys.hp[:], implementation)
	defer aes.reset_ecb(&ctx)
	mask: [16]u8
	defer crypto.zero_explicit(&mask, size_of(mask))
	aes.encrypt_ecb(&ctx, mask[:], packet[p + 4:p + 20])
	first := packet[0]
	if remove {
		first ~= mask[0] & 15
	}
	n := int(first & 3) + 1
	// The complete sample already guarantees space for every possible PN length.
	packet[0] ~= mask[0] & 15
	for i in 0 ..< n {packet[p + i] ~= mask[1 + i]}
	return .None
}
