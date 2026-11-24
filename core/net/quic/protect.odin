package quic

import "core:bytes"
import "core:crypto"
import "core:crypto/aes"
import "core:crypto/chacha20"
import "core:crypto/chacha20poly1305"
import "core:crypto/tls"
import "core:encoding/endian"

Aead :: enum {
	AES_128_GCM,
	ChaCha20_Poly1305,
}

// Packet protection keys for Handshake or 1-RTT. Initial keys stay Initial_Keys.
// ChaCha is only for the published RFC 9001 A.5 vector; native TLS installs AES.
// 1-RTT key update replaces secret, key, and IV. Header protection key stays.
Packet_Keys :: struct {
	aead:           Aead,
	key:            [32]u8,
	iv:             [12]u8,
	hp:             [32]u8,
	secret:         [32]u8,
	key_len:        u8,
	hp_len:         u8,
	phase:          u8,
	update_pending: bool,
	has_secret:     bool,
	one_rtt:        bool,
 zero_rtt:bool,
	initialized:    bool,
}

packet_keys_clear :: proc(keys: ^Packet_Keys) {
	if keys != nil {
		crypto.zero_explicit(keys, size_of(Packet_Keys))
	}
}

packet_keys_from_tls :: proc(dst: ^Packet_Keys, secret: [32]u8, level: tls.Quic_Secret_Level) -> Protection_Error {
	keys, e := tls.quic_packet_keys_derive(secret, level)
	defer tls.quic_direction_keys_clear(&keys)
	if e != nil || dst == nil {
		return .Invalid_Keys
	}
	return packet_keys_set_aes(dst, keys.key[:], keys.iv[:], keys.hp[:], keys.secret[:], level == .Application)
}

packet_keys_set_aes :: proc(dst: ^Packet_Keys, key, iv, hp, secret: []u8, one_rtt: bool) -> Protection_Error {
	if dst == nil || len(key) != 16 || len(iv) != 12 || len(hp) != 16 || len(secret) != 32 {
		return .Invalid_Keys
	}
	packet_keys_clear(dst)
	copy(dst.key[:], key)
	copy(dst.iv[:], iv)
	copy(dst.hp[:], hp)
	copy(dst.secret[:], secret)
	dst.key_len = 16
	dst.hp_len = 16
	dst.aead = .AES_128_GCM
	dst.has_secret = true
	dst.one_rtt = one_rtt
	dst.initialized = true
	return .None
}

// RFC 9001 Appendix A.5 lengths. Not installed by the TLS seam.
packet_keys_chacha :: proc(dst: ^Packet_Keys, secret: []u8) -> Protection_Error {
	if dst == nil || len(secret) != 32 {
		return .Invalid_Keys
	}
	key, hp: [32]u8
	iv: [12]u8
	defer crypto.zero_explicit(&key, size_of(key))
	defer crypto.zero_explicit(&hp, size_of(hp))
	defer crypto.zero_explicit(&iv, size_of(iv))
	if tls.hkdf_expand_label(secret, "quic key", nil, key[:]) != nil ||
	   tls.hkdf_expand_label(secret, "quic iv", nil, iv[:]) != nil ||
	   tls.hkdf_expand_label(secret, "quic hp", nil, hp[:]) != nil {
		return .Invalid_Keys
	}
	packet_keys_clear(dst)
	dst.key = key
	dst.hp = hp
	dst.iv = iv
	copy(dst.secret[:], secret)
	dst.key_len = 32
	dst.hp_len = 32
	dst.aead = .ChaCha20_Poly1305
	dst.has_secret = true
	dst.one_rtt = true
	dst.initialized = true
	return .None
}

// RFC 9001 §5.4 and §6. secret_n+1 = HKDF-Expand-Label(secret_n, "quic ku", "", 32).
// The next packet key and IV come from that secret. quic hp stays the connection key
// so the key-phase bit can be read with the installed header protection key.
// One unconfirmed generation at a time. A second update is Key_Update_Disabled.
packet_keys_advance :: proc(keys: ^Packet_Keys) -> Protection_Error {
	if keys == nil || !keys.initialized || !keys.has_secret || !keys.one_rtt || keys.update_pending {
		return .Key_Update_Disabled
	}
	next_secret, next_key: [32]u8
	next_iv: [12]u8
	defer crypto.zero_explicit(&next_secret, size_of(next_secret))
	defer crypto.zero_explicit(&next_key, size_of(next_key))
	defer crypto.zero_explicit(&next_iv, size_of(next_iv))
	if e := packet_keys_next(keys, &next_secret, &next_key, &next_iv); e != .None {
		return e
	}
	keys.secret = next_secret
	keys.key = next_key
	keys.iv = next_iv
	keys.phase ~= 1
	keys.update_pending = true
	return .None
}

// Clears the one-update gate. This is not an ACK.
packet_keys_confirm_update :: proc(keys: ^Packet_Keys) -> Protection_Error {
	if keys == nil || !keys.initialized || !keys.has_secret || !keys.one_rtt || !keys.update_pending {
		return .Key_Update_Disabled
	}
	keys.update_pending = false
	return .None
}

@(private)
packet_keys_next :: proc(keys: ^Packet_Keys, secret: ^[32]u8, key: ^[32]u8, iv: ^[12]u8) -> Protection_Error {
	if keys == nil || secret == nil || key == nil || iv == nil || !keys.has_secret {
		return .Invalid_Keys
	}
	if keys.key_len != 16 && keys.key_len != 32 {
		return .Invalid_Keys
	}
	current := keys.secret
	defer crypto.zero_explicit(&current, size_of(current))
	if tls.hkdf_expand_label(current[:], "quic ku", nil, secret[:]) != nil {
		return .Invalid_Keys
	}
	if tls.hkdf_expand_label(secret[:], "quic key", nil, key[:int(keys.key_len)]) != nil ||
	   tls.hkdf_expand_label(secret[:], "quic iv", nil, iv[:]) != nil {
		return .Invalid_Keys
	}
	return .None
}

packet_nonce :: proc(keys: ^Packet_Keys, full_packet_number: u64) -> ([12]u8, Protection_Error) {
	if keys == nil || !keys.initialized {
		return {}, .Invalid_Keys
	}
	return nonce_from_iv(keys.iv, full_packet_number)
}

@(private)
nonce_from_iv :: proc(iv: [12]u8, full_packet_number: u64) -> ([12]u8, Protection_Error) {
	if full_packet_number > MAX_VARINT {
		return {}, .Invalid_Packet_Number
	}
	nonce := iv
	for i in 0 ..< 8 {
		nonce[11 - i] ~= u8((full_packet_number >> uint(i * 8)) & 255)
	}
	return nonce, .None
}

// RFC 9000 Appendix A.3. has_largest false means no packet has been authenticated
// yet, so the next expected packet number is 0.
packet_number_reconstruct :: proc(
	has_largest: bool,
	largest, truncated: u64,
	pn_nbits: int,
) -> (
	u64,
	Protection_Error,
) {
	if pn_nbits != 8 && pn_nbits != 16 && pn_nbits != 24 && pn_nbits != 32 {
		return 0, .Invalid_Packet_Number
	}
	pn_win := u64(1) << uint(pn_nbits)
	if truncated >= pn_win {
		return 0, .Invalid_Packet_Number
	}
	expected: u64
	if has_largest {
		if largest >= (u64(1) << 62) - 1 {
			return 0, .Invalid_Packet_Number
		}
		expected = largest + 1
	}
	pn_hwin := pn_win / 2
	pn_mask := pn_win - 1
	candidate := (expected & ~pn_mask) | truncated
	limit := (u64(1) << 62) - pn_win
	if expected >= pn_hwin && candidate <= expected - pn_hwin && candidate < limit {
		candidate += pn_win
	} else if expected <= max(u64) - pn_hwin && candidate > expected + pn_hwin && candidate >= pn_win {
		candidate -= pn_win
	}
	if candidate >= u64(1) << 62 {
		return 0, .Invalid_Packet_Number
	}
	return candidate, .None
}

// header is the complete unprotected header through the packet number.
// Handshake long headers and 1-RTT short headers only. 0-RTT is refused.
payload_seal :: proc(
	dst, header, plaintext: []u8,
	keys: ^Packet_Keys,
	full_packet_number: u64,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> (
	int,
	Protection_Error,
) {
	return payload_aead(dst, header, plaintext, keys, full_packet_number, implementation, true)
}

payload_open :: proc(
	dst, header, ciphertext_and_tag: []u8,
	keys: ^Packet_Keys,
	full_packet_number: u64,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> (
	int,
	Protection_Error,
) {
	return payload_aead(dst, header, ciphertext_and_tag, keys, full_packet_number, implementation, false)
}

// dcid_len is the short-header Destination Connection ID length. Long headers
// parse it. One packet only. The fixed bit is not masked; PN length is.
header_protection_apply :: proc(
	packet: []u8,
	keys: ^Packet_Keys,
	kind: Packet_Kind,
	destination_id_len: int = 0,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> Protection_Error {
	return header_protection(packet, keys, kind, destination_id_len, false, implementation)
}

header_protection_remove :: proc(
	packet: []u8,
	keys: ^Packet_Keys,
	kind: Packet_Kind,
	destination_id_len: int = 0,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> Protection_Error {
	return header_protection(packet, keys, kind, destination_id_len, true, implementation)
}

@(private)
payload_aead :: proc(
	dst, header, text: []u8,
	keys: ^Packet_Keys,
	full_packet_number: u64,
	implementation: aes.Implementation,
	seal: bool,
) -> (
	int,
	Protection_Error,
) {
	if keys == nil || !keys.initialized {
		return 0, .Invalid_Keys
	}
	if keys.aead == .AES_128_GCM && implementation != .Portable && implementation != .Hardware {
		return 0, .Invalid_Implementation
	}
	nonce, e := packet_nonce(keys, full_packet_number)
	if e != .None {
		return 0, e
	}
	defer crypto.zero_explicit(&nonce, size_of(nonce))
	plain_len := len(text)
	if !seal {
		if len(text) < 16 {
			return 0, .Invalid_Length
		}
		plain_len = len(text) - 16
	}
	if u64(plain_len) > u64(0xfffffffe0) || plain_len > max(int) - 16 {
		return 0, .Invalid_Length
	}
	aead_len := u64(plain_len + 16)
	kind, header_error := protected_header_kind(header, full_packet_number, seal, aead_len)
	if header_error != .None {
		return 0, header_error
	}
	if kind == .Zero_RTT && !keys.zero_rtt {return 0,.Zero_RTT_Disabled}
 if keys.zero_rtt&&kind!=.Zero_RTT {return 0,.Invalid_Keys}
	if seal && kind == .One_RTT {
		header_phase: u8
		if header[0] & 4 != 0 {
			header_phase = 1
		}
		if !keys.one_rtt || header_phase != keys.phase {
			return 0, .Key_Update_Disabled
		}
	}
	need := plain_len
	if seal {
		need = plain_len + 16
	}
	if len(dst) < need {
		return 0, .Destination_Undersized
	}
	out := dst[:need]
	if bytes.alias(out, header) || bytes.alias(out, packet_key_storage(keys)) {
		return 0, .Overlapping_Buffers
	}
	if seal {
		if bytes.alias_inexactly(out[:plain_len], text) || bytes.alias(out[plain_len:], text) {
			return 0, .Overlapping_Buffers
		}
		if seal_error := aead_seal(keys, out[:plain_len], out[plain_len:], nonce[:], header, text, implementation);
		   seal_error != .None {
			return 0, seal_error
		}
		return need, .None
	}
	ciphertext := text[:plain_len]
	tag := text[plain_len:]
	if bytes.alias(out, tag) || bytes.alias_inexactly(out, ciphertext) {
		return 0, .Overlapping_Buffers
	}
	if kind == .One_RTT {
		header_phase: u8
		if header[0] & 4 != 0 {
			header_phase = 1
		}
		if header_phase != keys.phase {
			if !keys.one_rtt || !keys.has_secret || keys.update_pending {
				crypto.zero_explicit(raw_data(out), len(out))
				return 0, .Key_Update_Disabled
			}
			return payload_open_next(out, header, ciphertext, tag, keys, full_packet_number, implementation)
		}
	}
	if open_error := aead_open(keys.aead, keys.key[:int(keys.key_len)], out, nonce[:], header, ciphertext, tag, implementation); open_error != .None {
		return 0, open_error
	}
	if reserved_rejected(header, kind) {
		crypto.zero_explicit(raw_data(out), len(out))
		return 0, .Invalid_Header
	}
	return need, .None
}

// Trial-opens the immediate next 1-RTT generation. Installs it only after AEAD
// success. A failure wipes the trial secret, key, and IV and leaves the current
// generation, including its header protection key, unchanged.
@(private)
payload_open_next :: proc(
	dst, header, ciphertext, tag: []u8,
	keys: ^Packet_Keys,
	full_packet_number: u64,
	implementation: aes.Implementation,
) -> (
	int,
	Protection_Error,
) {
	next_secret, next_key: [32]u8
	next_iv: [12]u8
	defer crypto.zero_explicit(&next_secret, size_of(next_secret))
	defer crypto.zero_explicit(&next_key, size_of(next_key))
	defer crypto.zero_explicit(&next_iv, size_of(next_iv))
	if e := packet_keys_next(keys, &next_secret, &next_key, &next_iv); e != .None {
		return 0, e
	}
	nonce, ne := nonce_from_iv(next_iv, full_packet_number)
	if ne != .None {
		return 0, ne
	}
	defer crypto.zero_explicit(&nonce, size_of(nonce))
	if e := aead_open(keys.aead, next_key[:int(keys.key_len)], dst, nonce[:], header, ciphertext, tag, implementation); e != .None {
		return 0, e
	}
	if reserved_rejected(header, .One_RTT) {
		crypto.zero_explicit(raw_data(dst), len(dst))
		return 0, .Invalid_Header
	}
	keys.secret = next_secret
	keys.key = next_key
	keys.iv = next_iv
	keys.phase ~= 1
	keys.update_pending = true
	return len(dst), .None
}

@(private)
reserved_rejected :: proc(header: []u8, kind: Packet_Kind) -> bool {
	if len(header) == 0 {
		return true
	}
	if kind == .One_RTT {
		return header[0] & 0x18 != 0
	}
	return header[0] & 0x0c != 0
}

@(private)
protected_header_kind :: proc(
	header: []u8,
	pn: u64,
	sending: bool,
	aead_len: u64,
) -> (
	Packet_Kind,
	Protection_Error,
) {
	if len(header) == 0 {
		return {}, .Invalid_Header
	}
	if header[0] & 0x80 == 0 {
		if header[0] & 0x40 == 0 {
			return {}, .Invalid_Header
		}
		pn_len := int(header[0] & 3) + 1
		if len(header) < 1 + pn_len {
			return {}, .Invalid_Header
		}
		dcid_len := len(header) - 1 - pn_len
		if dcid_len > 20 {
			return {}, .Invalid_Header
		}
		if sending && header[0] & 0x18 != 0 {
			return {}, .Invalid_Header
		}
		for i in 0 ..< pn_len {
			if header[1 + dcid_len + i] != u8((pn >> uint((pn_len - 1 - i) * 8)) & 255) {
				return {}, .Invalid_Packet_Number
			}
		}
		return .One_RTT, .None
	}
	inv, e := invariant_decode(header)
	if e != .None || !inv.long_header || inv.version != 1 || len(inv.destination_id) > 20 || len(inv.source_id) > 20 {
		return {}, .Invalid_Header
	}
	kind := Packet_Kind((inv.first_byte >> 4) & 3)
	if kind != .Handshake && kind != .Zero_RTT {
		return {}, .Invalid_Header
	}
	if sending && inv.first_byte & 0x0c != 0 {
		return {}, .Invalid_Header
	}
	p := inv.prefix_length
	declared, lw, le := varint_decode(header[p:])
	if le != .None {
		return {}, .Invalid_Header
	}
	p += lw
	pn_len := int(inv.first_byte & 3) + 1
	if len(header) - p != pn_len {
		return {}, .Invalid_Header
	}
	for i in 0 ..< pn_len {
		if header[p + i] != u8((pn >> uint((pn_len - 1 - i) * 8)) & 255) {
			return {}, .Invalid_Packet_Number
		}
	}
	if declared != u64(pn_len) + aead_len {
		return {}, .Invalid_Length
	}
	return kind, .None
}

@(private)
aead_seal :: proc(
	keys: ^Packet_Keys,
	dst, tag, nonce, aad, plaintext: []u8,
	implementation: aes.Implementation,
) -> Protection_Error {
	switch keys.aead {
	case .AES_128_GCM:
		ctx: aes.Context_GCM
		aes.init_gcm(&ctx, keys.key[:16], implementation)
		defer aes.reset_gcm(&ctx)
		aes.seal_gcm(&ctx, dst, tag, nonce, aad, plaintext)
	case .ChaCha20_Poly1305:
		ctx: chacha20poly1305.Context
		chacha20poly1305.init(&ctx, keys.key[:32])
		defer crypto.zero_explicit(&ctx, size_of(ctx))
		chacha20poly1305.seal(&ctx, dst, tag, nonce, aad, plaintext)
	}
	return .None
}

@(private)
aead_open :: proc(
	aead: Aead,
	key, dst, nonce, aad, ciphertext, tag: []u8,
	implementation: aes.Implementation,
) -> Protection_Error {
	ok := false
	switch aead {
	case .AES_128_GCM:
		if len(key) != 16 {
			return .Invalid_Keys
		}
		ctx: aes.Context_GCM
		aes.init_gcm(&ctx, key, implementation)
		defer aes.reset_gcm(&ctx)
		ok = aes.open_gcm(&ctx, dst, nonce, aad, ciphertext, tag)
	case .ChaCha20_Poly1305:
		if len(key) != 32 {
			return .Invalid_Keys
		}
		ctx: chacha20poly1305.Context
		chacha20poly1305.init(&ctx, key)
		defer crypto.zero_explicit(&ctx, size_of(ctx))
		ok = chacha20poly1305.open(&ctx, dst, nonce, aad, ciphertext, tag)
	}
	if !ok {
		return .Authentication_Failed
	}
	return .None
}

@(private)
packet_key_storage :: proc(keys: ^Packet_Keys) -> []u8 {
	return (cast([^]u8)keys)[:size_of(Packet_Keys)]
}

@(private)
header_protection :: proc(
	packet: []u8,
	keys: ^Packet_Keys,
	kind: Packet_Kind,
	destination_id_len: int,
	remove: bool,
	implementation: aes.Implementation,
) -> Protection_Error {
	if keys == nil || !keys.initialized {
		return .Invalid_Keys
	}
	if kind == .Zero_RTT && !keys.zero_rtt {return .Zero_RTT_Disabled}
 if keys.zero_rtt&&kind!=.Zero_RTT {return .Invalid_Keys}
	if kind != .Handshake && kind != .One_RTT && kind != .Zero_RTT {
		return .Invalid_Header
	}
	if keys.aead == .AES_128_GCM && implementation != .Portable && implementation != .Hardware {
		return .Invalid_Implementation
	}
	pn_offset := 0
	mask_bits: u8 = 0x0f
	if kind == .One_RTT {
		if destination_id_len < 0 || destination_id_len > 20 {
			return .Invalid_Connection_ID
		}
		pn_offset = 1 + destination_id_len
		mask_bits = 0x1f
	} else {
		view, consumed, e := packet_decode_v1(packet)
		if e != .None || view.kind != kind || consumed != len(packet) {
			return .Invalid_Header
		}
		pn_offset = view.packet_number_offset
	}
	if pn_offset < 1 || len(packet) - pn_offset < 20 {
		return .Sample_Too_Short
	}
	if bytes.alias(packet, packet_key_storage(keys)) {
		return .Overlapping_Buffers
	}
	mask, me := header_protection_mask(keys, packet[pn_offset + 4:pn_offset + 20], implementation)
	if me != .None {
		return me
	}
	defer crypto.zero_explicit(&mask, size_of(mask))
	first := packet[0]
	if remove {
		first ~= mask[0] & mask_bits
	}
	if kind == .One_RTT && (first & 0x80 != 0 || first & 0x40 == 0) {
		return .Invalid_Header
	}
	n := int(first & 3) + 1
	packet[0] ~= mask[0] & mask_bits
	for i in 0 ..< n {
		packet[pn_offset + i] ~= mask[1 + i]
	}
	return .None
}

@(private)
header_protection_mask :: proc(
	keys: ^Packet_Keys,
	sample: []u8,
	implementation: aes.Implementation,
) -> (
	[5]u8,
	Protection_Error,
) {
	if len(sample) != 16 {
		return {}, .Sample_Too_Short
	}
	mask: [5]u8
	switch keys.aead {
	case .AES_128_GCM:
		ctx: aes.Context_ECB
		aes.init_ecb(&ctx, keys.hp[:16], implementation)
		defer aes.reset_ecb(&ctx)
		block: [16]u8
		defer crypto.zero_explicit(&block, size_of(block))
		aes.encrypt_ecb(&ctx, block[:], sample)
		copy(mask[:], block[:5])
	case .ChaCha20_Poly1305:
		counter := endian.unchecked_get_u32le(sample[:4])
		if counter == max(u32) {
			return {}, .Header_Protection_Failed
		}
		ctx: chacha20.Context
		chacha20.init(&ctx, keys.hp[:32], sample[4:16])
		defer chacha20.reset(&ctx)
		chacha20.seek(&ctx, u64(counter))
		zeros: [5]u8
		chacha20.xor_bytes(&ctx, mask[:], zeros[:])
	}
	return mask, .None
}
