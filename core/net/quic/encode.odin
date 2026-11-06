package quic
import "core:bytes"

Long_Header :: struct {
	kind:                             Packet_Kind,
	destination_id, source_id, token: []u8,
	packet_number:                    u32,
	packet_number_length:             int,
	// Ciphertext length including AEAD tag, excluding the PN encoded here.
	ciphertext_length:                u64,
	length_width, token_length_width: int,
}
Short_Header :: struct {
	destination_id:       []u8,
	packet_number:        u32,
	packet_number_length: int,
	spin, key_phase:      bool,
}

// Encodes an UNPROTECTED header only. Caller appends ciphertext and applies HP.
// All rejection paths leave dst unchanged; source buffers must not overlap the
// written prefix of dst. Nonminimal varint widths are explicitly supported.
long_header_encode_v1 :: proc(
	dst: []u8,
	h: Long_Header,
) -> (
	written, packet_number_offset: int,
	err: Error,
) {
	if h.kind != .Initial && h.kind != .Zero_RTT && h.kind != .Handshake {
		return 0, 0, .Invalid_Input
	}
	if len(h.destination_id) > 20 || len(h.source_id) > 20 {
		return 0, 0, .Invalid_Connection_ID
	}
	if !pn_fits(h.packet_number, h.packet_number_length) {
		return 0, 0, .Invalid_Packet_Number
	}
	if h.kind != .Initial && (len(h.token) != 0 || h.token_length_width != 0) {
		return 0, 0, .Invalid_Input
	}
	if h.ciphertext_length > MAX_VARINT - u64(h.packet_number_length) {
		return 0, 0, .Varint_Overflow
	}
	length := h.ciphertext_length + u64(h.packet_number_length)
	lw, e := varint_size(length, h.length_width)
	if e != .None {
		return 0, 0, e
	}
	tw := 0
	if h.kind == .Initial {
		tw, e = varint_size(u64(len(h.token)), h.token_length_width)
		if e != .None {
			return 0, 0, e
		}
	}
	base := 7 + len(h.destination_id) + len(h.source_id) + tw + lw + h.packet_number_length
	// Avoid signed addition overflow even for an arbitrary caller token slice.
	if len(h.token) > max(int) - base {
		return 0, 0, .Invalid_Length
	}
	need := base + len(h.token)
	if len(dst) < need {
		return 0, 0, .Destination_Undersized
	}
	out := dst[:need]
	if bytes.alias(out, h.destination_id) ||
	   bytes.alias(out, h.source_id) ||
	   bytes.alias(out, h.token) {
		return 0, 0, .Overlapping_Buffers
	}
	p := write_long_prefix(
		out,
		0xc0 | (u8(h.kind) << 4) | u8(h.packet_number_length - 1),
		1,
		h.destination_id,
		h.source_id,
	)
	if h.kind == .Initial {
		n, _ := varint_encode(out[p:], u64(len(h.token)), tw)
		p += n
		p += copy(out[p:], h.token)
	}
	n, _ := varint_encode(out[p:], length, lw)
	p += n
	write_pn(out[p:], h.packet_number, h.packet_number_length)
	return need, p, .None
}

short_header_encode_v1 :: proc(
	dst: []u8,
	h: Short_Header,
) -> (
	written, packet_number_offset: int,
	err: Error,
) {
	if len(h.destination_id) > 20 {
		return 0, 0, .Invalid_Connection_ID
	}
	if !pn_fits(h.packet_number, h.packet_number_length) {
		return 0, 0, .Invalid_Packet_Number
	}
	need := 1 + len(h.destination_id) + h.packet_number_length
	if len(dst) < need {
		return 0, 0, .Destination_Undersized
	}
	if bytes.alias(dst[:need], h.destination_id) {
		return 0, 0, .Overlapping_Buffers
	}
	first := u8(0x40) | u8(h.packet_number_length - 1)
	if h.spin {
		first |= 0x20
	}
	if h.key_phase {
		first |= 4
	}
	dst[0] = first
	copy(dst[1:], h.destination_id)
	p := 1 + len(h.destination_id)
	write_pn(dst[p:], h.packet_number, h.packet_number_length)
	return need, p, .None
}

// tag must contain the externally computed 16-byte Retry integrity tag. This
// codec neither computes nor verifies it. Low unused bits are caller-controlled.
retry_encode_v1 :: proc(
	dst, destination_id, source_id, token, tag: []u8,
	unused: u8 = 0,
) -> (
	int,
	Error,
) {
	if len(destination_id) > 20 || len(source_id) > 20 {
		return 0, .Invalid_Connection_ID
	}
	if len(token) == 0 || len(tag) != 16 || unused > 15 {
		return 0, .Invalid_Input
	}
	base := 7 + len(destination_id) + len(source_id) + 16
	if len(token) > max(int) - base {
		return 0, .Invalid_Length
	}
	need := base + len(token)
	if len(dst) < need {
		return 0, .Destination_Undersized
	}
	out := dst[:need]
	if bytes.alias(out, destination_id) ||
	   bytes.alias(out, source_id) ||
	   bytes.alias(out, token) ||
	   bytes.alias(out, tag) {
		return 0, .Overlapping_Buffers
	}
	p := write_long_prefix(out, 0xf0 | unused, 1, destination_id, source_id)
	p += copy(out[p:], token)
	copy(out[p:], tag)
	return need, .None
}

// Version list policy (e.g. supported versions, grease, negotiation validity)
// belongs to the caller. Invariant CID lengths through 255 are preserved.
version_negotiation_encode :: proc(
	dst, destination_id, source_id: []u8,
	versions: []u32,
	unused: u8 = 0x40,
) -> (
	int,
	Error,
) {
	if len(destination_id) > 255 || len(source_id) > 255 {
		return 0, .Invalid_Connection_ID
	}
	if len(versions) == 0 || unused > 127 {
		return 0, .Invalid_Input
	}
	base := 7 + len(destination_id) + len(source_id)
	if len(versions) > (max(int) - base) / 4 {
		return 0, .Invalid_Length
	}
	need := base + len(versions) * 4
	if len(dst) < need {
		return 0, .Destination_Undersized
	}
	version_bytes := (cast([^]u8)raw_data(versions))[:len(versions) * 4]
	out := dst[:need]
	if bytes.alias(out, destination_id) ||
	   bytes.alias(out, source_id) ||
	   bytes.alias(out, version_bytes) {
		return 0, .Overlapping_Buffers
	}
	p := write_long_prefix(out, 0x80 | unused, 0, destination_id, source_id)
	for v in versions {
		write_u32(out[p:], v)
		p += 4
	}
	return need, .None
}

@(private)
pn_fits :: proc(pn: u32, n: int) -> bool {
	if n < 1 || n > 4 {
		return false
	}
	return n == 4 || u64(pn) < (u64(1) << uint(n * 8))
}
@(private)
write_pn :: proc(dst: []u8, pn: u32, n: int) {
	for i in 0 ..< n {
		dst[i] = u8((pn >> uint((n - 1 - i) * 8)) & 255)
	}
}
@(private)
write_long_prefix :: proc(dst: []u8, first: u8, version: u32, dcid, scid: []u8) -> int {
	dst[0] = first
	write_u32(dst[1:], version)
	dst[5] = u8(len(dcid))
	p := 6
	p += copy(dst[p:], dcid)
	dst[p] = u8(len(scid))
	p += 1
	p += copy(dst[p:], scid)
	return p
}
