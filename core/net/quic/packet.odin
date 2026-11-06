package quic

Packet_Kind :: enum {
	Initial,
	Zero_RTT,
	Handshake,
	Retry,
	One_RTT,
	Version_Negotiation,
}
Invariant_View :: struct {
	first_byte:                u8,
	long_header:               bool,
	version:                   u32,
	destination_id, source_id: []u8,
	prefix_length:             int,
}
// All slices borrow src. Unknown versions permit invariant CID lengths through 255.
// Short CID length is external context, never inferred from the wire.
invariant_decode :: proc(
	src: []u8,
	short_destination_id_length: int = 0,
) -> (
	Invariant_View,
	Error,
) {
	if len(src) == 0 {
		return {}, .Truncated
	}
	v := Invariant_View {
		first_byte  = src[0],
		long_header = src[0] & 0x80 != 0,
	}
	if !v.long_header {
		if short_destination_id_length < 0 {
			return {}, .Invalid_Connection_ID
		}
		if short_destination_id_length > len(src) - 1 {
			return {}, .Truncated
		}
		v.destination_id = src[1:1 + short_destination_id_length]
		v.prefix_length = 1 + short_destination_id_length
		return v, .None
	}
	if len(src) < 6 {
		return {}, .Truncated
	}
	v.version = read_u32(src[1:5])
	p := 6
	n := int(src[5])
	if n > len(src) - p {
		return {}, .Truncated
	}
	v.destination_id = src[p:p + n]
	p += n
	if p == len(src) {
		return {}, .Truncated
	}
	n = int(src[p])
	p += 1
	if n > len(src) - p {
		return {}, .Truncated
	}
	v.source_id = src[p:p + n]
	v.prefix_length = p + n
	return v, .None
}

Packet_View :: struct {
	invariant:                  Invariant_View,
	kind:                       Packet_Kind,
	bytes:                      []u8,
	token, retry_tag, versions: []u8,
	// Protected PN plus ciphertext; PN length cannot be read before HP removal.
	protected_body:             []u8,
	packet_number_offset:       int,
}

// Structural prefix decode only: no AEAD, HP sample, Retry integrity, role/token,
// negotiation policy or 1200-byte Initial datagram validation is performed.
// On success consumed delimits a long protected packet; short/Retry/VN consume
// the remaining datagram. No protected PN/reserved/key-phase bits are interpreted.
packet_decode_v1 :: proc(
	src: []u8,
	short_destination_id_length: int = 0,
) -> (
	packet: Packet_View,
	consumed: int,
	err: Error,
) {
	inv, e := invariant_decode(src, short_destination_id_length)
	if e != .None {
		return {}, 0, e
	}
	v := Packet_View {
		invariant = inv,
	}
	p := inv.prefix_length
	if inv.long_header && inv.version == 0 {
		if len(src) - p == 0 || (len(src) - p) % 4 != 0 {
			return {}, 0, .Invalid_Version_List
		}
		v.kind = .Version_Negotiation
		v.versions = src[p:]
		v.bytes = src
		return v, len(src), .None
	}
	if inv.long_header && inv.version != 1 {
		return {}, 0, .Unsupported_Version
	}
	if len(inv.destination_id) > 20 || len(inv.source_id) > 20 {
		return {}, 0, .Invalid_Connection_ID
	}
	if inv.first_byte & 0x40 == 0 {
		return {}, 0, .Invalid_Fixed_Bit
	}
	if !inv.long_header {
		if p == len(src) {
			return {}, 0, .Truncated
		}
		v.kind = .One_RTT
		v.bytes = src
		v.packet_number_offset = p
		v.protected_body = src[p:]
		return v, len(src), .None
	}
	v.kind = Packet_Kind((inv.first_byte >> 4) & 3)
	if v.kind == .Retry {
		if len(src) - p < 17 {
			return {}, 0, .Invalid_Length
		}
		v.token = src[p:len(src) - 16]
		v.retry_tag = src[len(src) - 16:]
		v.bytes = src
		return v, len(src), .None
	}
	if v.kind == .Initial {
		n, w, ve := varint_decode(src[p:])
		if ve != .None {
			return {}, 0, ve
		}
		p += w
		if n > u64(len(src) - p) {
			return {}, 0, .Truncated
		}
		v.token = src[p:p + int(n)]
		p += int(n)
	}
	n, w, ve := varint_decode(src[p:])
	if ve != .None {
		return {}, 0, ve
	}
	p += w
	if n == 0 {
		return {}, 0, .Invalid_Length
	}
	if n > u64(len(src) - p) {
		return {}, 0, .Truncated
	}
	end := p + int(n)
	v.packet_number_offset = p
	v.protected_body = src[p:end]
	v.bytes = src[:end]
	return v, end, .None
}

version_at :: proc(packet: Packet_View, index: int) -> (u32, bool) {
	if packet.kind != .Version_Negotiation || index < 0 || index >= len(packet.versions) / 4 {
		return 0, false
	}
	return read_u32(packet.versions[index * 4:]), true
}

Unprotected_Fields :: struct {
	packet_number:        u32,
	packet_number_length: int,
	reserved_bits:        u8,
	key_phase:            bool,
}
// Caller MUST remove header protection first. Reserved bits are exposed, not
// validated: RFC 9000 permits validation only after packet authentication too.
// This truncated PN is not reconstructed and conveys no authentication claim.
unprotected_fields_decode :: proc(
	packet: Packet_View,
	unprotected_packet: []u8,
) -> (
	Unprotected_Fields,
	Error,
) {
	if packet.kind == .Retry || packet.kind == .Version_Negotiation {
		return {}, .Invalid_Input
	}
	p := packet.packet_number_offset
	if p < 1 || len(unprotected_packet) != len(packet.bytes) || p >= len(unprotected_packet) {
		return {}, .Invalid_Input
	}
	first := unprotected_packet[0]
	mask: u8 = 0xf0
	if packet.kind == .One_RTT {
		mask = 0xe0
	}
	if first & mask != packet.invariant.first_byte & mask {
		return {}, .Invalid_Input
	}
	n := int(first & 3) + 1
	if n > len(unprotected_packet) - p {
		return {}, .Truncated
	}
	f := Unprotected_Fields {
		packet_number_length = n,
	}
	if packet.kind == .One_RTT {
		f.reserved_bits = (first >> 3) & 3
		f.key_phase = first & 4 != 0
	} else {
		f.reserved_bits = (first >> 2) & 3
	}
	for b in unprotected_packet[p:p + n] {
		f.packet_number = (f.packet_number << 8) | u32(b)
	}
	return f, .None
}

@(private)
read_u32 :: proc(s: []u8) -> u32 {
	return (u32(s[0]) << 24) | (u32(s[1]) << 16) | (u32(s[2]) << 8) | u32(s[3])
}
@(private)
write_u32 :: proc(s: []u8, v: u32) {
	for i in 0 ..< 4 {
		s[i] = u8((v >> uint((3 - i) * 8)) & 255)
	}
}
