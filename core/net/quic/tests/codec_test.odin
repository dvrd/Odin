package tests
import "core:bytes"
import "core:mem"
import "core:net/quic"
import "core:testing"

hex :: proc(dst: []u8, s: string) -> []u8 {
	n := 0
	high := true
	v: u8
	for c in s {
		x: u8
		if c >= '0' && c <= '9' {
			x = u8(c - '0')
		} else if c >= 'a' && c <= 'f' {
			x = u8(c - 'a' + 10)
		} else {
			continue
		}
		if high {
			v = x << 4
		} else {
			dst[n] = v | x
			n += 1
		}
		high = !high
	}
	return dst[:n]
}

@(test)
rfc9000_varints :: proc(t: ^testing.T) {
	// RFC 9000 Appendix A.1, including legal nonminimal 37.
	values := [?]u64{37, 15293, 494878333, 151288809941952652, 37}
	wires := [?]string{"25", "7bbd", "9d7f3e7d", "c2197c5eff14e88c", "4025"}
	for value, i in values {
		b: [8]u8
		wire := hex(b[:], wires[i])
		v, n, e := quic.varint_decode(wire)
		testing.expect(t, e == .None && v == value && n == len(wire))
		encoded: [8]u8
		written, ee := quic.varint_encode(encoded[:], value, len(wire))
		testing.expect(
			t,
			ee == .None && written == len(wire) && bytes.equal(encoded[:written], wire),
		)
		for end in 0 ..< len(wire) {
			_, used, err := quic.varint_decode(wire[:end])
			testing.expect(t, err == .Truncated && used == 0)
		}
	}
	boundaries := [?]u64{0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, quic.MAX_VARINT}
	for value in boundaries {
		b: [8]u8
		n, e := quic.varint_encode(b[:], value)
		v, m, d := quic.varint_decode(b[:n])
		testing.expect(t, e == .None && d == .None && v == value && m == n)
	}
}

@(test)
rejected_encoders_are_transactional :: proc(t: ^testing.T) {
	dst: [64]u8
	for &b in dst[:] {b = 0xa5}
	before := dst
	_, e := quic.varint_encode(dst[:], quic.MAX_VARINT + 1)
	testing.expect_value(t, e, .Varint_Overflow)
	_, e = quic.varint_encode(dst[:], 64, 1)
	testing.expect_value(t, e, .Varint_Overflow)
	_, e = quic.varint_encode(dst[:], 1, 3)
	testing.expect_value(t, e, .Invalid_Input)
	_, e = quic.varint_encode(dst[:0], 1)
	testing.expect_value(t, e, .Destination_Undersized)
	_, _, e = quic.long_header_encode_v1(
		dst[:],
		{kind = .Initial, packet_number_length = 1, packet_number = 256},
	)
	testing.expect_value(t, e, .Invalid_Packet_Number)
	_, _, e = quic.long_header_encode_v1(
		dst[:],
		{kind = .Initial, packet_number_length = 4, ciphertext_length = quic.MAX_VARINT},
	)
	testing.expect_value(t, e, .Varint_Overflow)
	_, _, e = quic.long_header_encode_v1(
		dst[:],
		{kind = .Handshake, packet_number_length = 1, token = []u8{1}},
	)
	testing.expect_value(t, e, .Invalid_Input)
	_, _, e = quic.short_header_encode_v1(
		dst[:],
		{packet_number_length = 1, destination_id = dst[40:41]},
	)
	testing.expect_value(t, e, .None) // outside written prefix is allowed
	dst = before
	_, _, e = quic.short_header_encode_v1(
		dst[:],
		{packet_number_length = 1, destination_id = dst[:1]},
	)
	testing.expect_value(t, e, .Overlapping_Buffers)
	testing.expect(t, dst == before)
}

@(test)
rfc9001_initial_headers :: proc(t: ^testing.T) {
	dcid: [8]u8
	hex(dcid[:], "8394c8f03e515708")
	dst: [1200]u8
	n, p, e := quic.long_header_encode_v1(
		dst[:],
		{
			kind = .Initial,
			destination_id = dcid[:],
			packet_number_length = 4,
			packet_number = 2,
			ciphertext_length = 1178,
		},
	)
	expected: [22]u8
	want := hex(expected[:], "c300000001088394c8f03e5157080000449e00000002")
	testing.expect(t, e == .None && n == 22 && p == 18 && bytes.equal(dst[:n], want))
	// A protected header from RFC9001 A.2: protected PN length bits differ.
	hex(dst[:], "c000000001088394c8f03e5157080000449e7b9aec34")
	packet, used, de := quic.packet_decode_v1(dst[:])
	testing.expect(
		t,
		de == .None &&
		used == 1200 &&
		packet.packet_number_offset == 18 &&
		len(packet.protected_body) == 1182,
	)
	testing.expect(
		t,
		packet.kind == .Initial && bytes.equal(packet.invariant.destination_id, dcid[:]),
	)
	// Explicitly remove HP only for this field-codec test; no AEAD claim.
	copy(dst[:22], want)
	fields, fe := quic.unprotected_fields_decode(packet, dst[:])
	testing.expect(
		t,
		fe == .None &&
		fields.packet_number == 2 &&
		fields.packet_number_length == 4 &&
		fields.reserved_bits == 0,
	)
	for end in 0 ..< len(dst) {
		_, consumed, err := quic.packet_decode_v1(dst[:end])
		testing.expect(t, err != .None && consumed == 0)
	}
	// Server A.3 header has zero DCID and a fresh SCID.
	server: [135]u8
	hex(server[:], "cf000000010008f067a5502a4262b5004075c0d9")
	sp, sn, se := quic.packet_decode_v1(server[:])
	testing.expect(
		t,
		se == .None &&
		sn == 135 &&
		sp.packet_number_offset == 18 &&
		len(sp.invariant.source_id) == 8,
	)
}

@(test)
rfc9001_retry :: proc(t: ^testing.T) {
	wire: [36]u8
	src := hex(wire[:], "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
	packet, n, e := quic.packet_decode_v1(src)
	testing.expect(
		t,
		e == .None &&
		n == len(src) &&
		packet.kind == .Retry &&
		string(packet.token) == "token" &&
		len(packet.retry_tag) == 16,
	)
	out: [64]u8
	written, ee := quic.retry_encode_v1(
		out[:],
		packet.invariant.destination_id,
		packet.invariant.source_id,
		packet.token,
		packet.retry_tag,
		15,
	)
	testing.expect(t, ee == .None && bytes.equal(out[:written], src))
	_, _, bad := quic.packet_decode_v1(src[:15 + 16])
	testing.expect_value(t, bad, .Invalid_Length)
	_, fe := quic.unprotected_fields_decode(packet, src)
	testing.expect_value(t, fe, .Invalid_Input)
}

@(test)
invariant_versions_and_cid_boundaries :: proc(t: ^testing.T) {
	cid: [255]u8
	out: [540]u8
	versions := []u32{1, 0x6b3343cf, 0x0a0a0a0a}
	n, e := quic.version_negotiation_encode(out[:], cid[:], cid[:], versions, 0)
	testing.expect_value(t, e, .None)
	packet, used, pe := quic.packet_decode_v1(out[:n])
	testing.expect(t, pe == .None && used == n && len(packet.invariant.destination_id) == 255)
	v, ok := quic.version_at(packet, 1)
	testing.expect(t, ok && v == 0x6b3343cf)
	_, ok = quic.version_at(packet, -1)
	testing.expect(t, !ok)
	_, ok = quic.version_at(packet, 3)
	testing.expect(t, !ok)
	// Unknown-version invariants do not assume v1 type or fixed bit/CID bounds.
	out[4] = 2
	inv, ie := quic.invariant_decode(out[:n])
	testing.expect(t, ie == .None && inv.version == 2 && len(inv.source_id) == 255)
	_, _, ve := quic.packet_decode_v1(out[:n])
	testing.expect_value(t, ve, .Unsupported_Version)
	out[4] = 1
	_, _, ce := quic.packet_decode_v1(out[:n])
	testing.expect_value(t, ce, .Invalid_Connection_ID)
	out[4] = 0
	for cut in 0 ..< n {
		_, _, err := quic.packet_decode_v1(out[:cut])
		if cut < 517 || (cut - 517) % 4 != 0 {
			testing.expect(t, err != .None)
		}
	}
	_, _, err := quic.packet_decode_v1(out[:517])
	testing.expect_value(t, err, .Invalid_Version_List)
	short: [257]u8
	short[0] = 0x40
	si, se := quic.invariant_decode(short[:], 255)
	testing.expect(t, se == .None && len(si.destination_id) == 255)
	_, _, se = quic.packet_decode_v1(short[:], 255)
	testing.expect_value(t, se, .Invalid_Connection_ID)
	_, se = quic.invariant_decode(short[:], -1)
	testing.expect_value(t, se, .Invalid_Connection_ID)
}

@(test)
coalescing_and_protected_fields :: proc(t: ^testing.T) {
	data: [128]u8
	offset := 0
	for kind in ([]quic.Packet_Kind{.Initial, .Zero_RTT, .Handshake}) {
		n, p, e := quic.long_header_encode_v1(
			data[offset:],
			{
				kind = kind,
				packet_number_length = 1,
				packet_number = 7,
				ciphertext_length = 3,
				length_width = 2,
			},
		)
		testing.expect_value(t, e, .None)
		testing.expect_value(t, p, n - 1)
		data[offset] = data[offset] | 0x0f // protected low bits must not affect prefix decode
		offset += n + 3
	}
	n, _, e := quic.short_header_encode_v1(data[offset:], {packet_number_length = 1})
	testing.expect_value(t, e, .None)
	offset += n + 4
	cursor := 0
	for kind in ([]quic.Packet_Kind{.Initial, .Zero_RTT, .Handshake, .One_RTT}) {
		packet, used, err := quic.packet_decode_v1(data[cursor:offset])
		testing.expect(t, err == .None && packet.kind == kind && used > 0)
		testing.expect(t, raw_data(packet.bytes) == raw_data(data[cursor:]))
		cursor += used
	}
	testing.expect_value(t, cursor, offset)
	// Structurally delimited but crypto-incomplete one-byte protected body.
	minimal := []u8{0xc3, 0, 0, 0, 1, 0, 0, 0, 1, 0}
	packet, used, err := quic.packet_decode_v1(minimal)
	testing.expect(t, err == .None && used == len(minimal) && len(packet.protected_body) == 1)
	_, err = quic.unprotected_fields_decode(packet, minimal)
	testing.expect_value(t, err, .Truncated)
	// Reserved bits are not rejected before authenticated packet processing.
	short := []u8{0x5c, 9}
	sp, _, serr := quic.packet_decode_v1(short)
	f, fe := quic.unprotected_fields_decode(sp, short)
	testing.expect(
		t,
		serr == .None &&
		fe == .None &&
		f.reserved_bits == 3 &&
		f.key_phase &&
		f.packet_number == 9,
	)
}

@(test)
header_encoder_bounds_and_roundtrips :: proc(t: ^testing.T) {
	cid: [21]u8
	dst: [128]u8
	for width in 1 ..= 4 {
		for kind in ([]quic.Packet_Kind{.Initial, .Zero_RTT, .Handshake}) {
			h := quic.Long_Header {
				kind                 = kind,
				destination_id       = cid[:20],
				source_id            = cid[:20],
				packet_number_length = width,
				packet_number        = 15,
				ciphertext_length    = 16,
			}
			if kind == .Initial {
				h.token = []u8{1, 2, 3}
				h.token_length_width = 8
			}
			n, p, e := quic.long_header_encode_v1(dst[:], h)
			testing.expect_value(t, e, .None)
			packet, used, de := quic.packet_decode_v1(dst[:n + 16])
			f, fe := quic.unprotected_fields_decode(packet, dst[:n + 16])
			testing.expect(
				t,
				de == .None &&
				used == n + 16 &&
				fe == .None &&
				f.packet_number == 15 &&
				f.packet_number_length == width &&
				p == n - width,
			)
			before := dst
			for cut in 0 ..< n {
				_, _, err := quic.long_header_encode_v1(dst[:cut], h)
				testing.expect(t, err == .Destination_Undersized && dst == before)
			}
		}
	}
	_, _, err := quic.short_header_encode_v1(
		dst[:],
		{destination_id = cid[:], packet_number_length = 1},
	)
	testing.expect_value(t, err, .Invalid_Connection_ID)
	_, _, err = quic.packet_decode_v1([]u8{0x00, 1})
	testing.expect_value(t, err, .Invalid_Fixed_Bit)
	// Length=0 cannot contain a PN, and oversized token/lengths fail boundedly.
	for wire in ([]string {
			"c00000000100000000",
			"c00000000100003f",
			"e0000000010000ffffffffffffffff",
		}) {
		encoded: [32]u8
		b := hex(encoded[:], wire)
		_, _, e := quic.packet_decode_v1(b)
		testing.expect(t, e != .None)
	}
}

@(test)
seeded_bounded_prefix_inputs_allocate_nothing :: proc(t: ^testing.T) {
	context.allocator = mem.nil_allocator()
	context.temp_allocator = mem.nil_allocator()
	state: u64 = 0x9e3779b97f4a7c15
	storage: [512]u8
	for iteration in 0 ..< 20000 {
		state = state * 6364136223846793005 + 1442695040888963407
		length := int(state % 513)
		for &b in storage[:length] {
			state = state * 6364136223846793005 + 1442695040888963407
			b = u8(state >> 56)
		}
		// Exercise known-version type-specific paths as well as random invariants.
		if length >= 10 && iteration % 3 == 0 {
			storage[0] = 0xc0 | u8((iteration % 4) << 4) | (storage[0] & 15)
			storage[1] = 0
			storage[2] = 0
			storage[3] = 0
			storage[4] = 1
			storage[5] = 0
			storage[6] = 0
		}
		cidlen := int((state >> 32) % 260) - 2
		inv, ie := quic.invariant_decode(storage[:length], cidlen)
		if ie == .None {
			testing.expect(t, inv.prefix_length > 0 && inv.prefix_length <= length)
		}
		packet, consumed, e := quic.packet_decode_v1(storage[:length], cidlen)
		if e == .None {
			testing.expect(t, consumed > 0 && consumed <= length && len(packet.bytes) == consumed)
			if packet.kind != .Retry && packet.kind != .Version_Negotiation {
				_, _ = quic.unprotected_fields_decode(packet, packet.bytes)
			}
		} else {
			testing.expect_value(t, consumed, 0)
		}
		_, n, ve := quic.varint_decode(storage[:length])
		testing.expect(t, (ve == .None && n > 0 && n <= length) || (ve != .None && n == 0))
	}
}

@(test)
all_packet_encoders_validate_before_writing :: proc(t: ^testing.T) {
	dst: [128]u8
	for &b in dst[:] {b = 0xa5}
	initial := dst
	cid := []u8{1, 2, 3}
	token := []u8{9}
	tag: [16]u8
	versions := []u32{1, 0x6b3343cf}
	for cut in 0 ..< 27 {
		_, e := quic.retry_encode_v1(dst[:cut], cid, nil, token, tag[:])
		testing.expect(t, e == .Destination_Undersized && dst == initial)
	}
	for cut in 0 ..< 18 {
		_, e := quic.version_negotiation_encode(dst[:cut], cid, nil, versions)
		testing.expect(t, e == .Destination_Undersized && dst == initial)
	}
	for cut in 0 ..< 8 {
		_, _, e := quic.short_header_encode_v1(
			dst[:cut],
			{destination_id = cid, packet_number_length = 4},
		)
		testing.expect(t, e == .Destination_Undersized && dst == initial)
	}
	_, e := quic.retry_encode_v1(dst[:], cid, nil, nil, tag[:])
	testing.expect_value(t, e, .Invalid_Input)
	_, e = quic.retry_encode_v1(dst[:], cid, nil, token, tag[:15])
	testing.expect_value(t, e, .Invalid_Input)
	_, e = quic.retry_encode_v1(dst[:], cid, nil, token, tag[:], 16)
	testing.expect_value(t, e, .Invalid_Input)
	_, e = quic.retry_encode_v1(dst[:], cid, nil, dst[:1], tag[:])
	testing.expect_value(t, e, .Overlapping_Buffers)
	_, e = quic.version_negotiation_encode(dst[:], cid, nil, nil)
	testing.expect_value(t, e, .Invalid_Input)
	_, e = quic.version_negotiation_encode(dst[:], cid, nil, versions, 128)
	testing.expect_value(t, e, .Invalid_Input)
	_, e = quic.version_negotiation_encode(dst[:], dst[:1], nil, versions)
	testing.expect_value(t, e, .Overlapping_Buffers)
	_, _, e = quic.long_header_encode_v1(
		dst[:],
		{kind = .Initial, destination_id = dst[:1], packet_number_length = 1},
	)
	testing.expect_value(t, e, .Overlapping_Buffers)
	testing.expect(t, dst == initial)
	oversized: [256]u8
	_, e = quic.version_negotiation_encode(dst[:], oversized[:], nil, versions)
	testing.expect_value(t, e, .Invalid_Connection_ID)
	_, _, e = quic.long_header_encode_v1(
		dst[:],
		{kind = .Handshake, destination_id = oversized[:21], packet_number_length = 1},
	)
	testing.expect_value(t, e, .Invalid_Connection_ID)
	// All writers succeed with an allocator that cannot allocate.
	context.allocator = mem.nil_allocator()
	context.temp_allocator = mem.nil_allocator()
	_, e = quic.varint_encode(dst[:], quic.MAX_VARINT)
	testing.expect_value(t, e, .None)
	_, _, e = quic.long_header_encode_v1(dst[:], {kind = .Initial, packet_number_length = 1})
	testing.expect_value(t, e, .None)
	_, _, e = quic.short_header_encode_v1(dst[:], {packet_number_length = 1})
	testing.expect_value(t, e, .None)
	_, e = quic.retry_encode_v1(dst[:], cid, nil, token, tag[:])
	testing.expect_value(t, e, .None)
	_, e = quic.version_negotiation_encode(dst[:], cid, nil, versions)
	testing.expect_value(t, e, .None)
}
