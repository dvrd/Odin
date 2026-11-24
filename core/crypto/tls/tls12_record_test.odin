package tls
import "core:bytes"
import "core:crypto"
import "core:mem"
import "core:testing"

// Independent Go crypto/aes/cipher AEAD reference, full TLS1.2 framing/AAD.
// Exact generator: evidence/tls12-primitives/reference.go. Peer explicit nonce
// need not equal its record sequence; only sender uniqueness is required.
@(test)
tls12_record_independent_vectors :: proc(t: ^testing.T) {
	key: [16]u8
	for &v, i in key {v = u8(i)}
	iv := [4]u8{0xa0, 0xa1, 0xa2, 0xa3}
	samples := []struct {
		sequence:   u64,
		kind:       TLS_Content_Type,
		body, wire: string,
	} {
		{
			0,
			TLS_Content_Type(23),
			"696e646570656e64656e7420544c53312e322047434d",
			"170303002e0000000000000000e333aaf837ea5a0b36a85e032586289142baf5b0502dd4453105ef8a66377992f5a0906f76be",
		},
		{7, TLS_Content_Type(23), "", "17030300180000000000000007a2bf825ab4a95b76e1fae0463afbee4d"},
		{
			66051,
			TLS_Content_Type(22),
			"1400000c0102030405060708090a0b0c",
			"160303002800000000000102034dbc5a70010db872227de7ebe1aa7d4200cb90c25b42e5308a73d6d39db9ca27",
		},
		{5, TLS_Content_Type(21), "0100", "150303001a0000000000000005d01e68dd30a3e0f6bbd4719dadb71c707fdf"},
		{6, TLS_Content_Type(21), "01", "15030300190000000000000006b9bd2d6bfac1181b8aeecfc22e1e2a8e32"},
		{8, TLS_Content_Type(21), "0100020a", "150303001c00000000000000084f27f77d30a1017287dca118ef88a1034d2cecf9"},
		{
			9,
			TLS_Content_Type(23),
			"706565722d6e6f6e6365",
			"170303002200000000000000a594267233a93e96e353b701f99dca5c926117f1c8b7ba2997498f",
		},
	}
	for v in samples {
		plain := tls12_test_bytes(v.body)
		defer delete(plain)
		wire := tls12_test_bytes(v.wire)
		defer delete(wire)
		tx, rx: TLS12_Record_Protection
		tls12_record_protection_init(&tx, key, iv)
		defer tls12_record_protection_clear(&tx)
		tls12_record_protection_init(&rx, key, iv)
		defer tls12_record_protection_clear(&rx)
		tx.sequence, rx.sequence = v.sequence, v.sequence
		out: [256]u8
		decoded: [256]u8
		kind, body, e := tls12_record_open(&rx, decoded[:], wire)
		testing.expect(t, e == .None && kind == v.kind && bytes.equal(body, plain))
		testing.expect_value(t, rx.sequence, v.sequence + 1)
		if v.sequence != 9 {
			n, se := tls12_record_seal(&tx, out[:], v.kind, plain)
			testing.expect(t, se == .None && bytes.equal(out[:n], wire))
			testing.expect_value(t, tx.sequence, v.sequence + 1)
		}
	}
}

@(test)
tls12_record_tamper_replay_and_clear :: proc(t: ^testing.T) {
	tx: TLS12_Record_Protection
	tls12_record_protection_init(&tx, [16]u8{}, [4]u8{})
	defer tls12_record_protection_clear(&tx)
	source := [5]u8{1, 2, 3, 4, 5}
	wire: [64]u8
	n, e := tls12_record_seal(&tx, wire[:], .Application_Data, source[:])
	testing.expect_value(t, e, .None)
	for i in 0 ..< n {
		changed := wire
		changed[i] ~= 1
		rx: TLS12_Record_Protection
		tls12_record_protection_init(&rx, [16]u8{}, [4]u8{})
		output: [20]u8
		for &v in output {v = 0xee}
		_, body, oe := tls12_record_open(&rx, output[:], changed[:n])
		testing.expect(t, oe != .None && len(body) == 0 && !rx.initialized && rx.failure != .None)
		testing.expect(t, crypto.is_zero_constant_time(([^]u8)(rawptr(&rx.ctx))[:size_of(rx.ctx)]) == 1)
		testing.expect_value(t, rx.iv, [4]u8{})
		if oe == .Authentication_Failed {
			testing.expect(t, crypto.is_zero_constant_time(output[:len(source)]) == 1)
		}
		_, _, again := tls12_record_open(&rx, output[:], wire[:n])
		testing.expect_value(t, again, oe)
		tls12_record_protection_clear(&rx)
		testing.expect(t, crypto.is_zero_constant_time(([^]u8)(rawptr(&rx))[:size_of(rx)]) == 1)
	}
	rx: TLS12_Record_Protection
	tls12_record_protection_init(&rx, [16]u8{}, [4]u8{})
	defer tls12_record_protection_clear(&rx)
	output: [20]u8
	_, _, ok := tls12_record_open(&rx, output[:], wire[:n])
	testing.expect_value(t, ok, .None)
	_, _, replay := tls12_record_open(&rx, output[:], wire[:n])
	testing.expect_value(t, replay, .Authentication_Failed)
}

@(test)
tls12_record_validation_preserves_ownership :: proc(t: ^testing.T) {
	tx: TLS12_Record_Protection
	tls12_record_protection_init(&tx, [16]u8{}, [4]u8{})
	defer tls12_record_protection_clear(&tx)
	source: [MAX_PLAINTEXT_SIZE + 1]u8
	for &v in source {v = 0x55}
	old_source := source
	output: [MAX_PLAINTEXT_SIZE + TLS12_GCM_OVERHEAD + 5]u8
	for &v in output {v = 0xaa}
	old_output := output
	cases := []struct {
		kind:      TLS_Content_Type,
		body, dst: []u8,
		error:     Record_Protection_Error,
	} {
		{.Application_Data, source[:], output[:], .Record_Oversized},
		{.Application_Data, source[:4], output[:5], .Destination_Undersized},
		{.Handshake, nil, output[:], .Empty_Handshake},
		{.Alert, nil, output[:], .Invalid_Alert_Length},
		{.Change_Cipher_Spec, source[:1], output[:], .Unexpected_Outer_Content_Type},
		{TLS_Content_Type(99), source[:1], output[:], .Unexpected_Outer_Content_Type},
		{.Application_Data, output[:4], output[:], .Overlapping_Buffers},
	}
	context.allocator = mem.nil_allocator()
	context.temp_allocator = mem.nil_allocator()
	for c in cases {
		n, e := tls12_record_seal(&tx, c.dst, c.kind, c.body)
		testing.expect(t, n == 0 && e == c.error && tx.sequence == 0 && tx.initialized)
		testing.expect_value(t, output, old_output)
		testing.expect_value(t, source, old_source)
	}
	_, nil_error := tls12_record_seal(nil, output[:], .Application_Data, nil)
	testing.expect_value(t, nil_error, .Invalid_State)
}

@(test)
tls12_record_open_retryable_and_truncation :: proc(t: ^testing.T) {
	tx: TLS12_Record_Protection
	tls12_record_protection_init(&tx, [16]u8{}, [4]u8{})
	defer tls12_record_protection_clear(&tx)
	source := [5]u8{1, 2, 3, 4, 5}
	wire: [64]u8
	n, e := tls12_record_seal(&tx, wire[:], .Application_Data, source[:])
	testing.expect_value(t, e, .None)
	original := wire
	rx: TLS12_Record_Protection
	tls12_record_protection_init(&rx, [16]u8{}, [4]u8{})
	defer tls12_record_protection_clear(&rx)
	output: [64]u8
	for &v in output {v = 0x55}; old_output := output
	_, _, small := tls12_record_open(&rx, output[:4], wire[:n])
	testing.expect_value(t, small, .Destination_Undersized)
	testing.expect(t, rx.sequence == 0 && rx.initialized)
	testing.expect_value(t, output, old_output)
	_, _, alias := tls12_record_open(&rx, wire[:5], wire[:n])
	testing.expect_value(t, alias, .Overlapping_Buffers)
	testing.expect(t, rx.sequence == 0 && rx.initialized)
	testing.expect_value(t, wire, original)
	_, body, ok := tls12_record_open(&rx, output[:], wire[:n])
	testing.expect_value(t, ok, .None)
	testing.expect(t, bytes.equal(body, source[:]))
	for cut in 0 ..< n {
		tls12_record_protection_init(&rx, [16]u8{}, [4]u8{})
		_, truncated_body, error := tls12_record_open(&rx, output[:], wire[:cut])
		testing.expect(t, error != .None && len(truncated_body) == 0 && !rx.initialized)
	}
}

@(test)
tls12_record_empty_maximum_and_sequence_limits :: proc(t: ^testing.T) {
	tx, rx: TLS12_Record_Protection
	tls12_record_protection_init(&tx, [16]u8{}, [4]u8{})
	defer tls12_record_protection_clear(&tx)
	tls12_record_protection_init(&rx, [16]u8{}, [4]u8{})
	defer tls12_record_protection_clear(&rx)
	wire: [MAX_PLAINTEXT_SIZE + TLS12_GCM_OVERHEAD + 5]u8
	source, output: [MAX_PLAINTEXT_SIZE]u8
	for &v, i in source {v = u8(i)}
	context.allocator = mem.nil_allocator()
	context.temp_allocator = mem.nil_allocator()
	for size in ([4]int{0, 1, MAX_PLAINTEXT_SIZE - 1, MAX_PLAINTEXT_SIZE}) {
		n, e := tls12_record_seal(&tx, wire[:], .Application_Data, source[:size])
		testing.expect_value(t, e, .None)
		kind, body, oe := tls12_record_open(&rx, output[:], wire[:n])
		testing.expect(t, kind == .Application_Data && oe == .None && bytes.equal(body, source[:size]))
	}
	tx.sequence = TLS12_MAX_RECORDS_PER_KEY - 1
	rx.sequence = tx.sequence
	n, e := tls12_record_seal(&tx, wire[:], .Application_Data, nil)
	testing.expect_value(t, e, .None)
	_, _, oe := tls12_record_open(&rx, output[:], wire[:n])
	testing.expect_value(t, oe, .None)
	testing.expect(t, tx.sequence == TLS12_MAX_RECORDS_PER_KEY && rx.sequence == tx.sequence)
	for sequence in ([2]u64{TLS12_MAX_RECORDS_PER_KEY, max(u64)}) {
		tx.sequence, rx.sequence = sequence, sequence
		old_wire := wire
		old_output := output
		_, se := tls12_record_seal(&tx, wire[:], .Application_Data, nil)
		_, _, re := tls12_record_open(&rx, output[:], wire[:n])
		testing.expect(t, se == .Key_Usage_Limit && re == .Key_Usage_Limit)
		testing.expect(t, tx.sequence == sequence && rx.sequence == sequence)
		testing.expect_value(t, wire, old_wire)
		testing.expect_value(t, output, old_output)
	}
	encoded: [8]u8
	tls12_sequence_encode(encoded[:], 0x0102030405060708)
	testing.expect_value(t, encoded, [8]u8{1, 2, 3, 4, 5, 6, 7, 8})
}

@(test)
tls12_record_malformed_length_and_oversize :: proc(t: ^testing.T) {
	output: [MAX_PLAINTEXT_SIZE + 1]u8
	wire: [TLS12_MAX_CIPHERTEXT_SIZE + 6]u8
	wire[0], wire[1], wire[2] = 23, 3, 3
	for size in ([3]int{0, TLS12_GCM_OVERHEAD - 1, TLS12_MAX_CIPHERTEXT_SIZE + 1}) {
		wire[3], wire[4] = u8(size >> 8), u8(size)
		rx: TLS12_Record_Protection
		tls12_record_protection_init(&rx, [16]u8{}, [4]u8{})
		_, body, e := tls12_record_open(&rx, output[:], wire[:5 + size])
		testing.expect(t, e != .None && len(body) == 0 && !rx.initialized)
	}
}
