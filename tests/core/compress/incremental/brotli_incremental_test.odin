package incremental_test

import "core:bytes"
import "core:compress/step"
import "core:compress"
import "core:compress/brotli"
import "core:strings"
import "core:testing"

// Streams were produced by the reference `brotli` CLI (generate_brotli_vectors.py)
// at qualities 0, 1, 5, 9, 11 and lgwin 10, 16, 22 from six inputs.
BROTLI_VECTORS := #load_directory("testdata/brotli")

Brotli_Run :: struct {
	err:        step.Decode_Error,
	output:     [dynamic]u8,
	violations: int,
	steps:      int,
	work:       int,
}

Brotli_Vector :: struct {
	name:  string,
	wire:  []u8,
	plain: []u8,
	lgwin: int,
}

brotli_plain :: proc(stem: string) -> []u8 {
	for file in BROTLI_VECTORS {
		if strings.has_suffix(file.name, ".bin") && file.name[:len(file.name) - 4] == stem {
			return file.data
		}
	}

	return nil
}

brotli_vectors :: proc(allocator := context.allocator) -> (vectors: [dynamic]Brotli_Vector) {
	vectors.allocator = allocator

	for file in BROTLI_VECTORS {
		if !strings.has_suffix(file.name, ".br") {
			continue
		}

		stem := file.name[:strings.index(file.name, ".q")]
		lgwin := brotli_wbits(file.data)

		append(&vectors, Brotli_Vector{file.name, file.data, brotli_plain(stem), lgwin})
	}

	return
}

// WBITS of the stream header (RFC 7932 section 9.1); encoders may raise the requested lgwin.
brotli_wbits :: proc(wire: []u8) -> int {
	first := int(wire[0])

	switch {
	case first & 1 == 0:
		return 16
	case first >> 1 & 7 != 0:
		return 17 + first >> 1 & 7
	case first >> 4 & 7 == 0:
		return 17
	}

	return 8 + first >> 4 & 7
}

brotli_window_size :: proc(lgwin: int) -> int {
	return 1 << uint(lgwin) - 16
}

// Feeds `wire` in `input_size` pieces (final_input on the last) into
// `output_size` byte output slices and records every contract violation.
run_brotli :: proc(
	wire: []u8,
	input_size, output_size, work: int,
	window: []u8,
	max_encoded, max_decoded: u64,
	allocator := context.allocator,
) -> (
	run: Brotli_Run,
) {
	run.output.allocator = allocator

	d: brotli.Decoder
	run.err = brotli.decoder_init(&d, window, max_encoded, max_decoded, allocator)
	defer brotli.decoder_destroy(&d)

	if run.err != .None {
		return
	}

	output := make([]u8, output_size, allocator)
	defer delete(output, allocator)

	at := 0

	for _ in 0 ..< 8_000_000 {
		end := min(at + input_size, len(wire))
		r := brotli.decoder_step(&d, wire[at:end], output, end == len(wire), work)
		run.steps += 1
		run.work += r.work

		if r.consumed < 0 || r.consumed > end - at || r.produced < 0 || r.produced > output_size || r.work < 0 || r.work > work {
			run.violations += 1
			run.err = .Invalid_State
			return
		}

		append(&run.output, ..output[:r.produced])
		at += r.consumed

		if r.err != .None {
			run.err = r.err
			return
		}

		if r.status == .Done {
			if at != len(wire) || d.encoded_bytes != u64(at) || d.decoded_bytes != u64(len(run.output)) {
				run.violations += 1
			}

			run.err = .None
			return
		}

		if r.status == .Need_Input && at != end {
			run.violations += 1
		}

		if r.consumed == 0 && r.produced == 0 && r.work == 0 {
			run.violations += 1
		}
	}

	run.violations += 1
	run.err = .Invalid_State
	return
}

brotli_limits :: proc(wire, plain: []u8) -> (u64, u64) {
	return u64(len(wire)), u64(len(plain))
}

@(test)
brotli_reference_vectors_across_input_and_output_partitions :: proc(t: ^testing.T) {
	vectors := brotli_vectors()
	defer delete(vectors)

	testing.expect(t, len(vectors) >= 90)

	for vector in vectors {
		window := make([]u8, brotli_window_size(vector.lgwin))
		defer delete(window)

		enc, dec := brotli_limits(vector.wire, vector.plain)

		for input_size in ([5]int{1, 2, 7, 4096, 1 << 30}) {
			for output_size in ([4]int{1, 3, 4096, 1 << 20}) {
				run := run_brotli(vector.wire, input_size, output_size, step.DECODE_MAX_WORK, window, enc, dec)
				defer delete(run.output)

				testing.expectf(t, run.err == .None && run.violations == 0, "%s in=%d out=%d: %v violations %d", vector.name, input_size, output_size, run.err, run.violations)
				testing.expectf(t, bytes.equal(run.output[:], vector.plain), "%s in=%d out=%d: output differs", vector.name, input_size, output_size)
			}
		}
	}
}

@(test)
brotli_incremental_equals_one_shot_load :: proc(t: ^testing.T) {
	vectors := brotli_vectors()
	defer delete(vectors)

	window := make([]u8, brotli.DECODER_WINDOW_MAX)
	defer delete(window)

	for vector in vectors {
		buffer: [dynamic]u8
		defer delete(buffer)

		testing.expect_value(t, brotli.decompress(&buffer, vector.wire), nil)

		enc, dec := brotli_limits(vector.wire, vector.plain)
		run := run_brotli(vector.wire, 4096, 4096, step.DECODE_MAX_WORK, window, enc, dec)
		defer delete(run.output)

		testing.expect_value(t, run.err, step.Decode_Error.None)
		testing.expectf(t, bytes.equal(run.output[:], buffer[:]), "%s: incremental differs from brotli.decompress", vector.name)
	}
}

@(test)
brotli_work_budget_is_respected_and_makes_progress :: proc(t: ^testing.T) {
	vectors := brotli_vectors()
	defer delete(vectors)

	for vector in vectors {
		if len(vector.plain) > 70000 && !strings.contains(vector.name, ".q5.") {
			continue
		}

		window := make([]u8, brotli_window_size(vector.lgwin))
		defer delete(window)

		enc, dec := brotli_limits(vector.wire, vector.plain)

		for work in ([3]int{1, 3, 17}) {
			for sizes in ([2][2]int{{1, 1}, {13, 29}}) {
				run := run_brotli(vector.wire, sizes[0], sizes[1], work, window, enc, dec)
				defer delete(run.output)

				testing.expectf(t, run.err == .None && run.violations == 0, "%s work=%d: %v violations %d", vector.name, work, run.err, run.violations)
				testing.expectf(t, bytes.equal(run.output[:], vector.plain), "%s work=%d: output differs", vector.name, work)
			}
		}
	}
}

@(test)
brotli_every_truncation_is_truncated :: proc(t: ^testing.T) {
	vectors := brotli_vectors()
	defer delete(vectors)

	window := make([]u8, brotli.DECODER_WINDOW_MAX)
	defer delete(window)

	for vector in vectors {
		stride := max(1, len(vector.wire) / 100)

		for cut := 0; cut < len(vector.wire); cut += stride {
			run := run_brotli(vector.wire[:cut], 4096, 4096, step.DECODE_MAX_WORK, window, 1 << 30, 1 << 30)
			defer delete(run.output)

			testing.expectf(t, run.err == .Truncated && run.violations == 0, "%s cut %d: %v", vector.name, cut, run.err)
			testing.expectf(t, bytes.equal(run.output[:], vector.plain[:len(run.output)]), "%s cut %d: provisional output differs", vector.name, cut)
		}

		run := run_brotli(vector.wire[:len(vector.wire) - 1], 1, 4096, step.DECODE_MAX_WORK, window, 1 << 30, 1 << 30)
		defer delete(run.output)

		testing.expectf(t, run.err == .Truncated, "%s without last byte: %v", vector.name, run.err)
	}
}

@(test)
brotli_trailing_bytes_and_bad_padding_are_rejected :: proc(t: ^testing.T) {
	window := make([]u8, brotli.DECODER_WINDOW_MAX)
	defer delete(window)

	vectors := brotli_vectors()
	defer delete(vectors)

	for vector in vectors {
		if len(vector.plain) > 70000 || !strings.contains(vector.name, ".w16.") {
			continue
		}

		for extra in ([3][]u8{{0}, {0xff}, {0x06, 0x00, 0x00}}) {
			wire := make([]u8, len(vector.wire) + len(extra))
			defer delete(wire)

			copy(wire, vector.wire)
			copy(wire[len(vector.wire):], extra)

			for input_size in ([3]int{1, 5, 1 << 30}) {
				run := run_brotli(wire, input_size, 4096, step.DECODE_MAX_WORK, window, 1 << 30, 1 << 30)
				defer delete(run.output)

				testing.expectf(t, run.err == .Trailing_Data, "%s extra %v in=%d: %v", vector.name, extra, input_size, run.err)
			}
		}
	}

	// 0x06 is the empty stream: WBITS 16, ISLAST, ISLASTEMPTY, five zero padding bits.
	for pad in ([5]u8{0x86, 0x46, 0x26, 0x16, 0x0e}) {
		run := run_brotli([]u8{pad}, 1, 8, step.DECODE_MAX_WORK, window, 8, 8)
		defer delete(run.output)

		testing.expect_value(t, run.err, step.Decode_Error.Malformed)
	}

	run := run_brotli([]u8{0x06}, 1, 8, step.DECODE_MAX_WORK, window, 8, 8)
	defer delete(run.output)

	testing.expect_value(t, run.err, step.Decode_Error.None)
	testing.expect_value(t, len(run.output), 0)
}

@(test)
brotli_encoded_and_decoded_limits_are_exact :: proc(t: ^testing.T) {
	vectors := brotli_vectors()
	defer delete(vectors)

	for vector in vectors {
		if len(vector.plain) > 70000 || !strings.contains(vector.name, ".q5.w16") {
			continue
		}

		window := make([]u8, brotli_window_size(vector.lgwin))
		defer delete(window)

		enc, dec := brotli_limits(vector.wire, vector.plain)

		for input_size in ([2]int{1, 1 << 30}) {
			exact := run_brotli(vector.wire, input_size, 64, step.DECODE_MAX_WORK, window, enc, dec)
			defer delete(exact.output)

			testing.expect_value(t, exact.err, step.Decode_Error.None)

			short_wire := run_brotli(vector.wire, input_size, 64, step.DECODE_MAX_WORK, window, enc - 1, dec)
			defer delete(short_wire.output)

			testing.expectf(t, short_wire.err == .Encoded_Limit, "%s encoded limit: %v", vector.name, short_wire.err)

			if len(vector.plain) > 0 {
				short_plain := run_brotli(vector.wire, input_size, 64, step.DECODE_MAX_WORK, window, enc, dec - 1)
				defer delete(short_plain.output)

				testing.expectf(t, short_plain.err == .Decoded_Limit, "%s decoded limit: %v", vector.name, short_plain.err)
				testing.expect(t, len(short_plain.output) <= int(dec) - 1)
			}
		}
	}

	// A zero decoded limit lets the empty stream finish and fails any output
	// even when the destination has no room.
	window := make([]u8, brotli.DECODER_WINDOW_MAX)
	defer delete(window)

	d: brotli.Decoder
	defer brotli.decoder_destroy(&d)

	text := brotli_plain("text")
	wire: []u8

	for vector in vectors {
		if vector.name == "text.q5.w16.br" {
			wire = vector.wire
		}
	}

	testing.expect(t, len(text) > 0 && len(wire) > 0)
	testing.expect_value(t, brotli.decoder_init(&d, window, u64(len(wire)), 0), step.Decode_Error.None)

	r := brotli.decoder_step(&d, wire, nil, true)
	testing.expect_value(t, r.err, step.Decode_Error.Decoded_Limit)
	testing.expect_value(t, r.produced, 0)

	testing.expect_value(t, brotli.decoder_init(&d, window, 1, 0), step.Decode_Error.None)

	r = brotli.decoder_step(&d, []u8{0x06}, nil, true)
	testing.expect_value(t, r.err, step.Decode_Error.None)
	testing.expect_value(t, r.status, step.Decode_Status.Done)
}

@(test)
brotli_window_that_does_not_fit_is_invalid_config :: proc(t: ^testing.T) {
	vectors := brotli_vectors()
	defer delete(vectors)

	for vector in vectors {
		if vector.name != "text.q5.w22.br" && vector.name != "text.q5.w16.br" {
			continue
		}

		small := make([]u8, brotli.DECODER_WINDOW_MIN)
		defer delete(small)

		run := run_brotli(vector.wire, 1, 64, step.DECODE_MAX_WORK, small, 1 << 20, 1 << 20)
		defer delete(run.output)

		testing.expect_value(t, run.err, step.Decode_Error.Invalid_Config)
		testing.expect_value(t, len(run.output), 0)

		exact := make([]u8, brotli_window_size(vector.lgwin))
		defer delete(exact)

		run2 := run_brotli(vector.wire, 1, 64, step.DECODE_MAX_WORK, exact, 1 << 20, 1 << 20)
		defer delete(run2.output)

		testing.expect_value(t, run2.err, step.Decode_Error.None)

		// One byte short of the history the declared WBITS needs.
		short := exact[:len(exact) - 1]
		run3 := run_brotli(vector.wire, 1, 64, step.DECODE_MAX_WORK, short, 1 << 20, 1 << 20)
		defer delete(run3.output)

		testing.expect_value(t, run3.err, step.Decode_Error.Invalid_Config)
	}

	d: brotli.Decoder
	tiny: [brotli.DECODER_WINDOW_MIN - 1]u8
	testing.expect_value(t, brotli.decoder_init(&d, tiny[:], 1, 1), step.Decode_Error.Invalid_Config)
	testing.expect_value(t, brotli.decoder_init(nil, tiny[:], 1, 1), step.Decode_Error.Invalid_State)
}

// Hand-assembled meta-blocks the reference encoder never emits.
Bit_Writer :: struct {
	bytes:  [dynamic]u8,
	accum:  u64,
	count:  uint,
}

put_bits :: proc(w: ^Bit_Writer, value: u64, width: uint) {
	w.accum |= value << w.count
	w.count += width

	for w.count >= 8 {
		append(&w.bytes, u8(w.accum))
		w.accum >>= 8
		w.count -= 8
	}
}

put_padding :: proc(w: ^Bit_Writer) {
	if w.count > 0 {
		put_bits(w, 0, 8 - w.count)
	}
}

put_stored :: proc(w: ^Bit_Writer, data: []u8) {
	put_bits(w, 0, 1)
	put_bits(w, 0, 2)
	put_bits(w, u64(len(data) - 1), 16)
	put_bits(w, 1, 1)
	put_padding(w)

	for value in data {
		put_bits(w, u64(value), 8)
	}
}

put_metadata :: proc(w: ^Bit_Writer, data: []u8, size_bytes: uint) {
	put_bits(w, 0, 1)
	put_bits(w, 3, 2)
	put_bits(w, 0, 1)
	put_bits(w, u64(size_bytes), 2)

	if size_bytes > 0 {
		put_bits(w, u64(len(data) - 1), 8 * size_bytes)
	}

	put_padding(w)

	for value in data {
		put_bits(w, u64(value), 8)
	}
}

put_last_empty :: proc(w: ^Bit_Writer) {
	put_bits(w, 1, 1)
	put_bits(w, 1, 1)
	put_padding(w)
}

@(test)
brotli_metadata_and_uncompressed_meta_blocks :: proc(t: ^testing.T) {
	window := make([]u8, brotli.DECODER_WINDOW_MAX)
	defer delete(window)

	a := []u8{'a', 'b', 'c'}
	b := make([]u8, 300)
	defer delete(b)

	for &value, index in b {
		value = u8(index * 7)
	}

	w: Bit_Writer
	defer delete(w.bytes)

	// WBITS 16 (one 0 bit), then mixed meta-blocks.
	put_bits(&w, 0, 1)
	put_metadata(&w, a, 1)
	put_stored(&w, a)
	put_metadata(&w, b, 2)
	put_stored(&w, b)
	put_metadata(&w, nil, 0)
	put_stored(&w, a)
	put_last_empty(&w)

	expected: [dynamic]u8
	defer delete(expected)

	append(&expected, ..a)
	append(&expected, ..b)
	append(&expected, ..a)

	buffer: [dynamic]u8
	defer delete(buffer)

	testing.expect_value(t, brotli.decompress(&buffer, w.bytes[:]), nil)
	testing.expect(t, bytes.equal(buffer[:], expected[:]))

	for input_size in ([4]int{1, 3, 100, 1 << 30}) {
		for output_size in ([3]int{1, 5, 4096}) {
			for work in ([2]int{1, step.DECODE_MAX_WORK}) {
				run := run_brotli(w.bytes[:], input_size, output_size, work, window, u64(len(w.bytes)), u64(len(expected)))
				defer delete(run.output)

				testing.expect_value(t, run.err, step.Decode_Error.None)
				testing.expect_value(t, run.violations, 0)
				testing.expect(t, bytes.equal(run.output[:], expected[:]))
			}
		}
	}

	// Non-zero padding before stored data and before metadata, reserved bit,
	// non-minimal metadata length.
	for variant in 0 ..< 4 {
		bad: Bit_Writer
		defer delete(bad.bytes)

		put_bits(&bad, 0, 1)

		switch variant {
		case 0:
			put_bits(&bad, 0, 1)
			put_bits(&bad, 0, 2)
			put_bits(&bad, 2, 16)
			put_bits(&bad, 1, 1)
			put_bits(&bad, 1, 1)
			put_padding(&bad)
			put_bits(&bad, 0x1234, 24)
		case 1:
			put_bits(&bad, 0, 1)
			put_bits(&bad, 3, 2)
			put_bits(&bad, 0, 1)
			put_bits(&bad, 0, 2)
			put_bits(&bad, 1, 1)
			put_padding(&bad)
		case 2:
			put_bits(&bad, 0, 1)
			put_bits(&bad, 3, 2)
			put_bits(&bad, 1, 1)
			put_bits(&bad, 0, 2)
			put_padding(&bad)
		case 3:
			put_bits(&bad, 0, 1)
			put_bits(&bad, 3, 2)
			put_bits(&bad, 0, 1)
			put_bits(&bad, 2, 2)
			put_bits(&bad, 5, 16)
			put_padding(&bad)
		}

		put_last_empty(&bad)

		for input_size in ([2]int{1, 1 << 30}) {
			run := run_brotli(bad.bytes[:], input_size, 16, step.DECODE_MAX_WORK, window, 1 << 20, 1 << 20)
			defer delete(run.output)

			testing.expectf(t, run.err == .Malformed, "variant %d: %v", variant, run.err)
		}
	}
}

@(test)
brotli_claimed_lengths_do_not_amplify_work :: proc(t: ^testing.T) {
	window := make([]u8, brotli.DECODER_WINDOW_MAX)
	defer delete(window)

	for kind in 0 ..< 2 {
		w: Bit_Writer
		defer delete(w.bytes)

		put_bits(&w, 0, 1)

		if kind == 0 {
			// Metadata claiming 16 MiB with a few bytes behind it.
			put_bits(&w, 0, 1)
			put_bits(&w, 3, 2)
			put_bits(&w, 0, 1)
			put_bits(&w, 3, 2)
			put_bits(&w, 0xffffff, 24)
			put_padding(&w)
		} else {
			// Uncompressed meta-block claiming 64 KiB.
			put_bits(&w, 0, 1)
			put_bits(&w, 0, 2)
			put_bits(&w, 0xffff, 16)
			put_bits(&w, 1, 1)
			put_padding(&w)
		}

		for _ in 0 ..< 5 {
			put_bits(&w, 0, 8)
		}

		run := run_brotli(w.bytes[:], 1 << 20, 1 << 20, step.DECODE_MAX_WORK, window, 1 << 30, 1 << 30)
		defer delete(run.output)

		testing.expect_value(t, run.err, step.Decode_Error.Truncated)
		testing.expect(t, run.work < 64)
		testing.expect(t, run.steps < 8)
	}
}

// Every single-bit flip of a short stream: no crash, no hang, partition
// independence, and the same verdict and bytes as the one-shot decoder.
brotli_check_bit_flips :: proc(t: ^testing.T, wire: []u8, window: []u8, name: string) {
	flipped := make([]u8, len(wire))
	defer delete(flipped)

	for bit in 0 ..< len(wire) * 8 {
		copy(flipped, wire)
		flipped[bit / 8] ~= 1 << uint(bit % 8)

		whole := run_brotli(flipped, 1 << 30, 8192, step.DECODE_MAX_WORK, window, 1 << 30, 1 << 26)
		defer delete(whole.output)

		bytewise := run_brotli(flipped, 1, 7, 5, window, 1 << 30, 1 << 26)
		defer delete(bytewise.output)

		testing.expectf(t, whole.violations == 0 && bytewise.violations == 0, "%s bit %d: contract violation", name, bit)
		testing.expectf(t, whole.err == bytewise.err, "%s bit %d: %v vs %v", name, bit, whole.err, bytewise.err)
		testing.expectf(t, bytes.equal(whole.output[:], bytewise.output[:]), "%s bit %d: partitions differ", name, bit)

		buffer: [dynamic]u8
		defer delete(buffer)

		one_shot := brotli.decompress(&buffer, flipped)

		testing.expectf(t, (whole.err == .None) == (one_shot == nil), "%s bit %d: incremental %v, one-shot %v", name, bit, whole.err, one_shot)

		if whole.err == .None && one_shot == nil {
			testing.expectf(t, bytes.equal(whole.output[:], buffer[:]), "%s bit %d: output differs from one-shot", name, bit)
		}
	}
}

@(test)
brotli_single_bit_flips_never_crash_or_hang :: proc(t: ^testing.T) {
	window := make([]u8, brotli.DECODER_WINDOW_MAX)
	defer delete(window)

	vectors := brotli_vectors()
	defer delete(vectors)

	covered := 0

	for vector in vectors {
		switch vector.name {
		case "one.q11.w16.br", "empty.q5.w10.br", "repeat.q11.w16.br", "binary.q11.w16.br", "binary.q5.w10.br", "text.q11.w10.br":
			brotli_check_bit_flips(t, vector.wire, window, vector.name)
			covered += 1
		}
	}

	testing.expect_value(t, covered, 6)
}

@(test)
brotli_arguments_are_atomic_and_errors_are_sticky :: proc(t: ^testing.T) {
	window := make([]u8, brotli.DECODER_WINDOW_MAX)
	defer delete(window)

	vectors := brotli_vectors()
	defer delete(vectors)

	wire: []u8

	for vector in vectors {
		if vector.name == "text.q5.w16.br" {
			wire = vector.wire
		}
	}

	d: brotli.Decoder
	defer brotli.decoder_destroy(&d)

	testing.expect_value(t, brotli.decoder_init(&d, window, 1 << 20, 1 << 20), step.Decode_Error.None)

	buffer: [64]u8
	copy(buffer[:], wire)
	before_buffer := buffer
	before := d

	r := brotli.decoder_step(&d, buffer[:20], buffer[4:24], false)
	testing.expect_value(t, r.err, step.Decode_Error.Overlapping_Buffers)
	r = brotli.decoder_step(&d, window[:20], window[4:24], false)
	testing.expect_value(t, r.err, step.Decode_Error.Overlapping_Buffers)
	r = brotli.decoder_step(&d, wire, window[100:200], false)
	testing.expect_value(t, r.err, step.Decode_Error.Overlapping_Buffers)

	for budget in ([3]int{-1, 0, step.DECODE_MAX_WORK + 1}) {
		r = brotli.decoder_step(&d, wire, buffer[:], true, budget)
		testing.expect_value(t, r.err, step.Decode_Error.Invalid_Config)
	}

	testing.expect(t, bytes.equal(buffer[:], before_buffer[:]))
	testing.expect(t, bytes.equal((cast([^]u8)&d)[:size_of(d)], (cast([^]u8)&before)[:size_of(before)]))

	// final_input cannot be withdrawn; a failed stream stays failed.
	r = brotli.decoder_step(&d, wire[:1], buffer[:], true)
	testing.expect_value(t, r.err, step.Decode_Error.Truncated)
	r = brotli.decoder_step(&d, wire, buffer[:], true)
	testing.expect_value(t, r.err, step.Decode_Error.Truncated)

	testing.expect_value(t, brotli.decoder_init(&d, window, 1 << 20, 1 << 20), step.Decode_Error.None)

	out: [8192]u8
	r = brotli.decoder_step(&d, wire, out[:1], true)
	testing.expect(t, r.err == .None)
	r = brotli.decoder_step(&d, wire[r.consumed:], out[:], false)
	testing.expect_value(t, r.err, step.Decode_Error.Invalid_State)

	// Reinitialization keeps working after a failure and after completion.
	for _ in 0 ..< 2 {
		testing.expect_value(t, brotli.decoder_init(&d, window, 1 << 20, 1 << 20), step.Decode_Error.None)

		total := 0
		status := step.Decode_Status.Progress

		for status != .Done {
			r = brotli.decoder_step(&d, wire[total:], out[:], true)
			testing.expect_value(t, r.err, step.Decode_Error.None)
			total += r.consumed
			status = r.status

			if r.err != .None {
				break
			}
		}

		testing.expect_value(t, total, len(wire))

		garbage := [1]u8{0}
		r = brotli.decoder_step(&d, nil, out[:], true)
		testing.expect_value(t, r.status, step.Decode_Status.Done)
		r = brotli.decoder_step(&d, garbage[:], out[:], true)
		testing.expect_value(t, r.err, step.Decode_Error.Trailing_Data)
	}

	// Without final_input a finished stream waits for the end of the entity.
	testing.expect_value(t, brotli.decoder_init(&d, window, 1 << 20, 1 << 20), step.Decode_Error.None)

	r = brotli.decoder_step(&d, []u8{0x06}, out[:], false)
	testing.expect_value(t, r.err, step.Decode_Error.None)
	testing.expect_value(t, r.status, step.Decode_Status.Need_Input)
	r = brotli.decoder_step(&d, nil, out[:], true)
	testing.expect_value(t, r.status, step.Decode_Status.Done)
}
