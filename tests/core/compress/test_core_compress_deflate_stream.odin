package test_core_compress

import "core:bytes"
import "core:compress"
import "core:compress/deflate"
import "core:testing"

// Deterministic inputs that exercise literals, short and long matches, runs,
// incompressible data and the stored-block size boundaries.
deflate_sample :: proc(kind, size: int, allocator := context.allocator) -> []u8 {
	data := make([]u8, size, allocator)
	state := u32(0x9e3779b9) + u32(kind) * 7919

	next :: proc(state: ^u32) -> u32 {
		state^ ~= state^ << 13
		state^ ~= state^ >> 17
		state^ ~= state^ << 5

		return state^
	}

	pattern := "abcabcabd"
	words := [?]string{"stream", "window", "header", "value", "return", "import", "package", " ", "\n", "{", "}", "0123"}

	for index := 0; index < size; {
		switch kind {
		case 0:
			data[index] = u8(next(&state))
			index += 1
		case 1:
			word := words[next(&state) % len(words)]
			index += copy(data[index:], word)
		case 2:
			data[index] = pattern[index % 9]
			index += 1
		case 3:
			data[index] = 0
			index += 1
		case:
			// Mostly text with occasional noise and far back-references.
			if next(&state) % 16 == 0 || index < 64 {
				data[index] = u8(next(&state))
				index += 1
			} else {
				from := int(next(&state)) % index
				count := min(int(next(&state) % 300) + 3, size - index, index - from)
				copy(data[index:][:count], data[from:][:count])
				index += count
			}
		}
	}

	return data
}

DEFLATE_SAMPLE_KINDS :: 5

DEFLATE_STREAM_LEVELS :: [?]deflate.Deflate_Level{.Stored, .Level_1, .Level_2, .Level_3, .Level_4, .Level_5, .Level_6, .Level_7, .Level_8, .Level_9, .Level_10}

deflate_stream_one_shot :: proc(framing: deflate.Deflate_Stream_Framing, output: ^[dynamic]u8, input: []u8, level: deflate.Deflate_Level) -> compress.Error {
	switch framing {
	case .Raw:
		return deflate.deflate_raw(output, input, level)
	case .Zlib:
		return deflate.deflate_zlib(output, input, level)
	case .Gzip:
		return deflate.deflate_gzip(output, input, level)
	}

	return nil
}

deflate_stream_inflate :: proc(framing: deflate.Deflate_Stream_Framing, output: ^[dynamic]u8, input: []u8) -> compress.Error {
	switch framing {
	case .Raw:
		return deflate.inflate_raw(output, input)
	case .Zlib:
		return deflate.inflate_zlib(output, input)
	case .Gzip:
		return deflate.inflate_gzip(output, input)
	}

	return nil
}

// Feeds `plain` in writes of `write_size` bytes and drains through pulls of `pull_size`.
deflate_stream_drive :: proc(s: ^deflate.Deflate_Stream, plain: []u8, write_size, pull_size: int, packed: ^[dynamic]u8) {
	buffer: [4096]u8
	pull := buffer[:min(pull_size, len(buffer))]
	offset := 0

	for offset < len(plain) {
		end := min(offset + write_size, len(plain))

		for offset < end {
			offset += deflate.deflate_stream_write(s, plain[offset:end])
			append(packed, ..pull[:deflate.deflate_stream_pull(s, pull)])
		}
	}

	for !deflate.deflate_stream_finish(s) {
		append(packed, ..pull[:deflate.deflate_stream_pull(s, pull)])
	}

	for deflate.deflate_stream_pending(s) > 0 {
		append(packed, ..pull[:deflate.deflate_stream_pull(s, pull)])
	}
}

deflate_stream_expect_round_trip :: proc(t: ^testing.T, s: ^deflate.Deflate_Stream, plain: []u8, framing: deflate.Deflate_Stream_Framing, level: deflate.Deflate_Level, write_size, pull_size: int, loc := #caller_location) {
	packed: [dynamic]u8
	defer delete(packed)

	deflate.deflate_stream_reset(s, framing, level)
	deflate_stream_drive(s, plain, write_size, pull_size, &packed)
	testing.expectf(t, s.finished && !s.overflow, "%v %v size=%d: not finished", framing, level, len(plain), loc = loc)
	testing.expectf(t, len(packed) <= deflate.deflate_stream_bound(len(plain), framing), "%v %v size=%d: %d bytes exceed the bound", framing, level, len(plain), len(packed), loc = loc)

	// The stream is the one-shot compressor fed in pieces: same bytes out.
	reference: [dynamic]u8
	defer delete(reference)

	reference_error := deflate_stream_one_shot(framing, &reference, plain, level)
	testing.expectf(t, reference_error == nil, "%v %v size=%d: one-shot failed: %v", framing, level, len(plain), reference_error, loc = loc)
	testing.expectf(t, bytes.equal(packed[:], reference[:]), "%v %v size=%d write=%d: stream differs from the one-shot output", framing, level, len(plain), write_size, loc = loc)

	unpacked: [dynamic]u8
	defer delete(unpacked)

	inflate_error := deflate_stream_inflate(framing, &unpacked, packed[:])
	testing.expectf(t, inflate_error == nil, "%v %v size=%d: inflate failed: %v", framing, level, len(plain), inflate_error, loc = loc)
	testing.expectf(t, bytes.equal(unpacked[:], plain), "%v %v size=%d: round trip differs", framing, level, len(plain), loc = loc)
}

@(test)
deflate_stream_round_trips_every_level_and_framing :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Stream)
	defer free(s)

	// Around the block size, the look-ahead a block waits for, and the window slide.
	sizes := [?]int{0, 1, 2, 3, 4, 257, 258, 259, 1000, 32768, 65535, 65536, 65542, 65543, 65544}
	write_size := 1

	for kind in 0 ..< DEFLATE_SAMPLE_KINDS {
		for size in sizes {
			plain := deflate_sample(kind, size)
			defer delete(plain)

			for framing in deflate.Deflate_Stream_Framing {
				for level in DEFLATE_STREAM_LEVELS {
					write_size = write_size % 4099 + 17
					deflate_stream_expect_round_trip(t, s, plain, framing, level, write_size, 313)
				}
			}
		}
	}
}

@(test)
deflate_stream_round_trips_several_blocks :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Stream)
	defer free(s)

	for size in ([?]int{131070, 131071, 200000, 400000}) {
		plain := deflate_sample(4, size)
		defer delete(plain)

		for framing in deflate.Deflate_Stream_Framing {
			for level in DEFLATE_STREAM_LEVELS {
				deflate_stream_expect_round_trip(t, s, plain, framing, level, 70001, 4096)
			}
		}
	}
}

@(test)
deflate_stream_takes_one_byte_in_and_gives_one_byte_out :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Stream)
	defer free(s)

	for kind in 0 ..< DEFLATE_SAMPLE_KINDS {
		plain := deflate_sample(kind, 6000)
		defer delete(plain)

		for framing in deflate.Deflate_Stream_Framing {
			for level in DEFLATE_STREAM_LEVELS {
				deflate_stream_expect_round_trip(t, s, plain, framing, level, 1, 1)
			}
		}
	}

	plain := deflate_sample(4, 140000)
	defer delete(plain)

	deflate_stream_expect_round_trip(t, s, plain, .Gzip, .Level_6, 1, 1)
}

// After a flush the receiver can decode everything written so far.
@(test)
deflate_stream_flush_makes_the_written_input_decodable :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Stream)
	defer free(s)

	decoder := new(deflate.Inflate_Decoder)
	defer free(decoder)

	plain := deflate_sample(4, 200000)
	defer delete(plain)

	for level in DEFLATE_STREAM_LEVELS {
		packed: [dynamic]u8
		defer delete(packed)

		unpacked: [dynamic]u8
		defer delete(unpacked)

		deflate.deflate_stream_reset(s, .Raw, level)
		testing.expect_value(t, deflate.inflate_decoder_init(decoder, 1 << 30, 1 << 30), compress.Decode_Error.None)

		buffer: [1024]u8
		window: [1024]u8
		offset, fed := 0, 0
		piece := 1

		for offset < len(plain) {
			end := min(offset + piece, len(plain))
			piece = piece * 3 + 1

			for offset < end {
				offset += deflate.deflate_stream_write(s, plain[offset:end])
				append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
			}

			for !deflate.deflate_stream_flush(s) {
				append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
			}

			for deflate.deflate_stream_pending(s) > 0 {
				append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
			}

			for {
				r := deflate.inflate_decoder_step(decoder, packed[fed:], window[:], false, compress.DECODE_MAX_WORK)
				testing.expect_value(t, r.err, compress.Decode_Error.None)
				fed += r.consumed
				append(&unpacked, ..window[:r.produced])

				if r.err != .None || r.status == .Need_Input {
					break
				}
			}

			testing.expectf(t, bytes.equal(unpacked[:], plain[:offset]), "%v: %d of %d bytes decodable after a flush at %d", level, len(unpacked), offset, offset)
		}

		// A second flush with nothing written in between adds nothing.
		testing.expect(t, deflate.deflate_stream_flush(s))
		testing.expect_value(t, deflate.deflate_stream_pending(s), 0)

		for !deflate.deflate_stream_finish(s) {
			append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
		}

		for deflate.deflate_stream_pending(s) > 0 {
			append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
		}

		whole: [dynamic]u8
		defer delete(whole)

		inflate_error := deflate.inflate_raw(&whole, packed[:])
		testing.expectf(t, inflate_error == nil, "%v: inflate failed: %v", level, inflate_error)
		testing.expectf(t, bytes.equal(whole[:], plain), "%v: flushed stream round trip differs", level)
	}
}

@(test)
deflate_stream_to_slice_compresses_in_one_call :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Stream)
	defer free(s)

	plain := deflate_sample(1, 300000)
	defer delete(plain)

	packed := make([]u8, deflate.deflate_stream_bound(len(plain)))
	defer delete(packed)

	deflate.deflate_stream_reset(s, .Gzip, .Level_6)
	written, err := deflate.deflate_stream_to_slice(s, packed, plain)
	testing.expect_value(t, err, nil)
	testing.expect(t, s.finished)

	unpacked: [dynamic]u8
	defer delete(unpacked)

	testing.expect_value(t, deflate.inflate_gzip(&unpacked, packed[:written]), nil)
	testing.expect(t, bytes.equal(unpacked[:], plain))

	deflate.deflate_stream_reset(s, .Gzip, .Level_6)
	_, err = deflate.deflate_stream_to_slice(s, packed[:written - 1], plain)
	testing.expect_value(t, err, compress.General_Error.Output_Too_Short)
}

@(test)
deflate_stream_reports_overflow_at_its_cap :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Stream)
	defer free(s)

	plain := deflate_sample(0, 100000)
	defer delete(plain)

	packed := make([]u8, deflate.deflate_stream_bound(len(plain)))
	defer delete(packed)

	deflate.deflate_stream_reset(s, .Gzip, .Level_6, 4096)
	written, err := deflate.deflate_stream_to_slice(s, packed, plain)
	testing.expect_value(t, err, compress.General_Error.Output_Too_Short)
	testing.expect(t, s.overflow && !s.finished)
	testing.expect(t, written <= 4096)
	testing.expect_value(t, deflate.deflate_stream_write(s, plain), 0)
	testing.expect(t, !deflate.deflate_stream_finish(s))

	// The cap is exact: a stream that fits is not cut.
	small := plain[:1000]
	deflate.deflate_stream_reset(s, .Gzip, .Level_6)
	exact, _ := deflate.deflate_stream_to_slice(s, packed, small)

	deflate.deflate_stream_reset(s, .Gzip, .Level_6, exact)
	_, err = deflate.deflate_stream_to_slice(s, packed, small)
	testing.expect_value(t, err, nil)

	deflate.deflate_stream_reset(s, .Gzip, .Level_6, exact - 1)
	_, err = deflate.deflate_stream_to_slice(s, packed, small)
	testing.expect_value(t, err, compress.General_Error.Output_Too_Short)
	testing.expect(t, s.overflow)
}

@(test)
deflate_stream_stops_when_its_output_is_not_pulled :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Stream)
	defer free(s)

	plain := deflate_sample(0, 400000)
	defer delete(plain)

	deflate.deflate_stream_reset(s, .Raw, .Level_1)
	consumed := deflate.deflate_stream_write(s, plain)
	testing.expect(t, consumed > 0 && consumed < len(plain))
	testing.expect(t, !deflate.deflate_stream_accepts_input(s))
	testing.expect_value(t, deflate.deflate_stream_write(s, plain[consumed:]), 0)
	testing.expect(t, !deflate.deflate_stream_finish(s))
	testing.expect(t, !s.overflow)

	buffer: [512]u8

	for deflate.deflate_stream_pending(s) > 0 {
		deflate.deflate_stream_pull(s, buffer[:])
	}

	testing.expect(t, deflate.deflate_stream_accepts_input(s))
	testing.expect(t, deflate.deflate_stream_write(s, plain[consumed:]) > 0)
}
