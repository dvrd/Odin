package test_core_compress

import "core:bytes"
import "core:compress/deflate"
import "core:compress/step"
import "core:mem"
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

DEFLATE_ENCODER_LEVELS :: [?]deflate.Deflate_Level{.Stored, .Level_1, .Level_2, .Level_3, .Level_4, .Level_5, .Level_6, .Level_7, .Level_8, .Level_9, .Level_10}
DEFLATE_ENCODER_FORMATS :: [?]deflate.Format{.Raw, .Zlib, .Gzip}

deflate_encoder_one_shot :: proc(format: deflate.Format, output: ^[dynamic]u8, input: []u8, level: deflate.Deflate_Level) -> deflate.Error {
	#partial switch format {
	case .Raw:  return deflate.compress_raw(output, input, level)
	case .Zlib: return deflate.compress_zlib(output, input, level)
	}
	return deflate.compress_gzip(output, input, level)
}

deflate_encoder_inflate :: proc(format: deflate.Format, output: ^[dynamic]u8, input: []u8) -> deflate.Error {
	#partial switch format {
	case .Raw:  return deflate.decompress_raw(output, input)
	case .Zlib: return deflate.decompress_zlib(output, input)
	}
	return deflate.decompress_gzip(output, input)
}

// Writes `plain` in pieces of `write_size` and pulls in pieces of `pull_size`.
deflate_encoder_drive :: proc(e: ^step.Deflate_Encoder, plain: []u8, write_size, pull_size: int, packed: ^[dynamic]u8) {
	pull := make([]u8, pull_size)
	defer delete(pull)

	for offset := 0; offset < len(plain); {
		end := min(offset + write_size, len(plain))
		offset += step.deflate_encoder_write(e, plain[offset:end])
		append(packed, ..pull[:step.deflate_encoder_pull(e, pull)])
		if step.deflate_encoder_error(e) != nil {
			return
		}
	}
	for !step.deflate_encoder_finish(e) {
		if step.deflate_encoder_error(e) != nil {
			return
		}
		append(packed, ..pull[:step.deflate_encoder_pull(e, pull)])
	}
	for step.deflate_encoder_pending(e) > 0 {
		append(packed, ..pull[:step.deflate_encoder_pull(e, pull)])
	}
}

deflate_encoder_expect_round_trip :: proc(t: ^testing.T, e: ^step.Deflate_Encoder, plain: []u8, format: deflate.Format, level: deflate.Deflate_Level, write_size, pull_size: int, loc := #caller_location) {
	packed: [dynamic]u8
	defer delete(packed)

	testing.expect_value(t, step.deflate_encoder_reset(e, format, level), nil, loc = loc)
	deflate_encoder_drive(e, plain, write_size, pull_size, &packed)
	testing.expectf(t, e.finished && !e.overflow && step.deflate_encoder_error(e) == nil, "%v %v size=%d: not finished", format, level, len(plain), loc = loc)

	// The encoder is the one-shot compressor fed in pieces: same bytes out.
	reference: [dynamic]u8
	defer delete(reference)

	reference_error := deflate_encoder_one_shot(format, &reference, plain, level)
	testing.expectf(t, reference_error == nil, "%v %v size=%d: one-shot failed: %v", format, level, len(plain), reference_error, loc = loc)
	testing.expectf(t, bytes.equal(packed[:], reference[:]), "%v %v size=%d write=%d: encoder differs from the one-shot output", format, level, len(plain), write_size, loc = loc)

	unpacked: [dynamic]u8
	defer delete(unpacked)

	inflate_error := deflate_encoder_inflate(format, &unpacked, packed[:])
	testing.expectf(t, inflate_error == nil, "%v %v size=%d: inflate failed: %v", format, level, len(plain), inflate_error, loc = loc)
	testing.expectf(t, bytes.equal(unpacked[:], plain), "%v %v size=%d: round trip differs", format, level, len(plain), loc = loc)
}

@(test)
deflate_encoder_round_trips_every_level_and_format :: proc(t: ^testing.T) {
	e: step.Deflate_Encoder
	testing.expect_value(t, step.deflate_encoder_init(&e, .Gzip), nil)
	defer step.deflate_encoder_destroy(&e)

	// Around the block size, the look-ahead a block waits for, and the window slide.
	sizes := [?]int{0, 1, 2, 3, 4, 257, 258, 259, 1000, 32768, 65535, 65536, 65542, 65543, 65544}
	write_size := 1

	for kind in 0 ..< DEFLATE_SAMPLE_KINDS {
		for size in sizes {
			plain := deflate_sample(kind, size)
			defer delete(plain)

			for format in DEFLATE_ENCODER_FORMATS {
				for level in DEFLATE_ENCODER_LEVELS {
					write_size = write_size % 4099 + 17
					deflate_encoder_expect_round_trip(t, &e, plain, format, level, write_size, 313)
				}
			}
		}
	}
}

@(test)
deflate_encoder_round_trips_several_blocks :: proc(t: ^testing.T) {
	e: step.Deflate_Encoder
	testing.expect_value(t, step.deflate_encoder_init(&e, .Gzip), nil)
	defer step.deflate_encoder_destroy(&e)

	// Incompressible input makes the largest blocks the buffer has to hold.
	for kind in ([?]int{0, 4}) {
		for size in ([?]int{131070, 131071, 200000, 400000}) {
			plain := deflate_sample(kind, size)
			defer delete(plain)

			for format in DEFLATE_ENCODER_FORMATS {
				for level in DEFLATE_ENCODER_LEVELS {
					deflate_encoder_expect_round_trip(t, &e, plain, format, level, 70001, 4096)
				}
			}
		}
	}
}

@(test)
deflate_encoder_takes_one_byte_in_and_gives_one_byte_out :: proc(t: ^testing.T) {
	e: step.Deflate_Encoder
	testing.expect_value(t, step.deflate_encoder_init(&e, .Gzip), nil)
	defer step.deflate_encoder_destroy(&e)

	for kind in 0 ..< DEFLATE_SAMPLE_KINDS {
		plain := deflate_sample(kind, 6000)
		defer delete(plain)

		for format in DEFLATE_ENCODER_FORMATS {
			for level in DEFLATE_ENCODER_LEVELS {
				deflate_encoder_expect_round_trip(t, &e, plain, format, level, 1, 1)
			}
		}
	}

	plain := deflate_sample(4, 140000)
	defer delete(plain)

	deflate_encoder_expect_round_trip(t, &e, plain, .Gzip, .Level_6, 1, 1)
}

// After a flush the receiver can decode everything written so far.
@(test)
deflate_encoder_flush_makes_the_written_input_decodable :: proc(t: ^testing.T) {
	e: step.Deflate_Encoder
	testing.expect_value(t, step.deflate_encoder_init(&e, .Raw), nil)
	defer step.deflate_encoder_destroy(&e)

	decoder := new(step.Inflate_Decoder)
	defer free(decoder)

	plain := deflate_sample(4, 200000)
	defer delete(plain)

	buffer := make([]u8, 4096)
	defer delete(buffer)
	window := make([]u8, 65536)
	defer delete(window)

	for level in DEFLATE_ENCODER_LEVELS {
		unpacked: [dynamic]u8
		defer delete(unpacked)

		testing.expect_value(t, step.deflate_encoder_reset(&e, .Raw, level), nil)
		testing.expect_value(t, step.inflate_decoder_init(decoder, 1 << 30, 1 << 30), step.Decode_Error.None)

		// Feeds the decoder what the encoder has to give; it must never see the end.
		drain :: proc(t: ^testing.T, e: ^step.Deflate_Encoder, decoder: ^step.Inflate_Decoder, buffer, window: []u8, unpacked: ^[dynamic]u8, final: bool) -> (done: bool) {
			for step.deflate_encoder_pending(e) > 0 || final {
				packed := buffer[:step.deflate_encoder_pull(e, buffer)]
				last := final && step.deflate_encoder_pending(e) == 0
				for {
					r := step.inflate_decoder_step(decoder, packed, window, last, step.DECODE_MAX_WORK)
					if !testing.expect_value(t, r.err, step.Decode_Error.None) {
						return true
					}
					append(unpacked, ..window[:r.produced])
					packed = packed[r.consumed:]
					if r.status == .Done {
						return true
					}
					if r.status == .Need_Input {
						break
					}
				}
				if last {
					break
				}
			}
			return false
		}

		offset, piece := 0, 0
		for offset < len(plain) {
			piece = piece % 9973 + 1
			end := min(offset + piece, len(plain))
			for offset < end {
				offset += step.deflate_encoder_write(&e, plain[offset:end])
				testing.expect(t, !drain(t, &e, decoder, buffer, window, &unpacked, false))
			}
			for !step.deflate_encoder_flush(&e) {
				testing.expect(t, !drain(t, &e, decoder, buffer, window, &unpacked, false))
			}
			testing.expect(t, !drain(t, &e, decoder, buffer, window, &unpacked, false))
			if !testing.expectf(t, bytes.equal(unpacked[:], plain[:offset]), "%v: %d of %d bytes decodable after a flush at %d", level, len(unpacked), offset, offset) {
				return
			}
		}
		for !step.deflate_encoder_finish(&e) {
			testing.expect(t, !drain(t, &e, decoder, buffer, window, &unpacked, false))
		}
		testing.expect(t, drain(t, &e, decoder, buffer, window, &unpacked, true))
		testing.expect(t, bytes.equal(unpacked[:], plain))
	}
}

@(test)
deflate_encoder_waits_for_its_output_to_be_pulled :: proc(t: ^testing.T) {
	e: step.Deflate_Encoder
	testing.expect_value(t, step.deflate_encoder_init(&e, .Raw, .Level_1), nil)
	defer step.deflate_encoder_destroy(&e)

	plain := deflate_sample(0, 300000)
	defer delete(plain)

	// Incompressible input fills the buffer; nothing more is taken until it drains.
	consumed, peak := 0, 0
	for step.deflate_encoder_pending(&e) == 0 && consumed < len(plain) {
		consumed += step.deflate_encoder_write(&e, plain[consumed:])
	}
	testing.expect(t, step.deflate_encoder_pending(&e) > 0 && consumed < len(plain))
	testing.expect(t, !step.deflate_encoder_accepts_input(&e))
	testing.expect_value(t, step.deflate_encoder_write(&e, plain[consumed:]), 0)
	testing.expect(t, !step.deflate_encoder_flush(&e) && !step.deflate_encoder_finish(&e))
	testing.expect_value(t, step.deflate_encoder_error(&e), nil)

	packed: [dynamic]u8
	defer delete(packed)
	buffer: [1000]u8
	for consumed < len(plain) || !step.deflate_encoder_finish(&e) {
		peak = max(peak, step.deflate_encoder_pending(&e))
		for step.deflate_encoder_pending(&e) > 0 {
			append(&packed, ..buffer[:step.deflate_encoder_pull(&e, buffer[:])])
		}
		consumed += step.deflate_encoder_write(&e, plain[consumed:])
	}
	peak = max(peak, step.deflate_encoder_pending(&e))
	for step.deflate_encoder_pending(&e) > 0 {
		append(&packed, ..buffer[:step.deflate_encoder_pull(&e, buffer[:])])
	}
	// The buffer between writer and caller never needed more than it has.
	testing.expect(t, peak > 0 && peak <= len(e.sink))
	unpacked: [dynamic]u8
	defer delete(unpacked)
	testing.expect_value(t, deflate.decompress_raw(&unpacked, packed[:]), nil)
	testing.expect(t, bytes.equal(unpacked[:], plain))
}

@(test)
deflate_encoder_output_ceiling_fails_the_stream :: proc(t: ^testing.T) {
	e: step.Deflate_Encoder
	testing.expect_value(t, step.deflate_encoder_init(&e, .Gzip, .Level_6), nil)
	defer step.deflate_encoder_destroy(&e)

	small := deflate_sample(1, 5000)
	defer delete(small)

	exact: [dynamic]u8
	defer delete(exact)
	deflate_encoder_drive(&e, small, 700, 512, &exact)
	testing.expect(t, e.finished && len(exact) > 0)

	// Exactly enough is enough; one byte less fails, and the failure stays.
	for ceiling in ([2]int{len(exact), len(exact) - 1}) {
		packed: [dynamic]u8
		defer delete(packed)
		testing.expect_value(t, step.deflate_encoder_reset(&e, .Gzip, .Level_6, ceiling), nil)
		deflate_encoder_drive(&e, small, 700, 512, &packed)
		if ceiling == len(exact) {
			testing.expect(t, e.finished && !e.overflow && bytes.equal(packed[:], exact[:]))
			continue
		}
		testing.expect(t, !e.finished && e.overflow && step.deflate_encoder_error(&e) != nil)
		testing.expect_value(t, step.deflate_encoder_write(&e, small), 0)
		testing.expect(t, !step.deflate_encoder_finish(&e) && !step.deflate_encoder_flush(&e))
		testing.expect(t, len(packed) < len(exact))
	}

	// A reset clears the failure.
	packed: [dynamic]u8
	defer delete(packed)
	testing.expect_value(t, step.deflate_encoder_reset(&e, .Gzip, .Level_6), nil)
	deflate_encoder_drive(&e, small, 700, 512, &packed)
	testing.expect(t, e.finished && bytes.equal(packed[:], exact[:]))
}

@(test)
deflate_encoder_allocates_once_and_rejects_what_it_cannot_do :: proc(t: ^testing.T) {
	e: step.Deflate_Encoder
	testing.expect(t, step.deflate_encoder_init(&e, .Raw64) != nil)
	testing.expect(t, e.memory == nil && !step.deflate_encoder_accepts_input(&e))
	testing.expect(t, step.deflate_encoder_reset(&e, .Gzip) != nil)

	testing.expect_value(t, step.deflate_encoder_init(&e, .Gzip), nil)
	defer step.deflate_encoder_destroy(&e)
	testing.expect(t, step.deflate_encoder_reset(&e, .Gzip, .Level_6, -1) != nil)
	testing.expect(t, step.deflate_encoder_reset(&e, .Raw64) != nil)

	plain := deflate_sample(4, 150000)
	defer delete(plain)
	packed := make([dynamic]u8, 0, 2 * len(plain))
	defer delete(packed)
	pull: [4096]u8

	// Every stream after init runs without an allocator.
	previous := context.allocator
	context.allocator = mem.panic_allocator()
	for format in DEFLATE_ENCODER_FORMATS {
		for level in ([?]deflate.Deflate_Level{.Stored, .Level_1, .Level_6, .Level_10}) {
			clear(&packed)
			testing.expect_value(t, step.deflate_encoder_reset(&e, format, level), nil)
			for offset := 0; offset < len(plain); {
				offset += step.deflate_encoder_write(&e, plain[offset:min(offset + 9000, len(plain))])
				for step.deflate_encoder_pending(&e) > 0 {
					n := step.deflate_encoder_pull(&e, pull[:])
					(^mem.Raw_Dynamic_Array)(&packed).len += n
					copy(packed[len(packed) - n:], pull[:n])
				}
			}
			for !step.deflate_encoder_finish(&e) || step.deflate_encoder_pending(&e) > 0 {
				n := step.deflate_encoder_pull(&e, pull[:])
				(^mem.Raw_Dynamic_Array)(&packed).len += n
				copy(packed[len(packed) - n:], pull[:n])
			}
			testing.expect(t, e.finished && step.deflate_encoder_error(&e) == nil)
			context.allocator = previous
			unpacked: [dynamic]u8
			testing.expect_value(t, deflate_encoder_inflate(format, &unpacked, packed[:]), nil)
			testing.expect(t, bytes.equal(unpacked[:], plain))
			delete(unpacked)
			context.allocator = mem.panic_allocator()
		}
	}
	context.allocator = previous
}
