package test_core_compress

import "core:bytes"
import "base:runtime"
import "core:compress"
import "core:compress/brotli"
import "core:testing"

brotli_decode :: proc(data: []u8) -> (plain: []u8, err: brotli.Error) {
	output: [dynamic]u8
	err = brotli.decompress(&output, data)

	return output[:], err
}

brotli_encode :: proc(data: []u8, level: brotli.Level) -> (packed: []u8, err: brotli.Error) {
	output: [dynamic]u8
	err = brotli.compress(&output, data, level)

	return output[:], err
}

BROTLI_LEVELS := [?]brotli.Level{.Fastest, .Fast, .Default, .Best, .Optimal}

// Stream from the reference test data: several meta-blocks and block switches.
BROTLI_REFERENCE_TEXT :: "ukko nooa, ukko nooa oli kunnon mies, kun han meni saunaan, pisti laukun naulaan, ukko nooa, ukko nooa oli kunnon mies."

BROTLI_REFERENCE_STREAM := [?]u8 {
	0x1b, 0x76, 0x00, 0x00, 0x14, 0x4a, 0xac, 0x9b, 0x7a, 0xbd, 0xe1, 0x97, 0x9d, 0x7f, 0x8e, 0xc2, 0x82, 0x36, 0x0e, 0x9c,
	0xe0, 0x90, 0x03, 0xf7, 0x8b, 0x9e, 0x38, 0xe6, 0xb6, 0x00, 0xab, 0xc3, 0xca, 0xa0, 0xc2, 0xda, 0x66, 0x36, 0xdc, 0xcd,
	0x80, 0x8d, 0x2e, 0x21, 0xd7, 0x6e, 0xe3, 0xea, 0x4c, 0xb8, 0xf0, 0xd2, 0xb8, 0xc7, 0xc2, 0x70, 0x4d, 0x3a, 0xf0, 0x69,
	0x7e, 0xa1, 0xb8, 0x45, 0x73, 0xab, 0xc4, 0x57, 0x1e,
}

// Reference encoder output that leans on the static dictionary and its transforms.
BROTLI_DICTIONARY_TEXT :: "The quick brown fox jumps over the lazy dog. Information about the international development of language and government."

BROTLI_DICTIONARY_STREAM := [?]u8 {
	0xa1, 0xb8, 0x03, 0x00, 0x62, 0x91, 0x3c, 0xae, 0x7d, 0x2d, 0x46, 0xa1, 0x1d, 0xfa, 0x92, 0xaa, 0x0c, 0x2d, 0xc9, 0xcc,
	0xd8, 0x1a, 0xe4, 0x0c, 0x4f, 0x4f, 0x85, 0xbd, 0x35, 0x88, 0xcb, 0x5c, 0x5e, 0x0f, 0xb8, 0xf8, 0x30, 0xe1, 0xa9, 0xc1,
	0x26, 0xd8, 0x01, 0x5b, 0x23, 0x0c, 0xd8, 0x41, 0xc4, 0x29, 0x52, 0xe3, 0x82, 0xc3, 0xf8, 0xf7, 0x69, 0x13, 0xbe, 0x93,
	0x5b, 0xa2, 0x6b, 0xdd, 0xb2, 0x00, 0x00,
}

@(test)
brotli_decodes_reference_streams :: proc(t: ^testing.T) {
	text, text_error := brotli_decode(BROTLI_REFERENCE_STREAM[:])
	defer delete(text)

	testing.expect_value(t, text_error, nil)
	testing.expect_value(t, string(text), BROTLI_REFERENCE_TEXT)

	words, words_error := brotli_decode(BROTLI_DICTIONARY_STREAM[:])
	defer delete(words)

	testing.expect_value(t, words_error, nil)
	testing.expect_value(t, string(words), BROTLI_DICTIONARY_TEXT)

	empty, empty_error := brotli_decode([]u8{0x06})
	defer delete(empty)

	testing.expect_value(t, empty_error, nil)
	testing.expect_value(t, len(empty), 0)
}

@(test)
brotli_encode_round_trips_every_level :: proc(t: ^testing.T) {
	sizes := [?]int{0, 1, 2, 3, 4, 5, 17, 258, 4096, 65535, 65536, 65537, 200000}

	for kind in 0 ..< 5 {
		for size in sizes {
			data := deflate_sample(kind, size)
			defer delete(data)

			for level in BROTLI_LEVELS {
				packed, encode_error := brotli_encode(data, level)
				defer delete(packed)

				testing.expect_value(t, encode_error, nil)

				plain, decode_error := brotli_decode(packed)
				defer delete(plain)

				testing.expect_value(t, decode_error, nil)
				testing.expectf(t, bytes.equal(plain, data), "kind %d size %d level %v did not round trip", kind, size, level)
			}
		}
	}
}

@(test)
brotli_encode_uses_the_static_dictionary :: proc(t: ^testing.T) {
	text := BROTLI_DICTIONARY_TEXT
	packed, encode_error := brotli_encode(transmute([]u8)text, .Best)
	defer delete(packed)

	testing.expect_value(t, encode_error, nil)
	testing.expectf(t, len(packed) < len(text) * 3 / 4, "%d bytes for %d of dictionary text", len(packed), len(text))

	plain, decode_error := brotli_decode(packed)
	defer delete(plain)

	testing.expect_value(t, decode_error, nil)
	testing.expect_value(t, string(plain), text)
}

@(test)
brotli_encode_levels_order_by_size :: proc(t: ^testing.T) {
	data := deflate_sample(1, 300000)
	defer delete(data)

	previous := max(int) / 2

	for level in BROTLI_LEVELS {
		packed, encode_error := brotli_encode(data, level)
		defer delete(packed)

		testing.expect_value(t, encode_error, nil)
		testing.expectf(t, len(packed) <= previous + previous / 50, "level %v grew to %d from %d", level, len(packed), previous)
		previous = len(packed)
	}

	random := deflate_sample(0, 100000)
	defer delete(random)

	stored, stored_error := brotli_encode(random, .Default)
	defer delete(stored)

	testing.expect_value(t, stored_error, nil)
	testing.expect(t, len(stored) <= len(random) + 16, "incompressible data must be stored")
}

@(test)
brotli_decode_rejects_damaged_streams :: proc(t: ^testing.T) {
	data := deflate_sample(1, 20000)
	defer delete(data)

	packed, encode_error := brotli_encode(data, .Default)
	defer delete(packed)

	testing.expect_value(t, encode_error, nil)

	for size in 0 ..< len(packed) {
		plain, decode_error := brotli_decode(packed[:size])
		delete(plain)

		testing.expectf(t, decode_error != nil, "a %d byte prefix decoded", size)
	}

	trailing := make([]u8, len(packed) + 1)
	defer delete(trailing)

	copy(trailing, packed)

	extra, trailing_error := brotli_decode(trailing)
	delete(extra)

	testing.expect_value(t, trailing_error, brotli.Error(brotli.E_Brotli.Trailing_Data))
}

@(test)
brotli_stream_encoder_round_trips :: proc(t: ^testing.T) {
	e := new(brotli.Stream_Encoder)
	defer free(e)

	sizes := [?]int{0, 1, 5, 4096, brotli.STREAM_BLOCK, brotli.STREAM_BLOCK + 1, 200_000}
	chunks := [?]int{1, 7, 4096, 1 << 20}

	for kind in 0 ..< 3 {
		for size in sizes {
			sample := deflate_sample(kind, size)
			defer delete(sample)

			packed := make([]u8, brotli.stream_bound(size))
			defer delete(packed)

			brotli.stream_reset(e)
			written, ok := brotli.stream_encode_into(e, sample, packed)
			testing.expectf(t, ok, "stream encode failed: kind %d size %d", kind, size)

			unpacked, err := brotli_decode(packed[:written])
			defer delete(unpacked)

			testing.expectf(t, err == nil, "stream decode failed: kind %d size %d: %v", kind, size, err)
			testing.expectf(t, bytes.equal(unpacked, sample), "stream mismatch: kind %d size %d", kind, size)

			// Any partition of input and output yields the same stream.
			for chunk in chunks {
				if size > 20_000 && chunk == 1 {
					continue
				}

				pieces := make([dynamic]u8)
				defer delete(pieces)

				scratch: [97]u8
				brotli.stream_reset(e)

				for offset := 0; offset < size; {
					offset += brotli.stream_write(e, sample[offset:min(offset + chunk, size)])

					for count := brotli.stream_pull(e, scratch[:]); count > 0; count = brotli.stream_pull(e, scratch[:]) {
						append(&pieces, ..scratch[:count])
					}
				}

				for !brotli.stream_finish(e) {
					count := brotli.stream_pull(e, scratch[:])
					testing.expect(t, count > 0, "stream finish stalled")
					append(&pieces, ..scratch[:count])

					if count == 0 {
						break
					}
				}

				for count := brotli.stream_pull(e, scratch[:]); count > 0; count = brotli.stream_pull(e, scratch[:]) {
					append(&pieces, ..scratch[:count])
				}

				testing.expectf(t, bytes.equal(pieces[:], packed[:written]), "partition changed the stream: size %d chunk %d", size, chunk)
			}
		}
	}
}

@(test)
brotli_stream_encoder_respects_output_limit :: proc(t: ^testing.T) {
	e := new(brotli.Stream_Encoder)
	defer free(e)

	sample := deflate_sample(2, 100_000)
	defer delete(sample)

	packed := make([]u8, brotli.stream_bound(len(sample)))
	defer delete(packed)

	brotli.stream_reset(e)
	written, ok := brotli.stream_encode_into(e, sample, packed)
	testing.expect(t, ok)

	brotli.stream_reset(e, written)
	_, ok = brotli.stream_encode_into(e, sample, packed)
	testing.expect(t, ok, "exact limit must fit")

	brotli.stream_reset(e, written - 1)
	_, ok = brotli.stream_encode_into(e, sample, packed)
	testing.expect(t, !ok, "limit below the stream size must fail")

	_, ok = brotli.stream_encode_into(e, sample, packed[:written - 1])
	testing.expect(t, !ok, "short destination must fail")
}

@(test)
brotli_round_trips_across_meta_blocks :: proc(t: ^testing.T) {
	// Every meta-block has its own prefix codes; nothing may leak from one
	// to the next.
	sample := #load("../../../core/unicode/tables.odin")

	for level in 0 ..= 11 {
		for meta_block_max in ([?]int{1 << 12, 1 << 16, 1 << 18}) {
			packed: [dynamic]u8
			defer delete(packed)

			encode_error := brotli.compress_meta_blocks(&packed, sample, brotli.Level(level), meta_block_max)

			testing.expectf(t, encode_error == nil, "encode failed: level %d block %d: %v", level, meta_block_max, encode_error)

			unpacked, err := brotli_decode(packed[:])
			defer delete(unpacked)

			testing.expectf(t, err == nil, "decode failed: level %d block %d: %v", level, meta_block_max, err)
			testing.expectf(t, bytes.equal(unpacked, sample), "mismatch: level %d block %d", level, meta_block_max)
		}
	}
}

@(test)
brotli_compress_to_slice_matches_every_level :: proc(t: ^testing.T) {
	sizes := [?]int{0, 1, 5, 4096, 65537, 300000, 600000}
	state := new(brotli.Brotli)
	defer free(state)

	for kind in 0 ..< 5 {
		for size in sizes {
			data := deflate_sample(kind, size)
			defer delete(data)

			// Bytes past the bound that no level may write.
			GUARD :: 64
			bound := brotli.compress_bound(size)
			guarded := make([]u8, bound + GUARD)
			defer delete(guarded)

			output := guarded[:bound]

			for &value in guarded[bound:] {
				value = 0xa5
			}

			for level in 0 ..= 11 {
				if level >= 10 && size > 300000 {
					continue
				}

				packed, encode_error := brotli_encode(data, brotli.Level(level))
				defer delete(packed)

				testing.expect_value(t, encode_error, nil)
				testing.expectf(t, len(packed) <= bound - brotli.COMPRESS_SLACK, "kind %d size %d level %d: %d bytes past the bound", kind, size, level, len(packed))

				written: int
				slice_error: brotli.Error

				if brotli.Level(level) <= brotli.PLAIN_LEVEL_MAX {
					// These levels work from the state alone.
					context.allocator = runtime.panic_allocator()
					written, slice_error = brotli.compress(state, output, data, brotli.Level(level))
				} else {
					written, slice_error = brotli.compress(state, output, data, brotli.Level(level))
				}

				testing.expect_value(t, slice_error, nil)
				testing.expectf(t, bytes.equal(output[:written], packed), "kind %d size %d level %d: slice and dynamic differ", kind, size, level)

				for value in guarded[bound:] {
					testing.expectf(t, value == 0xa5, "kind %d size %d level %d: wrote past the output", kind, size, level)
				}
			}
		}
	}
}

@(test)
brotli_compress_checks_its_arguments :: proc(t: ^testing.T) {
	data := deflate_sample(1, 1000)
	defer delete(data)

	state := new(brotli.Brotli)
	defer free(state)

	bound := brotli.compress_bound(len(data))
	output := make([]u8, bound)
	defer delete(output)

	testing.expect_value(t, brotli.compress_bound(-1), -1)
	testing.expect_value(t, brotli.compress_bound(brotli.COMPRESS_INPUT_MAX + 1), -1)

	_, short_error := brotli.compress(state, output[:bound - 1], data, .Fast)
	testing.expect_value(t, short_error, brotli.Error(compress.General_Error.Output_Too_Short))

	_, state_error := brotli.compress(nil, output, data, .Fast)
	testing.expect_value(t, state_error, brotli.Error(compress.General_Error.Incompatible_Options))

	testing.expect_value(t, brotli.compress_to_dynamic(nil, data), brotli.Error(compress.General_Error.Incompatible_Options))

	// The output is overwritten, not appended to.
	packed: [dynamic]u8
	defer delete(packed)

	append(&packed, "stale")
	testing.expect_value(t, brotli.compress(&packed, data, .Fast), nil)

	written, slice_error := brotli.compress(state, output, data, .Fast)
	testing.expect_value(t, slice_error, nil)
	testing.expect(t, bytes.equal(packed[:], output[:written]))
}

@(test)
brotli_decompress_honours_its_limits :: proc(t: ^testing.T) {
	data := deflate_sample(1, 150000)
	defer delete(data)

	packed, encode_error := brotli_encode(data, .Default)
	defer delete(packed)

	testing.expect_value(t, encode_error, nil)

	Limit :: struct {
		expected: int,
		limit:    int,
		err:      brotli.Error,
	}

	limits := [?]Limit {
		{-1, compress.COMPRESS_OUTPUT_ALLOCATE_MAX, nil},
		{len(data), compress.COMPRESS_OUTPUT_ALLOCATE_MAX, nil},
		{len(data) + 1, compress.COMPRESS_OUTPUT_ALLOCATE_MAX, nil},
		{-1, len(data), nil},
		{len(data) - 1, compress.COMPRESS_OUTPUT_ALLOCATE_MAX, compress.General_Error.Output_Too_Short},
		{-1, len(data) - 1, compress.General_Error.Output_Too_Short},
		{-1, len(data) / 2, compress.General_Error.Output_Too_Short},
		{-1, 0, compress.General_Error.Output_Too_Short},
		{len(data), len(data) - 1, compress.General_Error.Output_Too_Short},
		{-1, -1, compress.General_Error.Incompatible_Options},
	}

	output: [dynamic]u8
	defer delete(output)

	for limit in limits {
		append(&output, "stale")
		err := brotli.decompress(&output, packed, limit.expected, limit.limit)

		testing.expectf(t, err == limit.err, "expected %d limit %d: %v", limit.expected, limit.limit, err)

		if limit.limit < 0 {
			// Refused before the output is touched.
			clear(&output)
			continue
		}

		testing.expectf(t, len(output) <= limit.limit, "expected %d limit %d: %d bytes out", limit.expected, limit.limit, len(output))

		if err == nil {
			testing.expectf(t, bytes.equal(output[:], data), "expected %d limit %d: output differs", limit.expected, limit.limit)
		}
	}

	testing.expect_value(t, brotli.decompress_from_bytes(nil, packed), brotli.Error(compress.General_Error.Incompatible_Options))
}

@(test)
brotli_decompress_reads_a_stream_context :: proc(t: ^testing.T) {
	data := deflate_sample(1, 400000)
	defer delete(data)

	for level in ([?]brotli.Level{.Fastest, .Default}) {
		packed, encode_error := brotli_encode(data, level)
		defer delete(packed)

		testing.expect_value(t, encode_error, nil)

		reader: bytes.Reader
		output: [dynamic]u8
		defer delete(output)

		// A backing smaller than the stream: the window is refilled many times.
		backing: [300]u8
		z := compress.init_context(bytes.reader_init(&reader, packed), &output, buffer = backing[:])
		defer compress.destroy_context(&z)

		testing.expect_value(t, brotli.decompress(&z), nil)
		testing.expect_value(t, z.bytes_written, i64(len(data)))
		testing.expect(t, bytes.equal(output[:], data))

		// One byte short, and one byte more.
		bytes.reader_init(&reader, packed[:len(packed) - 1])
		z = compress.init_context(bytes.reader_to_stream(&reader), &output, buffer = backing[:])
		testing.expect(t, brotli.decompress(&z) != nil)

		longer := make([]u8, len(packed) + 1)
		defer delete(longer)

		copy(longer, packed)
		bytes.reader_init(&reader, longer)
		z = compress.init_context(bytes.reader_to_stream(&reader), &output, buffer = backing[:])
		testing.expect_value(t, brotli.decompress(&z), brotli.Error(brotli.E_Brotli.Trailing_Data))
	}

}
