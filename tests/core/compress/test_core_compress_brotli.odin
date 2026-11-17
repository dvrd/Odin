package test_core_compress

import "core:bytes"
import "core:compress/brotli"
import "core:testing"

brotli_decode :: proc(data: []u8) -> (plain: []u8, err: brotli.Error) {
	buf: bytes.Buffer
	err = brotli.load(data, &buf)

	return buf.buf[:], err
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
			data := encode_sample(kind, size)
			defer delete(data)

			for level in BROTLI_LEVELS {
				packed, encode_error := brotli.encode(data, level)
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
	packed, encode_error := brotli.encode(transmute([]u8)text, .Best)
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
	data := encode_sample(1, 300000)
	defer delete(data)

	previous := max(int) / 2

	for level in BROTLI_LEVELS {
		packed, encode_error := brotli.encode(data, level)
		defer delete(packed)

		testing.expect_value(t, encode_error, nil)
		testing.expectf(t, len(packed) <= previous + previous / 50, "level %v grew to %d from %d", level, len(packed), previous)
		previous = len(packed)
	}

	random := encode_sample(0, 100000)
	defer delete(random)

	stored, stored_error := brotli.encode(random, .Default)
	defer delete(stored)

	testing.expect_value(t, stored_error, nil)
	testing.expect(t, len(stored) <= len(random) + 16, "incompressible data must be stored")
}

@(test)
brotli_decode_rejects_damaged_streams :: proc(t: ^testing.T) {
	data := encode_sample(1, 20000)
	defer delete(data)

	packed, encode_error := brotli.encode(data, .Default)
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
			sample := encode_sample(kind, size)
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

	sample := encode_sample(2, 100_000)
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
			packed, encode_error := brotli.encode_meta_blocks(sample, brotli.Level(level), meta_block_max)
			defer delete(packed)

			testing.expectf(t, encode_error == nil, "encode failed: level %d block %d: %v", level, meta_block_max, encode_error)

			unpacked, err := brotli_decode(packed)
			defer delete(unpacked)

			testing.expectf(t, err == nil, "decode failed: level %d block %d: %v", level, meta_block_max, err)
			testing.expectf(t, bytes.equal(unpacked, sample), "mismatch: level %d block %d", level, meta_block_max)
		}
	}
}
