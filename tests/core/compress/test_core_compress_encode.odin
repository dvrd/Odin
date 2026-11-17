package test_core_compress

import "core:bytes"
import "core:compress/deflate"
import "core:compress/gzip"
import "core:compress/zlib"
import "core:testing"

ENCODE_LEVELS := [?]zlib.Level{.Store, .Fastest, .Fast, .Default, .Best, .Optimal}

// Deterministic inputs that exercise literals, short and long matches, runs,
// incompressible data and the stored-block size boundaries.
encode_sample :: proc(kind, size: int, allocator := context.allocator) -> []u8 {
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

@(test)
deflate_encode_round_trips_every_level :: proc(t: ^testing.T) {
	sizes := [?]int{0, 1, 2, 3, 4, 257, 258, 259, 1000, 32768, 65535, 65536, 65537, 200000}

	for kind in 0 ..< 5 {
		for size in sizes {
			plain := encode_sample(kind, size)
			defer delete(plain)

			for level in ENCODE_LEVELS {
				packed, encode_error := zlib.encode(plain, level)
				testing.expectf(t, encode_error == nil, "zlib encode kind=%d size=%d level=%v: %v", kind, size, level, encode_error)

				buffer: bytes.Buffer
				inflate_error := deflate.inflate_zlib(&buffer.buf, packed)
				testing.expectf(t, inflate_error == nil, "zlib inflate kind=%d size=%d level=%v: %v", kind, size, level, inflate_error)
				testing.expectf(t, bytes.equal(buffer.buf[:], plain), "zlib round trip kind=%d size=%d level=%v", kind, size, level)
				testing.expectf(t, len(packed) <= zlib.deflate_bound(size) + 6, "bound kind=%d size=%d level=%v", kind, size, level)

				bytes.buffer_destroy(&buffer)
				delete(packed)
			}
		}
	}
}

@(test)
deflate_encode_levels_order_by_size :: proc(t: ^testing.T) {
	plain := encode_sample(1, 300000)
	defer delete(plain)

	previous := max(int)

	for level in ([?]zlib.Level{.Fastest, .Default, .Best, .Optimal}) {
		packed, encode_error := zlib.deflate(plain, level)
		testing.expect(t, encode_error == nil)
		testing.expectf(t, len(packed) <= previous, "level %v produced %d bytes, weaker level %d", level, len(packed), previous)
		previous = len(packed)
		delete(packed)
	}

	testing.expect(t, previous < len(plain) / 3)
}

@(test)
gzip_encode_round_trips :: proc(t: ^testing.T) {
	for kind in 0 ..< 5 {
		plain := encode_sample(kind, 70000)
		defer delete(plain)

		for level in ENCODE_LEVELS {
			packed, encode_error := gzip.encode(plain, level)
			testing.expect(t, encode_error == nil)

			buffer: bytes.Buffer
			load_error := deflate.inflate_gzip(&buffer.buf, packed)
			testing.expectf(t, load_error == nil, "gzip load kind=%d level=%v: %v", kind, level, load_error)
			testing.expectf(t, bytes.equal(buffer.buf[:], plain), "gzip round trip kind=%d level=%v", kind, level)

			bytes.buffer_destroy(&buffer)
			delete(packed)
		}
	}
}

@(test)
gzip_stream_encoder_round_trips_with_short_writes :: proc(t: ^testing.T) {
	encoder := new(gzip.Stream_Encoder)
	defer free(encoder)

	for kind in 0 ..< 5 {
		plain := encode_sample(kind, 150000)
		defer delete(plain)

		packed := make([]u8, gzip.stream_bound(len(plain)))
		defer delete(packed)

		gzip.stream_reset(encoder)
		written := 0
		offset := 0
		step := 1

		for offset < len(plain) {
			count := gzip.stream_write(encoder, plain[offset:min(offset + step, len(plain))])
			offset += count
			step = step % 4099 + 17

			if count == 0 {
				pulled := gzip.stream_pull(encoder, packed[written:])
				testing.expect(t, pulled > 0, "a stalled write must have output to drain")
				written += pulled
			}
		}

		for !gzip.stream_finish(encoder) {
			pulled := gzip.stream_pull(encoder, packed[written:])
			testing.expect(t, pulled > 0)
			written += pulled
		}

		for {
			pulled := gzip.stream_pull(encoder, packed[written:])

			if pulled == 0 {
				break
			}

			written += pulled
		}

		testing.expect(t, !encoder.overflow)

		buffer: bytes.Buffer
		load_error := deflate.inflate_gzip(&buffer.buf, packed[:written])
		testing.expectf(t, load_error == nil, "stream load kind=%d: %v", kind, load_error)
		testing.expectf(t, bytes.equal(buffer.buf[:], plain), "stream round trip kind=%d", kind)
		bytes.buffer_destroy(&buffer)
	}
}

@(test)
gzip_stream_encoder_reports_overflow_at_its_cap :: proc(t: ^testing.T) {
	encoder := new(gzip.Stream_Encoder)
	defer free(encoder)

	plain := encode_sample(0, 100000)
	defer delete(plain)

	packed := make([]u8, gzip.stream_bound(len(plain)))
	defer delete(packed)

	gzip.stream_reset(encoder, 4096)
	_, ok := gzip.stream_encode_into(encoder, plain, packed)
	testing.expect(t, !ok)
	testing.expect(t, encoder.overflow)
}
