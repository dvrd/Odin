package test_core_compress

import "core:bytes"
import "core:compress"
import "core:compress/deflate"
import "core:testing"

deflate_optimal_expect_round_trip :: proc(t: ^testing.T, s: ^deflate.Deflate_Optimal, plain: []u8, kind: int, framings: []deflate.Deflate_Stream_Framing) {
	for framing in framings {
		bound := deflate.deflate_gzip_bound(len(plain)) if framing == .Gzip else deflate.deflate_bound(len(plain))
		packed := make([]u8, bound)
		defer delete(packed)

		written: int
		err: compress.Error

		switch framing {
		case .Raw:
			written, err = deflate.deflate_optimal_raw(s, packed, plain)
		case .Zlib:
			written, err = deflate.deflate_optimal_zlib(s, packed, plain)
		case .Gzip:
			written, err = deflate.deflate_optimal_gzip(s, packed, plain)
		}

		testing.expectf(t, err == nil, "%v kind=%d size=%d: %v", framing, kind, len(plain), err)

		unpacked: [dynamic]u8
		defer delete(unpacked)

		inflate_error := deflate_stream_inflate(framing, &unpacked, packed[:written])
		testing.expectf(t, inflate_error == nil, "%v kind=%d size=%d: inflate failed: %v", framing, kind, len(plain), inflate_error)
		testing.expectf(t, bytes.equal(unpacked[:], plain), "%v kind=%d size=%d: round trip differs", framing, kind, len(plain))
	}
}

@(test)
deflate_optimal_round_trips_every_framing :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Optimal)
	defer free(s)

	sizes := [?]int{0, 1, 2, 3, 4, 257, 258, 259, 1000, 20000}

	for kind in 0 ..< DEFLATE_SAMPLE_KINDS {
		for size in sizes {
			plain := deflate_sample(kind, size)
			defer delete(plain)

			deflate_optimal_expect_round_trip(t, s, plain, kind, {.Raw, .Zlib, .Gzip})
		}
	}
}

// Around the size of a stored block, which bounds what a block may cost.
@(test)
deflate_optimal_round_trips_around_the_block_size :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Optimal)
	defer free(s)

	for kind in ([?]int{0, 1, 4}) {
		for size in ([?]int{65535, 65536, 65537}) {
			plain := deflate_sample(kind, size)
			defer delete(plain)

			deflate_optimal_expect_round_trip(t, s, plain, kind, {.Raw})
		}
	}

	zeros := deflate_sample(3, 65536)
	defer delete(zeros)

	deflate_optimal_expect_round_trip(t, s, zeros, 3, {.Raw})
}

// Blocks never span two chunks: an input must survive ending right at one and just after it.
@(test)
deflate_optimal_round_trips_across_chunks :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Optimal)
	defer free(s)

	for size in ([?]int{deflate.DEFLATE_OPTIMAL_CHUNK, deflate.DEFLATE_OPTIMAL_CHUNK + 1}) {
		plain := deflate_sample(4, size)
		defer delete(plain)

		deflate_optimal_expect_round_trip(t, s, plain, 4, {.Raw})
	}
}

@(test)
deflate_optimal_is_no_larger_than_the_best_level :: proc(t: ^testing.T) {
	for kind in ([?]int{1, 4}) {
		plain := deflate_sample(kind, 300000)
		defer delete(plain)

		best: [dynamic]u8
		defer delete(best)

		optimal: [dynamic]u8
		defer delete(optimal)

		testing.expect_value(t, deflate.deflate_raw(&best, plain, .Best), nil)
		testing.expect_value(t, deflate.deflate_optimal_raw(&optimal, plain), nil)
		testing.expectf(t, len(optimal) <= len(best), "kind=%d: optimal %d bytes, best level %d", kind, len(optimal), len(best))

		unpacked: [dynamic]u8
		defer delete(unpacked)

		testing.expect_value(t, deflate.inflate_raw(&unpacked, optimal[:]), nil)
		testing.expect(t, bytes.equal(unpacked[:], plain))
	}
}

@(test)
deflate_optimal_to_dynamic_frames_like_the_slice_procedures :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Optimal)
	defer free(s)

	plain := deflate_sample(4, 50000)
	defer delete(plain)

	packed := make([]u8, deflate.deflate_gzip_bound(len(plain)))
	defer delete(packed)

	grown: [dynamic]u8
	defer delete(grown)

	written, err := deflate.deflate_optimal_zlib(s, packed, plain)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, deflate.deflate_optimal_zlib(&grown, plain), nil)
	testing.expect(t, bytes.equal(grown[:], packed[:written]))

	written, err = deflate.deflate_optimal_gzip(s, packed, plain)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, deflate.deflate_optimal_gzip(&grown, plain), nil)
	testing.expect(t, bytes.equal(grown[:], packed[:written]))
}

@(test)
deflate_optimal_rejects_bad_arguments :: proc(t: ^testing.T) {
	s := new(deflate.Deflate_Optimal)
	defer free(s)

	plain := deflate_sample(1, 1000)
	defer delete(plain)

	packed := make([]u8, deflate.deflate_gzip_bound(len(plain)))
	defer delete(packed)

	_, err := deflate.deflate_optimal_raw(nil, packed, plain)
	testing.expect_value(t, err, compress.General_Error.Incompatible_Options)

	_, err = deflate.deflate_optimal_raw(s, packed[:deflate.deflate_bound(len(plain)) - 1], plain)
	testing.expect_value(t, err, compress.General_Error.Output_Too_Short)

	_, err = deflate.deflate_optimal_gzip(s, packed[:len(packed) - 1], plain)
	testing.expect_value(t, err, compress.General_Error.Output_Too_Short)

	testing.expect_value(t, deflate.deflate_optimal_raw(nil, plain), compress.General_Error.Incompatible_Options)
}
