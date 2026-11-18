package incremental_test

import "core:bytes"
import "core:compress"
import "core:compress/deflate"
import "core:mem"
import "core:testing"

payload := #load("testdata/payload.bin")
small := #load("testdata/small.bin")
dynamic_gzip := #load("testdata/dynamic.gz")
small_gzip := #load("testdata/small.gz")
optional_gzip := #load("testdata/optional.gz")
empty_gzip := #load("testdata/empty.gz")

// Input partitions, output capacity and work budgets vary independently.
// Compare every successful output span against independent reference bytes.
drive_gzip :: proc(encoded, expected: []u8, input_size, output_size, work: int,
	config: deflate.Gzip_Decoder_Config) -> compress.Decode_Error {
	d: deflate.Gzip_Decoder
	if e := deflate.inflate_gzip_decoder_init(&d, config); e != .None {return e}
	at, produced := 0, 0
	output: [8192]u8
	for _ in 0..<2_000_000 {
		end := min(at+input_size, len(encoded))
		r := deflate.inflate_gzip_decoder_step(&d, encoded[at:end], output[:output_size], end == len(encoded), work)
		if r.consumed < 0 || r.consumed > end-at || r.produced < 0 ||
			r.produced > output_size || r.work < 0 || r.work > work {return .Invalid_State}
		at += r.consumed
		if r.err != .None {return r.err}
		if r.produced > len(expected)-produced {return .Decoded_Limit}
		if !bytes.equal(output[:r.produced], expected[produced:produced+r.produced]) {return .Malformed}
		produced += r.produced
		if r.status == .Done {
			if at != len(encoded) || produced != len(expected) ||
				d.encoded_bytes != u64(at) || d.decoded_bytes != u64(produced) {return .Invalid_State}
			return .None
		}
		if r.status == .Need_Input && r.consumed != end-(at-r.consumed) {return .Invalid_State}
		if r.consumed == 0 && r.produced == 0 && r.work == 0 {return .Invalid_State}
	}
	return .Invalid_State
}

limits :: proc(encoded, decoded: int, members: u32 = 1, header: u32 = 8192) -> deflate.Gzip_Decoder_Config {
	return {u64(encoded), u64(decoded), header, members}
}

@(test)
gzip_independent_vectors_partition_output_and_work :: proc(t: ^testing.T) {
	previous := context
	context.allocator = mem.panic_allocator()
	context.temp_allocator = mem.panic_allocator()
	defer context = previous
	for vector in ([]struct{wire, plain: []u8}{
		{dynamic_gzip, payload}, {small_gzip, small},
		{optional_gzip, small}, {empty_gzip, nil},
	}) {
		for input_size in ([3]int{1, 7, len(vector.wire)}) {
			for output_size in ([3]int{1, 31, 8192}) {
				for work in ([3]int{1, 17, 4096}) {
					e := drive_gzip(vector.wire, vector.plain, input_size, output_size, work,
						limits(len(vector.wire), len(vector.plain)))
					testing.expect_value(t, e, .None)
				}
			}
		}
	}
}

@(test)
raw_stored_fixed_dynamic_and_precise_trailer_boundary :: proc(t: ^testing.T) {
	for wire in ([]([]u8){#load("testdata/stored.deflate"),
		#load("testdata/fixed.deflate"), #load("testdata/dynamic.deflate")}) {
		for input_size in ([2]int{1, len(wire)}) {
			d: deflate.Inflate_Decoder
			testing.expect_value(t, deflate.inflate_decoder_init(&d, u64(len(wire)), u64(len(payload))), .None)
			at, produced := 0, 0
			output: [113]u8
			finished := false
			for _ in 0..<2_000_000 {
				end := min(at+input_size, len(wire))
				r := deflate.inflate_decoder_step(&d, wire[at:end], output[:], end == len(wire), 7)
				testing.expect(t, r.work <= 7 && r.consumed <= end-at && r.produced <= len(output))
				if r.err != .None {testing.expect_value(t, r.err, .None); break}
				at += r.consumed
				if r.produced > len(payload)-produced {testing.expect(t, false); break}
				testing.expect(t, bytes.equal(output[:r.produced], payload[produced:produced+r.produced]))
				produced += r.produced
				if r.status == .Done {finished = true; break}
			}
			testing.expect(t, finished && at == len(wire) && produced == len(payload))
		}
	}
	// DEFLATE must leave the following gzip trailer bytes unread.
	d: deflate.Inflate_Decoder
	_ = deflate.inflate_decoder_init(&d, u64(len(small_gzip)), u64(len(small)))
	output: [128]u8
	r := deflate.inflate_decoder_step(&d, small_gzip[10:], output[:], true)
	testing.expect(t, r.err == .None && r.status == .Done)
	testing.expect_value(t, r.consumed, len(small_gzip)-18)
}

@(test)
gzip_limits_metadata_members_and_zero_remaining_credit :: proc(t: ^testing.T) {
	concat := #load("testdata/concat.gz")
	for test in ([]struct{wire, plain: []u8, config: deflate.Gzip_Decoder_Config, error: compress.Decode_Error}{
		{small_gzip, small, limits(len(small_gzip)-1, len(small)), .Encoded_Limit},
		{small_gzip, small, limits(len(small_gzip), len(small)-1), .Decoded_Limit},
		{optional_gzip, small, limits(len(optional_gzip), len(small), 1, 12), .Metadata_Limit},
		{concat, small, limits(len(concat), len(small), 1), .Member_Limit},
		{concat, small, limits(len(concat), len(small), 2), .None},
		{#load("testdata/trailing.gz"), small, limits(1000, 1000), .Trailing_Data},
		{empty_gzip, nil, limits(len(empty_gzip), 0), .None},
	}) {
		testing.expect_value(t, drive_gzip(test.wire, test.plain, 1, 17, 1, test.config), test.error)
	}
}

@(test)
gzip_corrupt_trailers_headers_and_every_truncation :: proc(t: ^testing.T) {
	for test in ([]struct{wire: []u8, error: compress.Decode_Error}{
		{#load("testdata/bad_crc.gz"), .Checksum_Mismatch},
		{#load("testdata/bad_size.gz"), .Size_Mismatch},
		{#load("testdata/bad_header_crc.gz"), .Checksum_Mismatch},
		{#load("testdata/bad_flags.gz"), .Malformed},
	}) {
		testing.expect_value(t, drive_gzip(test.wire, small, 1, 3, 1, limits(1000, 1000)), test.error)
	}
	for n in 0..<len(optional_gzip) {
		testing.expect_value(t, drive_gzip(optional_gzip[:n], small, 1, 17, 1, limits(1000, 1000)), .Truncated)
	}
	d: deflate.Inflate_Decoder
	_ = deflate.inflate_decoder_init(&d, 1, 10)
	bad := [1]u8{7} // RFC1951 reserved BTYPE=11.
	output: [8]u8
	r := deflate.inflate_decoder_step(&d, bad[:], output[:], true, 1)
	testing.expect_value(t, r.err, .Malformed)
}

@(test)
gzip_argument_atomicity_sticky_failure_and_terminal_state :: proc(t: ^testing.T) {
	d: deflate.Gzip_Decoder
	_ = deflate.inflate_gzip_decoder_init(&d)
	before := d
	buffer: [64]u8
	copy(buffer[:], small_gzip)
	bytes_before := buffer
	r := deflate.inflate_gzip_decoder_step(&d, buffer[:20], buffer[4:24], false)
	testing.expect_value(t, r.err, .Overlapping_Buffers)
	testing.expect(t, bytes.equal(mem.byte_slice(&d, size_of(d)), mem.byte_slice(&before, size_of(before))))
	testing.expect(t, bytes.equal(buffer[:], bytes_before[:]))
	for budget in ([3]int{-1, 0, compress.DECODE_MAX_WORK+1}) {
		r = deflate.inflate_gzip_decoder_step(&d, small_gzip, buffer[:], true, budget)
		testing.expect_value(t, r.err, .Invalid_Config)
		testing.expect(t, bytes.equal(mem.byte_slice(&d, size_of(d)), mem.byte_slice(&before, size_of(before))))
	}
	r = deflate.inflate_gzip_decoder_step(&d, small_gzip[:1], buffer[:], true)
	testing.expect_value(t, r.err, .Truncated)
	r = deflate.inflate_gzip_decoder_step(&d, small_gzip, buffer[:], false)
	testing.expect_value(t, r.err, .Truncated)
	_ = deflate.inflate_gzip_decoder_init(&d)
	r = deflate.inflate_gzip_decoder_step(&d, small_gzip, buffer[:], false)
	testing.expect(t, r.err == .None && r.status == .Need_Input)
	r = deflate.inflate_gzip_decoder_step(&d, nil, buffer[:], true)
	testing.expect(t, r.err == .None && r.status == .Done)
	r = deflate.inflate_gzip_decoder_step(&d, nil, buffer[:], true)
	testing.expect(t, r.err == .None && r.status == .Done)
	garbage := [1]u8{0}
	r = deflate.inflate_gzip_decoder_step(&d, garbage[:], buffer[:], true)
	testing.expect_value(t, r.err, .Trailing_Data)
}
