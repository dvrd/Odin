package incremental_test

import "core:bytes"
import "core:compress"
import "core:compress/deflate"
import "core:mem"
import "core:testing"

// These streams were assembled by an independent Python bitwriter and rejected
// by Python zlib; raw-invalid-manifest.json records each rejection and hash.
@(test)
malformed_raw_trees_symbols_and_distances_are_bounded :: proc(t: ^testing.T) {
	for wire in ([]([]u8){
		#load("testdata/raw-invalid-stored-complement.deflate"),
		#load("testdata/raw-invalid-literal-286.deflate"),
		#load("testdata/raw-invalid-literal-287.deflate"),
		#load("testdata/raw-invalid-distance-before-history.deflate"),
		#load("testdata/raw-invalid-distance-30.deflate"),
		#load("testdata/raw-invalid-distance-31.deflate"),
		#load("testdata/raw-invalid-empty-code-tree.deflate"),
		#load("testdata/raw-invalid-oversubscribed-code-tree.deflate"),
		#load("testdata/raw-invalid-incomplete-code-tree.deflate"),
		#load("testdata/raw-invalid-repeat-16-first.deflate"),
		#load("testdata/raw-invalid-repeat-overflow.deflate"),
		#load("testdata/raw-invalid-missing-end-code.deflate"),
	}) {
		for partition in ([2]int{1, len(wire)}) {
			d: deflate.Inflate_Decoder
			_ = deflate.inflate_decoder_init(&d, u64(len(wire)), 1024)
			at := 0
			detected := false
			output: [8]u8
			for _ in 0..<4096 {
				end := min(at+partition, len(wire))
				r := deflate.inflate_decoder_step(&d, wire[at:end], output[:], end == len(wire), 1)
				testing.expect(t, r.work <= 1 && r.consumed <= end-at && r.produced <= len(output))
				at += r.consumed
				if r.err != .None {
					testing.expect_value(t, r.err, .Malformed)
					sticky := deflate.inflate_decoder_step(&d, nil, nil, false, 1)
					testing.expect_value(t, sticky.err, .Malformed)
					detected = true
					break
				}
				if r.status == .Done {break}
			}
			testing.expect(t, detected)
		}
	}
}

@(test)
zero_output_resumes_literal_and_history_copy_without_loss :: proc(t: ^testing.T) {
	for vector in ([]struct{wire, plain: []u8}{
		{small_gzip, small}, {dynamic_gzip, payload},
	}) {
		d: deflate.Gzip_Decoder
		_ = deflate.inflate_gzip_decoder_init(&d, limits(len(vector.wire), len(vector.plain)))
		at, produced, stalls := 0, 0, 0
		finished := false
		output: [17]u8
		for _ in 0..<20000 {
			paused := deflate.inflate_gzip_decoder_step(&d, vector.wire[at:], nil, true)
			at += paused.consumed
			testing.expect(t, paused.err == .None && paused.produced == 0)
			if paused.status == .Done {finished = true; break}
			testing.expect_value(t, paused.status, .Need_Output)
			stalls += 1
			r := deflate.inflate_gzip_decoder_step(&d, vector.wire[at:], output[:], true)
			at += r.consumed
			testing.expect_value(t, r.err, .None)
			if r.produced > len(vector.plain)-produced {testing.expect(t, false); break}
			testing.expect(t, bytes.equal(output[:r.produced], vector.plain[produced:produced+r.produced]))
			produced += r.produced
			if r.status == .Done {finished = true; break}
		}
		testing.expect(t, finished && stalls > 0 && at == len(vector.wire) && produced == len(vector.plain))
	}
	// Zero destination capacity cannot hide a decoded-limit violation.
	d: deflate.Gzip_Decoder
	_ = deflate.inflate_gzip_decoder_init(&d, limits(len(small_gzip), 0))
	r := deflate.inflate_gzip_decoder_step(&d, small_gzip, nil, true)
	testing.expect(t, r.err == .Decoded_Limit && r.produced == 0 && d.decoded_bytes == 0)
	_ = deflate.inflate_gzip_decoder_init(&d, limits(len(empty_gzip), 0))
	r = deflate.inflate_gzip_decoder_step(&d, empty_gzip, nil, true)
	testing.expect(t, r.err == .None && r.status == .Done && d.decoded_bytes == 0)
}

@(test)
configuration_rejection_alias_directions_and_reinitialization_are_atomic :: proc(t: ^testing.T) {
	d: deflate.Gzip_Decoder
	_ = deflate.inflate_gzip_decoder_init(&d)
	before := d
	for config in ([]deflate.Gzip_Decoder_Config{
		{1000, 1000, 9, 1}, {1000, 1000, (1<<20)+1, 1},
		{1000, 1000, 8192, 0}, {1000, 1000, 8192, 1025},
	}) {
		testing.expect_value(t, deflate.inflate_gzip_decoder_init(&d, config), .Invalid_Config)
		testing.expect(t, bytes.equal(mem.byte_slice(&d, size_of(d)), mem.byte_slice(&before, size_of(before))))
	}
	buffer: [64]u8
	for &b in buffer {b = 0xa5}
	bytes_before := buffer
	for reverse in ([2]bool{false, true}) {
		input, output := buffer[:20], buffer[4:24]
		if reverse {input, output = output, input}
		r := deflate.inflate_gzip_decoder_step(&d, input, output, false)
		testing.expect_value(t, r.err, .Overlapping_Buffers)
		testing.expect(t, bytes.equal(mem.byte_slice(&d, size_of(d)), mem.byte_slice(&before, size_of(before))))
		testing.expect(t, bytes.equal(buffer[:], bytes_before[:]))
		raw: deflate.Inflate_Decoder
		_ = deflate.inflate_decoder_init(&raw, 1000, 1000)
		raw_before := raw
		rr := deflate.inflate_decoder_step(&raw, input, output, false)
		testing.expect_value(t, rr.err, .Overlapping_Buffers)
		testing.expect(t, bytes.equal(mem.byte_slice(&raw, size_of(raw)), mem.byte_slice(&raw_before, size_of(raw_before))))
		testing.expect(t, bytes.equal(buffer[:], bytes_before[:]))
	}
	failed := deflate.inflate_gzip_decoder_step(&d, small_gzip[:1], buffer[:], true)
	testing.expect_value(t, failed.err, .Truncated)
	testing.expect_value(t, deflate.inflate_gzip_decoder_init(&d), .None)
	complete := deflate.inflate_gzip_decoder_step(&d, small_gzip, buffer[:], true)
	testing.expect(t, complete.err == .None && complete.status == .Done)
	testing.expect(t, bytes.equal(buffer[:complete.produced], small))
}
