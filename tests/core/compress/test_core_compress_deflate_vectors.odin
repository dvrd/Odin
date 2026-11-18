package test_core_compress

import "core:bytes"
import "core:compress"
import "core:compress/deflate"
import "core:testing"

// Fixed gzip members written by `deflate_vectors/generate.odin`; `deflate_vectors/check.sh`
// decodes the same files with the system gzip.
@(test)
deflate_vectors_decode_to_their_payload :: proc(t: ^testing.T) {
	payload := #load("incremental/testdata/payload.bin")
	vectors := [?][]u8{
		#load("deflate_vectors/stream-level-1.gz"),
		#load("deflate_vectors/stream-level-6.gz"),
		#load("deflate_vectors/stream-level-10.gz"),
		#load("deflate_vectors/stream-flushed.gz"),
		#load("deflate_vectors/optimal.gz"),
	}

	decoder := new(deflate.Gzip_Decoder)
	defer free(decoder)

	for vector, index in vectors {
		unpacked: [dynamic]u8
		defer delete(unpacked)

		inflate_error := deflate.inflate_gzip(&unpacked, vector)
		testing.expectf(t, inflate_error == nil, "vector %d: inflate failed: %v", index, inflate_error)
		testing.expectf(t, bytes.equal(unpacked[:], payload), "vector %d: inflate differs from the payload", index)

		// One byte at a time in and out through the resumable decoder.
		config := deflate.Gzip_Decoder_Config{u64(len(vector)), u64(len(payload)), 8192, 1}
		testing.expect_value(t, deflate.inflate_gzip_decoder_init(decoder, config), compress.Decode_Error.None)

		at, produced := 0, 0
		done := false
		output: [1]u8

		for _ in 0 ..< 4 * len(payload) {
			end := min(at + 1, len(vector))
			r := deflate.inflate_gzip_decoder_step(decoder, vector[at:end], output[:], end == len(vector))
			at += r.consumed

			if r.err != .None || (r.produced == 1 && (produced == len(payload) || output[0] != payload[produced])) {
				testing.expectf(t, false, "vector %d: resumable decode failed at %d: %v", index, produced, r.err)
				break
			}

			produced += r.produced

			if r.status == .Done {
				done = true
				break
			}
		}

		testing.expectf(t, done && at == len(vector) && produced == len(payload), "vector %d: resumable decode stopped at %d of %d", index, produced, len(payload))
	}
}
