// Regenerates the gzip members of this directory from the incremental decoder's payload:
//
//	odin run tests/core/compress/deflate_vectors
//
// `check.sh` then decodes each one with the system `gzip`.
package deflate_vectors

import "core:compress/deflate"
import "core:compress/step"
import "core:fmt"
import "core:os"

PAYLOAD :: #load("../incremental/testdata/payload.bin")

FLUSH_EVERY :: 10000

write_vector :: proc(name: string, packed: []u8) {
	path := fmt.tprintf("%s/%s", #directory, name)

	if err := os.write_entire_file(path, packed); err != nil {
		fmt.eprintfln("%s: %v", path, err)
		os.exit(1)
	}

	fmt.printfln("%s: %d bytes", name, len(packed))
}

// One gzip member from the pull-style encoder, flushed every `flush_every` input bytes when not zero.
stream_vector :: proc(e: ^step.Deflate_Encoder, level: deflate.Deflate_Level, flush_every: int) -> []u8 {
	packed: [dynamic]u8
	buffer: [4096]u8
	rest := PAYLOAD

	if err := step.deflate_encoder_reset(e, .Gzip, level); err != nil {
		fmt.eprintfln("reset: %v", err)
		os.exit(1)
	}

	for len(rest) > 0 {
		piece := rest[:min(len(rest), flush_every)] if flush_every > 0 else rest
		rest = rest[len(piece):]

		for len(piece) > 0 {
			piece = piece[step.deflate_encoder_write(e, piece):]
			append(&packed, ..buffer[:step.deflate_encoder_pull(e, buffer[:])])
		}

		for flush_every > 0 && !step.deflate_encoder_flush(e) {
			append(&packed, ..buffer[:step.deflate_encoder_pull(e, buffer[:])])
		}
	}

	for !step.deflate_encoder_finish(e) {
		append(&packed, ..buffer[:step.deflate_encoder_pull(e, buffer[:])])
	}

	for step.deflate_encoder_pending(e) > 0 {
		append(&packed, ..buffer[:step.deflate_encoder_pull(e, buffer[:])])
	}

	return packed[:]
}

main :: proc() {
	e: step.Deflate_Encoder

	if err := step.deflate_encoder_init(&e, .Gzip); err != nil {
		fmt.eprintfln("init: %v", err)
		os.exit(1)
	}

	defer step.deflate_encoder_destroy(&e)

	write_vector("stream-level-1.gz", stream_vector(&e, .Level_1, 0))
	write_vector("stream-level-6.gz", stream_vector(&e, .Level_6, 0))
	write_vector("stream-level-10.gz", stream_vector(&e, .Level_10, 0))
	write_vector("stream-flushed.gz", stream_vector(&e, .Level_6, FLUSH_EVERY))

	// `optimal.gz` came from an encoder this tree no longer has. It stays as a
	// vector for the decoders and is not regenerated.
}
