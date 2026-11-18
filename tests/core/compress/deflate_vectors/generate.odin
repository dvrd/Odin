// Regenerates the gzip members of this directory from the incremental decoder's payload:
//
//	odin run tests/core/compress/deflate_vectors
//
// `check.sh` then decodes each one with the system `gzip`.
package deflate_vectors

import "core:compress/deflate"
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

// One gzip member from the streaming compressor, flushed every `flush_every` input bytes when not zero.
stream_vector :: proc(s: ^deflate.Deflate_Stream, level: deflate.Deflate_Level, flush_every: int) -> []u8 {
	packed: [dynamic]u8
	buffer: [4096]u8
	rest := PAYLOAD

	deflate.deflate_stream_reset(s, .Gzip, level)

	for len(rest) > 0 {
		piece := rest[:min(len(rest), flush_every)] if flush_every > 0 else rest
		rest = rest[len(piece):]

		for len(piece) > 0 {
			piece = piece[deflate.deflate_stream_write(s, piece):]
			append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
		}

		for flush_every > 0 && !deflate.deflate_stream_flush(s) {
			append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
		}
	}

	for !deflate.deflate_stream_finish(s) {
		append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
	}

	for deflate.deflate_stream_pending(s) > 0 {
		append(&packed, ..buffer[:deflate.deflate_stream_pull(s, buffer[:])])
	}

	return packed[:]
}

main :: proc() {
	s := new(deflate.Deflate_Stream)

	write_vector("stream-level-1.gz", stream_vector(s, .Level_1, 0))
	write_vector("stream-level-6.gz", stream_vector(s, .Level_6, 0))
	write_vector("stream-level-10.gz", stream_vector(s, .Level_10, 0))
	write_vector("stream-flushed.gz", stream_vector(s, .Level_6, FLUSH_EVERY))

	optimal: [dynamic]u8

	if err := deflate.deflate_optimal_gzip(&optimal, PAYLOAD); err != nil {
		fmt.eprintfln("optimal: %v", err)
		os.exit(1)
	}

	write_vector("optimal.gz", optimal[:])
}
