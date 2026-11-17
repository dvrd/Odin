package compress_zlib

import "core:compress"
import "core:hash"

// zlib container (RFC 1950) around the DEFLATE encoder.
encode :: proc(src: []u8, level := Level.Default, allocator := context.allocator) -> (output: []u8, err: compress.Error) {
	body := deflate(src, level, allocator) or_return
	defer delete(body, allocator)

	output = make([]u8, len(body) + 6, allocator) or_return

	output[0] = 0x78
	output[1] = zlib_flags(level)
	copy(output[2:], body)

	checksum := hash.adler32(src)
	tail := output[2 + len(body):]
	tail[0] = u8(checksum >> 24)
	tail[1] = u8(checksum >> 16)
	tail[2] = u8(checksum >> 8)
	tail[3] = u8(checksum)

	return output, nil
}

@(private)
zlib_flags :: proc(level: Level) -> u8 {
	switch {
	case level <= .Fastest:
		return 0x01
	case level < .Default:
		return 0x5e
	case level == .Default:
		return 0x9c
	}

	return 0xda
}
