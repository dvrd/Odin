package compress_gzip

import "core:compress"
import "core:compress/zlib"
import "core:hash"

Level :: zlib.Level

// gzip member (RFC 1952) holding `src` compressed at `level`.
encode :: proc(src: []u8, level := Level.Default, allocator := context.allocator) -> (output: []u8, err: compress.Error) {
	body := zlib.deflate(src, level, allocator) or_return
	defer delete(body, allocator)

	output = make([]u8, len(body) + 18, allocator) or_return

	extra_flags: u8

	if level >= .Best {
		extra_flags = 2
	} else if level <= .Fastest {
		extra_flags = 4
	}

	copy(output, []u8{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, extra_flags, 0xff})
	copy(output[10:], body)

	tail := output[10 + len(body):]
	checksum := hash.crc32(src)
	size := u32(len(src))

	for shift, index in ([4]u32{0, 8, 16, 24}) {
		tail[index] = u8(checksum >> shift)
		tail[4 + index] = u8(size >> shift)
	}

	return output, nil
}
