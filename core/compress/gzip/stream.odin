package compress_gzip

import "core:hash"
import "core:math/bits"
import "core:mem"

// Bounded-state streaming gzip encoder: one final fixed-Huffman DEFLATE block,
// a 32 KiB window and a short hash chain. It never allocates, accepts input in
// arbitrary pieces and applies backpressure through a small output buffer, so
// it suits bodies produced on the fly. Use `encode` when the whole input is in
// memory and ratio matters.

STREAM_PROBE_LIMIT :: 8
STREAM_WINDOW :: 32768
STREAM_HASH_BITS :: 12

@(private = "file")
STREAM_LENGTH_BASE := [29]int {
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	13,
	15,
	17,
	19,
	23,
	27,
	31,
	35,
	43,
	51,
	59,
	67,
	83,
	99,
	115,
	131,
	163,
	195,
	227,
	258,
}
@(private = "file")
STREAM_LENGTH_EXTRA := [29]int{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
@(private = "file")
STREAM_DISTANCE_BASE := [30]int {
	1,
	2,
	3,
	4,
	5,
	7,
	9,
	13,
	17,
	25,
	33,
	49,
	65,
	97,
	129,
	193,
	257,
	385,
	513,
	769,
	1025,
	1537,
	2049,
	3073,
	4097,
	6145,
	8193,
	12289,
	16385,
	24577,
}
@(private = "file")
STREAM_DISTANCE_EXTRA := [30]int {
	0,
	0,
	0,
	0,
	1,
	1,
	2,
	2,
	3,
	3,
	4,
	4,
	5,
	5,
	6,
	6,
	7,
	7,
	8,
	8,
	9,
	9,
	10,
	10,
	11,
	11,
	12,
	12,
	13,
	13,
}

// One final fixed-Huffman deflate block. State is about 184 KiB plus the caller's chunk.
Stream_Encoder :: struct {
	window:                                        [STREAM_WINDOW]u8,
	head:                                          [1 << STREAM_HASH_BITS]i32,
	prev:                                          [STREAM_WINDOW]i32,
	out:                                           [8192]u8,
	out_len, out_off, pos, total, produced, nbits: int,
	bits:                                          u32,
	crc:                                           u32,
	opened, finished, overflow:                    bool,
	// Zero means unbounded; otherwise exceeding it sets `overflow`.
	max_output:                                    int,
}

stream_bound :: proc(n: int) -> int {
	if n < 0 do return 0

	return 20 + (n * 9 + 7) / 8
}

stream_reset :: proc(e: ^Stream_Encoder, max_output := 0) {
	e^ = {}
	e.max_output = max_output
	mem.set(raw_data(e.head[:]), 0xff, size_of(e.head))
}

@(private = "file")
stream_byte :: proc(e: ^Stream_Encoder, value: u8) {
	if e.overflow do return

	if e.max_output > 0 && e.produced >= e.max_output || e.out_len >= len(e.out) {
		e.overflow = true
		return
	}

	e.out[e.out_len] = value
	e.out_len += 1
	e.produced += 1
}

@(private = "file")
stream_put :: proc(e: ^Stream_Encoder, value: u32, count: int) {
	if count <= 0 do return
	mask := (u32(1) << uint(count)) - 1
	e.bits |= (value & mask) << uint(e.nbits)
	e.nbits += count

	for e.nbits >= 8 {
		stream_byte(e, u8(e.bits))
		e.bits >>= 8
		e.nbits -= 8
	}
}

@(private = "file")
stream_reverse :: proc(code: u32, count: int) -> u32 {
	return bits.reverse_bits(code) >> uint(32 - count)
}

@(private = "file")
stream_fixed_code :: proc(symbol: int) -> (u32, int) {
	switch {
	case symbol <= 143:
		return u32(0x30 + symbol), 8
	case symbol <= 255:
		return u32(0x190 + symbol - 144), 9
	case symbol <= 279:
		return u32(symbol - 256), 7
	}

	return u32(0xc0 + symbol - 280), 8
}

@(private = "file")
stream_symbol :: proc(e: ^Stream_Encoder, symbol: int) {
	code, count := stream_fixed_code(symbol)
	stream_put(e, stream_reverse(code, count), count)
}

@(private = "file")
stream_open :: proc(e: ^Stream_Encoder) {
	if e.opened do return

	for value in ([10]u8{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff}) {
		stream_byte(e, value)
	}

	stream_put(e, 3, 3) // Final fixed-Huffman block.
	e.opened = true
}

@(private = "file")
stream_match :: proc(e: ^Stream_Encoder, length, distance: int) {
	for index := 28; index >= 0; index -= 1 {
		if length >= STREAM_LENGTH_BASE[index] {
			stream_symbol(e, 257 + index)
			extra := STREAM_LENGTH_EXTRA[index]
			if extra > 0 do stream_put(e, u32(length - STREAM_LENGTH_BASE[index]), extra)
			break
		}
	}

	for index := 29; index >= 0; index -= 1 {
		if distance >= STREAM_DISTANCE_BASE[index] {
			stream_put(e, stream_reverse(u32(index), 5), 5)
			extra := STREAM_DISTANCE_EXTRA[index]
			if extra > 0 do stream_put(e, u32(distance - STREAM_DISTANCE_BASE[index]), extra)
			return
		}
	}

	e.overflow = true
}

@(private = "file")
stream_hash :: proc(a, b, c: u8) -> int {
	value := (u32(a) | u32(b) << 8 | u32(c) << 16) * 0x1e35a7bd

	return int(value >> (32 - STREAM_HASH_BITS))
}

@(private = "file")
stream_source :: proc(e: ^Stream_Encoder, abs, base: int, src: []u8) -> u8 {
	if abs >= base do return src[abs - base]

	return e.window[abs & (STREAM_WINDOW - 1)]
}

// Consumes a prefix. A full emission buffer stops progress without failing.
stream_write :: proc(e: ^Stream_Encoder, src: []u8) -> int {
	if e.finished || e.overflow || len(src) == 0 do return 0
	stream_open(e)
	if e.overflow do return 0
	base, consumed := e.pos, 0

	for consumed < len(src) {
		if len(e.out) - e.out_len < 16 do break
		current := base + consumed
		best_length, best_distance := 0, 0

		if consumed + 2 < len(src) {
			hash := stream_hash(src[consumed], src[consumed + 1], src[consumed + 2])
			candidate := int(e.head[hash])

			for _ in 0 ..< STREAM_PROBE_LIMIT {
				if candidate < 0 do break
				distance := current - candidate
				if distance <= 0 || distance > STREAM_WINDOW do break
				limit := min(258, len(src) - consumed)
				length := 0

				for length < limit {
					if stream_source(e, candidate + length, base, src) != src[consumed + length] do break
					length += 1
				}

				if length > best_length {
					best_length, best_distance = length, distance
				}

				next := int(e.prev[candidate & (STREAM_WINDOW - 1)])
				if next >= candidate do break
				candidate = next
			}

			slot := current & (STREAM_WINDOW - 1)
			e.prev[slot] = e.head[hash]
			e.head[hash] = i32(current)
		}

		if best_length >= 3 {
			stream_match(e, best_length, best_distance)

			for offset in 1 ..< best_length {
				at := current + offset
				e.window[at & (STREAM_WINDOW - 1)] = src[consumed + offset]

				if consumed + offset + 2 < len(src) {
					hash := stream_hash(src[consumed + offset], src[consumed + offset + 1], src[consumed + offset + 2])
					index := at & (STREAM_WINDOW - 1)
					e.prev[index] = e.head[hash]
					e.head[hash] = i32(at)
				}
			}

			e.window[current & (STREAM_WINDOW - 1)] = src[consumed]
			consumed += best_length
		} else {
			stream_symbol(e, int(src[consumed]))
			e.window[current & (STREAM_WINDOW - 1)] = src[consumed]
			consumed += 1
		}

		if e.overflow do return 0
	}

	if consumed > 0 {
		e.crc = hash.crc32(src[:consumed], e.crc)
		e.total += consumed
		e.pos += consumed
	}

	return consumed
}

stream_finish :: proc(e: ^Stream_Encoder) -> bool {
	if e.finished do return true
	if e.overflow || len(e.out) - e.out_len < 24 do return false
	stream_open(e)
	stream_symbol(e, 256)

	if e.nbits > 0 {
		stream_byte(e, u8(e.bits))
		e.bits, e.nbits = 0, 0
	}

	crc, size := e.crc, u32(e.total)
	for shift in ([4]u32{0, 8, 16, 24}) do stream_byte(e, u8(crc >> shift))
	for shift in ([4]u32{0, 8, 16, 24}) do stream_byte(e, u8(size >> shift))
	e.finished = !e.overflow

	return e.finished
}

stream_pull :: proc(e: ^Stream_Encoder, dst: []u8) -> int {
	available := e.out_len - e.out_off
	count := min(len(dst), available)
	if count <= 0 do return 0
	copy(dst[:count], e.out[e.out_off:][:count])
	remain := e.out_len - (e.out_off + count)
	if remain > 0 do copy(e.out[:remain], e.out[e.out_off + count:][:remain])
	e.out_len, e.out_off = remain, 0

	return count
}

stream_encode_into :: proc(e: ^Stream_Encoder, src, dst: []u8) -> (written: int, ok: bool) {
	offset := 0

	for offset < len(src) {
		if e.overflow do return 0, false

		if len(e.out) - e.out_len < 32 {
			count := stream_pull(e, dst[written:])
			if count == 0 do return 0, false
			written += count
			continue
		}

		count := stream_write(e, src[offset:])
		if count <= 0 do return 0, false
		offset += count
	}

	for !e.finished {
		if e.overflow do return 0, false

		if len(e.out) - e.out_len < 32 {
			count := stream_pull(e, dst[written:])
			if count == 0 do return 0, false
			written += count
			continue
		}

		stream_finish(e)
	}

	for e.out_len != e.out_off {
		count := stream_pull(e, dst[written:])
		if count == 0 do return 0, false
		written += count
	}

	return written, !e.overflow
}
