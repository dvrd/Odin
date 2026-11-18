package compress_brotli

import "base:runtime"
import "core:compress"

// Bounded streaming encoder: fixed memory, no allocation, any partition of
// the input. Each STREAM_BLOCK of input becomes one meta-block with its own
// prefix codes, matched against the last STREAM_WINDOW bytes. For a better
// ratio on data held in memory use `compress`.

STREAM_WINDOW_BITS :: 16
STREAM_WINDOW :: 1 << STREAM_WINDOW_BITS
STREAM_BLOCK :: 1 << 14
STREAM_HASH_BITS :: 13
// Copies are at least four bytes; the trailing literals take one more command.
STREAM_COMMANDS_MAX :: STREAM_BLOCK / 4 + 1
// A coded block stays below 18 bits per input byte plus its prefix codes.
STREAM_OUTPUT_MAX :: 3 * STREAM_BLOCK

Stream_Encoder :: struct {
	// History followed by the block being filled.
	data:        [STREAM_WINDOW + STREAM_BLOCK]u8,
	head:        [1 << STREAM_HASH_BITS]u32,
	commands:    [STREAM_COMMANDS_MAX]Command,
	out:         [STREAM_OUTPUT_MAX]u8,
	scratch:     compress.Huffman_Scratch,
	accumulator: u64,
	count:       uint,
	out_len:     int,
	out_off:     int,
	block_start: int,
	filled:      int,
	produced:    int,
	max_output:  int,
	ring:        Ring,
	opened:      bool,
	finished:    bool,
	overflow:    bool,
}

// Upper bound of the stream for `n` bytes of input.
stream_bound :: proc(n: int) -> int {
	if n < 0 {
		return 0
	}

	return n + 5 * (n / STREAM_BLOCK + 1) + 2
}

// Readies `e` for a new stream; `max_output` > 0 caps the stream size.
stream_reset :: proc(e: ^Stream_Encoder, max_output := 0) {
	e.accumulator = 0
	e.count = 0
	e.out_len = 0
	e.out_off = 0
	e.block_start = 0
	e.filled = 0
	e.produced = 0
	e.max_output = max_output
	e.ring = {4, 11, 15, 16}
	e.opened = false
	e.finished = false
	e.overflow = false

	for &slot in e.head {
		slot = NIL
	}
}

// A fixed-capacity dynamic array over `backing`; it must never grow.
stream_buffer :: proc(backing: []$T, length: int) -> [dynamic]T {
	return transmute([dynamic]T)runtime.Raw_Dynamic_Array{raw_data(backing), length, len(backing), runtime.panic_allocator()}
}

// Drops the history that fell out of the window to make room for a block.
stream_slide :: proc(e: ^Stream_Encoder) {
	shift := e.block_start - STREAM_WINDOW

	if shift <= 0 {
		return
	}

	copy(e.data[:], e.data[shift:e.filled])
	e.block_start -= shift
	e.filled -= shift

	for &slot in e.head {
		slot = slot - u32(shift) if slot != NIL && slot >= u32(shift) else NIL
	}
}

// Greedy parse of the pending block into x.commands.
stream_parse :: proc(e: ^Stream_Encoder, x: ^Encoder, start, end: int) #no_bounds_check {
	src := x.src
	literal_start := start

	for position := start; position + 4 <= end; {
		limit := end - position
		slot := hash4(src, position) >> (32 - STREAM_HASH_BITS)
		candidate := e.head[slot]
		e.head[slot] = u32(position)
		length := 0
		distance := int(x.ring[0])

		if distance <= position {
			length = common_length(src, position - distance, position, limit)
		}

		if length < 4 && candidate != NIL && position - int(candidate) <= x.window_max {
			distance = position - int(candidate)
			length = common_length(src, int(candidate), position, limit)
		}

		if length < 4 {
			position += 1
			continue
		}

		// Cannot fail: the command buffer holds the worst case.
		_ = push_command(x, position, position - literal_start, length, distance, 0)

		for covered := position + 1; covered < position + length && covered + 4 <= end; covered += 1 {
			e.head[hash4(src, covered) >> (32 - STREAM_HASH_BITS)] = u32(covered)
		}

		position += length
		literal_start = position
	}

	if literal_start < end {
		_ = push_command(x, end, end - literal_start, 0, 0, 0)
	}
}

// Codes the pending block into e.out, which must be empty.
stream_emit :: proc(e: ^Stream_Encoder) {
	start := e.block_start
	end := e.filled
	length := end - start

	x: Encoder
	x.src = e.data[:end]
	x.ring = e.ring
	x.window_max = STREAM_WINDOW - 16
	x.huffman = &e.scratch
	x.commands = stream_buffer(e.commands[:], 0)
	x.writer = {stream_buffer(e.out[:], e.out_len), e.accumulator, e.count, nil}
	w := &x.writer

	if !e.opened {
		// WBITS 16.
		write_bits(w, 0, 1)
		e.opened = true
	}

	if length > 0 {
		ring := x.ring
		stream_parse(e, &x, start, end)
		// Cannot fail: the output buffer holds the worst case.
		_ = write_plain_meta_block(&x, start, end, false, ring)
		e.ring = x.ring
	}

	e.accumulator = w.accumulator
	e.count = w.count
	stream_account(e, len(w.out))
	e.block_start = end
}

stream_account :: proc(e: ^Stream_Encoder, out_len: int) {
	e.produced += out_len - e.out_len
	e.out_len = out_len

	if e.max_output > 0 && e.produced > e.max_output {
		e.overflow = true
	}
}

// Takes bytes of `src` into the stream and returns how many; fewer than
// len(src) means the output must be pulled first.
stream_write :: proc(e: ^Stream_Encoder, src: []u8) -> int {
	if e.finished || e.overflow {
		return 0
	}

	consumed := 0

	for consumed < len(src) {
		if e.filled - e.block_start == STREAM_BLOCK {
			if e.out_len != e.out_off {
				break
			}

			stream_emit(e)

			if e.overflow {
				return 0
			}
		}

		stream_slide(e)
		count := min(len(src) - consumed, e.block_start + STREAM_BLOCK - e.filled)
		copy(e.data[e.filled:][:count], src[consumed:][:count])
		e.filled += count
		consumed += count
	}

	return consumed
}

// Ends the stream; false while pending output must be pulled first, or after
// an overflow.
stream_finish :: proc(e: ^Stream_Encoder) -> bool {
	if e.finished {
		return true
	}

	if e.overflow || e.out_len != e.out_off {
		return false
	}

	stream_emit(e)

	// An empty last meta-block.
	w := Bit_Writer{stream_buffer(e.out[:], e.out_len), e.accumulator, e.count, nil}
	write_bits(&w, 3, 2)
	flush_bits(&w)
	e.accumulator = 0
	e.count = 0
	stream_account(e, len(w.out))
	e.finished = !e.overflow

	return e.finished
}

// Moves pending output into `dst` and returns how many bytes.
stream_pull :: proc(e: ^Stream_Encoder, dst: []u8) -> int {
	count := min(len(dst), e.out_len - e.out_off)

	if count <= 0 {
		return 0
	}

	copy(dst[:count], e.out[e.out_off:][:count])
	e.out_off += count

	if e.out_off == e.out_len {
		e.out_off = 0
		e.out_len = 0
	}

	return count
}

// Encodes all of `src` as a complete stream into `dst`.
stream_encode_into :: proc(e: ^Stream_Encoder, src, dst: []u8) -> (written: int, ok: bool) {
	offset := 0

	for !e.finished {
		if e.overflow {
			return 0, false
		}

		if e.out_len != e.out_off {
			count := stream_pull(e, dst[written:])

			if count == 0 {
				return 0, false
			}

			written += count
			continue
		}

		if offset < len(src) {
			offset += stream_write(e, src[offset:])

			if offset < len(src) {
				continue
			}
		}

		stream_finish(e)
	}

	for e.out_len != e.out_off {
		count := stream_pull(e, dst[written:])

		if count == 0 {
			return 0, false
		}

		written += count
	}

	return written, !e.overflow
}
