package compress_brotli

import "base:runtime"
import "core:compress"

// Bounded streaming encoder: fixed memory, no allocation, any partition of
// the input. Each STREAM_BLOCK of input becomes one meta-block with its own
// prefix codes, matched against the last STREAM_WINDOW bytes. For a better
// ratio on data held in memory use `encode`.

STREAM_WINDOW_BITS :: 16
STREAM_WINDOW :: 1 << STREAM_WINDOW_BITS
STREAM_BLOCK :: 1 << 14
STREAM_HASH_BITS :: 13
// Copies are at least four bytes; the trailing literals take one more command.
STREAM_COMMANDS_MAX :: STREAM_BLOCK / 4 + 1
// A coded block stays below 18 bits per input byte plus its prefix codes.
STREAM_OUTPUT_MAX :: 3 * STREAM_BLOCK
STREAM_DISTANCE_ALPHABET :: 64

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
@(private = "file")
stream_buffer :: proc(backing: []$T, length: int) -> [dynamic]T {
	return transmute([dynamic]T)runtime.Raw_Dynamic_Array{raw_data(backing), length, len(backing), runtime.panic_allocator()}
}

// Drops the history that fell out of the window to make room for a block.
@(private = "file")
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
@(private = "file")
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
@(private = "file")
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
		stream_parse(e, &x, start, end)
		stream_code(e, &x, start, end)
		e.ring = x.ring
	}

	e.accumulator = w.accumulator
	e.count = w.count
	stream_account(e, len(w.out))
	e.block_start = end
}

@(private = "file")
stream_account :: proc(e: ^Stream_Encoder, out_len: int) {
	e.produced += out_len - e.out_len
	e.out_len = out_len

	if e.max_output > 0 && e.produced > e.max_output {
		e.overflow = true
	}
}

// Writes x.commands as a meta-block with one prefix code per alphabet, or
// the block as stored bytes when that is smaller.
@(private = "file")
stream_code :: proc(e: ^Stream_Encoder, x: ^Encoder, start, end: int) #no_bounds_check {
	w := &x.writer
	src := x.src
	length := end - start
	ring := e.ring
	mark_size := len(w.out)
	mark_accumulator := w.accumulator
	mark_count := w.count

	literal_histogram: [LITERAL_ALPHABET]u32
	command_histogram: [COMMAND_ALPHABET]u32
	distance_histogram: [STREAM_DISTANCE_ALPHABET]u32
	position := start

	for command in x.commands {
		command_histogram[command.symbol] += 1

		for _ in 0 ..< command.insert_length {
			literal_histogram[src[position]] += 1
			position += 1
		}

		if command.copy_length > 0 && !distance_is_implicit(command.symbol) {
			prefix, _, _ := distance_prefix(command.code, 0, 0)
			distance_histogram[prefix] += 1
		}

		position += int(command.copy_length)
	}

	// Not last, MLEN in four nibbles, compressed; one block type per
	// category; NPOSTFIX and NDIRECT zero; context mode; one literal and one
	// distance tree.
	write_bits(w, 0, 3)
	write_bits(w, u64(length - 1), 16)
	write_bits(w, 0, 1 + 3 + 6 + 2 + 2)

	literal_lengths: [LITERAL_ALPHABET]u8
	literal_codes: [LITERAL_ALPHABET]u16
	command_lengths: [COMMAND_ALPHABET]u8
	command_codes: [COMMAND_ALPHABET]u16
	distance_lengths: [STREAM_DISTANCE_ALPHABET]u8
	distance_codes: [STREAM_DISTANCE_ALPHABET]u16
	build_and_write_code(x, literal_histogram[:], literal_lengths[:], literal_codes[:])
	build_and_write_code(x, command_histogram[:], command_lengths[:], command_codes[:])
	build_and_write_code(x, distance_histogram[:], distance_lengths[:], distance_codes[:])
	position = start

	for command in x.commands {
		insert := command.insert_code
		copy := command.copy_code
		write_bits(w, u64(command_codes[command.symbol]), uint(command_lengths[command.symbol]))
		write_bits(w, u64(command.insert_length - INSERT_BASE[insert]), uint(INSERT_EXTRA[insert]))
		write_bits(w, u64(max(command.copy_length, 2) - COPY_BASE[copy]), uint(COPY_EXTRA[copy]))

		for _ in 0 ..< command.insert_length {
			write_bits(w, u64(literal_codes[src[position]]), uint(literal_lengths[src[position]]))
			position += 1
		}

		if command.copy_length > 0 && !distance_is_implicit(command.symbol) {
			prefix, extra_bits, extra := distance_prefix(command.code, 0, 0)
			write_bits(w, u64(distance_codes[prefix]), uint(distance_lengths[prefix]))
			write_bits(w, u64(extra), uint(extra_bits))
		}

		position += int(command.copy_length)
	}

	coded := (len(w.out) - mark_size) * 8 + int(w.count) - int(mark_count)

	if coded <= (length + 4) * 8 {
		return
	}

	(^runtime.Raw_Dynamic_Array)(&w.out).len = mark_size
	w.accumulator = mark_accumulator
	w.count = mark_count
	x.ring = ring

	write_bits(w, 0, 3)
	write_bits(w, u64(length - 1), 16)
	write_bits(w, 1, 1)
	flush_bits(w)
	append(&w.out, ..src[start:end])
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
