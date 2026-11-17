package compress_brotli

import "base:intrinsics"
import "base:runtime"
import "core:compress"
import "core:math/bits"

// Brotli (RFC 7932) encoder for input held in memory.
//
// The input is parsed into insert-and-copy commands against a sliding window
// and the static dictionary, then each meta-block stores its literals under
// context-clustered prefix codes, its commands under one code and its
// distances under copy-length contexts.

// Levels 0..11 follow the qualities of the reference encoder; any value in
// that range is valid, the names mark the usual choices.
Level :: enum u8 {
	Fastest = 0,
	Fast    = 2,
	Default = 6,
	Best    = 9,
	// Iterated shortest-path parse; for data compressed once and served often.
	Optimal = 11,
}

OPTIMAL_BLOCK :: 1 << 20
// Levels up to here parse with a single probe per position.
FAST_LEVEL_MAX :: Level(1)
// Levels from here on parse optimally.
OPTIMAL_LEVEL_MIN :: Level(10)
OPTIMAL_ITERATIONS :: 3
// Matches this long are taken whole instead of being explored byte by byte.
OPTIMAL_LONG :: 325
WINDOW_BITS_MIN :: 10
WINDOW_BITS_MAX :: 24
META_BLOCK_MAX :: 1 << 24
// 16 + NDIRECT + (48 << NPOSTFIX) at its largest.
DISTANCE_ALPHABET :: 520
LITERAL_CONTEXTS :: 64
DISTANCE_CONTEXTS :: 4
CONTEXT_MODE_UTF8 :: 2
CONTEXT_MODE_SIGNED :: 3
NIL :: max(u32)

Command :: struct {
	insert_length: u32,
	// Zero only for the trailing literals of a meta-block.
	copy_length:   u32,
	// Value the decoder reconstructs: a backward distance, or past the window
	// for a static dictionary word.
	distance:      u32,
	// 0..15 for a recent-distance code, else distance + 15. Fixed when the
	// command is created because it depends on the ring at that point.
	code:          u32,
	// Command alphabet symbol and the insert and copy length codes behind it.
	symbol:        u16,
	insert_code:   u8,
	copy_code:     u8,
	// Bytes of the copy length a dictionary transform does not produce (or,
	// negative, adds): the copy covers copy_length - omit.
	omit:          i8,
}

Ring :: [4]i32

Parameters :: struct {
	// log2 of the positions kept per hash bucket.
	block_bits: uint,
	cache_size: int,
	lazy:       bool,
	// Static dictionary matching and literal context modelling.
	modelled:   bool,
	// Block splitting.
	split:      bool,
}

// One row per level 0..11, as the qualities of the reference encoder; the
// last two rows parse optimally and only use the modelling flags.
@(rodata)
PARAMETERS := [12]Parameters {
	{0, 4, false, false, false},
	{2, 4, false, false, false},
	{1, 2, true, false, false},
	{2, 4, true, false, false},
	{3, 4, true, false, false},
	{4, 4, true, true, false},
	{5, 4, true, true, false},
	{6, 10, true, true, false},
	{7, 10, true, true, false},
	{8, 16, true, true, true},
	{0, 0, true, true, true},
	{0, 0, true, true, true},
}

Bit_Writer :: struct {
	out:         [dynamic]u8,
	accumulator: u64,
	count:       uint,
	err:         runtime.Allocator_Error,
}

Encoder :: struct {
	src:           []u8,
	writer:        Bit_Writer,
	window_max:    int,
	parameters:    Parameters,
	level:         Level,
	ring:          Ring,
	commands:      [dynamic]Command,
	huffman:       ^compress.Huffman_Scratch,
	allocator:     runtime.Allocator,
	finder:        Finder,
}


// Compresses `src` into a complete Brotli stream.
encode :: proc(src: []u8, level := Level.Default, allocator := context.allocator) -> (output: []u8, err: Error) {
	return encode_meta_blocks(src, level, META_BLOCK_MAX, allocator)
}

// `encode` with at most `meta_block_max` input bytes per meta-block; smaller
// meta-blocks adapt their prefix codes sooner and cost more headers.
encode_meta_blocks :: proc(
	src: []u8,
	level: Level,
	meta_block_max: int,
	allocator := context.allocator,
) -> (
	output: []u8,
	err: Error,
) {
	assert(meta_block_max > 0 && meta_block_max <= META_BLOCK_MAX)

	e := new(Encoder, allocator) or_return
	defer free(e, allocator)

	e.src = src
	e.allocator = allocator
	e.ring = {4, 11, 15, 16}
	e.writer.out = make([dynamic]u8, 0, len(src) / 3 + 64, allocator) or_return
	e.commands = make([dynamic]Command, 0, len(src) / 16 + 16, allocator) or_return
	defer delete(e.commands)

	// The scratch is written before it is read: skip clearing its half megabyte.
	scratch, scratch_error := runtime.mem_alloc_non_zeroed(
		size_of(compress.Huffman_Scratch),
		align_of(compress.Huffman_Scratch),
		allocator,
	)

	if scratch_error != nil {
		return nil, scratch_error
	}

	e.huffman = (^compress.Huffman_Scratch)(raw_data(scratch))
	defer free(e.huffman, allocator)

	e.level = Level(min(int(level), len(PARAMETERS) - 1))
	e.parameters = PARAMETERS[e.level]

	window_bits := clamp(bits.len_u32(u32(min(len(src) + 15, 1 << 30))), WINDOW_BITS_MIN, WINDOW_BITS_MAX)
	e.window_max = 1 << uint(window_bits) - 16

	block := block_make(allocator) or_return
	defer block_destroy(block, allocator)

	optimal: ^Optimal
	parsed: [dynamic]Command

	if e.level >= OPTIMAL_LEVEL_MIN {
		optimal = optimal_make(e, min(len(src), OPTIMAL_BLOCK), allocator) or_return
		parsed = make([dynamic]Command, allocator) or_return
	} else {
		finder_make(&e.finder, len(src), e.parameters.block_bits, e.parameters.cache_size, allocator) or_return
	}

	defer optimal_destroy(optimal, allocator)
	defer delete(parsed)
	defer finder_destroy(&e.finder, allocator)

	w := &e.writer

	switch {
	case window_bits == 16:
		write_bits(w, 0, 1)
	case window_bits == 17:
		write_bits(w, 1, 7)
	case window_bits > 17:
		write_bits(w, u64(1 | (window_bits - 17) << 1), 4)
	case:
		write_bits(w, u64(1 | (window_bits - 8) << 4), 7)
	}

	if len(src) == 0 {
		write_bits(w, 3, 2)
	}

	for start := 0; start < len(src); {
		end := min(start + (meta_block_max if e.parameters.modelled else min(meta_block_max, PLAIN_BLOCK)), len(src))
		ring := e.ring
		clear(&e.commands)

		if optimal != nil {
			// Parsed a block at a time, modelled and coded as one meta-block.
			clear(&parsed)

			for from := start; from < end; from += OPTIMAL_BLOCK {
				clear(&e.commands)
				parse_optimal(e, optimal, block, from, min(from + OPTIMAL_BLOCK, end)) or_return
				join_commands(&parsed, e.commands[:]) or_return
			}

			e.commands, parsed = parsed, e.commands
		} else if e.level <= FAST_LEVEL_MAX {
			parse_fast(e, start, end) or_return
		} else {
			parse_range(e, start, end) or_return
		}

		if e.parameters.modelled {
			gather(e, block, start, end, e.parameters.split) or_return
			write_meta_block(e, block, start, end, end == len(src), ring) or_return
		} else {
			write_plain_meta_block(e, start, end, end == len(src), ring) or_return
		}

		start = end
	}

	flush_bits(w)

	if w.err != nil {
		delete(w.out)
		return nil, w.err
	}

	shrink(&w.out)

	return w.out[:], nil
}

// ----------------------------------------------------------------- bit output

// At most 32 bits per call: the accumulator holds up to 31 pending ones.
write_bits :: #force_inline proc(w: ^Bit_Writer, value: u64, count: uint) {
	w.accumulator |= value << w.count
	w.count += count

	if w.count >= 32 {
		flush_word(w)
	}
}

// Writes a run of literals under one prefix code; `table` holds each code
// with its length above bit 16. Room for the whole run is made once, and the
// loop stores whole words, keeping the bytes that are complete.
write_literals :: proc(w: ^Bit_Writer, literals: []u8, table: ^[LITERAL_ALPHABET]u32) -> runtime.Allocator_Error #no_bounds_check {
	raw := (^runtime.Raw_Dynamic_Array)(&w.out)
	// Codes are at most 15 bits; slack for the pending bits and a word store.
	needed := raw.len + 2 * len(literals) + 16

	if needed > raw.cap {
		reserve(&w.out, max(raw.cap * 2, needed)) or_return
	}

	accumulator := w.accumulator
	count := w.count
	out := uintptr(raw.data) + uintptr(raw.len)
	start := out
	index := 0

	// 31 pending bits and two codes fit the accumulator.
	for ; index + 2 <= len(literals); index += 2 {
		first := table[literals[index]]
		second := table[literals[index + 1]]
		accumulator |= u64(first & 0xffff) << count
		count += uint(first >> 16)
		accumulator |= u64(second & 0xffff) << count
		count += uint(second >> 16)
		intrinsics.unaligned_store((^u64le)(rawptr(out)), u64le(accumulator))
		out += uintptr(count >> 3)
		accumulator >>= count & ~uint(7)
		count &= 7
	}

	if index < len(literals) {
		entry := table[literals[index]]
		accumulator |= u64(entry & 0xffff) << count
		count += uint(entry >> 16)
		intrinsics.unaligned_store((^u64le)(rawptr(out)), u64le(accumulator))
		out += uintptr(count >> 3)
		accumulator >>= count & ~uint(7)
		count &= 7
	}

	raw.len += int(out - start)
	w.accumulator = accumulator
	w.count = count

	return nil
}

// Moves the low 32 bits of the accumulator to the output.
flush_word :: proc(w: ^Bit_Writer) {
	raw := (^runtime.Raw_Dynamic_Array)(&w.out)

	if raw.len + 4 > raw.cap {
		reserve_error := reserve(&w.out, max(raw.cap * 2, 64))

		if reserve_error != nil {
			w.err = reserve_error
		}
	}

	if raw.len + 4 <= raw.cap {
		intrinsics.unaligned_store((^u32le)(rawptr(uintptr(raw.data) + uintptr(raw.len))), u32le(w.accumulator))
		raw.len += 4
	}

	w.accumulator >>= 32
	w.count -= 32
}

flush_bits :: proc(w: ^Bit_Writer) {
	for w.count > 0 {
		_, append_error := append(&w.out, u8(w.accumulator))

		if append_error != nil {
			w.err = append_error
		}

		w.accumulator >>= 8
		w.count -= min(w.count, 8)
	}
}

// --------------------------------------------------------------- symbol codes

insert_code :: #force_inline proc(length: int) -> int {
	value := u32(length)

	switch {
	case value < 6:
		return length
	case value < 130:
		width := u32(bits.len_u32(value - 2)) - 2

		return int(width << 1 + (value - 2) >> width + 2)
	case value < 2114:
		return bits.len_u32(value - 66) + 9
	case value < 6210:
		return 21
	case value < 22594:
		return 22
	}

	return 23
}

copy_code :: #force_inline proc(length: int) -> int {
	value := u32(length)

	switch {
	case value < 10:
		return length - 2
	case value < 134:
		width := u32(bits.len_u32(value - 6)) - 2

		return int(width << 1 + (value - 6) >> width + 4)
	case value < 2118:
		return bits.len_u32(value - 70) + 11
	}

	return 23
}

COMMAND_CELLS := [3][3]int{{2, 3, 6}, {4, 5, 8}, {7, 9, 10}}

// Symbol of the 704-symbol command alphabet for an insert and a copy code.
command_symbol :: proc(insert, copy: int, implicit_distance: bool) -> int {
	cell := COMMAND_CELLS[insert >> 3][copy >> 3]

	if implicit_distance && insert < 8 && copy < 16 {
		cell -= 2
	}

	return cell << 6 | (insert & 7) << 3 | copy & 7
}

// Distance code for `distance` given the recent-distance ring: the two most
// recent distances, then those within three of either, then the older two.
distance_code :: proc(ring: ^Ring, distance: int) -> u32 {
	if distance == int(ring[0]) {
		return 0
	}

	if distance == int(ring[1]) {
		return 1
	}

	for base in 0 ..< 2 {
		offset := distance - int(ring[base])

		if offset >= -3 && offset <= 3 {
			step := abs(offset)

			return u32(4 + base * 6 + (step - 1) * 2 + (1 if offset > 0 else 0))
		}
	}

	if distance == int(ring[2]) {
		return 2
	}

	if distance == int(ring[3]) {
		return 3
	}

	return u32(distance) + 15
}

// Symbol and extra bits of a distance code under NPOSTFIX and NDIRECT.
distance_prefix :: #force_inline proc(code: u32, postfix, direct: uint) -> (symbol: u16, extra_bits: u8, extra: u32) {
	if code < 16 + u32(direct) {
		return u16(code), 0, 0
	}

	value := 1 << (postfix + 2) + code - 16 - u32(direct)
	bucket := uint(bits.len_u32(value)) - 2
	half := (value >> bucket) & 1
	width := bucket - postfix
	low := value & (1 << postfix - 1)
	offset := (2 + half) << bucket

	return u16(16 + u32(direct) + (2 * (u32(width) - 1) + half) << postfix + low), u8(width), (value - offset) >> postfix
}

ring_push :: #force_inline proc(ring: ^Ring, distance: int) {
	ring[3] = ring[2]
	ring[2] = ring[1]
	ring[1] = ring[0]
	ring[0] = i32(distance)
}

// --------------------------------------------------------------- match finder

hash4 :: #force_inline proc(src: []u8, position: int) -> u32 {
	value := intrinsics.unaligned_load((^u32)(&src[position]))

	when ODIN_ENDIAN == .Big {
		value = intrinsics.byte_swap(value)
	}

	return value * 0x1e35a7bd
}

common_length :: #force_inline proc(src: []u8, a, b, limit: int) -> int {
	length := 0

	when ODIN_ENDIAN == .Little {
		for length + 8 <= limit {
			difference :=
				intrinsics.unaligned_load((^u64)(&src[a + length])) ~ intrinsics.unaligned_load((^u64)(&src[b + length]))

			if difference != 0 {
				return length + int(intrinsics.count_trailing_zeros(difference)) >> 3
			}

			length += 8
		}
	}

	for length < limit && src[a + length] == src[b + length] {
		length += 1
	}

	return length
}

// -------------------------------------------------------------------- parsing

// Appends `commands`; literals left over at the end of `list` move into the
// insert of the first one, since only a meta-block's last command may lack a
// copy.
join_commands :: proc(list: ^[dynamic]Command, commands: []Command) -> runtime.Allocator_Error {
	carried := 0

	if len(list) > 0 && list[len(list) - 1].copy_length == 0 {
		carried = int(pop(list).insert_length)
	}

	first := len(list)
	append(list, ..commands) or_return

	if carried > 0 && len(commands) > 0 {
		command := &list[first]
		command.insert_length += u32(carried)
		insert := insert_code(int(command.insert_length))
		command.insert_code = u8(insert)
		command.symbol = u16(command_symbol(insert, int(command.copy_code), command.copy_length == 0 || command.code == 0))
	}

	return nil
}

push_command :: proc(e: ^Encoder, position, insert_length, copy_length, distance, omit: int) -> runtime.Allocator_Error {
	command := Command {
		insert_length = u32(insert_length),
		copy_length   = u32(copy_length),
		distance      = u32(distance),
		omit          = i8(omit),
	}

	if copy_length > 0 {
		command.code = distance_code(&e.ring, distance)

		// Dictionary references leave the recent distances alone.
		if command.code != 0 && distance <= min(position, e.window_max) {
			ring_push(&e.ring, distance)
		}
	}

	insert := insert_code(insert_length)
	copy := copy_code(max(copy_length, 2))
	command.insert_code = u8(insert)
	command.copy_code = u8(copy)
	command.symbol = u16(command_symbol(insert, copy, copy_length == 0 || command.code == 0))

	_, append_error := append(&e.commands, command)

	return append_error
}

// --------------------------------------------------------------- prefix codes

write_variable_byte :: proc(w: ^Bit_Writer, value: int) {
	if value == 0 {
		write_bits(w, 0, 1)
		return
	}

	width := uint(bits.len_u32(u32(value)) - 1)
	write_bits(w, 1, 1)
	write_bits(w, u64(width), 3)
	write_bits(w, u64(value - 1 << width), width)
}

// Context map as move-to-front indices with runs of zeros coded by length.
write_context_map :: proc(e: ^Encoder, mapping: []u8, trees: int) {
	w := &e.writer
	write_variable_byte(w, trees - 1)

	if trees < 2 {
		return
	}

	order: [256]u8
	moved: [256 * LITERAL_CONTEXTS]u8

	for index in 0 ..< 256 {
		order[index] = u8(index)
	}

	longest := 0
	run := 0

	for tree, index in mapping {
		at := 0

		for order[at] != tree {
			at += 1
		}

		for slot := at; slot > 0; slot -= 1 {
			order[slot] = order[slot - 1]
		}

		order[0] = tree
		moved[index] = u8(at)
		run = run + 1 if at == 0 else 0
		longest = max(longest, run)
	}

	run_max := min(bits.len_u32(u32(longest)) - 1, 6) if longest > 0 else 0
	symbols: [256 * LITERAL_CONTEXTS]u16
	extras: [256 * LITERAL_CONTEXTS]u16
	total := 0

	for index := 0; index < len(mapping); {
		if moved[index] != 0 {
			symbols[total] = u16(int(moved[index]) + run_max)
			total += 1
			index += 1
			continue
		}

		zeros := 1

		for index + zeros < len(mapping) && moved[index + zeros] == 0 {
			zeros += 1
		}

		index += zeros

		for zeros > 0 {
			if zeros < 2 << uint(run_max) {
				width := bits.len_u32(u32(zeros)) - 1
				symbols[total] = u16(width)
				extras[total] = u16(zeros - 1 << uint(width))
				zeros = 0
			} else {
				symbols[total] = u16(run_max)
				extras[total] = u16(1 << uint(run_max) - 1)
				zeros -= 2 << uint(run_max) - 1
			}

			total += 1
		}
	}

	write_bits(w, 1 if run_max > 0 else 0, 1)

	if run_max > 0 {
		write_bits(w, u64(run_max - 1), 4)
	}

	alphabet := trees + run_max
	histogram: [256 + 16]u32
	lengths: [256 + 16]u8
	codes: [256 + 16]u16

	for symbol in symbols[:total] {
		histogram[symbol] += 1
	}

	build_and_write_code(e, histogram[:alphabet], lengths[:alphabet], codes[:alphabet])

	for symbol, index in symbols[:total] {
		write_bits(w, u64(codes[symbol]), uint(lengths[symbol]))

		if int(symbol) > 0 && int(symbol) <= run_max {
			write_bits(w, u64(extras[index]), uint(symbol))
		}
	}

	write_bits(w, 1, 1)
}

// Builds the length-limited code for `histogram`, writes its description and
// leaves `lengths`/`codes` ready for writing symbols.
build_and_write_code :: proc(e: ^Encoder, histogram: []u32, lengths: []u8, codes: []u16) {
	w := &e.writer
	alphabet := len(histogram)
	used: [4]int
	used_count := 0

	for frequency, symbol in histogram {
		if frequency != 0 {
			if used_count < 4 {
				used[used_count] = symbol
			}

			used_count += 1
		}
	}

	width := uint(bits.len_u32(u32(alphabet - 1)))

	if used_count <= 1 {
		// A lone symbol costs zero bits per occurrence. The codes are cleared
		// as well: a stale one would still be or-ed into the output.
		for &length in lengths {
			length = 0
		}

		for &code in codes {
			code = 0
		}

		write_bits(w, 1, 4)
		write_bits(w, u64(used[0]), width)

		return
	}

	compress.huffman_lengths(e.huffman, histogram, CODE_LENGTH_MAX, lengths)
	compress.huffman_codes(lengths, codes)

	if used_count <= 4 {
		// Simple code: symbols in order of (length, value).
		for index in 1 ..< used_count {
			value := used[index]
			at := index

			for at > 0 && lengths[used[at - 1]] > lengths[value] {
				used[at] = used[at - 1]
				at -= 1
			}

			used[at] = value
		}

		write_bits(w, 1, 2)
		write_bits(w, u64(used_count - 1), 2)

		for index in 0 ..< used_count {
			write_bits(w, u64(used[index]), width)
		}

		if used_count == 4 {
			write_bits(w, 0 if lengths[used[0]] == 2 else 1, 1)
		}

		return
	}

	write_complex_code(e, lengths)
}

write_complex_code :: proc(e: ^Encoder, lengths: []u8) {
	w := &e.writer
	size := len(lengths)

	for size > 0 && lengths[size - 1] == 0 {
		size -= 1
	}

	// Run-length encode with 16 (repeat previous non-zero) and 17 (zeros);
	// consecutive repeat symbols extend one run in base 4 or base 8.
	symbols: [ALPHABET_MAX + 8]u8
	extras: [ALPHABET_MAX + 8]u8
	total := 0
	previous: u8 = 8

	for index := 0; index < size; {
		value := lengths[index]
		run := 1

		for index + run < size && lengths[index + run] == value {
			run += 1
		}

		index += run

		if value == 0 {
			if run < 3 {
				for _ in 0 ..< run {
					symbols[total] = 0
					total += 1
				}
			} else {
				total = push_repeat(symbols[:], extras[:], total, 17, run, 3)
			}

			continue
		}

		if value != previous {
			symbols[total] = value
			total += 1
			run -= 1
			previous = value
		}

		if run < 3 {
			for _ in 0 ..< run {
				symbols[total] = value
				total += 1
			}
		} else {
			total = push_repeat(symbols[:], extras[:], total, 16, run, 2)
		}
	}

	histogram: [18]u32
	meta_lengths: [18]u8
	meta_codes: [18]u16

	for index in 0 ..< total {
		histogram[symbols[index]] += 1
	}

	used := 0

	for frequency in histogram {
		if frequency != 0 {
			used += 1
		}
	}

	if used == 1 {
		for frequency, symbol in histogram {
			if frequency != 0 {
				meta_lengths[symbol] = 3
			}
		}
	} else {
		compress.huffman_lengths(e.huffman, histogram[:], 5, meta_lengths[:])
		compress.huffman_codes(meta_lengths[:], meta_codes[:])
	}

	skip := 0

	if meta_lengths[CODE_LENGTH_ORDER[0]] == 0 && meta_lengths[CODE_LENGTH_ORDER[1]] == 0 {
		skip = 2

		if meta_lengths[CODE_LENGTH_ORDER[2]] == 0 {
			skip = 3
		}
	}

	write_bits(w, u64(skip), 2)

	// Fixed variable-length code for the lengths 0..5 of the code-length code.
	fixed_values := [6]u64{0, 7, 3, 2, 1, 15}
	fixed_widths := [6]uint{2, 4, 3, 2, 2, 4}
	space := 32

	for index := skip; index < 18; index += 1 {
		length := meta_lengths[CODE_LENGTH_ORDER[index]]
		write_bits(w, fixed_values[length], fixed_widths[length])

		if length != 0 {
			space -= 32 >> length

			if space <= 0 && used != 1 {
				break
			}
		}
	}

	for index in 0 ..< total {
		symbol := symbols[index]

		if used != 1 {
			write_bits(w, u64(meta_codes[symbol]), uint(meta_lengths[symbol]))
		}

		switch symbol {
		case 16:
			write_bits(w, u64(extras[index]), 2)
		case 17:
			write_bits(w, u64(extras[index]), 3)
		}
	}
}

// Appends `symbol` repeated so that the decoder accumulates exactly `run`:
// each further occurrence multiplies the count so far by 2^width.
push_repeat :: proc(symbols, extras: []u8, total: int, symbol: u8, run: int, width: uint) -> int {
	digits: [16]u8
	count := 0
	remaining := run - 3

	for {
		digits[count] = u8(remaining & (1 << width - 1))
		count += 1
		remaining >>= width

		if remaining == 0 {
			break
		}

		remaining -= 1
	}

	next := total

	for index := count - 1; index >= 0; index -= 1 {
		symbols[next] = symbol
		extras[next] = digits[index]
		next += 1
	}

	return next
}

// Meta-block size of the levels without modelling: small blocks keep their
// single prefix codes close to the data.
PLAIN_BLOCK :: 1 << 18

// Distance symbols without postfix or direct codes.
PLAIN_DISTANCE_ALPHABET :: 64

// Writes e.commands for src[start:end] as a meta-block with one prefix code
// per alphabet and no context modelling, or as stored bytes when smaller.
// `ring` is the recent-distance state before these commands.
write_plain_meta_block :: proc(e: ^Encoder, start, end: int, last: bool, ring: Ring) -> runtime.Allocator_Error #no_bounds_check {
	w := &e.writer
	src := e.src
	length := end - start
	nibbles := 6 if length > 1 << 20 else 5 if length > 1 << 16 else 4
	mark_size := len(w.out)
	mark_accumulator := w.accumulator
	mark_count := w.count

	literal_histogram: [LITERAL_ALPHABET]u32
	command_histogram: [COMMAND_ALPHABET]u32
	distance_histogram: [PLAIN_DISTANCE_ALPHABET]u32
	position := start

	for &command in e.commands {
		command_histogram[command.symbol] += 1

		for value in src[position:][:command.insert_length] {
			literal_histogram[value] += 1
		}

		if command.copy_length > 0 && !distance_is_implicit(command.symbol) {
			// From here on `code` is the distance symbol with the number of
			// extra bits above it, and `distance` those bits: the second
			// pass writes them without deriving them again.
			prefix, extra_bits, extra := distance_prefix(command.code, 0, 0)
			distance_histogram[prefix] += 1
			command.code = u32(prefix) | u32(extra_bits) << 16
			command.distance = extra
		}

		position += int(command.insert_length) + int(command.copy_length) - int(command.omit)
	}

	if e.level >= SMOOTH_LEVEL_MIN {
		smooth_for_rle(literal_histogram[:])
		smooth_for_rle(command_histogram[:])
		smooth_for_rle(distance_histogram[:])
	}

	write_bits(w, 1 if last else 0, 1)

	if last {
		write_bits(w, 0, 1)
	}

	write_bits(w, u64(nibbles - 4), 2)
	write_bits(w, u64(length - 1), uint(nibbles * 4))

	if !last {
		write_bits(w, 0, 1)
	}

	// One block type per category; NPOSTFIX and NDIRECT zero; a context
	// mode; one literal and one distance tree.
	write_bits(w, 0, 3 + 6 + 2 + 2)

	literal_lengths: [LITERAL_ALPHABET]u8
	literal_codes: [LITERAL_ALPHABET]u16
	command_lengths: [COMMAND_ALPHABET]u8
	command_codes: [COMMAND_ALPHABET]u16
	distance_lengths: [PLAIN_DISTANCE_ALPHABET]u8
	distance_codes: [PLAIN_DISTANCE_ALPHABET]u16
	build_and_write_code(e, literal_histogram[:], literal_lengths[:], literal_codes[:])
	build_and_write_code(e, command_histogram[:], command_lengths[:], command_codes[:])
	build_and_write_code(e, distance_histogram[:], distance_lengths[:], distance_codes[:])
	literal_table: [LITERAL_ALPHABET]u32

	for &entry, value in literal_table {
		entry = u32(literal_codes[value]) | u32(literal_lengths[value]) << 16
	}

	position = start

	for command in e.commands {
		insert := command.insert_code
		copy := command.copy_code
		write_bits(w, u64(command_codes[command.symbol]), uint(command_lengths[command.symbol]))
		write_bits(w, u64(command.insert_length - INSERT_BASE[insert]), uint(INSERT_EXTRA[insert]))
		write_bits(w, u64(max(command.copy_length, 2) - COPY_BASE[copy]), uint(COPY_EXTRA[copy]))

		write_literals(w, src[position:][:command.insert_length], &literal_table) or_return

		if command.copy_length > 0 && !distance_is_implicit(command.symbol) {
			prefix := command.code & 0xffff
			write_bits(w, u64(distance_codes[prefix]), uint(distance_lengths[prefix]))
			write_bits(w, u64(command.distance), uint(command.code >> 16))
		}

		position += int(command.insert_length) + int(command.copy_length) - int(command.omit)
	}

	coded := (len(w.out) - mark_size) * 8 + int(w.count) - int(mark_count)

	if coded <= (length + 4) * 8 {
		return nil
	}

	// Stored meta-block; it cannot be the last one, so an empty one follows.
	(^runtime.Raw_Dynamic_Array)(&w.out).len = mark_size
	w.accumulator = mark_accumulator
	w.count = mark_count
	e.ring = ring

	write_bits(w, 0, 1)
	write_bits(w, u64(nibbles - 4), 2)
	write_bits(w, u64(length - 1), uint(nibbles * 4))
	write_bits(w, 1, 1)
	flush_bits(w)
	append(&w.out, ..src[start:end]) or_return

	if last {
		write_bits(w, 3, 2)
	}

	return nil
}
