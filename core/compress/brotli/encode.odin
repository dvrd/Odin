package compress_brotli

import "base:intrinsics"
import "base:runtime"
import "core:compress"
import "core:math"
import "core:math/bits"

// Brotli (RFC 7932) encoder for input held in memory.
//
// The input is parsed into insert-and-copy commands against a sliding window
// and the static dictionary, then each meta-block stores its literals under
// context-clustered prefix codes, its commands under one code and its
// distances under copy-length contexts.

Level :: enum u8 {
	Fastest = 1,
	Fast    = 3,
	Default = 6,
	Best    = 9,
	// Iterated shortest-path parse; for data compressed once and served often.
	Optimal = 11,
}

OPTIMAL_BLOCK :: 1 << 20
OPTIMAL_ITERATIONS :: 3
OPTIMAL_CHAIN :: 512
// Matches this long are taken whole instead of being explored byte by byte.
OPTIMAL_LONG :: 512
DICTIONARY_WORDS :: 13504
DICTIONARY_HASH_BITS :: 14
DICTIONARY_NONE :: max(u16)
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
}

Ring :: [4]i32

Parameters :: struct {
	chain_limit: int,
	lazy:        bool,
	nice_length: int,
	// Static dictionary matching and literal context modelling.
	modelled:    bool,
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
	head:          []u32,
	hash_shift:    u32,
	chain:         []u32,
	ring:          Ring,
	commands:      [dynamic]Command,
	huffman:       compress.Huffman_Scratch,
	allocator:     runtime.Allocator,
	// Static dictionary words chained by the hash of their first four bytes.
	word_head:     [1 << DICTIONARY_HASH_BITS]u16,
	word_next:     [DICTIONARY_WORDS]u16,
	word_length:   [DICTIONARY_WORDS]u8,
	word_offset:   [DICTIONARY_WORDS]u32,
	word_base:     [DICTIONARY_WORD_MAX + 1]u32,
}

HASH_BITS_MIN :: 15
HASH_BITS_MAX :: 20

// Compresses `src` into a complete Brotli stream.
encode :: proc(src: []u8, level := Level.Default, allocator := context.allocator) -> (output: []u8, err: Error) {
	e := new(Encoder, allocator) or_return
	defer free(e, allocator)

	e.src = src
	e.level = level
	e.allocator = allocator
	e.ring = {4, 11, 15, 16}
	e.writer.out = make([dynamic]u8, 0, len(src) / 3 + 64, allocator) or_return
	e.commands = make([dynamic]Command, allocator) or_return
	defer delete(e.commands)

	hash_bits := clamp(bits.len_u32(u32(min(len(src), 1 << 30))), HASH_BITS_MIN, HASH_BITS_MAX)
	e.hash_shift = u32(32 - hash_bits)
	e.head = make([]u32, 1 << uint(hash_bits), allocator) or_return
	defer delete(e.head, allocator)

	e.chain = make([]u32, len(src), allocator) or_return
	defer delete(e.chain, allocator)

	for &slot in e.head {
		slot = NIL
	}

	switch {
	case level <= .Fastest:
		e.parameters = {4, false, 32, false}
	case level <= .Fast:
		e.parameters = {8, false, 64, false}
	case level <= .Default:
		e.parameters = {16, true, 128, true}
	case:
		e.parameters = {256, true, 512, true}
	}

	if e.parameters.modelled {
		index_dictionary(e)
	}

	block := new(Meta_Block, allocator) or_return
	defer free(block, allocator)

	block_max := META_BLOCK_MAX
	optimal: ^Optimal

	if level >= .Optimal {
		block_max = OPTIMAL_BLOCK
		optimal = optimal_make(min(len(src), block_max), allocator) or_return
	}

	defer optimal_destroy(optimal, allocator)

	window_bits := clamp(bits.len_u32(u32(min(len(src) + 15, 1 << 30))), WINDOW_BITS_MIN, WINDOW_BITS_MAX)
	e.window_max = 1 << uint(window_bits) - 16
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
		end := min(start + block_max, len(src))
		ring := e.ring
		clear(&e.commands)

		if optimal != nil {
			parse_optimal(e, optimal, block, start, end) or_return
		} else {
			parse_range(e, start, end) or_return
			gather(e, block, start, end)
		}

		write_meta_block(e, block, start, end, end == len(src), ring)
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

@(private)
write_bits :: #force_inline proc(w: ^Bit_Writer, value: u64, count: uint) {
	w.accumulator |= value << w.count
	w.count += count

	if w.count >= 32 {
		flush_word(w)
	}
}

// Moves the low 32 bits of the accumulator to the output.
@(private)
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

@(private)
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

@(private)
insert_code :: #force_inline proc(length: int) -> int {
	for code := 23; code > 0; code -= 1 {
		if u32(length) >= INSERT_BASE[code] {
			return code
		}
	}

	return 0
}

@(private)
copy_code :: #force_inline proc(length: int) -> int {
	for code := 23; code > 0; code -= 1 {
		if u32(length) >= COPY_BASE[code] {
			return code
		}
	}

	return 0
}

COMMAND_CELLS := [3][3]int{{2, 3, 6}, {4, 5, 8}, {7, 9, 10}}

// Symbol of the 704-symbol command alphabet for an insert and a copy code.
@(private)
command_symbol :: proc(insert, copy: int, implicit_distance: bool) -> int {
	cell := COMMAND_CELLS[insert >> 3][copy >> 3]

	if implicit_distance && insert < 8 && copy < 16 {
		cell -= 2
	}

	return cell << 6 | (insert & 7) << 3 | copy & 7
}

// Distance code for `distance` given the recent-distance ring: the two most
// recent distances, then those within three of either, then the older two.
@(private)
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
@(private)
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

@(private)
ring_push :: #force_inline proc(ring: ^Ring, distance: int) {
	ring[3] = ring[2]
	ring[2] = ring[1]
	ring[1] = ring[0]
	ring[0] = i32(distance)
}

// --------------------------------------------------------------- match finder

@(private)
hash4 :: #force_inline proc(src: []u8, position: int) -> u32 {
	value := intrinsics.unaligned_load((^u32)(&src[position]))

	when ODIN_ENDIAN == .Big {
		value = intrinsics.byte_swap(value)
	}

	return value * 0x1e35a7bd
}

@(private)
insert_hash :: #force_inline proc(e: ^Encoder, position: int) {
	if position + 4 > len(e.src) {
		return
	}

	slot := hash4(e.src, position) >> e.hash_shift
	e.chain[position] = e.head[slot]
	e.head[slot] = u32(position)
}

@(private)
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

// Rough benefit of a copy in units where one literal is worth 135.
@(private)
match_score :: #force_inline proc(length, distance: int) -> int {
	return 135 * length - 30 * bits.len_u32(u32(distance)) + 1920
}

@(private)
recent_score :: #force_inline proc(length, index: int) -> int {
	return 135 * length + 1935 - 40 * index
}

Match :: struct {
	length:   int,
	distance: int,
	score:    int,
}

// Best match for `position` that ends by `end`; length 0 when none is worth it.
@(private)
find_match :: proc(e: ^Encoder, position, end: int) -> Match {
	src := e.src
	limit := end - position
	reach := min(position, e.window_max)
	best := Match{}

	if limit < 4 {
		return best
	}

	for recent, index in e.ring {
		distance := int(recent)

		if distance > reach {
			continue
		}

		length := common_length(src, position - distance, position, limit)

		if length >= 3 {
			score := recent_score(length, index)

			if score > best.score {
				best = {length, distance, score}
			}
		}
	}

	candidate := e.head[hash4(src, position) >> e.hash_shift]

	for chain := e.parameters.chain_limit; candidate != NIL && chain > 0; chain -= 1 {
		distance := position - int(candidate)

		if distance > reach {
			break
		}

		if best.length == 0 || best.length < limit && src[int(candidate) + best.length] == src[position + best.length] {
			length := common_length(src, int(candidate), position, limit)

			if length >= 4 {
				score := match_score(length, distance)

				if score > best.score {
					best = {length, distance, score}

					if length >= e.parameters.nice_length {
						break
					}
				}
			}
		}

		candidate = e.chain[candidate]
	}

	if e.parameters.modelled {
		words: [8]Match

		for word in words[:dictionary_matches(e, position, limit, words[:])] {
			distance := reach + word.distance
			score := match_score(word.length, distance)

			if score > best.score {
				best = {word.length, distance, score}
			}
		}
	}

	return best
}

// ---------------------------------------------------------- static dictionary

@(private)
index_dictionary :: proc(e: ^Encoder) {
	for &slot in e.word_head {
		slot = DICTIONARY_NONE
	}

	offset := 0
	word := 0

	for length in DICTIONARY_WORD_MIN ..= DICTIONARY_WORD_MAX {
		e.word_base[length] = u32(offset)

		for _ in 0 ..< 1 << DICTIONARY_SIZE_BITS[length] {
			slot := hash4(DICTIONARY, offset) >> (32 - DICTIONARY_HASH_BITS)
			e.word_next[word] = e.word_head[slot]
			e.word_head[slot] = u16(word)
			e.word_length[word] = u8(length)
			e.word_offset[word] = u32(offset)
			offset += length
			word += 1
		}
	}
}

// Dictionary words that src[position:] starts with. Each match carries the
// word length and its distance beyond the reachable window.
@(private)
dictionary_matches :: proc(e: ^Encoder, position, limit: int, matches: []Match) -> int {
	if limit < DICTIONARY_WORD_MIN {
		return 0
	}

	count := 0
	word := e.word_head[hash4(e.src, position) >> (32 - DICTIONARY_HASH_BITS)]

	for steps := 0; word != DICTIONARY_NONE && steps < 64 && count < len(matches); steps += 1 {
		length := int(e.word_length[word])
		offset := int(e.word_offset[word])

		if length <= limit && string(e.src[position:][:length]) == string(DICTIONARY[offset:][:length]) {
			matches[count] = {
				length   = length,
				distance = (offset - int(e.word_base[length])) / length + 1,
			}
			count += 1
		}

		word = e.word_next[word]
	}

	return count
}

// -------------------------------------------------------------------- parsing

@(private)
push_command :: proc(e: ^Encoder, position, insert_length, copy_length, distance: int) -> runtime.Allocator_Error {
	command := Command {
		insert_length = u32(insert_length),
		copy_length   = u32(copy_length),
		distance      = u32(distance),
	}

	if copy_length > 0 {
		command.code = distance_code(&e.ring, distance)

		// Dictionary references leave the recent distances alone.
		if command.code != 0 && distance <= min(position, e.window_max) {
			ring_push(&e.ring, distance)
		}
	}

	_, append_error := append(&e.commands, command)

	return append_error
}

// Greedy or lazy parse of src[start:end] into e.commands.
@(private)
parse_range :: proc(e: ^Encoder, start, end: int) -> runtime.Allocator_Error {
	position := start
	literal_start := start

	for position < end {
		match := find_match(e, position, end)

		if match.length == 0 {
			insert_hash(e, position)
			position += 1
			continue
		}

		if e.parameters.lazy {
			// Give up to four literals when a later start scores clearly better.
			for _ in 0 ..< 4 {
				if position + 1 >= end {
					break
				}

				insert_hash(e, position)
				next := find_match(e, position + 1, end)

				if next.score < match.score + 175 {
					break
				}

				position += 1
				match = next
			}
		}

		push_command(e, position, position - literal_start, match.length, match.distance) or_return

		// The first position may already be indexed by the lazy step; a
		// duplicate entry only shortens the useful part of its chain.
		stride := 1 if match.length <= 4096 else 8

		for covered := 0; covered < match.length; covered += stride {
			if e.head[hash4_safe(e, position + covered)] != u32(position + covered) {
				insert_hash(e, position + covered)
			}
		}

		position += match.length
		literal_start = position
	}

	if literal_start < end {
		push_command(e, end, end - literal_start, 0, 0) or_return
	}

	return nil
}

@(private)
hash4_safe :: #force_inline proc(e: ^Encoder, position: int) -> u32 {
	if position + 4 > len(e.src) {
		return 0
	}

	return hash4(e.src, position) >> e.hash_shift
}

// ---------------------------------------------------------------- meta-blocks

Meta_Block :: struct {
	// Literal context mode and distance parameters.
	mode:               int,
	postfix:            uint,
	direct:             uint,
	literal_map:        [LITERAL_CONTEXTS]u8,
	literal_trees:      int,
	distance_map:       [DISTANCE_CONTEXTS]u8,
	distance_trees:     int,
	literal_lengths:    [LITERAL_CONTEXTS][LITERAL_ALPHABET]u8,
	literal_codes:      [LITERAL_CONTEXTS][LITERAL_ALPHABET]u16,
	command_lengths:    [COMMAND_ALPHABET]u8,
	command_codes:      [COMMAND_ALPHABET]u16,
	distance_lengths:   [DISTANCE_CONTEXTS][DISTANCE_ALPHABET]u8,
	distance_codes:     [DISTANCE_CONTEXTS][DISTANCE_ALPHABET]u16,
	literal_histogram:  [LITERAL_CONTEXTS][LITERAL_ALPHABET]u32,
	command_histogram:  [COMMAND_ALPHABET]u32,
	distance_histogram: [DISTANCE_CONTEXTS][DISTANCE_ALPHABET]u32,
}

@(private)
literal_context :: #force_inline proc(src: []u8, position, mode: int) -> int {
	p1 := int(src[position - 1]) if position > 0 else 0
	p2 := int(src[position - 2]) if position > 1 else 0

	return int(CONTEXT_LOOKUP[mode * 512 + p1] | CONTEXT_LOOKUP[mode * 512 + 256 + p2])
}

// Whether at least three quarters of `data` is well-formed UTF-8.
@(private)
mostly_utf8 :: proc(data: []u8) -> bool {
	valid := 0

	for index := 0; index < len(data); {
		lead := data[index]
		size := 1

		switch {
		case lead < 0x80:
		case lead >= 0xc2 && lead < 0xe0:
			size = 2
		case lead >= 0xe0 && lead < 0xf0:
			size = 3
		case lead >= 0xf0 && lead < 0xf5:
			size = 4
		case:
			index += 1
			continue
		}

		whole := index + size <= len(data)

		for tail := 1; whole && tail < size; tail += 1 {
			whole = data[index + tail] & 0xc0 == 0x80
		}

		if whole {
			valid += size
			index += size
		} else {
			index += 1
		}
	}

	return valid * 4 >= len(data) * 3
}

@(private)
distance_context :: #force_inline proc(copy_length: u32) -> int {
	return 3 if copy_length > 4 else int(copy_length) - 2
}

@(private)
command_code :: proc(command: Command) -> (symbol, insert, copy: int) {
	insert = insert_code(int(command.insert_length))
	copy = copy_code(int(max(command.copy_length, 2)))
	symbol = command_symbol(insert, copy, command.copy_length == 0 || command.code == 0)

	return
}

// True when the command's distance is carried by the command symbol itself.
@(private)
distance_is_implicit :: #force_inline proc(symbol: int) -> bool {
	return symbol < 128
}

// Fills the histograms of e.commands over src[start:end] and clusters the
// contexts into trees.
@(private)
gather :: proc(e: ^Encoder, block: ^Meta_Block, start, end: int) {
	src := e.src
	block^ = {}
	block.mode = CONTEXT_MODE_UTF8

	if e.parameters.modelled && !mostly_utf8(src[start:end]) {
		block.mode = CONTEXT_MODE_SIGNED
	}

	if e.level >= .Best {
		choose_distance_parameters(e, block)
	}

	position := start

	for command in e.commands {
		symbol, _, _ := command_code(command)
		block.command_histogram[symbol] += 1

		for _ in 0 ..< command.insert_length {
			block.literal_histogram[literal_context(src, position, block.mode)][src[position]] += 1
			position += 1
		}

		if command.copy_length > 0 {
			if !distance_is_implicit(symbol) {
				prefix, _, _ := distance_prefix(command.code, block.postfix, block.direct)
				block.distance_histogram[distance_context(command.copy_length)][prefix] += 1
			}

			position += int(command.copy_length)
		}
	}

	assert(position == end)

	block.literal_trees = cluster_histograms(block.literal_histogram[:], block.literal_map[:], e.parameters.modelled)
	block.distance_trees = cluster_histograms(block.distance_histogram[:], block.distance_map[:], e.parameters.modelled)
}

// Picks the NPOSTFIX and NDIRECT that code the explicit distances of
// e.commands in the fewest bits.
@(private)
choose_distance_parameters :: proc(e: ^Encoder, block: ^Meta_Block) {
	histogram: [DISTANCE_ALPHABET]u32
	best := max(f64)
	direct_high: uint

	for postfix in uint(0) ..= 3 {
		for ; direct_high < 16; direct_high += 1 {
			direct := direct_high << postfix
			histogram = {}
			extra: f64

			for command in e.commands {
				if command.copy_length == 0 {
					continue
				}

				symbol, _, _ := command_code(command)

				if !distance_is_implicit(symbol) {
					prefix, extra_bits, _ := distance_prefix(command.code, postfix, direct)
					histogram[prefix] += 1
					extra += f64(extra_bits)
				}
			}

			cost := histogram_cost(histogram[:]) + extra

			if cost >= best {
				break
			}

			best = cost
			block.postfix = postfix
			block.direct = direct
		}

		if direct_high > 0 {
			direct_high -= 1
		}

		direct_high /= 2
	}
}

// Writes src[start:end] as one meta-block, stored when coding does not pay.
// `ring` is the recent-distance state from before the block was parsed.
@(private)
write_meta_block :: proc(e: ^Encoder, block: ^Meta_Block, start, end: int, last: bool, ring: Ring) {
	w := &e.writer
	src := e.src
	length := end - start
	nibbles := 6 if length > 1 << 20 else 5 if length > 1 << 16 else 4
	mark_size := len(w.out)
	mark_accumulator := w.accumulator
	mark_count := w.count

	write_bits(w, 1 if last else 0, 1)

	if last {
		write_bits(w, 0, 1)
	}

	write_bits(w, u64(nibbles - 4), 2)
	write_bits(w, u64(length - 1), uint(nibbles * 4))

	if !last {
		write_bits(w, 0, 1)
	}

	// One block type for literals, commands and distances.
	write_bits(w, 0, 3)

	write_bits(w, u64(block.postfix), 2)
	write_bits(w, u64(block.direct >> block.postfix), 4)
	write_bits(w, u64(block.mode), 2)

	distance_alphabet := 16 + int(block.direct) + 48 << block.postfix

	write_context_map(e, block.literal_map[:], block.literal_trees)
	write_context_map(e, block.distance_map[:], block.distance_trees)

	for tree in 0 ..< block.literal_trees {
		build_and_write_code(e, block.literal_histogram[tree][:], block.literal_lengths[tree][:], block.literal_codes[tree][:])
	}

	build_and_write_code(e, block.command_histogram[:], block.command_lengths[:], block.command_codes[:])

	for tree in 0 ..< block.distance_trees {
		build_and_write_code(
			e,
			block.distance_histogram[tree][:distance_alphabet],
			block.distance_lengths[tree][:distance_alphabet],
			block.distance_codes[tree][:distance_alphabet],
		)
	}

	position := start

	for command in e.commands {
		symbol, insert, copy := command_code(command)
		write_bits(w, u64(block.command_codes[symbol]), uint(block.command_lengths[symbol]))
		write_bits(w, u64(command.insert_length - INSERT_BASE[insert]), uint(INSERT_EXTRA[insert]))
		write_bits(w, u64(max(command.copy_length, 2) - COPY_BASE[copy]), uint(COPY_EXTRA[copy]))

		for _ in 0 ..< command.insert_length {
			tree := block.literal_map[literal_context(src, position, block.mode)]
			literal := src[position]
			write_bits(w, u64(block.literal_codes[tree][literal]), uint(block.literal_lengths[tree][literal]))
			position += 1
		}

		if command.copy_length > 0 {
			if !distance_is_implicit(symbol) {
				tree := block.distance_map[distance_context(command.copy_length)]
				prefix, extra_bits, extra := distance_prefix(command.code, block.postfix, block.direct)
				write_bits(w, u64(block.distance_codes[tree][prefix]), uint(block.distance_lengths[tree][prefix]))
				write_bits(w, u64(extra), uint(extra_bits))
			}

			position += int(command.copy_length)
		}
	}

	coded := (len(w.out) - mark_size) * 8 + int(w.count) - int(mark_count)

	if coded <= (length + 4) * 8 {
		return
	}

	// Stored meta-block; it cannot be the last one, so an empty one follows.
	resize(&w.out, mark_size)
	w.accumulator = mark_accumulator
	w.count = mark_count
	e.ring = ring

	write_bits(w, 0, 1)
	write_bits(w, u64(nibbles - 4), 2)
	write_bits(w, u64(length - 1), uint(nibbles * 4))
	write_bits(w, 1, 1)
	flush_bits(w)

	_, append_error := append(&w.out, ..src[start:end])

	if append_error != nil {
		w.err = append_error
	}

	if last {
		write_bits(w, 3, 2)
	}
}

// Estimated bits to store a histogram's code and all of its symbols.
@(private)
histogram_cost :: proc(histogram: []u32) -> f64 {
	total: u64
	used := 0
	weighted: f64

	for frequency in histogram {
		if frequency != 0 {
			total += u64(frequency)
			used += 1
			weighted += f64(frequency) * math.log2(f64(frequency))
		}
	}

	switch used {
	case 0:
		return 0
	case 1:
		return 12
	}

	return f64(total) * math.log2(f64(total)) - weighted + 20 + 5 * f64(used)
}

// Merges the per-context histograms into trees while that saves bits; context
// `c` then uses tree `mapping[c]`, and histograms[t] holds the counts of tree `t`.
@(private)
cluster_histograms :: proc(histograms: [][$N]u32, mapping: []u8, modelled: bool) -> int {
	count := len(histograms)

	if !modelled {
		for index in 1 ..< count {
			for symbol in 0 ..< N {
				histograms[0][symbol] += histograms[index][symbol]
			}
		}

		for &tree in mapping {
			tree = 0
		}

		return 1
	}

	cost: [LITERAL_CONTEXTS]f64
	alive: [LITERAL_CONTEXTS]bool
	gain: [LITERAL_CONTEXTS][LITERAL_CONTEXTS]f64
	merged: [N]u32

	for index in 0 ..< count {
		cost[index] = histogram_cost(histograms[index][:])
		alive[index] = cost[index] != 0
		mapping[index] = u8(index)
	}

	for a in 0 ..< count {
		for b in a + 1 ..< count {
			if alive[a] && alive[b] {
				for symbol in 0 ..< N {
					merged[symbol] = histograms[a][symbol] + histograms[b][symbol]
				}

				gain[a][b] = cost[a] + cost[b] - histogram_cost(merged[:])
			}
		}
	}

	for {
		best: f64
		best_a, best_b := -1, -1

		for a in 0 ..< count {
			for b in a + 1 ..< count {
				if alive[a] && alive[b] && gain[a][b] > best {
					best = gain[a][b]
					best_a, best_b = a, b
				}
			}
		}

		if best_a < 0 {
			break
		}

		for symbol in 0 ..< N {
			histograms[best_a][symbol] += histograms[best_b][symbol]
		}

		alive[best_b] = false
		cost[best_a] = histogram_cost(histograms[best_a][:])

		for &tree in mapping[:count] {
			if int(tree) == best_b {
				tree = u8(best_a)
			}
		}

		for other in 0 ..< count {
			if !alive[other] || other == best_a {
				continue
			}

			for symbol in 0 ..< N {
				merged[symbol] = histograms[best_a][symbol] + histograms[other][symbol]
			}

			low, high := min(best_a, other), max(best_a, other)
			gain[low][high] = cost[low] + cost[high] - histogram_cost(merged[:])
		}
	}

	// Renumber the surviving trees densely; a tree never moves to a later slot.
	renumbered: [LITERAL_CONTEXTS]u8
	trees := 0

	for index in 0 ..< count {
		if alive[index] {
			histograms[trees] = histograms[index]
			renumbered[index] = u8(trees)
			trees += 1
		}
	}

	// Contexts that never occur may use any tree.
	for &tree, index in mapping[:count] {
		tree = renumbered[tree] if cost[index] != 0 || alive[tree] else 0
	}

	return max(trees, 1)
}

// --------------------------------------------------------------- prefix codes

@(private)
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
@(private)
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
@(private)
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
		// A lone symbol costs zero bits per occurrence.
		for &length in lengths {
			length = 0
		}

		write_bits(w, 1, 4)
		write_bits(w, u64(used[0]), width)

		return
	}

	compress.huffman_lengths(&e.huffman, histogram, CODE_LENGTH_MAX, lengths)
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

@(private)
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
		compress.huffman_lengths(&e.huffman, histogram[:], 5, meta_lengths[:])
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
@(private)
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
