package compress_brotli

import "base:intrinsics"
import "base:runtime"
import "core:compress"
import "core:math/bits"
import "core:slice"

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
// Levels up to here write meta-blocks without context modelling, from
// records their parser makes.
PLAIN_LEVEL_MAX :: Level(4)
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
	// Recent distances probed before the bucket: 4, 10 or 16 from level 5 on.
	cache_size: int,
	// Static dictionary matching and literal context modelling.
	modelled:   bool,
	// Block splitting: of commands and distances at level 9, of literals as
	// well above it.
	split:      bool,
}

// One row per level 0..11, as the qualities of the reference encoder; the
// rows up to PLAIN_LEVEL_MAX only size their table with block_bits, the rest
// being compiled into their parsers, the last two parse optimally and only
// use the modelling flags.
@(rodata)
PARAMETERS := [12]Parameters {
	{0, 4, false, false},
	{2, 4, false, false},
	{1, 1, false, false},
	{2, 2, false, false},
	{3, 2, false, false},
	{4, 4, true, false},
	{5, 4, true, false},
	{6, 10, true, false},
	{7, 10, true, false},
	{8, 16, true, true},
	{0, 0, true, true},
	{0, 0, true, true},
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

// Working memory of `compress_to_slice`, owned by the caller: the match table,
// the records of a block and the prefix code scratch of the levels 0..4. It
// needs no initialisation and may be reused, by one call at a time. About
// 4.6 MiB: allocate it, do not declare it on the stack.
Brotli :: struct #align(64) {
	table:   [PLAIN_TABLE_SLOTS_MAX]u32,
	records: [PLAIN_BLOCK / LAZY_MATCH_MIN + 1]Fast_Record,
	huffman: compress.Huffman_Scratch,
}

// Slots of the largest table of the levels 0..4: level 4 on a large input.
PLAIN_TABLE_SLOTS_MAX :: 1 << (LAZY_BUCKET_BITS_MAX + 3)

#assert(BUCKET_BITS_MAX + 2 <= LAZY_BUCKET_BITS_MAX + 3)
#assert(FAST_MATCH_MIN >= LAZY_MATCH_MIN)

// Bytes a meta-block may add to the data it holds: one that does not shrink
// is stored behind a header of at most 28 bits, byte aligned.
COMPRESS_BLOCK_OVERHEAD :: 5

// Room `compress_to_slice` needs past the stream itself: the prefix codes of
// a meta-block are written before it is known whether it shrinks, and whole
// words are stored at the end of the output.
COMPRESS_SLACK :: 1024

// Positions in the input are 32-bit.
when size_of(int) == 8 {
	COMPRESS_INPUT_MAX :: 1 << 32 - 2
} else {
	COMPRESS_INPUT_MAX :: max(int) / 2
}

compress :: proc{compress_to_slice, compress_to_dynamic}

// Size of the output `compress_to_slice` asks for to compress `length` bytes,
// which no stream of `compress` at any level exceeds; -1 when `length` is
// negative or more than `COMPRESS_INPUT_MAX`.
compress_bound :: proc(length: int) -> int {
	if length < 0 || length > COMPRESS_INPUT_MAX {
		return -1
	}

	return length + COMPRESS_BLOCK_OVERHEAD * (length / BLOCK_CHUNK + 1) + COMPRESS_SLACK
}

// Compresses `input` into `output`, which is overwritten and grown as needed,
// as a complete Brotli stream. The working memory of the encoder comes from
// `allocator` and is freed before returning; `output` is left empty on error.
compress_to_dynamic :: proc(output: ^[dynamic]u8, input: []u8, level := Level.Default, allocator := context.allocator) -> (err: Error) {
	return compress_meta_blocks(output, input, level, META_BLOCK_MAX, allocator)
}

// Compresses `input` into `output` as a complete Brotli stream, the same
// bytes `compress_to_dynamic` gives for `level`, and returns its size.
// `output` must hold at least `compress_bound(len(input))` bytes.
//
// Levels 0..4 allocate nothing: their tables are those of `s` and the stream
// is written straight into `output`. Levels 5..11 size their tables and their
// model by the input and cannot work from a fixed state: they take their
// working memory and a temporary copy of the stream from `context.allocator`,
// free both before returning, and leave `s` untouched.
compress_to_slice :: proc(s: ^Brotli, output, input: []u8, level := Level.Default) -> (written: int, err: Error) {
	bound := compress_bound(len(input))

	if s == nil || bound < 0 {
		return 0, E_General.Incompatible_Options
	}

	if len(output) < bound {
		return 0, E_General.Output_Too_Short
	}

	if level > PLAIN_LEVEL_MAX {
		packed: [dynamic]u8
		defer delete(packed)

		compress_to_dynamic(&packed, input, level) or_return

		return copy(output, packed[:]), nil
	}

	e: Encoder
	window_bits := encoder_begin(&e, input, level)
	e.huffman = &s.huffman
	e.writer.out = fixed_buffer(output)

	records: []Fast_Record

	if e.level <= FAST_LEVEL_MAX {
		table_bits := fast_table_bits(len(input), e.parameters.block_bits)
		e.finder.bucket_shift = u32(32 - table_bits)
		e.finder.buckets = s.table[:1 << uint(table_bits)]
		records = s.records[:fast_record_count(min(len(input), PLAIN_BLOCK), FAST_MATCH_MIN)]
	} else {
		bucket_bits := lazy_bucket_bits(len(input))
		e.finder.bucket_shift = u32(32 - bucket_bits)
		e.finder.buckets = s.table[:(1 << uint(bucket_bits)) << e.parameters.block_bits]
		records = s.records[:fast_record_count(min(len(input), PLAIN_BLOCK), LAZY_MATCH_MIN)]
	}

	// Every slot points into the data from the start.
	slice.zero(e.finder.buckets)

	stream_error := encode_stream(&e, nil, nil, nil, records, window_bits, META_BLOCK_MAX)

	// Only a stream past the bound would not fit.
	if stream_error != nil || e.writer.err != nil {
		return 0, E_General.Output_Too_Short
	}

	return len(e.writer.out), nil
}

// `compress_to_dynamic` with at most `meta_block_max` input bytes per
// meta-block; smaller meta-blocks adapt their prefix codes sooner and cost
// more headers, beyond what `compress_bound` allows for.
compress_meta_blocks :: proc(output: ^[dynamic]u8, input: []u8, level: Level, meta_block_max: int, allocator := context.allocator) -> (err: Error) {
	assert(meta_block_max > 0 && meta_block_max <= META_BLOCK_MAX)

	context.allocator = allocator
	bound := compress_bound(len(input))

	if output == nil || bound < 0 {
		return E_General.Incompatible_Options
	}

	if bound > compress.COMPRESS_OUTPUT_ALLOCATE_MAX {
		return E_General.Output_Too_Short
	}

	e := new(Encoder, allocator) or_return
	defer free(e, allocator)

	window_bits := encoder_begin(e, input, level)
	e.allocator = allocator

	clear(output)
	non_zero_reserve(output, len(input) / 3 + 64) or_return

	// The writer grows the caller's array; it is handed back whatever happens.
	e.writer.out = output^
	defer output^ = e.writer.out
	defer if err != nil {
		clear(&e.writer.out)
	}

	e.commands = make([dynamic]Command, 0, len(input) / 16 + 16, allocator) or_return
	defer delete(e.commands)

	// The scratch is written before it is read: skip clearing its half megabyte.
	scratch := runtime.mem_alloc_non_zeroed(size_of(compress.Huffman_Scratch), align_of(compress.Huffman_Scratch), allocator) or_return
	e.huffman = (^compress.Huffman_Scratch)(raw_data(scratch))
	defer free(e.huffman, allocator)

	block := block_make(allocator) or_return
	defer block_destroy(block, allocator)

	optimal: ^Optimal
	parsed: [dynamic]Command
	records: []Fast_Record

	defer optimal_destroy(optimal, allocator)
	defer delete(parsed)
	defer finder_destroy(&e.finder, allocator)
	defer delete(records, allocator)

	switch {
	case e.level >= OPTIMAL_LEVEL_MIN:
		optimal = optimal_make(e, min(len(input), OPTIMAL_BLOCK), allocator) or_return
		parsed = make([dynamic]Command, allocator) or_return
	case e.level <= FAST_LEVEL_MAX:
		fast_finder_make(&e.finder, len(input), e.parameters.block_bits, allocator) or_return
		records = fast_records_make(min(len(input), PLAIN_BLOCK), FAST_MATCH_MIN, allocator) or_return
	case e.level <= PLAIN_LEVEL_MAX:
		lazy_finder_make(&e.finder, len(input), e.parameters.block_bits, allocator) or_return
		records = fast_records_make(min(len(input), PLAIN_BLOCK), LAZY_MATCH_MIN, allocator) or_return
	case:
		finder_make(&e.finder, len(input), e.parameters.block_bits, allocator) or_return
	}

	encode_stream(e, block, optimal, &parsed, records, window_bits, meta_block_max) or_return

	return e.writer.err
}

// Readies `e` to encode `src` at `level`; returns the window bits of the
// stream.
encoder_begin :: proc(e: ^Encoder, src: []u8, level: Level) -> (window_bits: int) {
	e.src = src
	e.ring = {4, 11, 15, 16}
	e.level = Level(min(int(level), len(PARAMETERS) - 1))
	e.parameters = PARAMETERS[e.level]
	window_bits = clamp(bits.len_u32(u32(min(len(src) + 15, 1 << 30))), WINDOW_BITS_MIN, WINDOW_BITS_MAX)
	e.window_max = 1 << uint(window_bits) - 16

	return
}

// Allocator of a buffer that cannot grow: every request fails.
fixed_allocator_proc :: proc(
	allocator_data: rawptr,
	mode: runtime.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> ([]byte, runtime.Allocator_Error) {
	return nil, .Out_Of_Memory
}

// An empty dynamic array over `backing` that reports an error instead of
// growing past it.
fixed_buffer :: proc(backing: []u8) -> [dynamic]u8 {
	return transmute([dynamic]u8)runtime.Raw_Dynamic_Array{raw_data(backing), 0, len(backing), {fixed_allocator_proc, nil}}
}

// Writes the whole stream for e.src to e.writer, at most `meta_block_max`
// input bytes per meta-block. `block` is the model of the levels above
// PLAIN_LEVEL_MAX, `optimal` and `parsed` the state of the optimal ones,
// `records` the room of the others.
encode_stream :: proc(
	e: ^Encoder,
	block: ^Meta_Block,
	optimal: ^Optimal,
	parsed: ^[dynamic]Command,
	records: []Fast_Record,
	window_bits, meta_block_max: int,
) -> runtime.Allocator_Error {
	src := e.src
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

		// The levels that parse as they go end a meta-block where the data
		// changes: its codes then fit what it holds.
		if optimal == nil && e.parameters.modelled {
			end = block_end(src, start, end)
		}

		if optimal != nil {
			// Parsed a block at a time, modelled and coded as one meta-block.
			clear(parsed)

			for from := start; from < end; from += OPTIMAL_BLOCK {
				clear(&e.commands)
				parse_optimal(e, optimal, block, from, min(from + OPTIMAL_BLOCK, end)) or_return
				join_commands(parsed, e.commands[:]) or_return
			}

			e.commands, parsed^ = parsed^, e.commands
		} else if e.level <= PLAIN_LEVEL_MAX {
			write_fast_meta_block(e, records, start, end, end == len(src)) or_return
			start = end

			continue
		} else {
			switch e.parameters.cache_size {
			case 4:
				parse_deep(e, start, end, 4) or_return
			case 10:
				parse_deep(e, start, end, 10) or_return
			case:
				parse_deep(e, start, end, 16) or_return
			}
		}

		gather(e, block, start, end, e.parameters.split) or_return
		write_meta_block(e, block, start, end, end == len(src), ring) or_return

		start = end
	}

	flush_bits(w)

	return nil
}

// Bytes looked at together when the end of a meta-block is chosen.
BLOCK_CHUNK :: 1 << 15

// Bits per byte of a chunk that coding it together with the bytes before it
// may cost, going by the counts of their bytes: beyond that it starts a
// meta-block. Less cuts text that only drifts, more keeps unlike data together.
BLOCK_LOSS_MAX :: 0.25

// Counts the bytes of `data`, four at a time into tables of their own: a
// count is not held up by the one before it.
byte_histogram :: proc(data: []u8) -> (histogram: [256]u32) #no_bounds_check {
	parts: [3][256]u32
	index := 0

	for ; index + 4 <= len(data); index += 4 {
		histogram[data[index]] += 1
		parts[0][data[index + 1]] += 1
		parts[1][data[index + 2]] += 1
		parts[2][data[index + 3]] += 1
	}

	for ; index < len(data); index += 1 {
		histogram[data[index]] += 1
	}

	for &count, value in histogram {
		count += parts[0][value] + parts[1][value] + parts[2][value]
	}

	return
}

// Where the meta-block that starts at `start` should end, `limit` at most:
// before the first chunk whose bytes are too unlike those before it.
block_end :: proc(src: []u8, start, limit: int) -> int {
	if limit - start < 2 * BLOCK_CHUNK {
		return limit
	}

	total := byte_histogram(src[start:][:BLOCK_CHUNK])
	end := start + BLOCK_CHUNK

	for end < limit {
		next_end := end + BLOCK_CHUNK

		// A short rest is not worth codes of its own.
		if limit - next_end < BLOCK_CHUNK / 2 {
			next_end = limit
		}

		next := byte_histogram(src[end:next_end])
		merged := total

		for count, value in next {
			merged[value] += count
		}

		_, _, merged_bits := entropy_bits(merged[:])
		_, _, total_bits := entropy_bits(total[:])
		_, _, next_bits := entropy_bits(next[:])

		if merged_bits - total_bits - next_bits > BLOCK_LOSS_MAX * f64(next_end - end) {
			return end
		}

		total = merged
		end = next_end
	}

	return limit
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
	_, append_error := append(&e.commands, command_make(&e.ring, insert_length, copy_length, distance, omit, distance <= min(position, e.window_max)))

	return append_error
}

// Command for `insert_length` literals and a copy, none when `copy_length` is
// zero; the distance enters `ring` when it is new and `inside` the window,
// which a dictionary reference is not.
command_make :: #force_inline proc(ring: ^Ring, insert_length, copy_length, distance, omit: int, inside: bool) -> Command {
	command := Command {
		insert_length = u32(insert_length),
		copy_length   = u32(copy_length),
		distance      = u32(distance),
		omit          = i8(omit),
	}

	if copy_length > 0 {
		command.code = distance_code(ring, distance)

		if command.code != 0 && inside {
			ring_push(ring, distance)
		}
	}

	insert := insert_code(insert_length)
	copy := copy_code(max(copy_length, 2))
	command.insert_code = u8(insert)
	command.copy_code = u8(copy)
	command.symbol = u16(command_symbol(insert, copy, copy_length == 0 || command.code == 0))

	return command
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

// Code lengths of at most `limit`, and their canonical codes, for the
// `symbols` of `frequencies` that occur, two or more and in order: a plain
// Huffman tree, built again with the rarest counts raised while it comes out
// too deep. Rarely worse than the package merge and several times quicker,
// which is what the fast levels need. Only the symbols that occur are gone
// through: a small block has few of its alphabet.
quick_code :: proc(frequencies: []u32, symbols: []u16, limit: u16, lengths: []u8, codes: []u16) #no_bounds_check {
	// Leaves in order of weight, then the inner nodes in the order made.
	gathered: [ALPHABET_MAX]u64 = ---
	spare: [ALPHABET_MAX]u64 = ---
	weights: [2 * ALPHABET_MAX]u64 = ---
	parents: [2 * ALPHABET_MAX]u16 = ---
	depths: [2 * ALPHABET_MAX]u16 = ---
	used := len(symbols)
	highest := u32(0)

	for symbol, index in symbols {
		frequency := frequencies[symbol]
		gathered[index] = u64(frequency) << 16 | u64(symbol)
		highest = max(highest, frequency)
	}

	keys := sort_by_count(gathered[:used], spare[:used], highest)

	for floor := u64(1);; floor *= 2 {
		for key, index in keys {
			weights[index] = max(key >> 16, floor)
		}

		// Both queues are sorted: the two lightest nodes are at their heads.
		leaf := 0
		inner := used
		root := 2 * used - 2

		for node in used ..= root {
			weight := u64(0)

			for _ in 0 ..< 2 {
				if leaf < used && (inner == node || weights[leaf] <= weights[inner]) {
					weight += weights[leaf]
					parents[leaf] = u16(node)
					leaf += 1
				} else {
					weight += weights[inner]
					parents[inner] = u16(node)
					inner += 1
				}
			}

			weights[node] = weight
		}

		depths[root] = 0

		for node := root - 1; node >= 0; node -= 1 {
			depths[node] = depths[parents[node]] + 1
		}

		// The lightest leaf is the deepest.
		if depths[0] <= limit {
			break
		}
	}

	counts: [CODE_LENGTH_MAX + 1]u32
	first: [CODE_LENGTH_MAX + 1]u32
	slice.zero(lengths)
	slice.zero(codes)

	for key, index in keys {
		lengths[key & 0xffff] = u8(depths[index])
		counts[depths[index]] += 1
	}

	code: u32

	for length in 1 ..= CODE_LENGTH_MAX {
		code = (code + counts[length - 1]) << 1
		first[length] = code
	}

	for symbol in symbols {
		length := lengths[symbol]
		codes[symbol] = u16(bits.reverse_bits(first[length]) >> (32 - u32(length)))
		first[length] += 1
	}
}

SORT_BY_INSERTION_MAX :: 16

// Sorts keys of a count above a 16-bit symbol that come in order of symbol:
// a stable pass per byte of the largest count orders them by count and leaves
// equal counts by symbol, in a few hundred steps where a comparison sort of
// a small block's symbols takes thousands. Returns whichever of the two
// slices ends up holding them.
sort_by_count :: proc(keys, spare: []u64, highest: u32) -> []u64 #no_bounds_check {
	// A handful is in place sooner than the passes are set up; no two keys
	// are equal, so the order is the same.
	if len(keys) <= SORT_BY_INSERTION_MAX {
		for key, index in keys {
			slot := index

			for slot > 0 && keys[slot - 1] > key {
				keys[slot] = keys[slot - 1]
				slot -= 1
			}

			keys[slot] = key
		}

		return keys
	}

	from := keys
	to := spare

	for shift := uint(16); highest >> (shift - 16) != 0; shift += 8 {
		starts: [257]u32

		for key in from {
			starts[(key >> shift) & 0xff + 1] += 1
		}

		for digit in 1 ..< 256 {
			starts[digit] += starts[digit - 1]
		}

		for key in from {
			digit := (key >> shift) & 0xff
			to[starts[digit]] = key
			starts[digit] += 1
		}

		from, to = to, from
	}

	return from
}

// Canonical codes for `lengths`, bit-reversed for the LSB-first bit order and
// zero where there is no code. The symbols without one are passed over
// without being counted: each count waits on the one before it.
canonical_codes :: proc(lengths: []u8, codes: []u16) #no_bounds_check {
	counts: [CODE_LENGTH_MAX + 1]u32
	first: [CODE_LENGTH_MAX + 1]u32

	for length in lengths {
		if length != 0 {
			counts[length] += 1
		}
	}

	code: u32

	for length in 1 ..= CODE_LENGTH_MAX {
		code = (code + counts[length - 1]) << 1
		first[length] = code
	}

	for length, symbol in lengths {
		if length == 0 {
			codes[symbol] = 0

			continue
		}

		codes[symbol] = u16(bits.reverse_bits(first[length]) >> (32 - u32(length)))
		first[length] += 1
	}
}

// Builds the length-limited code for `histogram`, writes its description and
// leaves `lengths`/`codes` ready for writing symbols. `quick` trades a little
// of the code's quality for the time to build it.
build_and_write_code :: proc(e: ^Encoder, histogram: []u32, lengths: []u8, codes: []u16, quick := false) {
	w := &e.writer
	alphabet := len(histogram)
	// The symbols that occur, in order: a slot is kept only when its symbol
	// does.
	symbols: [ALPHABET_MAX]u16 = ---
	used: [4]int
	used_count := 0

	#no_bounds_check for base := 0; base < alphabet; base += 4 {
		group := histogram[base:min(base + 4, alphabet)]

		// Most of a small block's alphabet goes unused, four counts at a time.
		if len(group) == 4 && intrinsics.unaligned_load((^u64)(&group[0])) | intrinsics.unaligned_load((^u64)(&group[2])) == 0 {
			continue
		}

		for frequency, offset in group {
			symbols[used_count] = u16(base + offset)
			used_count += int(frequency != 0)
		}
	}

	for index in 0 ..< min(used_count, len(used)) {
		used[index] = int(symbols[index])
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

	if quick {
		quick_code(histogram, symbols[:used_count], CODE_LENGTH_MAX, lengths, codes)
	} else {
		compress.huffman_lengths(e.huffman, histogram, CODE_LENGTH_MAX, lengths)
		canonical_codes(lengths, codes)
	}

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

// How many of the first bytes of `data`, which is not empty, are the same:
// the runs of symbols without a code are long, and go by eight at a time.
run_length :: proc(data: []u8) -> int #no_bounds_check {
	value := data[0]
	run := 1

	when ODIN_ENDIAN == .Little {
		same := u64(value) * 0x0101010101010101

		for run + 8 <= len(data) {
			difference := intrinsics.unaligned_load((^u64)(&data[run])) ~ same

			if difference != 0 {
				return run + int(intrinsics.count_trailing_zeros(difference)) >> 3
			}

			run += 8
		}
	}

	for run < len(data) && data[run] == value {
		run += 1
	}

	return run
}

write_complex_code :: proc(e: ^Encoder, lengths: []u8) {
	w := &e.writer
	size := len(lengths)

	for size >= 8 && intrinsics.unaligned_load((^u64)(&lengths[size - 8])) == 0 {
		size -= 8
	}

	for size > 0 && lengths[size - 1] == 0 {
		size -= 1
	}

	// Run-length encode with 16 (repeat previous non-zero) and 17 (zeros);
	// consecutive repeat symbols extend one run in base 4 or base 8.
	// Written up to `total` before they are read.
	symbols: [ALPHABET_MAX + 8]u8 = ---
	extras: [ALPHABET_MAX + 8]u8 = ---
	total := 0
	previous: u8 = 8

	for index := 0; index < size; {
		value := lengths[index]
		run := run_length(lengths[index:size])
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
		canonical_codes(meta_lengths[:], meta_codes[:])
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

	// A code and its extra bits are 8 bits at most: they are gathered and
	// handed over three symbols at a time, the writer being slow to take them.
	pending: u64
	width: uint

	for index in 0 ..< total {
		symbol := symbols[index]

		if used != 1 {
			pending |= u64(meta_codes[symbol]) << width
			width += uint(meta_lengths[symbol])
		}

		switch symbol {
		case 16:
			pending |= u64(extras[index]) << width
			width += 2
		case 17:
			pending |= u64(extras[index]) << width
			width += 3
		}

		if width > 24 {
			write_bits(w, pending, width)
			pending = 0
			width = 0
		}
	}

	write_bits(w, pending, width)
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

	write_plain_header(w, length, last)

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

	(^runtime.Raw_Dynamic_Array)(&w.out).len = mark_size
	w.accumulator = mark_accumulator
	w.count = mark_count
	e.ring = ring

	return write_stored_meta_block(w, src[start:end], last)
}

meta_block_nibbles :: proc(length: int) -> int {
	return 6 if length > 1 << 20 else 5 if length > 1 << 16 else 4
}

// Header of a meta-block of `length` bytes without block splits or context
// modelling, up to where its three prefix codes follow.
write_plain_header :: proc(w: ^Bit_Writer, length: int, last: bool) {
	nibbles := meta_block_nibbles(length)
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
}

// Stored meta-block; it cannot be the last one, so an empty one follows.
write_stored_meta_block :: proc(w: ^Bit_Writer, data: []u8, last: bool) -> runtime.Allocator_Error {
	nibbles := meta_block_nibbles(len(data))
	write_bits(w, 0, 1)
	write_bits(w, u64(nibbles - 4), 2)
	write_bits(w, u64(len(data) - 1), uint(nibbles * 4))
	write_bits(w, 1, 1)
	flush_bits(w)
	append(&w.out, ..data) or_return

	if last {
		write_bits(w, 3, 2)
	}

	return nil
}
