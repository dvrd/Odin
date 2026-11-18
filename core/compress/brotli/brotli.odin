package compress_brotli

/*
	This package implements the Brotli compressed data format,
	as specified in RFC 7932.

	Decoding reads from a `compress.Context`, writes to its `[dynamic]u8`
	output and reports `compress.Error`.
*/

import "core:compress"
import "core:math/bits"

Error     :: compress.Error
E_General :: compress.General_Error
E_Brotli  :: compress.Brotli_Error

@(rodata)
DICTIONARY := #load("dictionary.bin")

@(rodata)
DICTIONARY_SIZE_BITS := [25]u8{0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5}

DICTIONARY_WORD_MIN :: 4
DICTIONARY_WORD_MAX :: 24

@(rodata)
INSERT_BASE := [24]u32 {
	0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594,
}

@(rodata)
INSERT_EXTRA := [24]u8{0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24}

@(rodata)
COPY_BASE := [24]u32 {
	2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
}

@(rodata)
COPY_EXTRA := [24]u8{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24}

@(rodata)
BLOCK_COUNT_BASE := [26]u32 {
	1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433,
	16625,
}

@(rodata)
BLOCK_COUNT_EXTRA := [26]u8{2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24}

// Insert and copy code bases for each of the 11 cells of the command alphabet.
@(rodata)
COMMAND_INSERT_CELL := [11]u8{0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16}

@(rodata)
COMMAND_COPY_CELL := [11]u8{0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16}

@(rodata)
CODE_LENGTH_ORDER := [18]u8{1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15}

LITERAL_ALPHABET     :: 256
COMMAND_ALPHABET     :: 704
BLOCK_COUNT_ALPHABET :: 26
ALPHABET_MAX         :: 704
CODE_LENGTH_MAX      :: 15
ROOT_BITS            :: 8

// Entries a two-level table needs for a complete code over up to 256, 272
// (context maps, block types) and 704 symbols with an 8-bit root.
LITERAL_TABLE_SIZE :: 630
SMALL_TABLE_SIZE   :: 662
LARGE_TABLE_SIZE   :: 1080

// Prefix code table entry. In the root table an entry with `bits` above
// ROOT_BITS points at a second-level table that starts at `value` and is
// indexed by the next `bits - ROOT_BITS` bits.
Entry :: struct {
	bits:  u8,
	value: u16,
}

Block_State :: struct {
	type_count:  int,
	current:     int,
	previous:    int,
	remaining:   int,
	type_table:  [SMALL_TABLE_SIZE]Entry,
	count_table: [SMALL_TABLE_SIZE]Entry,
}

Command_Entry :: struct {
	insert_base:  u16,
	copy_base:    u16,
	insert_extra: u8,
	copy_extra:   u8,
}

Load_Decoder :: struct {
	// Set when a read ran past the end of the input.
	short:         bool,
	// Most bytes the output may hold.
	limit:         int,
	literal:       Block_State,
	command:       Block_State,
	distance:      Block_State,
	scratch:       [SMALL_TABLE_SIZE]Entry,
	context_modes: [256]u8,
	literal_map:   [256 * 64]u8,
	distance_map:  [256 * 4]u8,
	commands:      [COMMAND_ALPHABET]Command_Entry,
	tables:        [dynamic]Entry,
}

// Insert and copy parameters of command alphabet symbol `symbol`.
command_entry :: proc(symbol: int) -> Command_Entry {
	cell   := symbol >> 6
	insert := int(COMMAND_INSERT_CELL[cell]) + symbol >> 3 & 7
	copy   := int(COMMAND_COPY_CELL[cell]) + symbol & 7

	return {u16(INSERT_BASE[insert]), u16(COPY_BASE[copy]), INSERT_EXTRA[insert], COPY_EXTRA[copy]}
}

decompress :: proc{decompress_from_bytes, decompress_from_context}

// Decodes the complete Brotli stream `input` into `output`, which is
// overwritten and grown as needed with `allocator`.
decompress_from_bytes :: proc(output: ^[dynamic]u8, input: []u8, expected_output_size := -1, max_output_size := compress.COMPRESS_OUTPUT_ALLOCATE_MAX, allocator := context.allocator) -> (err: Error) {
	input := input
	ctx := compress.init_context_from_slice(&input, output = output)

	return decompress_from_context(&ctx, expected_output_size, max_output_size, allocator)
}

// Decodes one complete Brotli stream from `z` into `z.output`, which is
// overwritten. Bytes after the end of the stream are an error.
//
// The output never exceeds `max_output_size`, nor `expected_output_size` (or
// `z.size_unpacked`) when that is positive: a stream that holds more fails
// with `.Output_Too_Short`. What was decoded before an error stays in
// `z.output`.
decompress_from_context :: proc(z: ^compress.Context, expected_output_size := -1, max_output_size := compress.COMPRESS_OUTPUT_ALLOCATE_MAX, allocator := context.allocator) -> (err: Error) {
	context.allocator = allocator

	if z.output == nil || max_output_size < 0 {
		return E_General.Incompatible_Options
	}

	expected := expected_output_size

	if expected <= 0 && z.size_unpacked > 0 && z.size_unpacked <= i64(max(int)) {
		expected = int(z.size_unpacked)
	}

	limit := max_output_size

	if expected > 0 {
		if expected > limit {
			return E_General.Output_Too_Short
		}

		limit = expected
	}

	z.bytes_written = 0
	z.num_bits = 0
	z.code_buffer = 0

	clear(z.output)
	defer non_zero_resize(z.output, int(z.bytes_written))

	d := new(Load_Decoder) or_return
	defer free(d)
	defer delete(d.tables)

	d.limit = limit
	d.tables = make([dynamic]Entry) or_return

	for &entry, symbol in d.commands {
		entry = command_entry(symbol)
	}

	non_zero_resize(z.output, min(compress.output_reservation(expected, -1, compress.input_size(z)), limit)) or_return

	return decode_stream(z, d)
}

// ------------------------------------------------------------------ bit input

// Makes more input available in `z.window`; false at the end of the input.
refill_input :: proc(z: ^compress.Context) -> bool {
	if compress.is_memory_context(z) {
		return false
	}

	return compress.refill_window(z, 1) == nil && len(z.window) > 0
}

// Tops the LSB-first bit buffer of `z` up to more than `width` bits while
// input remains.
refill_bits :: proc(z: ^compress.Context, width := u64(48)) {
	for z.num_bits <= width {
		if z.code_buffer == 0 && z.num_bits > 63 {
			z.num_bits = 0
		}

		if z.code_buffer >= 1 << uint(z.num_bits) {
			// Code buffer is malformed.
			z.num_bits = max(u64)
			return
		}

		if len(z.window) == 0 && !refill_input(z) {
			return
		}

		z.code_buffer |= u64(z.window[0]) << u8(z.num_bits)
		z.window = z.window[1:]
		z.num_bits += 8
	}
}

read_bits :: #force_inline proc(z: ^compress.Context, d: ^Load_Decoder, width: u8) -> u32 {
	if z.num_bits < u64(width) {
		refill_bits(z)

		if z.num_bits < u64(width) {
			d.short = true
			return 0
		}
	}

	value := u32(z.code_buffer & (u64(1) << width - 1))
	z.code_buffer >>= width
	z.num_bits -= u64(width)

	return value
}

// Discards the bits up to the next byte boundary; false if any was set.
align_to_byte :: proc(z: ^compress.Context, d: ^Load_Decoder) -> bool {
	return read_bits(z, d, u8(z.num_bits & 7)) == 0
}

// Grows the output so that `extra` more bytes fit.
reserve_output :: proc(z: ^compress.Context, d: ^Load_Decoder, extra: int) -> Error {
	need := int(z.bytes_written) + extra

	if need <= len(z.output) {
		return nil
	}

	if need > d.limit {
		return E_General.Output_Too_Short
	}

	return non_zero_resize(z.output, compress.output_grow_capacity(len(z.output), need, d.limit))
}

// --------------------------------------------------------------- prefix codes

// Builds the two-level decoding table for the complete canonical code
// `lengths`; false if `table` is too small for it.
build_table :: proc(table: []Entry, lengths: []u8) -> bool {
	counts: [CODE_LENGTH_MAX + 1]int
	offsets: [CODE_LENGTH_MAX + 2]int
	sorted: [ALPHABET_MAX]u16

	for length in lengths {
		counts[length] += 1
	}

	counts[0] = 0

	for length in 1 ..= CODE_LENGTH_MAX {
		offsets[length + 1] = offsets[length] + counts[length]
	}

	for length, symbol in lengths {
		if length != 0 {
			sorted[offsets[length]] = u16(symbol)
			offsets[length] += 1
		}
	}

	if len(table) < 1 << ROOT_BITS {
		return false
	}

	code: u32
	index := 0
	next := 1 << ROOT_BITS
	sub_size := 0
	sub_root := -1

	for length in 1 ..= CODE_LENGTH_MAX {
		for ; counts[length] > 0; counts[length] -= 1 {
			symbol := sorted[index]
			index += 1
			key := int(bits.reverse_bits(code) >> (32 - u32(length)))
			code += 1

			if length <= ROOT_BITS {
				for slot := key; slot < 1 << ROOT_BITS; slot += 1 << uint(length) {
					table[slot] = {u8(length), symbol}
				}

				continue
			}

			root := key & (1 << ROOT_BITS - 1)

			if root != sub_root {
				// Size the next second-level table from the codes still unassigned.
				next += sub_size
				longest := length
				left := 1 << uint(longest - ROOT_BITS)

				for longest < CODE_LENGTH_MAX {
					left -= counts[longest]

					if left <= 0 {
						break
					}

					longest += 1
					left <<= 1
				}

				sub_size = 1 << uint(longest - ROOT_BITS)
				sub_root = root

				if next + sub_size > len(table) {
					return false
				}

				table[root] = {u8(longest), u16(next)}
			}

			for slot := key >> ROOT_BITS; slot < sub_size; slot += 1 << uint(length - ROOT_BITS) {
				table[next + slot] = {u8(length - ROOT_BITS), symbol}
			}
		}

		code <<= 1
	}

	return true
}

// A code with one symbol takes no bits.
fill_table :: proc(table: []Entry, symbol: int) {
	for &entry in table[:1 << ROOT_BITS] {
		entry = {0, u16(symbol)}
	}
}

read_symbol :: #force_inline proc(z: ^compress.Context, d: ^Load_Decoder, table: []Entry) -> u32 #no_bounds_check {
	if z.num_bits < CODE_LENGTH_MAX {
		refill_bits(z)
	}

	entry := table[z.code_buffer & (1 << ROOT_BITS - 1)]
	used := u64(entry.bits)

	if entry.bits > ROOT_BITS {
		index := (z.code_buffer >> ROOT_BITS) & (u64(1) << (entry.bits - ROOT_BITS) - 1)
		entry = table[u64(entry.value) + index]
		used = ROOT_BITS + u64(entry.bits)
	}

	if used > z.num_bits {
		d.short = true
		return 0
	}

	z.code_buffer >>= used
	z.num_bits -= used

	return u32(entry.value)
}

read_prefix_code :: proc(z: ^compress.Context, d: ^Load_Decoder, table: []Entry, alphabet: int) -> Error {
	lengths: [ALPHABET_MAX]u8
	skip := int(read_bits(z, d, 2))

	if skip == 1 {
		return read_simple_code(z, d, table, alphabet, lengths[:alphabet])
	}

	// Lengths of the code that encodes the symbol lengths.
	meta_lengths: [18]u8
	space := 32
	used := 0

	for index := skip; index < 18 && space > 0; index += 1 {
		if z.num_bits < 4 {
			refill_bits(z)
		}

		peek := z.code_buffer & 15
		length, width: u8

		switch {
		case peek & 3 == 0:
			length, width = 0, 2
		case peek & 3 == 1:
			length, width = 4, 2
		case peek & 3 == 2:
			length, width = 3, 2
		case peek & 7 == 3:
			length, width = 2, 3
		case peek == 7:
			length, width = 1, 4
		case:
			length, width = 5, 4
		}

		if u64(width) > z.num_bits {
			return E_General.Stream_Too_Short
		}

		z.code_buffer >>= width
		z.num_bits -= u64(width)
		meta_lengths[CODE_LENGTH_ORDER[index]] = length

		if length != 0 {
			space -= 32 >> length
			used += 1
		}
	}

	if used != 1 && space != 0 || used == 0 {
		return E_Brotli.Invalid_Prefix_Code
	}

	// The code-length code is at most 5 bits deep: a root table alone holds it.
	meta: [1 << ROOT_BITS]Entry

	if used == 1 {
		for length, symbol in meta_lengths {
			if length != 0 {
				fill_table(meta[:], symbol)
			}
		}
	} else if !build_table(meta[:], meta_lengths[:]) {
		return E_Brotli.Invalid_Prefix_Code
	}

	symbol := 0
	previous: u8 = 8
	repeat := 0
	repeat_length: u8
	room := 32768

	for symbol < alphabet && room > 0 {
		value := u8(read_symbol(z, d, meta[:]))

		if d.short {
			return E_General.Stream_Too_Short
		}

		if value < 16 {
			lengths[symbol] = value
			symbol += 1
			repeat = 0

			if value != 0 {
				previous = value
				room -= 32768 >> value
			}

			continue
		}

		extra: u8 = 2 if value == 16 else 3
		fill: u8 = previous if value == 16 else 0

		if repeat_length != fill {
			repeat = 0
			repeat_length = fill
		}

		before := repeat

		if repeat > 0 {
			repeat = (repeat - 2) << extra
		}

		repeat += int(read_bits(z, d, extra)) + 3
		delta := repeat - before

		if symbol + delta > alphabet {
			return E_Brotli.Invalid_Prefix_Code
		}

		for _ in 0 ..< delta {
			lengths[symbol] = fill
			symbol += 1
		}

		if fill != 0 {
			room -= delta << (15 - fill)
		}
	}

	if room != 0 || !build_table(table, lengths[:alphabet]) {
		return E_Brotli.Invalid_Prefix_Code
	}

	return nil
}

read_simple_code :: proc(z: ^compress.Context, d: ^Load_Decoder, table: []Entry, alphabet: int, lengths: []u8) -> Error {
	count := int(read_bits(z, d, 2)) + 1
	width := u8(bits.len_u32(u32(alphabet - 1)))
	symbols: [4]int

	for index in 0 ..< count {
		symbols[index] = int(read_bits(z, d, width))

		if symbols[index] >= alphabet {
			return E_Brotli.Invalid_Prefix_Code
		}

		for other in 0 ..< index {
			if symbols[other] == symbols[index] {
				return E_Brotli.Invalid_Prefix_Code
			}
		}
	}

	switch count {
	case 1:
		fill_table(table, symbols[0])
		return nil
	case 2:
		lengths[symbols[0]] = 1
		lengths[symbols[1]] = 1
	case 3:
		lengths[symbols[0]] = 1
		lengths[symbols[1]] = 2
		lengths[symbols[2]] = 2
	case 4:
		if read_bits(z, d, 1) == 0 {
			for index in 0 ..< 4 {
				lengths[symbols[index]] = 2
			}
		} else {
			lengths[symbols[0]] = 1
			lengths[symbols[1]] = 2
			lengths[symbols[2]] = 3
			lengths[symbols[3]] = 3
		}
	}

	if !build_table(table, lengths) {
		return E_Brotli.Invalid_Prefix_Code
	}

	return nil
}

// ---------------------------------------------------------------- block types

read_variable_byte :: proc(z: ^compress.Context, d: ^Load_Decoder) -> int {
	if read_bits(z, d, 1) == 0 {
		return 0
	}

	width := u8(read_bits(z, d, 3))

	if width == 0 {
		return 1
	}

	return 1 << width + int(read_bits(z, d, width))
}

read_block_count :: proc(z: ^compress.Context, d: ^Load_Decoder, table: []Entry) -> int {
	symbol := read_symbol(z, d, table)

	return int(BLOCK_COUNT_BASE[symbol] + read_bits(z, d, BLOCK_COUNT_EXTRA[symbol]))
}

read_block_state :: proc(z: ^compress.Context, d: ^Load_Decoder, state: ^Block_State) -> Error {
	state.type_count = read_variable_byte(z, d) + 1
	state.current = 0
	state.previous = 1
	state.remaining = 1 << 28

	if state.type_count < 2 {
		return nil
	}

	read_prefix_code(z, d, state.type_table[:], state.type_count + 2) or_return
	read_prefix_code(z, d, state.count_table[:], BLOCK_COUNT_ALPHABET) or_return
	state.remaining = read_block_count(z, d, state.count_table[:])

	return nil
}

switch_block :: proc(z: ^compress.Context, d: ^Load_Decoder, state: ^Block_State) {
	if state.type_count < 2 {
		state.remaining = 1 << 28
		return
	}

	symbol := int(read_symbol(z, d, state.type_table[:]))
	next: int

	switch symbol {
	case 0:
		next = state.previous
	case 1:
		next = state.current + 1
	case:
		next = symbol - 2
	}

	if next >= state.type_count {
		next -= state.type_count
	}

	state.previous = state.current
	state.current = next
	state.remaining = read_block_count(z, d, state.count_table[:])
}

read_context_map :: proc(z: ^compress.Context, d: ^Load_Decoder, values: []u8) -> (trees: int, err: Error) {
	trees = read_variable_byte(z, d) + 1

	for &value in values {
		value = 0
	}

	if trees < 2 {
		return trees, nil
	}

	run_max := 0

	if read_bits(z, d, 1) == 1 {
		run_max = int(read_bits(z, d, 4)) + 1
	}

	read_prefix_code(z, d, d.scratch[:], trees + run_max) or_return

	for index := 0; index < len(values); {
		symbol := int(read_symbol(z, d, d.scratch[:]))

		switch {
		case symbol == 0:
			index += 1
		case symbol <= run_max:
			run := 1 << uint(symbol) + int(read_bits(z, d, u8(symbol)))

			if index + run > len(values) {
				return trees, E_Brotli.Invalid_Context_Map
			}

			index += run
		case:
			values[index] = u8(symbol - run_max)
			index += 1
		}

		if d.short {
			return trees, E_General.Stream_Too_Short
		}
	}

	if read_bits(z, d, 1) == 1 {
		order: [256]u8

		for index in 0 ..< 256 {
			order[index] = u8(index)
		}

		for &value in values {
			at := value
			moved := order[at]
			value = moved

			for at > 0 {
				order[at] = order[at - 1]
				at -= 1
			}

			order[0] = moved
		}
	}

	return trees, nil
}

// --------------------------------------------------------------------- stream

decode_stream :: proc(z: ^compress.Context, d: ^Load_Decoder) -> Error {
	window_bits := 16

	if read_bits(z, d, 1) == 1 {
		wide := int(read_bits(z, d, 3))

		if wide != 0 {
			window_bits = 17 + wide
		} else {
			narrow := int(read_bits(z, d, 3))

			switch narrow {
			case 0:
				window_bits = 17
			case 1:
				return E_Brotli.Invalid_Window_Size
			case:
				window_bits = 8 + narrow
			}
		}
	}

	window_max := 1 << uint(window_bits) - 16
	distances := [4]int{4, 11, 15, 16}
	dictionary_offsets: [DICTIONARY_WORD_MAX + 2]int

	for length in DICTIONARY_WORD_MIN ..= DICTIONARY_WORD_MAX {
		dictionary_offsets[length + 1] = dictionary_offsets[length] + length << DICTIONARY_SIZE_BITS[length]
	}

	for last := false; !last; {
		last = read_bits(z, d, 1) == 1

		if last && read_bits(z, d, 1) == 1 {
			break
		}

		nibbles := int(read_bits(z, d, 2))

		if nibbles == 3 {
			skip_metadata(z, d) or_return
			continue
		}

		nibbles += 4
		length := 0

		for index in 0 ..< nibbles {
			nibble := int(read_bits(z, d, 4))

			if index == nibbles - 1 && nibbles > 4 && nibble == 0 {
				return E_Brotli.Invalid_Meta_Block
			}

			length |= nibble << uint(4 * index)
		}

		length += 1
		stored := !last && read_bits(z, d, 1) == 1

		if d.short {
			return E_General.Stream_Too_Short
		}

		if stored {
			copy_stored(z, d, length) or_return
			continue
		}

		reserve_output(z, d, length) or_return
		decode_meta_block(z, d, length, window_max, &distances, dictionary_offsets[:]) or_return
	}

	if d.short {
		return E_General.Stream_Too_Short
	}

	if !align_to_byte(z, d) {
		return E_Brotli.Invalid_Padding
	}

	refill_bits(z)

	if z.num_bits >= 8 {
		return E_Brotli.Trailing_Data
	}

	return nil
}

// Bytes of input known to remain; unbounded for streams.
input_remaining :: proc(z: ^compress.Context) -> int {
	if compress.is_memory_context(z) {
		return int(z.num_bits / 8) + len(z.window)
	}

	return max(int)
}

// Metadata meta-block: its bytes carry no output.
skip_metadata :: proc(z: ^compress.Context, d: ^Load_Decoder) -> Error {
	if read_bits(z, d, 1) != 0 {
		return E_Brotli.Invalid_Meta_Block
	}

	size_bytes := u8(read_bits(z, d, 2))
	skip := 0

	if size_bytes > 0 {
		skip = int(read_bits(z, d, 8 * size_bytes)) + 1

		if size_bytes > 1 && skip - 1 < 1 << (8 * (size_bytes - 1)) {
			return E_Brotli.Invalid_Meta_Block
		}
	}

	if !align_to_byte(z, d) {
		return E_Brotli.Invalid_Meta_Block
	}

	if skip > input_remaining(z) {
		return E_General.Stream_Too_Short
	}

	for _ in 0 ..< skip {
		read_bits(z, d, 8)

		if d.short {
			return E_General.Stream_Too_Short
		}
	}

	return nil
}

copy_stored :: proc(z: ^compress.Context, d: ^Load_Decoder, length: int) -> Error {
	if !align_to_byte(z, d) {
		return E_Brotli.Invalid_Meta_Block
	}

	if length > input_remaining(z) {
		return E_General.Stream_Too_Short
	}

	reserve_output(z, d, length) or_return

	for _ in 0 ..< length {
		z.output[z.bytes_written] = u8(read_bits(z, d, 8))
		z.bytes_written += 1

		if d.short {
			return E_General.Stream_Too_Short
		}
	}

	return nil
}

decode_meta_block :: proc(
	z: ^compress.Context,
	d: ^Load_Decoder,
	length, window_max: int,
	distances: ^[4]int,
	dictionary_offsets: []int,
) -> Error #no_bounds_check {
	read_block_state(z, d, &d.literal) or_return
	read_block_state(z, d, &d.command) or_return
	read_block_state(z, d, &d.distance) or_return

	postfix := u8(read_bits(z, d, 2))
	direct := int(read_bits(z, d, 4)) << postfix

	for index in 0 ..< d.literal.type_count {
		d.context_modes[index] = u8(read_bits(z, d, 2))
	}

	literal_trees := read_context_map(z, d, d.literal_map[:d.literal.type_count * 64]) or_return
	distance_trees := read_context_map(z, d, d.distance_map[:d.distance.type_count * 4]) or_return
	command_trees := d.command.type_count

	command_base := literal_trees * LITERAL_TABLE_SIZE
	distance_base := command_base + command_trees * LARGE_TABLE_SIZE
	resize(&d.tables, distance_base + distance_trees * LARGE_TABLE_SIZE) or_return

	tables := d.tables[:]
	distance_alphabet := 16 + direct + 48 << postfix

	for tree in 0 ..< literal_trees {
		read_prefix_code(z, d, tables[tree * LITERAL_TABLE_SIZE:][:LITERAL_TABLE_SIZE], LITERAL_ALPHABET) or_return
	}

	for tree in 0 ..< command_trees {
		read_prefix_code(z, d, tables[command_base + tree * LARGE_TABLE_SIZE:][:LARGE_TABLE_SIZE], COMMAND_ALPHABET) or_return
	}

	for tree in 0 ..< distance_trees {
		read_prefix_code(z, d, tables[distance_base + tree * LARGE_TABLE_SIZE:][:LARGE_TABLE_SIZE], distance_alphabet) or_return
	}

	if d.short {
		return E_General.Stream_Too_Short
	}

	out := z.output[:]
	position := int(z.bytes_written)
	defer z.bytes_written = i64(position)

	remaining := length
	postfix_mask := int(1) << postfix - 1
	contextual := literal_trees > 1
	literal_table := tables[:LITERAL_TABLE_SIZE]
	mode := int(d.context_modes[0]) * 512
	literal_map := d.literal_map[:64]

	for remaining > 0 {
		if d.short {
			return E_General.Stream_Too_Short
		}

		if d.command.remaining == 0 {
			switch_block(z, d, &d.command)
		}

		d.command.remaining -= 1

		symbol := int(read_symbol(z, d, tables[command_base + d.command.current * LARGE_TABLE_SIZE:][:LARGE_TABLE_SIZE]))
		command := d.commands[symbol]
		insert_length := int(command.insert_base) + int(read_bits(z, d, command.insert_extra))
		copy_length := int(command.copy_base) + int(read_bits(z, d, command.copy_extra))

		if insert_length > remaining {
			return E_Brotli.Invalid_Command
		}

		remaining -= insert_length

		for insert_length > 0 {
			if d.literal.remaining == 0 {
				switch_block(z, d, &d.literal)
				mode = int(d.context_modes[d.literal.current]) * 512
				literal_map = d.literal_map[d.literal.current * 64:][:64]

				if !contextual {
					literal_table = tables[int(literal_map[0]) * LITERAL_TABLE_SIZE:][:LITERAL_TABLE_SIZE]
				}
			}

			run := min(insert_length, d.literal.remaining)
			d.literal.remaining -= run
			insert_length -= run

			if !contextual {
				for _ in 0 ..< run {
					out[position] = u8(read_symbol(z, d, literal_table))
					position += 1
				}

				continue
			}

			p1 := int(out[position - 1]) if position > 0 else 0
			p2 := int(out[position - 2]) if position > 1 else 0

			for _ in 0 ..< run {
				tree := int(literal_map[CONTEXT_LOOKUP[mode + p1] | CONTEXT_LOOKUP[mode + 256 + p2]])
				p2 = p1
				p1 = int(read_symbol(z, d, tables[tree * LITERAL_TABLE_SIZE:][:LITERAL_TABLE_SIZE]))
				out[position] = u8(p1)
				position += 1
			}
		}

		if remaining == 0 {
			break
		}

		distance: int
		push := true

		if symbol < 128 {
			distance = distances[0]
			push = false
		} else {
			if d.distance.remaining == 0 {
				switch_block(z, d, &d.distance)
			}

			d.distance.remaining -= 1

			slot := 3 if copy_length > 4 else copy_length - 2
			tree := int(d.distance_map[d.distance.current * 4 + slot])
			code := int(read_symbol(z, d, tables[distance_base + tree * LARGE_TABLE_SIZE:][:LARGE_TABLE_SIZE]))

			switch {
			case code == 0:
				distance = distances[0]
				push = false
			case code < 4:
				distance = distances[code]
			case code < 10:
				step := (code - 4) >> 1 + 1
				distance = distances[0] + (step if code & 1 == 1 else -step)
			case code < 16:
				step := (code - 10) >> 1 + 1
				distance = distances[1] + (step if code & 1 == 1 else -step)
			case code < 16 + direct:
				distance = code - 15
			case:
				value := code - direct - 16
				extra_bits := u8(1 + value >> (postfix + 1))
				high := value >> postfix
				low := value & postfix_mask
				offset := (2 + high & 1) << extra_bits - 4
				distance = (offset + int(read_bits(z, d, extra_bits))) << postfix + low + direct + 1
			}

			if distance <= 0 {
				return E_Brotli.Invalid_Distance
			}
		}

		reach := min(position, window_max)

		if distance > reach {
			if copy_length < DICTIONARY_WORD_MIN || copy_length > DICTIONARY_WORD_MAX {
				return E_Brotli.Invalid_Dictionary_Reference
			}

			size_bits := uint(DICTIONARY_SIZE_BITS[copy_length])
			word_id := distance - reach - 1
			transform := word_id >> size_bits
			index := word_id & (1 << size_bits - 1)

			if transform >= TRANSFORM_COUNT {
				return E_Brotli.Invalid_Dictionary_Reference
			}

			start := dictionary_offsets[copy_length] + index * copy_length
			word: [TRANSFORMED_WORD_MAX]u8
			produced := transform_word(word[:], DICTIONARY[start:][:copy_length], TRANSFORMS[transform])

			if produced > remaining {
				return E_Brotli.Invalid_Dictionary_Reference
			}

			copy(out[position:], word[:produced])
			position += produced
			remaining -= produced

			continue
		}

		if push {
			distances[3] = distances[2]
			distances[2] = distances[1]
			distances[1] = distances[0]
			distances[0] = distance
		}

		if copy_length > remaining {
			return E_Brotli.Invalid_Command
		}

		if distance >= copy_length {
			copy(out[position:][:copy_length], out[position - distance:][:copy_length])
		} else {
			for index in 0 ..< copy_length {
				out[position + index] = out[position + index - distance]
			}
		}

		position += copy_length
		remaining -= copy_length
	}

	if d.short {
		return E_General.Stream_Too_Short
	}

	return nil
}

// Longest transform prefix and suffix are 5 and 8 bytes.
TRANSFORMED_WORD_MAX :: DICTIONARY_WORD_MAX + 16

// Writes `transform` applied to `word` into `out`; returns its length.
transform_word :: proc(out: []u8, word: []u8, transform: Transform) -> int {
	size := copy(out, transform.prefix)
	body := word
	kind := int(transform.kind)

	switch {
	case kind >= int(Transform_Kind.Omit_First_1) && kind <= int(Transform_Kind.Omit_First_9):
		body = body[min(kind - int(Transform_Kind.Omit_First_1) + 1, len(body)):]
	case kind >= int(Transform_Kind.Omit_Last_1) && kind <= int(Transform_Kind.Omit_Last_9):
		body = body[:max(len(body) - kind, 0)]
	}

	start := size
	size += copy(out[size:], body)

	switch Transform_Kind(kind) {
	case .Uppercase_First:
		uppercase(out[start:size])
	case .Uppercase_All:
		for at := start; at < size; {
			at += uppercase(out[at:size])
		}
	case .Identity, .Omit_Last_1, .Omit_Last_9, .Omit_First_1, .Omit_First_9:
	}

	size += copy(out[size:], transform.suffix)

	return size
}

// RFC 7932 "uppercase": flips one UTF-8 scalar and reports its byte length.
uppercase :: proc(text: []u8) -> int {
	if len(text) == 0 {
		return 1
	}

	if text[0] < 0xc0 {
		if text[0] >= 'a' && text[0] <= 'z' {
			text[0] ~= 32
		}

		return 1
	}

	if text[0] < 0xe0 {
		if len(text) > 1 {
			text[1] ~= 32
		}

		return 2
	}

	if len(text) > 2 {
		text[2] ~= 5
	}

	return 3
}
