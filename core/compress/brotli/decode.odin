package compress_brotli

import "base:runtime"
import "core:math/bits"

// Brotli (RFC 7932) decoder for a complete stream held in memory.

Decode_Error :: enum {
	None = 0,
	Truncated_Input,
	Invalid_Window,
	Invalid_Meta_Block,
	Invalid_Prefix_Code,
	Invalid_Context_Map,
	Invalid_Block_Switch,
	Invalid_Command,
	Invalid_Distance,
	Invalid_Dictionary_Reference,
	Output_Limit_Exceeded,
}

Error :: union #shared_nil {
	Decode_Error,
	runtime.Allocator_Error,
}

DECODE_OUTPUT_MAX_DEFAULT :: 1 << 30

DICTIONARY := #load("dictionary.bin")

DICTIONARY_SIZE_BITS := [25]u8{0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5}

DICTIONARY_WORD_MIN :: 4
DICTIONARY_WORD_MAX :: 24

INSERT_BASE := [24]u32 {
	0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594,
}

INSERT_EXTRA := [24]u8{0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24}

COPY_BASE := [24]u32 {
	2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
}

COPY_EXTRA := [24]u8{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24}

BLOCK_COUNT_BASE := [26]u32 {
	1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433,
	16625,
}

BLOCK_COUNT_EXTRA := [26]u8{2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24}

// Insert and copy code bases for each of the 11 cells of the command alphabet.
COMMAND_INSERT_CELL := [11]u8{0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16}
COMMAND_COPY_CELL := [11]u8{0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16}

CODE_LENGTH_ORDER := [18]u8{1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15}

LITERAL_ALPHABET :: 256
COMMAND_ALPHABET :: 704
BLOCK_COUNT_ALPHABET :: 26
ALPHABET_MAX :: 704
CODE_LENGTH_MAX :: 15
ROOT_BITS :: 8

// ------------------------------------------------------------------ bit input

Bit_Reader :: struct {
	src:         []u8,
	position:    int,
	accumulator: u64,
	count:       uint,
	// Zero bytes supplied past the end; consuming any of them is truncation.
	padding:     int,
}

@(private)
refill :: #force_inline proc(r: ^Bit_Reader) {
	for r.count <= 56 {
		if r.position < len(r.src) {
			r.accumulator |= u64(r.src[r.position]) << r.count
			r.position += 1
		} else {
			r.padding += 1
		}

		r.count += 8
	}
}

@(private)
read_bits :: #force_inline proc(r: ^Bit_Reader, count: uint) -> u32 {
	if count == 0 {
		return 0
	}

	refill(r)
	value := u32(r.accumulator & (u64(1) << count - 1))
	r.accumulator >>= count
	r.count -= count

	return value
}

@(private)
truncated :: proc(r: ^Bit_Reader) -> bool {
	return int(r.count) < r.padding * 8
}

@(private)
align_to_byte :: proc(r: ^Bit_Reader) -> bool {
	discard := r.count & 7

	return read_bits(r, discard) == 0
}

// --------------------------------------------------------------- prefix codes

Prefix_Code :: struct {
	// (length << 16 | symbol) for codes of at most ROOT_BITS bits; 0 otherwise.
	root:    [1 << ROOT_BITS]u32,
	counts:  [CODE_LENGTH_MAX + 1]u16,
	symbols: [ALPHABET_MAX]u16,
	single:  bool,
	only:    u16,
}

// Builds the decoding tables for canonical code `lengths`; false if they do
// not describe a complete prefix code.
@(private)
code_build :: proc(code: ^Prefix_Code, lengths: []u8) -> bool {
	code.counts = {}
	code.single = false
	used := 0

	for length, symbol in lengths {
		if length != 0 {
			code.counts[length] += 1
			code.only = u16(symbol)
			used += 1
		}
	}

	if used == 0 {
		return false
	}

	if used == 1 {
		code.single = true
		return true
	}

	space := 1 << CODE_LENGTH_MAX
	offsets: [CODE_LENGTH_MAX + 2]int

	for length in 1 ..= CODE_LENGTH_MAX {
		space -= int(code.counts[length]) << uint(CODE_LENGTH_MAX - length)
		offsets[length + 1] = offsets[length] + int(code.counts[length])
	}

	if space != 0 {
		return false
	}

	for length, symbol in lengths {
		if length != 0 {
			code.symbols[offsets[length]] = u16(symbol)
			offsets[length] += 1
		}
	}

	code.root = {}
	value: u32
	index := 0

	for length in 1 ..= ROOT_BITS {
		for _ in 0 ..< code.counts[length] {
			reversed := bits.reverse_bits(value) >> (32 - u32(length))
			entry := u32(length) << 16 | u32(code.symbols[index])

			for slot := reversed; slot < 1 << ROOT_BITS; slot += 1 << u32(length) {
				code.root[slot] = entry
			}

			value += 1
			index += 1
		}

		value <<= 1
	}

	return true
}

@(private)
code_read :: #force_inline proc(r: ^Bit_Reader, code: ^Prefix_Code) -> u32 {
	if code.single {
		return u32(code.only)
	}

	refill(r)
	entry := code.root[r.accumulator & (1 << ROOT_BITS - 1)]

	if entry != 0 {
		length := uint(entry >> 16)
		r.accumulator >>= length
		r.count -= length

		return entry & 0xffff
	}

	return code_read_long(r, code)
}

// Canonical decoding one bit at a time, for codes longer than ROOT_BITS.
@(private)
code_read_long :: proc(r: ^Bit_Reader, code: ^Prefix_Code) -> u32 {
	value, first, index: int

	for length in 1 ..= CODE_LENGTH_MAX {
		value |= int(r.accumulator & 1)
		r.accumulator >>= 1
		r.count -= 1
		count := int(code.counts[length])

		if value - count < first {
			return u32(code.symbols[index + value - first])
		}

		index += count
		first += count
		first <<= 1
		value <<= 1
	}

	return 0
}

@(private)
read_prefix_code :: proc(r: ^Bit_Reader, code: ^Prefix_Code, alphabet: int) -> Decode_Error {
	lengths: [ALPHABET_MAX]u8
	skip := int(read_bits(r, 2))

	if skip == 1 {
		return read_simple_code(r, code, alphabet, lengths[:alphabet])
	}

	// Lengths of the code that encodes the symbol lengths.
	meta_lengths: [18]u8
	space := 32
	used := 0

	for index := skip; index < 18 && space > 0; index += 1 {
		refill(r)
		peek := r.accumulator & 15
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

		r.accumulator >>= width
		r.count -= uint(width)
		meta_lengths[CODE_LENGTH_ORDER[index]] = length

		if length != 0 {
			space -= 32 >> length
			used += 1
		}
	}

	if used != 1 && space != 0 {
		return Decode_Error.Invalid_Prefix_Code
	}

	meta := Prefix_Code{}

	if !code_build_partial(&meta, meta_lengths[:], used) {
		return Decode_Error.Invalid_Prefix_Code
	}

	symbol := 0
	previous: u8 = 8
	repeat := 0
	repeat_length: u8
	room := 32768

	for symbol < alphabet && room > 0 {
		value := u8(code_read(r, &meta))

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

		extra: uint = 2 if value == 16 else 3
		fill: u8 = previous if value == 16 else 0

		if repeat_length != fill {
			repeat = 0
			repeat_length = fill
		}

		before := repeat

		if repeat > 0 {
			repeat = (repeat - 2) << extra
		}

		repeat += int(read_bits(r, extra)) + 3
		delta := repeat - before

		if symbol + delta > alphabet {
			return Decode_Error.Invalid_Prefix_Code
		}

		for _ in 0 ..< delta {
			lengths[symbol] = fill
			symbol += 1
		}

		if fill != 0 {
			room -= delta << (15 - fill)
		}
	}

	if room != 0 {
		return Decode_Error.Invalid_Prefix_Code
	}

	if !code_build(code, lengths[:alphabet]) {
		return Decode_Error.Invalid_Prefix_Code
	}

	return .None
}

// The code-length code may consist of a single symbol; its Kraft sum was
// checked by the caller.
@(private)
code_build_partial :: proc(code: ^Prefix_Code, lengths: []u8, used: int) -> bool {
	if used == 1 {
		for length, symbol in lengths {
			if length != 0 {
				code.single = true
				code.only = u16(symbol)
			}
		}

		return true
	}

	// Scale 5-bit lengths so the shared completeness check applies.
	return code_build(code, lengths)
}

@(private)
read_simple_code :: proc(r: ^Bit_Reader, code: ^Prefix_Code, alphabet: int, lengths: []u8) -> Decode_Error {
	count := int(read_bits(r, 2)) + 1
	width := uint(bits.len_u32(u32(alphabet - 1)))
	symbols: [4]int

	for index in 0 ..< count {
		symbols[index] = int(read_bits(r, width))

		if symbols[index] >= alphabet {
			return Decode_Error.Invalid_Prefix_Code
		}

		for other in 0 ..< index {
			if symbols[other] == symbols[index] {
				return Decode_Error.Invalid_Prefix_Code
			}
		}
	}

	switch count {
	case 1:
		lengths[symbols[0]] = 1
	case 2:
		lengths[symbols[0]] = 1
		lengths[symbols[1]] = 1
	case 3:
		lengths[symbols[0]] = 1
		lengths[symbols[1]] = 2
		lengths[symbols[2]] = 2
	case 4:
		if read_bits(r, 1) == 0 {
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

	if !code_build(code, lengths) {
		return Decode_Error.Invalid_Prefix_Code
	}

	return .None
}

// ---------------------------------------------------------------- block types

Block_State :: struct {
	type_count: int,
	type_code:  Prefix_Code,
	count_code: Prefix_Code,
	current:    int,
	previous:   int,
	remaining:  int,
}

@(private)
read_variable_byte :: proc(r: ^Bit_Reader) -> int {
	if read_bits(r, 1) == 0 {
		return 0
	}

	width := uint(read_bits(r, 3))

	if width == 0 {
		return 1
	}

	return 1 << width + int(read_bits(r, width))
}

@(private)
read_block_count :: proc(r: ^Bit_Reader, code: ^Prefix_Code) -> int {
	symbol := code_read(r, code)

	return int(BLOCK_COUNT_BASE[symbol] + read_bits(r, uint(BLOCK_COUNT_EXTRA[symbol])))
}

@(private)
read_block_state :: proc(r: ^Bit_Reader, state: ^Block_State) -> Decode_Error {
	state.type_count = read_variable_byte(r) + 1
	state.current = 0
	state.previous = 1
	state.remaining = 1 << 24

	if state.type_count < 2 {
		return .None
	}

	if err := read_prefix_code(r, &state.type_code, state.type_count + 2); err != .None {
		return err
	}

	if err := read_prefix_code(r, &state.count_code, BLOCK_COUNT_ALPHABET); err != .None {
		return err
	}

	state.remaining = read_block_count(r, &state.count_code)

	return .None
}

@(private)
switch_block :: proc(r: ^Bit_Reader, state: ^Block_State) -> bool {
	if state.type_count < 2 {
		return false
	}

	symbol := int(code_read(r, &state.type_code))
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
	state.remaining = read_block_count(r, &state.count_code)

	return true
}

@(private)
read_context_map :: proc(r: ^Bit_Reader, values: []u8, scratch: ^Prefix_Code) -> (trees: int, err: Decode_Error) {
	trees = read_variable_byte(r) + 1

	for &value in values {
		value = 0
	}

	if trees < 2 {
		return trees, .None
	}

	run_max := 0

	if read_bits(r, 1) == 1 {
		run_max = int(read_bits(r, 4)) + 1
	}

	if code_error := read_prefix_code(r, scratch, trees + run_max); code_error != .None {
		return trees, code_error
	}

	for index := 0; index < len(values); {
		symbol := int(code_read(r, scratch))

		switch {
		case symbol == 0:
			index += 1
		case symbol <= run_max:
			run := 1 << uint(symbol) + int(read_bits(r, uint(symbol)))

			if index + run > len(values) {
				return trees, .Invalid_Context_Map
			}

			index += run
		case:
			values[index] = u8(symbol - run_max)
			index += 1
		}

		if truncated(r) {
			return trees, .Truncated_Input
		}
	}

	if read_bits(r, 1) == 1 {
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

	return trees, .None
}

// --------------------------------------------------------------------- decode

Decoder :: struct {
	reader:        Bit_Reader,
	literal:       Block_State,
	command:       Block_State,
	distance:      Block_State,
	scratch:       Prefix_Code,
	context_modes: [256]u8,
	literal_map:   [256 * 64]u8,
	distance_map:  [256 * 4]u8,
	codes:         [dynamic]Prefix_Code,
}

// Decodes a complete Brotli stream. `output_max` bounds the decoded size.
decode :: proc(
	src: []u8,
	allocator := context.allocator,
	output_max := DECODE_OUTPUT_MAX_DEFAULT,
) -> (
	output: []u8,
	err: Error,
) {
	d := new(Decoder, allocator) or_return
	defer free(d, allocator)

	d.codes = make([dynamic]Prefix_Code, allocator) or_return
	defer delete(d.codes)

	out := make([dynamic]u8, 0, max(len(src) * 4, 64), allocator) or_return

	decode_error := decode_stream(d, src, &out, output_max)

	if decode_error != nil {
		delete(out)
		return nil, decode_error
	}

	shrink(&out)

	return out[:], nil
}

@(private)
decode_stream :: proc(d: ^Decoder, src: []u8, out: ^[dynamic]u8, output_max: int) -> Error {
	r := &d.reader
	r^ = {
		src = src,
	}

	window_bits := 16

	if read_bits(r, 1) == 1 {
		wide := int(read_bits(r, 3))

		if wide != 0 {
			window_bits = 17 + wide
		} else {
			narrow := int(read_bits(r, 3))

			switch narrow {
			case 0:
				window_bits = 17
			case 1:
				return Decode_Error.Invalid_Window
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

	for {
		last := read_bits(r, 1) == 1

		if last && read_bits(r, 1) == 1 {
			break
		}

		nibbles := int(read_bits(r, 2))

		if nibbles == 3 {
			// Metadata block: skipped bytes carry no output.
			if read_bits(r, 1) != 0 {
				return Decode_Error.Invalid_Meta_Block
			}

			skip_bytes := uint(read_bits(r, 2))
			skip := 0

			if skip_bytes > 0 {
				skip = int(read_bits(r, 8 * skip_bytes)) + 1

				if skip_bytes > 1 && skip - 1 < 1 << (8 * (skip_bytes - 1)) {
					return Decode_Error.Invalid_Meta_Block
				}
			}

			if !align_to_byte(r) {
				return Decode_Error.Invalid_Meta_Block
			}

			for _ in 0 ..< skip {
				read_bits(r, 8)
			}

			if truncated(r) {
				return Decode_Error.Truncated_Input
			}

			if last {
				break
			}

			continue
		}

		nibbles += 4
		length := 0

		for index in 0 ..< nibbles {
			nibble := int(read_bits(r, 4))

			if index == nibbles - 1 && nibbles > 4 && nibble == 0 {
				return Decode_Error.Invalid_Meta_Block
			}

			length |= nibble << uint(4 * index)
		}

		length += 1

		if len(out) + length > output_max {
			return Decode_Error.Output_Limit_Exceeded
		}

		if !last && read_bits(r, 1) == 1 {
			if !align_to_byte(r) {
				return Decode_Error.Invalid_Meta_Block
			}

			for _ in 0 ..< length {
				append(out, u8(read_bits(r, 8))) or_return
			}

			if truncated(r) {
				return Decode_Error.Truncated_Input
			}

			continue
		}

		decode_meta_block(d, out, length, window_max, &distances, dictionary_offsets[:]) or_return

		if truncated(r) {
			return Decode_Error.Truncated_Input
		}

		if last {
			break
		}
	}

	if truncated(r) {
		return Decode_Error.Truncated_Input
	}

	return nil
}

@(private)
decode_meta_block :: proc(
	d: ^Decoder,
	out: ^[dynamic]u8,
	length, window_max: int,
	distances: ^[4]int,
	dictionary_offsets: []int,
) -> Error {
	r := &d.reader

	if err := read_block_state(r, &d.literal); err != .None {
		return err
	}

	if err := read_block_state(r, &d.command); err != .None {
		return err
	}

	if err := read_block_state(r, &d.distance); err != .None {
		return err
	}

	postfix := uint(read_bits(r, 2))
	direct := int(read_bits(r, 4)) << postfix

	for index in 0 ..< d.literal.type_count {
		d.context_modes[index] = u8(read_bits(r, 2))
	}

	literal_trees, literal_error := read_context_map(r, d.literal_map[:d.literal.type_count * 64], &d.scratch)

	if literal_error != .None {
		return literal_error
	}

	distance_trees, distance_error := read_context_map(r, d.distance_map[:d.distance.type_count * 4], &d.scratch)

	if distance_error != .None {
		return distance_error
	}

	command_trees := d.command.type_count
	resize(&d.codes, literal_trees + command_trees + distance_trees) or_return

	literal_codes := d.codes[:literal_trees]
	command_codes := d.codes[literal_trees:][:command_trees]
	distance_codes := d.codes[literal_trees + command_trees:]
	distance_alphabet := 16 + direct + 48 << postfix

	for &code in literal_codes {
		if err := read_prefix_code(r, &code, LITERAL_ALPHABET); err != .None {
			return err
		}
	}

	for &code in command_codes {
		if err := read_prefix_code(r, &code, COMMAND_ALPHABET); err != .None {
			return err
		}
	}

	for &code in distance_codes {
		if err := read_prefix_code(r, &code, distance_alphabet); err != .None {
			return err
		}
	}

	if truncated(r) {
		return Decode_Error.Truncated_Input
	}

	remaining := length
	postfix_mask := int(1) << postfix - 1

	for remaining > 0 {
		if truncated(r) {
			return Decode_Error.Truncated_Input
		}

		if d.command.remaining == 0 {
			switch_block(r, &d.command)
		}

		d.command.remaining -= 1

		symbol := int(code_read(r, &command_codes[d.command.current]))
		cell := symbol >> 6
		insert_code := int(COMMAND_INSERT_CELL[cell]) + symbol >> 3 & 7
		copy_code := int(COMMAND_COPY_CELL[cell]) + symbol & 7
		insert_length := int(INSERT_BASE[insert_code] + read_bits(r, uint(INSERT_EXTRA[insert_code])))
		copy_length := int(COPY_BASE[copy_code] + read_bits(r, uint(COPY_EXTRA[copy_code])))

		if insert_length > remaining {
			return Decode_Error.Invalid_Command
		}

		for _ in 0 ..< insert_length {
			if d.literal.remaining == 0 {
				switch_block(r, &d.literal)
			}

			d.literal.remaining -= 1

			size := len(out)
			p1: int = int(out[size - 1]) if size > 0 else 0
			p2: int = int(out[size - 2]) if size > 1 else 0
			mode := int(d.context_modes[d.literal.current]) * 512
			id := CONTEXT_LOOKUP[mode + p1] | CONTEXT_LOOKUP[mode + 256 + p2]
			tree := d.literal_map[d.literal.current * 64 + int(id)]

			append(out, u8(code_read(r, &literal_codes[tree]))) or_return
		}

		remaining -= insert_length

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
				switch_block(r, &d.distance)
			}

			d.distance.remaining -= 1

			slot := 3 if copy_length > 4 else copy_length - 2
			tree := d.distance_map[d.distance.current * 4 + slot]
			code := int(code_read(r, &distance_codes[tree]))

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
				extra_bits := uint(1 + value >> (postfix + 1))
				high := value >> postfix
				low := value & postfix_mask
				offset := (2 + high & 1) << extra_bits - 4
				distance = (offset + int(read_bits(r, extra_bits))) << postfix + low + direct + 1
			}

			if distance <= 0 {
				return Decode_Error.Invalid_Distance
			}
		}

		position := len(out)
		reach := min(position, window_max)

		if distance > reach {
			if copy_length < DICTIONARY_WORD_MIN || copy_length > DICTIONARY_WORD_MAX {
				return Decode_Error.Invalid_Dictionary_Reference
			}

			size_bits := uint(DICTIONARY_SIZE_BITS[copy_length])
			word_id := distance - reach - 1
			transform := word_id >> size_bits
			index := word_id & (1 << size_bits - 1)

			if transform >= TRANSFORM_COUNT {
				return Decode_Error.Invalid_Dictionary_Reference
			}

			start := dictionary_offsets[copy_length] + index * copy_length
			before := len(out)
			append_transformed(out, DICTIONARY[start:][:copy_length], TRANSFORMS[transform]) or_return
			produced := len(out) - before

			if produced > remaining {
				return Decode_Error.Invalid_Dictionary_Reference
			}

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
			return Decode_Error.Invalid_Command
		}

		resize(out, position + copy_length) or_return

		for index in 0 ..< copy_length {
			out[position + index] = out[position + index - distance]
		}

		remaining -= copy_length
	}

	return nil
}

@(private)
append_transformed :: proc(out: ^[dynamic]u8, word: []u8, transform: Transform) -> runtime.Allocator_Error {
	append(out, transform.prefix) or_return

	body := word
	kind := int(transform.kind)

	switch {
	case kind >= int(Transform_Kind.Omit_First_1) && kind <= int(Transform_Kind.Omit_First_9):
		body = body[min(kind - int(Transform_Kind.Omit_First_1) + 1, len(body)):]
	case kind >= int(Transform_Kind.Omit_Last_1) && kind <= int(Transform_Kind.Omit_Last_9):
		body = body[:max(len(body) - kind, 0)]
	}

	start := len(out)
	append(out, ..body) or_return

	switch Transform_Kind(kind) {
	case .Uppercase_First:
		uppercase(out[start:])
	case .Uppercase_All:
		for at := start; at < len(out); {
			at += uppercase(out[at:])
		}
	case .Identity, .Omit_Last_1, .Omit_Last_9, .Omit_First_1, .Omit_First_9:
	}

	append(out, transform.suffix) or_return

	return nil
}

// RFC 7932 "uppercase": flips one UTF-8 scalar and reports its byte length.
@(private)
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
