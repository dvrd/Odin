package compress_brotli

/*
	Bounded incremental Brotli (RFC 7932) decoder with the same contract as
	`core:compress/gzip` and `core:compress/zlib`: caller-partitioned input and
	output, an explicit work budget per step, byte limits and terminal errors.

	The decoder pulls an input byte only when the bits of the item being parsed
	are not yet available, so it never consumes a byte beyond the end of the
	stream. Bytes after the stream are `Trailing_Data`.
*/

import "core:compress"
import "core:math/bits"

// Smallest history a valid stream can declare: WBITS 10 keeps (1 << 10) - 16 bytes.
DECODER_WINDOW_MIN :: 1008

// History a stream with the largest regular WBITS (24) needs.
DECODER_WINDOW_MAX :: 1 << 24 - 16

Decoder_Phase :: enum u8 {
	Uninitialized,
	Failed,
	End,
	Window_1,
	Window_2,
	Window_3,
	Header_Last,
	Header_Last_Empty,
	Header_Nibbles,
	Header_Length,
	Header_Uncompressed,
	Metadata_Reserved,
	Metadata_Size_Bytes,
	Metadata_Length,
	Metadata_Align,
	Metadata_Skip,
	Stored_Align,
	Stored_Copy,
	Var_Flag,
	Var_Width,
	Var_Extra,
	Block_Types_Start,
	Block_Types_Done,
	Block_Count_Code,
	Block_First_Count,
	Count_Symbol,
	Count_Extra,
	Category_Next,
	Distance_Params,
	Context_Modes,
	Literal_Trees_Start,
	Literal_Trees_Done,
	Distance_Trees_Start,
	Distance_Trees_Done,
	Map_Start,
	Map_Rle_Flag,
	Map_Rle_Bits,
	Map_Symbol,
	Map_Run,
	Map_Imtf_Flag,
	Map_Imtf,
	Tables_Alloc,
	Tree_Next,
	Tree_Advance,
	Code_Kind,
	Simple_Count,
	Simple_Symbol,
	Simple_Shape,
	Simple_Build,
	Meta_Length,
	Meta_Build,
	Lengths_Symbol,
	Lengths_Repeat,
	Code_Finish,
	Switch_Type,
	Command,
	Insert_Extra,
	Copy_Extra,
	Literal,
	After_Insert,
	Distance_Symbol,
	Distance_Extra,
	Copy_Prepare,
	Copy,
	Dictionary,
	Block_End,
	Final_Padding,
}

Code_Target :: enum u8 {
	Block_Type,
	Block_Count,
	Scratch,
	Heap,
}

// The decoder borrows `window` for its whole life and owns `tables`, which
// grows to at most 2.9 MiB (prefix codes of one meta-block) from the allocator
// given to decoder_init. It retains no input or output slice. Call
// decoder_destroy to release the tables.
Decoder :: struct {
	window:                    []u8,
	tables:                    [dynamic]Entry,
	max_encoded_bytes:         u64,
	max_decoded_bytes:         u64,
	encoded_bytes:             u64,
	decoded_bytes:             u64,
	phase:                     Decoder_Phase,
	error:                     compress.Decode_Error,
	final_declared:            bool,
	bits:                      u64,
	bit_count:                 u8,
	window_at:                 int,
	window_max:                int,

	// Meta-block.
	last:                      bool,
	nibbles:                   int,
	length:                    int,
	mb_remaining:              int,
	skip_remaining:            int,

	// Variable-length integers and block counts.
	var_next:                  Decoder_Phase,
	var_width:                 u8,
	var_value:                 int,
	category:                  int,
	count_after:               Decoder_Phase,
	count_symbol:              int,
	switch_after:              Decoder_Phase,

	blocks:                    [3]Block_State,
	postfix:                   u8,
	direct:                    int,
	context_modes:             [256]u8,
	literal_map:               [256 * 64]u8,
	distance_map:              [256 * 4]u8,
	literal_trees:             int,
	command_trees:             int,
	distance_trees:            int,
	command_base:              int,
	distance_base:             int,
	index:                     int,

	// Context maps.
	map_distance:              bool,
	map_trees:                 int,
	map_length:                int,
	map_run_max:               int,
	map_index:                 int,
	map_symbol:                int,
	map_after:                 Decoder_Phase,
	imtf:                      [256]u8,

	// Tree sequence of a meta-block.
	tree_kind:                 int,
	tree_index:                int,

	// Prefix code under construction.
	code_target:               Code_Target,
	code_offset:               int,
	code_size:                 int,
	code_alphabet:             int,
	code_after:                Decoder_Phase,
	code_index:                int,
	code_space:                int,
	code_used:                 int,
	code_symbol:               int,
	code_previous:             u8,
	code_repeat:               int,
	code_repeat_length:        u8,
	code_repeat_symbol:        int,
	code_room:                 int,
	code_select:               bool,
	simple_count:              int,
	simple_width:              u8,
	simple_symbols:            [4]int,
	lengths:                   [ALPHABET_MAX]u8,
	meta_lengths:              [18]u8,
	meta:                      [1 << ROOT_BITS]Entry,
	scratch:                   [SMALL_TABLE_SIZE]Entry,

	// Commands.
	cmd_symbol:                int,
	insert_length:             int,
	copy_length:               int,
	distance:                  int,
	push:                      bool,
	distances:                 [4]int,
	distance_bits:             u8,
	distance_offset:           int,
	distance_low:              int,
	copy_remaining:            int,
	word:                      [TRANSFORMED_WORD_MAX]u8,
	word_length:               int,
	word_at:                   int,
}

// Fails with Invalid_Config when `window` is shorter than DECODER_WINDOW_MIN.
// A stream whose WBITS needs more than len(window) - 15 bytes of history ends
// with Invalid_Config in decoder_step. Reinitializing keeps the table storage
// (and its allocator) of an initialized decoder.
decoder_init :: proc(
	d: ^Decoder,
	window: []u8,
	max_encoded_bytes, max_decoded_bytes: u64,
	allocator := context.allocator,
) -> compress.Decode_Error {
	if d == nil {
		return .Invalid_State
	}

	if len(window) < DECODER_WINDOW_MIN {
		return .Invalid_Config
	}

	tables := d.tables

	if tables.allocator.procedure == nil {
		tables.allocator = allocator
	}

	clear(&tables)

	d^ = Decoder {
		window            = window,
		tables            = tables,
		max_encoded_bytes = max_encoded_bytes,
		max_decoded_bytes = max_decoded_bytes,
		phase             = .Window_1,
		distances         = {4, 11, 15, 16},
	}

	return .None
}

decoder_destroy :: proc(d: ^Decoder) {
	if d == nil {
		return
	}

	delete(d.tables)
	d^ = {}
}

@(private = "file")
pull_byte :: proc(d: ^Decoder, input: []u8, r: ^compress.Decode_Result) -> bool {
	if r.consumed == len(input) {
		return false
	}

	if d.encoded_bytes == d.max_encoded_bytes {
		r.err = .Encoded_Limit
		return false
	}

	d.bits |= u64(input[r.consumed]) << d.bit_count
	d.bit_count += 8
	r.consumed += 1
	d.encoded_bytes += 1

	return true
}

@(private = "file")
take_bits :: proc(d: ^Decoder, input: []u8, r: ^compress.Decode_Result, width: u8) -> (u32, bool) {
	for d.bit_count < width {
		if !pull_byte(d, input, r) {
			return 0, false
		}
	}

	value := u32(d.bits & (u64(1) << width - 1))
	d.bits >>= width
	d.bit_count -= width

	return value, true
}

// A code is decoded from the bits already held; one more byte is pulled only
// when the entry found with zero-extended bits is longer than what is held.
@(private = "file")
take_symbol :: proc(d: ^Decoder, input: []u8, r: ^compress.Decode_Result, table: []Entry) -> (u32, bool) {
	for {
		entry := table[d.bits & (1 << ROOT_BITS - 1)]
		used := entry.bits

		if entry.bits > ROOT_BITS {
			index := (d.bits >> ROOT_BITS) & (u64(1) << (entry.bits - ROOT_BITS) - 1)
			entry = table[int(entry.value) + int(index)]
			used = ROOT_BITS + entry.bits
		}

		if used <= d.bit_count {
			d.bits >>= used
			d.bit_count -= used

			return u32(entry.value), true
		}

		if !pull_byte(d, input, r) {
			return 0, false
		}
	}
}

// Decoded bytes of the stream, oldest first, fall out of the ring at `len(window)`.
@(private = "file")
window_push :: proc(d: ^Decoder, value: u8) {
	d.window[d.window_at] = value
	d.window_at += 1

	if d.window_at == len(d.window) {
		d.window_at = 0
	}
}

@(private = "file")
window_back :: proc(d: ^Decoder, back: int) -> u8 {
	at := d.window_at - back

	if at < 0 {
		at += len(d.window)
	}

	return d.window[at]
}

@(private = "file")
emit :: proc(d: ^Decoder, output: []u8, r: ^compress.Decode_Result, value: u8) {
	output[r.produced] = value
	r.produced += 1
	d.decoded_bytes += 1
	window_push(d, value)
}

// Bytes that may be emitted now; 0 with r.err set at the decoded limit, or
// with Need_Output when only the destination is full.
@(private = "file")
output_room :: proc(d: ^Decoder, output: []u8, r: ^compress.Decode_Result) -> int {
	if d.decoded_bytes == d.max_decoded_bytes {
		r.err = .Decoded_Limit
		return 0
	}

	room := len(output) - r.produced

	if room == 0 {
		r.status = .Need_Output
		return 0
	}

	return int(min(u64(room), d.max_decoded_bytes - d.decoded_bytes))
}

@(private = "file")
start_code :: proc(d: ^Decoder, target: Code_Target, alphabet: int, after: Decoder_Phase, offset := 0, size := 0) {
	d.code_target = target
	d.code_alphabet = alphabet
	d.code_after = after
	d.code_offset = offset
	d.code_size = size
	d.lengths = {}
	d.phase = .Code_Kind
}

@(private = "file")
code_table :: proc(d: ^Decoder) -> []Entry {
	switch d.code_target {
	case .Block_Type:
		return d.blocks[d.category].type_table[:]
	case .Block_Count:
		return d.blocks[d.category].count_table[:]
	case .Scratch:
		return d.scratch[:]
	case .Heap:
		return d.tables[d.code_offset:][:d.code_size]
	}

	return nil
}

@(private = "file")
build_simple :: proc(d: ^Decoder) -> bool {
	table := code_table(d)
	symbols := d.simple_symbols
	lengths := d.lengths[:d.code_alphabet]

	switch d.simple_count {
	case 1:
		fill_table(table, symbols[0])
		return true
	case 2:
		lengths[symbols[0]] = 1
		lengths[symbols[1]] = 1
	case 3:
		lengths[symbols[0]] = 1
		lengths[symbols[1]] = 2
		lengths[symbols[2]] = 2
	case 4:
		if !d.code_select {
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

	return build_table(table, lengths)
}

// Length and width of the code-length code symbol that starts `peek`.
@(private = "file")
meta_code :: proc(peek: u64) -> (length, width: u8) {
	switch {
	case peek & 3 == 0:
		return 0, 2
	case peek & 3 == 1:
		return 4, 2
	case peek & 3 == 2:
		return 3, 2
	case peek & 7 == 3:
		return 2, 3
	case peek == 7:
		return 1, 4
	}

	return 5, 4
}

// Starts a switch of block type of `category`; one block type never switches.
@(private = "file")
start_switch :: proc(d: ^Decoder, category: int, after: Decoder_Phase) {
	state := &d.blocks[category]

	if state.type_count < 2 {
		state.remaining = 1 << 28
		return
	}

	d.category = category
	d.switch_after = after
	d.phase = .Switch_Type
}

@(private = "file")
map_values :: proc(d: ^Decoder) -> []u8 {
	if d.map_distance {
		return d.distance_map[:d.map_length]
	}

	return d.literal_map[:d.map_length]
}

@(private = "file")
dictionary_offset :: proc(length: int) -> int {
	offset := 0

	for size in DICTIONARY_WORD_MIN ..< length {
		offset += size << DICTIONARY_SIZE_BITS[size]
	}

	return offset
}

// Applies distance code `code`; true when extra bits must still be read.
@(private = "file")
apply_distance_code :: proc(d: ^Decoder, code: int) -> bool {
	d.push = true

	switch {
	case code == 0:
		d.distance = d.distances[0]
		d.push = false
	case code < 4:
		d.distance = d.distances[code]
	case code < 10:
		step := (code - 4) >> 1 + 1
		d.distance = d.distances[0] + (step if code & 1 == 1 else -step)
	case code < 16:
		step := (code - 10) >> 1 + 1
		d.distance = d.distances[1] + (step if code & 1 == 1 else -step)
	case code < 16 + d.direct:
		d.distance = code - 15
	case:
		value := code - d.direct - 16
		d.distance_bits = u8(1 + value >> (d.postfix + 1))
		high := value >> d.postfix
		d.distance_low = value & (int(1) << d.postfix - 1)
		d.distance_offset = (2 + high & 1) << d.distance_bits - 4

		return true
	}

	return false
}

// Static dictionary reference: prepares the transformed word. False if invalid.
@(private = "file")
begin_dictionary :: proc(d: ^Decoder, reach: int) -> bool {
	if d.copy_length < DICTIONARY_WORD_MIN || d.copy_length > DICTIONARY_WORD_MAX {
		return false
	}

	size_bits := uint(DICTIONARY_SIZE_BITS[d.copy_length])
	word_id := d.distance - reach - 1
	transform := word_id >> size_bits
	index := word_id & (1 << size_bits - 1)

	if transform >= TRANSFORM_COUNT {
		return false
	}

	start := dictionary_offset(d.copy_length) + index * d.copy_length
	d.word_length = transform_word(d.word[:], DICTIONARY[start:][:d.copy_length], TRANSFORMS[transform])
	d.word_at = 0

	return d.word_length <= d.mb_remaining
}

@(private = "file")
finish_stream :: proc(d: ^Decoder, input: []u8, final_input: bool, r: ^compress.Decode_Result) {
	if r.consumed < len(input) {
		r.err = .Trailing_Data
		d.error = r.err
		d.phase = .Failed
	} else if final_input {
		r.status = .Done
	} else {
		r.status = .Need_Input
	}
}

// final_input declares the end of the complete encoded entity, not of this
// call's slice: keep it true when resubmitting the unconsumed suffix after
// Need_Output or a spent work budget. Once declared it cannot be withdrawn.
// Done needs final_input and an input without bytes after the stream; bytes
// after it (or non-zero padding in its last byte) fail with Trailing_Data or
// Malformed. A stream whose window does not fit fails with Invalid_Config.
// Errors are sticky until decoder_init; invalid arguments and overlapping
// buffers change nothing. Bytes produced before Done are provisional.
decoder_step :: proc(
	d: ^Decoder,
	input, output: []u8,
	final_input: bool,
	max_work := compress.DECODE_MAX_WORK,
) -> (
	r: compress.Decode_Result,
) {
	r.status = .Progress

	if d == nil || d.phase == .Uninitialized {
		r.err = .Invalid_State
		return
	}

	if max_work <= 0 || max_work > compress.DECODE_MAX_WORK {
		r.err = .Invalid_Config
		return
	}

	if compress.decode_buffers_overlap(input, output) ||
	   compress.decode_buffers_overlap(d.window, input) ||
	   compress.decode_buffers_overlap(d.window, output) {
		r.err = .Overlapping_Buffers
		return
	}

	if d.phase == .Failed {
		r.err = d.error
		return
	}

	if d.final_declared && !final_input {
		r.err = .Invalid_State
		return
	}

	d.final_declared = final_input

	if d.phase == .End {
		finish_stream(d, input, final_input, &r)
		return
	}

	for r.work < max_work {
		r.work += 1
		need_input := false
		budget := max_work - r.work + 1

		#partial switch d.phase {
		case .Window_1:
			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			if v == 0 {
				d.window_max = 1 << 16 - 16
				d.phase = .Header_Last
			} else {
				d.phase = .Window_2
			}
		case .Window_2:
			v, ok := take_bits(d, input, &r, 3)
			if !ok {
				need_input = true
				break
			}

			if v != 0 {
				d.window_max = 1 << uint(17 + v) - 16
				d.phase = .Header_Last
			} else {
				d.phase = .Window_3
			}
		case .Window_3:
			v, ok := take_bits(d, input, &r, 3)
			if !ok {
				need_input = true
				break
			}

			switch v {
			case 0:
				d.window_max = 1 << 17 - 16
			case 1:
				r.err = .Malformed
			case:
				d.window_max = 1 << uint(8 + v) - 16
			}

			d.phase = .Header_Last
		case .Header_Last:
			if d.window_max > len(d.window) {
				r.err = .Invalid_Config
				break
			}

			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			d.last = v == 1
			d.phase = .Header_Last_Empty if d.last else .Header_Nibbles
		case .Header_Last_Empty:
			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			d.phase = .Final_Padding if v == 1 else .Header_Nibbles
		case .Header_Nibbles:
			v, ok := take_bits(d, input, &r, 2)
			if !ok {
				need_input = true
				break
			}

			if v == 3 {
				d.phase = .Metadata_Reserved
			} else {
				d.nibbles = int(v) + 4
				d.phase = .Header_Length
			}
		case .Header_Length:
			v, ok := take_bits(d, input, &r, u8(4 * d.nibbles))
			if !ok {
				need_input = true
				break
			}

			if d.nibbles > 4 && v >> uint(4 * (d.nibbles - 1)) == 0 {
				r.err = .Malformed
				break
			}

			d.length = int(v) + 1

			if d.last {
				d.category = 0
				d.phase = .Block_Types_Start
			} else {
				d.phase = .Header_Uncompressed
			}
		case .Header_Uncompressed:
			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			if v == 1 {
				d.mb_remaining = d.length
				d.phase = .Stored_Align
			} else {
				d.category = 0
				d.phase = .Block_Types_Start
			}
		case .Metadata_Reserved:
			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			if v != 0 {
				r.err = .Malformed
				break
			}

			d.phase = .Metadata_Size_Bytes
		case .Metadata_Size_Bytes:
			v, ok := take_bits(d, input, &r, 2)
			if !ok {
				need_input = true
				break
			}

			d.nibbles = int(v)
			d.skip_remaining = 0
			d.phase = .Metadata_Length if v > 0 else .Metadata_Align
		case .Metadata_Length:
			v, ok := take_bits(d, input, &r, u8(8 * d.nibbles))
			if !ok {
				need_input = true
				break
			}

			if d.nibbles > 1 && int(v) < 1 << uint(8 * (d.nibbles - 1)) {
				r.err = .Malformed
				break
			}

			d.skip_remaining = int(v) + 1
			d.phase = .Metadata_Align
		case .Metadata_Align, .Stored_Align:
			if d.bits != 0 {
				r.err = .Malformed
				break
			}

			d.bit_count = 0
			d.phase = .Metadata_Skip if d.phase == .Metadata_Align else .Stored_Copy
		case .Metadata_Skip:
			if d.skip_remaining == 0 {
				d.phase = .Block_End
				break
			}

			available := len(input) - r.consumed

			if available == 0 {
				need_input = true
				break
			}

			left := d.max_encoded_bytes - d.encoded_bytes

			if left == 0 {
				r.err = .Encoded_Limit
				break
			}

			count := min(available, d.skip_remaining, budget, int(min(left, u64(max(int)))))
			r.consumed += count
			d.encoded_bytes += u64(count)
			d.skip_remaining -= count
			r.work += count - 1
		case .Stored_Copy:
			if d.mb_remaining == 0 {
				d.phase = .Block_End
				break
			}

			room := output_room(d, output, &r)

			if room == 0 {
				if r.err == .None {
					return
				}

				break
			}

			available := len(input) - r.consumed

			if available == 0 {
				need_input = true
				break
			}

			left := d.max_encoded_bytes - d.encoded_bytes

			if left == 0 {
				r.err = .Encoded_Limit
				break
			}

			count := min(room, available, d.mb_remaining, budget, int(min(left, u64(max(int)))))

			for index in 0 ..< count {
				emit(d, output, &r, input[r.consumed + index])
			}

			r.consumed += count
			d.encoded_bytes += u64(count)
			d.mb_remaining -= count
			r.work += count - 1
		case .Var_Flag:
			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			if v == 0 {
				d.var_value = 0
				d.phase = d.var_next
			} else {
				d.phase = .Var_Width
			}
		case .Var_Width:
			v, ok := take_bits(d, input, &r, 3)
			if !ok {
				need_input = true
				break
			}

			if v == 0 {
				d.var_value = 1
				d.phase = d.var_next
			} else {
				d.var_width = u8(v)
				d.phase = .Var_Extra
			}
		case .Var_Extra:
			v, ok := take_bits(d, input, &r, d.var_width)
			if !ok {
				need_input = true
				break
			}

			d.var_value = 1 << d.var_width + int(v)
			d.phase = d.var_next
		case .Block_Types_Start:
			d.var_next = .Block_Types_Done
			d.phase = .Var_Flag
		case .Block_Types_Done:
			state := &d.blocks[d.category]
			state.type_count = d.var_value + 1
			state.current = 0
			state.previous = 1
			state.remaining = 1 << 28

			if state.type_count < 2 {
				d.phase = .Category_Next
			} else {
				start_code(d, .Block_Type, state.type_count + 2, .Block_Count_Code)
			}
		case .Block_Count_Code:
			start_code(d, .Block_Count, BLOCK_COUNT_ALPHABET, .Block_First_Count)
		case .Block_First_Count:
			d.count_after = .Category_Next
			d.phase = .Count_Symbol
		case .Count_Symbol:
			v, ok := take_symbol(d, input, &r, d.blocks[d.category].count_table[:])
			if !ok {
				need_input = true
				break
			}

			d.count_symbol = int(v)
			d.phase = .Count_Extra
		case .Count_Extra:
			v, ok := take_bits(d, input, &r, BLOCK_COUNT_EXTRA[d.count_symbol])
			if !ok {
				need_input = true
				break
			}

			d.blocks[d.category].remaining = int(BLOCK_COUNT_BASE[d.count_symbol] + v)
			d.phase = d.count_after
		case .Category_Next:
			d.category += 1
			d.phase = .Distance_Params if d.category == 3 else .Block_Types_Start
		case .Distance_Params:
			v, ok := take_bits(d, input, &r, 6)
			if !ok {
				need_input = true
				break
			}

			d.postfix = u8(v & 3)
			d.direct = int(v >> 2) << d.postfix
			d.index = 0
			d.phase = .Context_Modes
		case .Context_Modes:
			if d.index == d.blocks[0].type_count {
				d.phase = .Literal_Trees_Start
				break
			}

			v, ok := take_bits(d, input, &r, 2)
			if !ok {
				need_input = true
				break
			}

			d.context_modes[d.index] = u8(v)
			d.index += 1
		case .Literal_Trees_Start:
			d.var_next = .Literal_Trees_Done
			d.phase = .Var_Flag
		case .Literal_Trees_Done:
			d.literal_trees = d.var_value + 1
			d.map_distance = false
			d.map_trees = d.literal_trees
			d.map_length = d.blocks[0].type_count * 64
			d.map_after = .Distance_Trees_Start
			d.phase = .Map_Start
		case .Distance_Trees_Start:
			d.var_next = .Distance_Trees_Done
			d.phase = .Var_Flag
		case .Distance_Trees_Done:
			d.distance_trees = d.var_value + 1
			d.map_distance = true
			d.map_trees = d.distance_trees
			d.map_length = d.blocks[2].type_count * 4
			d.map_after = .Tables_Alloc
			d.phase = .Map_Start
		case .Map_Start:
			values := map_values(d)

			for &value in values {
				value = 0
			}

			d.map_index = 0
			d.map_run_max = 0
			d.phase = .Map_Rle_Flag if d.map_trees >= 2 else d.map_after
		case .Map_Rle_Flag:
			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			if v == 1 {
				d.phase = .Map_Rle_Bits
			} else {
				start_code(d, .Scratch, d.map_trees, .Map_Symbol)
			}
		case .Map_Rle_Bits:
			v, ok := take_bits(d, input, &r, 4)
			if !ok {
				need_input = true
				break
			}

			d.map_run_max = int(v) + 1
			start_code(d, .Scratch, d.map_trees + d.map_run_max, .Map_Symbol)
		case .Map_Symbol:
			if d.map_index >= d.map_length {
				d.phase = .Map_Imtf_Flag
				break
			}

			v, ok := take_symbol(d, input, &r, d.scratch[:])
			if !ok {
				need_input = true
				break
			}

			symbol := int(v)

			switch {
			case symbol == 0:
				d.map_index += 1
			case symbol <= d.map_run_max:
				d.map_symbol = symbol
				d.phase = .Map_Run
			case:
				map_values(d)[d.map_index] = u8(symbol - d.map_run_max)
				d.map_index += 1
			}
		case .Map_Run:
			v, ok := take_bits(d, input, &r, u8(d.map_symbol))
			if !ok {
				need_input = true
				break
			}

			run := 1 << uint(d.map_symbol) + int(v)

			if d.map_index + run > d.map_length {
				r.err = .Malformed
				break
			}

			d.map_index += run
			d.phase = .Map_Symbol
		case .Map_Imtf_Flag:
			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			if v == 1 {
				for index in 0 ..< 256 {
					d.imtf[index] = u8(index)
				}

				d.map_index = 0
				d.phase = .Map_Imtf
			} else {
				d.phase = d.map_after
			}
		case .Map_Imtf:
			if d.map_index >= d.map_length {
				d.phase = d.map_after
				break
			}

			value := &map_values(d)[d.map_index]
			at := value^
			moved := d.imtf[at]
			value^ = moved

			for at > 0 {
				d.imtf[at] = d.imtf[at - 1]
				at -= 1
			}

			d.imtf[0] = moved
			d.map_index += 1
		case .Tables_Alloc:
			d.command_trees = d.blocks[1].type_count
			d.command_base = d.literal_trees * LITERAL_TABLE_SIZE
			d.distance_base = d.command_base + d.command_trees * LARGE_TABLE_SIZE
			total := d.distance_base + d.distance_trees * LARGE_TABLE_SIZE

			if total > len(d.tables) {
				if resize(&d.tables, total) != nil {
					r.err = .Invalid_State
					break
				}
			}

			d.tree_kind = 0
			d.tree_index = 0
			d.phase = .Tree_Next
		case .Tree_Next:
			count := d.literal_trees

			switch d.tree_kind {
			case 1:
				count = d.command_trees
			case 2:
				count = d.distance_trees
			}

			if d.tree_index == count {
				d.tree_kind += 1
				d.tree_index = 0

				if d.tree_kind == 3 {
					d.mb_remaining = d.length
					d.phase = .Command
				}

				break
			}

			switch d.tree_kind {
			case 0:
				start_code(
					d,
					.Heap,
					LITERAL_ALPHABET,
					.Tree_Advance,
					d.tree_index * LITERAL_TABLE_SIZE,
					LITERAL_TABLE_SIZE,
				)
			case 1:
				start_code(
					d,
					.Heap,
					COMMAND_ALPHABET,
					.Tree_Advance,
					d.command_base + d.tree_index * LARGE_TABLE_SIZE,
					LARGE_TABLE_SIZE,
				)
			case:
				start_code(
					d,
					.Heap,
					16 + d.direct + 48 << d.postfix,
					.Tree_Advance,
					d.distance_base + d.tree_index * LARGE_TABLE_SIZE,
					LARGE_TABLE_SIZE,
				)
			}
		case .Tree_Advance:
			d.tree_index += 1
			d.phase = .Tree_Next
		case .Code_Kind:
			v, ok := take_bits(d, input, &r, 2)
			if !ok {
				need_input = true
				break
			}

			if v == 1 {
				d.phase = .Simple_Count
			} else {
				d.meta_lengths = {}
				d.code_index = int(v)
				d.code_space = 32
				d.code_used = 0
				d.phase = .Meta_Length
			}
		case .Simple_Count:
			v, ok := take_bits(d, input, &r, 2)
			if !ok {
				need_input = true
				break
			}

			d.simple_count = int(v) + 1
			d.simple_width = u8(bits.len_u32(u32(d.code_alphabet - 1)))
			d.index = 0
			d.phase = .Simple_Symbol
		case .Simple_Symbol:
			v, ok := take_bits(d, input, &r, d.simple_width)
			if !ok {
				need_input = true
				break
			}

			symbol := int(v)

			if symbol >= d.code_alphabet {
				r.err = .Malformed
				break
			}

			for other in 0 ..< d.index {
				if d.simple_symbols[other] == symbol {
					r.err = .Malformed
				}
			}

			if r.err != .None {
				break
			}

			d.simple_symbols[d.index] = symbol
			d.index += 1

			if d.index == d.simple_count {
				d.code_select = false
				d.phase = .Simple_Shape if d.simple_count == 4 else .Simple_Build
			}
		case .Simple_Shape:
			v, ok := take_bits(d, input, &r, 1)
			if !ok {
				need_input = true
				break
			}

			d.code_select = v == 1
			d.phase = .Simple_Build
		case .Simple_Build:
			if !build_simple(d) {
				r.err = .Malformed
				break
			}

			d.phase = d.code_after
		case .Meta_Length:
			if d.code_index >= 18 || d.code_space <= 0 {
				d.phase = .Meta_Build
				break
			}

			length, width := meta_code(d.bits & 15)

			if width > d.bit_count {
				if !pull_byte(d, input, &r) {
					need_input = true
				}

				break
			}

			d.bits >>= width
			d.bit_count -= width
			d.meta_lengths[CODE_LENGTH_ORDER[d.code_index]] = length
			d.code_index += 1

			if length != 0 {
				d.code_space -= 32 >> length
				d.code_used += 1
			}
		case .Meta_Build:
			if d.code_used != 1 && d.code_space != 0 || d.code_used == 0 {
				r.err = .Malformed
				break
			}

			if d.code_used == 1 {
				for length, symbol in d.meta_lengths {
					if length != 0 {
						fill_table(d.meta[:], symbol)
					}
				}
			} else if !build_table(d.meta[:], d.meta_lengths[:]) {
				r.err = .Malformed
				break
			}

			d.code_symbol = 0
			d.code_previous = 8
			d.code_repeat = 0
			d.code_repeat_length = 0
			d.code_room = 32768
			d.phase = .Lengths_Symbol
		case .Lengths_Symbol:
			if d.code_symbol >= d.code_alphabet || d.code_room <= 0 {
				d.phase = .Code_Finish
				break
			}

			v, ok := take_symbol(d, input, &r, d.meta[:])
			if !ok {
				need_input = true
				break
			}

			value := u8(v)

			if value < 16 {
				d.lengths[d.code_symbol] = value
				d.code_symbol += 1
				d.code_repeat = 0

				if value != 0 {
					d.code_previous = value
					d.code_room -= 32768 >> value
				}
			} else {
				d.code_repeat_symbol = int(value)
				d.phase = .Lengths_Repeat
			}
		case .Lengths_Repeat:
			extra: u8 = 2 if d.code_repeat_symbol == 16 else 3
			v, ok := take_bits(d, input, &r, extra)
			if !ok {
				need_input = true
				break
			}

			fill: u8 = d.code_previous if d.code_repeat_symbol == 16 else 0

			if d.code_repeat_length != fill {
				d.code_repeat = 0
				d.code_repeat_length = fill
			}

			before := d.code_repeat

			if d.code_repeat > 0 {
				d.code_repeat = (d.code_repeat - 2) << extra
			}

			d.code_repeat += int(v) + 3
			delta := d.code_repeat - before

			if d.code_symbol + delta > d.code_alphabet {
				r.err = .Malformed
				break
			}

			for _ in 0 ..< delta {
				d.lengths[d.code_symbol] = fill
				d.code_symbol += 1
			}

			if fill != 0 {
				d.code_room -= delta << (15 - fill)
			}

			d.phase = .Lengths_Symbol
		case .Code_Finish:
			if d.code_room != 0 || !build_table(code_table(d), d.lengths[:d.code_alphabet]) {
				r.err = .Malformed
				break
			}

			d.phase = d.code_after
		case .Switch_Type:
			state := &d.blocks[d.category]
			v, ok := take_symbol(d, input, &r, state.type_table[:])
			if !ok {
				need_input = true
				break
			}

			next: int

			switch v {
			case 0:
				next = state.previous
			case 1:
				next = state.current + 1
			case:
				next = int(v) - 2
			}

			if next >= state.type_count {
				next -= state.type_count
			}

			state.previous = state.current
			state.current = next
			d.count_after = d.switch_after
			d.phase = .Count_Symbol
		case .Command:
			if d.mb_remaining == 0 {
				d.phase = .Block_End
				break
			}

			state := &d.blocks[1]

			if state.remaining == 0 {
				start_switch(d, 1, .Command)
				break
			}

			table := d.tables[d.command_base + state.current * LARGE_TABLE_SIZE:][:LARGE_TABLE_SIZE]
			v, ok := take_symbol(d, input, &r, table)
			if !ok {
				need_input = true
				break
			}

			state.remaining -= 1
			d.cmd_symbol = int(v)
			d.phase = .Insert_Extra
		case .Insert_Extra:
			entry := command_entry(d.cmd_symbol)
			v, ok := take_bits(d, input, &r, entry.insert_extra)
			if !ok {
				need_input = true
				break
			}

			d.insert_length = int(entry.insert_base) + int(v)
			d.phase = .Copy_Extra
		case .Copy_Extra:
			entry := command_entry(d.cmd_symbol)
			v, ok := take_bits(d, input, &r, entry.copy_extra)
			if !ok {
				need_input = true
				break
			}

			d.copy_length = int(entry.copy_base) + int(v)

			if d.insert_length > d.mb_remaining {
				r.err = .Malformed
				break
			}

			d.phase = .Literal
		case .Literal:
			if d.insert_length == 0 {
				d.phase = .After_Insert
				break
			}

			state := &d.blocks[0]

			if state.remaining == 0 {
				start_switch(d, 0, .Literal)
				break
			}

			room := output_room(d, output, &r)

			if room == 0 {
				if r.err == .None {
					return
				}

				break
			}

			p1, p2: int

			if d.decoded_bytes > 0 {
				p1 = int(window_back(d, 1))
			}

			if d.decoded_bytes > 1 {
				p2 = int(window_back(d, 2))
			}

			mode := int(d.context_modes[state.current]) * 512
			literal_context := int(CONTEXT_LOOKUP[mode + p1] | CONTEXT_LOOKUP[mode + 256 + p2])
			tree := int(d.literal_map[state.current * 64 + literal_context])
			v, ok := take_symbol(d, input, &r, d.tables[tree * LITERAL_TABLE_SIZE:][:LITERAL_TABLE_SIZE])
			if !ok {
				need_input = true
				break
			}

			emit(d, output, &r, u8(v))
			state.remaining -= 1
			d.insert_length -= 1
			d.mb_remaining -= 1
		case .After_Insert:
			if d.mb_remaining == 0 {
				d.phase = .Block_End
			} else if d.cmd_symbol < 128 {
				d.distance = d.distances[0]
				d.push = false
				d.phase = .Copy_Prepare
			} else {
				d.phase = .Distance_Symbol
			}
		case .Distance_Symbol:
			state := &d.blocks[2]

			if state.remaining == 0 {
				start_switch(d, 2, .Distance_Symbol)
				break
			}

			slot := 3 if d.copy_length > 4 else d.copy_length - 2
			tree := int(d.distance_map[state.current * 4 + slot])
			table := d.tables[d.distance_base + tree * LARGE_TABLE_SIZE:][:LARGE_TABLE_SIZE]
			v, ok := take_symbol(d, input, &r, table)
			if !ok {
				need_input = true
				break
			}

			state.remaining -= 1
			d.phase = .Distance_Extra if apply_distance_code(d, int(v)) else .Copy_Prepare
		case .Distance_Extra:
			v, ok := take_bits(d, input, &r, d.distance_bits)
			if !ok {
				need_input = true
				break
			}

			d.distance = (d.distance_offset + int(v)) << d.postfix + d.distance_low + d.direct + 1
			d.phase = .Copy_Prepare
		case .Copy_Prepare:
			if d.distance <= 0 {
				r.err = .Malformed
				break
			}

			reach := int(min(d.decoded_bytes, u64(d.window_max)))

			if d.distance > reach {
				if !begin_dictionary(d, reach) {
					r.err = .Malformed
					break
				}

				d.phase = .Dictionary
				break
			}

			if d.push {
				d.distances[3] = d.distances[2]
				d.distances[2] = d.distances[1]
				d.distances[1] = d.distances[0]
				d.distances[0] = d.distance
			}

			if d.copy_length > d.mb_remaining {
				r.err = .Malformed
				break
			}

			d.copy_remaining = d.copy_length
			d.phase = .Copy
		case .Copy:
			if d.copy_remaining == 0 {
				d.phase = .Command
				break
			}

			room := output_room(d, output, &r)

			if room == 0 {
				if r.err == .None {
					return
				}

				break
			}

			count := min(room, d.copy_remaining, budget)

			for _ in 0 ..< count {
				emit(d, output, &r, window_back(d, d.distance))
			}

			d.copy_remaining -= count
			d.mb_remaining -= count
			r.work += count - 1
		case .Dictionary:
			if d.word_at == d.word_length {
				d.mb_remaining -= d.word_length
				d.phase = .Command
				break
			}

			room := output_room(d, output, &r)

			if room == 0 {
				if r.err == .None {
					return
				}

				break
			}

			count := min(room, d.word_length - d.word_at, budget)

			for index in 0 ..< count {
				emit(d, output, &r, d.word[d.word_at + index])
			}

			d.word_at += count
			r.work += count - 1
		case .Block_End:
			d.phase = .Final_Padding if d.last else .Header_Last
		case .Final_Padding:
			if d.bits != 0 {
				r.err = .Malformed
				break
			}

			d.bit_count = 0
			d.phase = .End
		case .End:
			finish_stream(d, input, final_input, &r)
			return
		case:
			r.err = .Invalid_State
		}

		if r.err != .None {
			d.error = r.err
			d.phase = .Failed
			return
		}

		if need_input {
			if final_input {
				r.err = .Truncated
				d.error = r.err
				d.phase = .Failed
			} else {
				r.status = .Need_Input
			}

			return
		}

		if d.phase == .End {
			finish_stream(d, input, final_input, &r)
			return
		}
	}

	return
}
