package compress_deflate

import "core:compress"

/*
Resumable raw DEFLATE decoding for input that arrives in pieces.

An `Inflate_Decoder` has fixed size, allocates nothing and keeps no slice between
calls: each `inflate_decoder_step` consumes a prefix of `input`, appends to `output`
and stops when it needs more of either or has spent its work budget. Encoded and
decoded totals are checked against explicit ceilings before a byte is consumed or
published. It trades the speed of `inflate_raw` for those bounds; use `inflate_raw`
when the whole input is in memory and trusted to fit.

The Huffman tables are the ones `inflate_raw` builds and reads.
*/

INFLATE_DECODER_PRECODE_BITS  :: 7
INFLATE_DECODER_LITERAL_BITS  :: 10
INFLATE_DECODER_DISTANCE_BITS :: 8

Inflate_Decoder_Phase :: enum {
	Uninitialized,
	Block,
	Stored_Length,
	Stored_Copy,
	Dynamic_Header,
	Code_Lengths,
	Build_Code_Lengths,
	Dynamic_Lengths,
	Repeat_Lengths,
	Build_Tables,
	Symbol,
	Literal,
	Length_Extra,
	Distance,
	Distance_Extra,
	Copy,
	End,
	Failed,
}

// Fixed storage: no allocator, borrowed input, or complete-output buffer. History
// and parsing state belong exclusively to the caller, including between steps.
Inflate_Decoder :: struct {
	phase:             Inflate_Decoder_Phase,
	encoded_bytes:     u64,
	decoded_bytes:     u64,
	max_encoded_bytes: u64,
	max_decoded_bytes: u64,
	error:             compress.Decode_Error,
	final_declared:    bool,
	bit_buffer:        u64,
	bit_count:         u8,
	last_block:        bool,
	// The block uses the fixed codes instead of `literals` and `distances`.
	fixed:             bool,
	history:           [DEFLATE_WINDOW_SIZE]u8,
	history_at:        int,
	history_size:      int,
	literals:          [INFLATE_LITERAL_TABLE_SIZE]u32,
	distances:         [INFLATE_DISTANCE_TABLE_SIZE]u32,
	precodes:          [INFLATE_PRECODE_TABLE_SIZE]u32,
	lengths:           [DEFLATE_LITERAL_SYMBOLS + DEFLATE_DISTANCE_SYMBOLS]u8,
	precode_lengths:   [DEFLATE_PRECODE_SYMBOLS]u8,
	literal_count:     int,
	distance_count:    int,
	precode_count:     int,
	index:             int,
	// Code bits read so far, first bit lowest.
	prefix:            u16,
	prefix_bits:       u8,
	repeat_symbol:     i32,
	remaining:         int,
	distance:          int,
	extra_bits:        u8,
	literal:           u8,
}

// Initialization also resets a terminal decoder. Zero byte ceilings are valid
// (notably for an empty member after an aggregate decoded budget is exhausted).
inflate_decoder_init :: proc(d: ^Inflate_Decoder, max_encoded_bytes, max_decoded_bytes: u64) -> compress.Decode_Error {
	if d == nil {
		return .Invalid_State
	}

	d^ = Inflate_Decoder{
		phase             = .Block,
		max_encoded_bytes = max_encoded_bytes,
		max_decoded_bytes = max_decoded_bytes,
	}

	return .None
}

// Raw DEFLATE stops exactly at its final block, leaving following bytes
// unconsumed. Done does not require final_input (envelope decoders need the
// trailer). final_input means this slice contains all remaining input; callers
// resubmit its unconsumed suffix with final_input=true after backpressure/work
// yields. Once declared, final_input cannot be withdrawn. Errors are terminal;
// invalid arguments/overlap are rejected without changing state or buffers.
//
// One work unit is a bounded parser action, code bit, output byte or table
// construction phase; `work_limit` must be 1 through `compress.DECODE_MAX_WORK`.
inflate_decoder_step :: proc(d: ^Inflate_Decoder, input, output: []u8, final_input: bool, work_limit := 4096) -> (r: compress.Decode_Result) {
	r.status = .Progress

	if d == nil || d.phase == .Uninitialized {
		r.err = .Invalid_State
		return
	}

	if work_limit <= 0 || work_limit > compress.DECODE_MAX_WORK {
		r.err = .Invalid_Config
		return
	}

	if compress.decode_buffers_overlap(input, output) {
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

	if d.phase == .End {
		r.status = .Done
		return
	}

	d.final_declared = final_input

	for r.work < work_limit {
		r.work += 1
		need_input := false

		#partial switch d.phase {
		case .Block:
			need_input = inflate_decoder_block(d, input, &r)
		case .Stored_Length:
			value, ok := inflate_decoder_bits(d, input, &r, 32)

			if !ok {
				need_input = true
				break
			}

			if u16(value) != ~u16(value >> 16) {
				r.err = .Malformed
				break
			}

			d.remaining = int(value & 0xffff)
			d.phase = .Stored_Copy
		case .Stored_Copy:
			if d.remaining == 0 {
				d.phase = .End if d.last_block else .Block
				break
			}

			if d.decoded_bytes == d.max_decoded_bytes {
				r.err = .Decoded_Limit
				break
			}

			if r.produced == len(output) {
				r.status = .Need_Output
				return
			}

			value, ok := inflate_decoder_bits(d, input, &r, 8)

			if !ok {
				need_input = true
				break
			}

			if inflate_decoder_emit(d, output, &r, u8(value)) {
				d.remaining -= 1
			}
		case .Dynamic_Header:
			value, ok := inflate_decoder_bits(d, input, &r, 14)

			if !ok {
				need_input = true
				break
			}

			d.literal_count = int(value & 31) + 257
			d.distance_count = int((value >> 5) & 31) + 1
			d.precode_count = int((value >> 10) & 15) + 4

			if d.literal_count > 286 {
				r.err = .Malformed
				break
			}

			d.precode_lengths = {}
			d.index = 0
			d.phase = .Code_Lengths
		case .Code_Lengths:
			if d.index == d.precode_count {
				d.phase = .Build_Code_Lengths
				break
			}

			value, ok := inflate_decoder_bits(d, input, &r, 3)

			if !ok {
				need_input = true
				break
			}

			d.precode_lengths[DEFLATE_PRECODE_ORDER[d.index]] = u8(value)
			d.index += 1
		case .Build_Code_Lengths:
			// The code-length code must be complete.
			if !inflate_build(d.precodes[:], d.precode_lengths[:], INFLATE_DECODER_PRECODE_BITS, DEFLATE_PRECODE_MAX_CODE_LENGTH, -1) {
				r.err = .Malformed
				break
			}

			d.index = 0
			d.phase = .Dynamic_Lengths
		case .Dynamic_Lengths:
			if d.index == d.literal_count + d.distance_count {
				d.phase = .Build_Tables
				break
			}

			symbol, ok := inflate_decoder_symbol(d, d.precodes[:], INFLATE_DECODER_PRECODE_BITS, input, &r)

			if !ok {
				need_input = inflate_decoder_is_starved(d, input, &r)
				break
			}

			if symbol < 16 {
				d.lengths[d.index] = u8(symbol)
				d.index += 1
				break
			}

			if symbol > 18 || (symbol == 16 && d.index == 0) {
				r.err = .Malformed
				break
			}

			d.repeat_symbol = symbol
			d.phase = .Repeat_Lengths
		case .Repeat_Lengths:
			need_input = inflate_decoder_repeat_lengths(d, input, &r)
		case .Build_Tables:
			// RFC 1951 permits a one-symbol literal/distance code, and an unused
			// empty distance code.
			literal_lengths := d.lengths[:d.literal_count]
			distance_lengths := d.lengths[d.literal_count:][:d.distance_count]

			if d.lengths[DEFLATE_END_OF_BLOCK] == 0 ||
			   !inflate_build(d.literals[:], literal_lengths, INFLATE_DECODER_LITERAL_BITS, DEFLATE_CODE_LENGTH_MAX, INFLATE_BAD_LITERAL) ||
			   !inflate_build(d.distances[:], distance_lengths, INFLATE_DECODER_DISTANCE_BITS, DEFLATE_CODE_LENGTH_MAX, INFLATE_BAD_DISTANCE) {
				r.err = .Malformed
				break
			}

			d.fixed = false
			d.phase = .Symbol
		case .Symbol:
			literals := INFLATE_FIXED_LITERALS[:] if d.fixed else d.literals[:]
			symbol, ok := inflate_decoder_symbol(d, literals, INFLATE_DECODER_LITERAL_BITS, input, &r)

			if !ok {
				need_input = inflate_decoder_is_starved(d, input, &r)
				break
			}

			switch {
			case symbol < DEFLATE_END_OF_BLOCK:
				d.literal = u8(symbol)
				d.phase = .Literal
			case symbol == DEFLATE_END_OF_BLOCK:
				d.phase = .Block

				if d.last_block {
					d.phase = .End
					d.bit_buffer = 0
					d.bit_count = 0
				}
			case symbol <= 285:
				d.remaining = int(DEFLATE_LENGTH_BASE[symbol - 257])
				d.extra_bits = DEFLATE_LENGTH_EXTRA_BITS[symbol - 257]
				d.phase = .Length_Extra
			case:
				r.err = .Malformed
			}
		case .Literal:
			if !inflate_decoder_emit(d, output, &r, d.literal) {
				if r.err == .None {
					return
				}

				break
			}

			d.phase = .Symbol
		case .Length_Extra:
			value, ok := inflate_decoder_bits(d, input, &r, d.extra_bits)

			if !ok {
				need_input = true
				break
			}

			d.remaining += int(value)
			d.phase = .Distance
		case .Distance:
			distances := INFLATE_FIXED_DISTANCES[:] if d.fixed else d.distances[:]
			symbol, ok := inflate_decoder_symbol(d, distances, INFLATE_DECODER_DISTANCE_BITS, input, &r)

			if !ok {
				need_input = inflate_decoder_is_starved(d, input, &r)
				break
			}

			if symbol > 29 {
				r.err = .Malformed
				break
			}

			d.distance = int(DEFLATE_DISTANCE_BASE[symbol])
			d.extra_bits = DEFLATE_DISTANCE_EXTRA_BITS[symbol]
			d.phase = .Distance_Extra
		case .Distance_Extra:
			value, ok := inflate_decoder_bits(d, input, &r, d.extra_bits)

			if !ok {
				need_input = true
				break
			}

			d.distance += int(value)

			if d.distance > d.history_size {
				r.err = .Malformed
				break
			}

			d.phase = .Copy
		case .Copy:
			if d.remaining == 0 {
				d.phase = .Symbol
				break
			}

			value := d.history[(d.history_at - d.distance + DEFLATE_WINDOW_SIZE) & DEFLATE_WINDOW_MASK]

			if !inflate_decoder_emit(d, output, &r, value) {
				if r.err == .None {
					return
				}

				break
			}

			d.remaining -= 1
		case .End:
			r.status = .Done
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
			r.status = .Done
			return
		}
	}

	return
}

// Reads a block header. Returns true when it needs more input.
@(private)
inflate_decoder_block :: proc(d: ^Inflate_Decoder, input: []u8, r: ^compress.Decode_Result) -> (need_input: bool) {
	value, ok := inflate_decoder_bits(d, input, r, 3)

	if !ok {
		return true
	}

	d.last_block = value & 1 != 0

	switch value >> 1 {
	case 0:
		d.bit_buffer = 0
		d.bit_count = 0
		d.phase = .Stored_Length
	case 1:
		d.fixed = true
		d.phase = .Symbol
	case 2:
		d.phase = .Dynamic_Header
	case 3:
		r.err = .Malformed
	}

	return false
}

// Expands a repeat code of the code-length alphabet. Returns true when it needs more input.
@(private)
inflate_decoder_repeat_lengths :: proc(d: ^Inflate_Decoder, input: []u8, r: ^compress.Decode_Result) -> (need_input: bool) {
	extra_bits := DEFLATE_PRECODE_EXTRA_BITS[d.repeat_symbol]
	value, ok := inflate_decoder_bits(d, input, r, extra_bits)

	if !ok {
		return true
	}

	count := int(value) + 3

	if d.repeat_symbol == 18 {
		count = int(value) + 11
	}

	if count > d.literal_count + d.distance_count - d.index {
		r.err = .Malformed
		return false
	}

	length := u8(0)

	if d.repeat_symbol == 16 {
		length = d.lengths[d.index - 1]
	}

	for i in 0 ..< count {
		d.lengths[d.index + i] = length
	}

	d.index += count
	d.phase = .Dynamic_Lengths

	return false
}

// A code that did not complete is starved only when no input and no buffered bit is left.
@(private)
inflate_decoder_is_starved :: proc(d: ^Inflate_Decoder, input: []u8, r: ^compress.Decode_Result) -> bool {
	return r.consumed == len(input) && d.bit_count == 0
}

// Moves the next input byte into the bit buffer, if there is one within the encoded ceiling.
@(private)
inflate_decoder_fill :: #force_inline proc(d: ^Inflate_Decoder, input: []u8, r: ^compress.Decode_Result) -> bool {
	if r.consumed == len(input) {
		return false
	}

	if d.encoded_bytes == d.max_encoded_bytes {
		r.err = .Encoded_Limit
		return false
	}

	d.bit_buffer |= u64(input[r.consumed]) << d.bit_count
	d.bit_count += 8
	r.consumed += 1
	d.encoded_bytes += 1

	return true
}

@(private)
inflate_decoder_bits :: proc(d: ^Inflate_Decoder, input: []u8, r: ^compress.Decode_Result, count: u8) -> (value: u32, ok: bool) {
	for d.bit_count < count {
		if !inflate_decoder_fill(d, input, r) {
			return 0, false
		}
	}

	value = u32(d.bit_buffer & ((u64(1) << count) - 1))
	d.bit_buffer >>= count
	d.bit_count -= count

	return value, true
}

// Decodes at most one code bit per call: arbitrarily partitioned input cannot
// cause speculative reads into a following gzip trailer. The bits read so far,
// padded with zeros, index the table: the entry found is the code they begin,
// and it is complete once its length is the number of bits read.
@(private)
inflate_decoder_symbol :: #force_inline proc(d: ^Inflate_Decoder, table: []u32, $TABLE_BITS: u8, input: []u8, r: ^compress.Decode_Result) -> (symbol: i32, ready: bool) {
	if d.bit_count == 0 && !inflate_decoder_fill(d, input, r) {
		return
	}

	d.prefix |= u16(d.bit_buffer & 1) << d.prefix_bits
	d.prefix_bits += 1
	d.bit_buffer >>= 1
	d.bit_count -= 1

	key := table[d.prefix & ((u16(1) << TABLE_BITS) - 1)]
	length := u8(key & 0x0f)

	if key & 0x10 != 0 {
		if d.prefix_bits <= TABLE_BITS {
			return
		}

		key = table[(key >> 16) + u32(d.prefix >> TABLE_BITS)]
		length = TABLE_BITS + u8(key & 0x0f)
	}

	if length > d.prefix_bits {
		return
	}

	d.prefix = 0
	d.prefix_bits = 0

	return i32((key >> 16) & 0x0fff), true
}

@(private)
inflate_decoder_emit :: proc(d: ^Inflate_Decoder, output: []u8, r: ^compress.Decode_Result, value: u8) -> bool {
	if d.decoded_bytes == d.max_decoded_bytes {
		r.err = .Decoded_Limit
		return false
	}

	if r.produced == len(output) {
		r.status = .Need_Output
		return false
	}

	output[r.produced] = value
	r.produced += 1
	d.decoded_bytes += 1
	d.history[d.history_at] = value
	d.history_at = (d.history_at + 1) & DEFLATE_WINDOW_MASK
	d.history_size = min(d.history_size + 1, DEFLATE_WINDOW_SIZE)

	return true
}
