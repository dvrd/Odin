package compress_step

import "base:intrinsics"

/*
Resumable raw DEFLATE decoding for input that arrives in pieces.

An `Inflate_Decoder` has fixed size, allocates nothing and keeps no slice between
calls: each `inflate_decoder_step` consumes a prefix of `input`, appends to `output`
and stops when it needs more of either or has spent its work budget. Encoded and
decoded totals are checked against explicit ceilings before a byte is consumed or
published.

Two paths decode the same stream. While a step has plenty of input, output room and
work budget, a fast loop reads eight input bytes at a time, decodes whole symbols
from two-level tables and copies matches in blocks. Near the end of either buffer
the careful path takes over: it pulls one input byte only when the operation in
hand cannot finish without it, so a step never reads past the last bit of the
stream and can stop between any two operations. The fast loop hands back every
whole byte it read ahead before it returns.

It uses nothing of `core:compress/deflate`; it is the decoder for callers that
cannot block or allocate. With the whole input in memory, `deflate.decompress_raw`
is the simpler call.
*/

INFLATE_WINDOW_SIZE :: 32768

@(private)
WINDOW_MASK :: INFLATE_WINDOW_SIZE - 1

@(private)
LITERAL_SYMBOLS :: 288
@(private)
DISTANCE_SYMBOLS :: 32
@(private)
PRECODE_SYMBOLS :: 19
@(private)
MATCH_MAX :: 258
@(private)
CODE_LENGTH_MAX :: 15

// Bits that index the first level of each table. A longer code continues in a
// second level of its own, sized for the longest code that shares its prefix.
@(private)
LITERAL_ROOT :: 10
@(private)
DISTANCE_ROOT :: 8
@(private)
PRECODE_ROOT :: 7

// A complete code leaves every prefix with a full subtree, and a full subtree of
// depth d has at least d+1 leaves. The second levels are largest when every long
// code sits in a subtree of the greatest depth: 288/6 subtrees of 32 entries for
// literals, 30/8 of 128 for distances.
@(private)
LITERAL_TABLE_SIZE :: 1 << LITERAL_ROOT + 1536
@(private)
DISTANCE_TABLE_SIZE :: 1 << DISTANCE_ROOT + 512
@(private)
PRECODE_TABLE_SIZE :: 1 << PRECODE_ROOT

// A table entry: the bits it consumes in the low byte, extra bits to read next,
// what it is, and its value (a literal, a base length or distance, a code length
// or the offset of a second level).
@(private)
Entry :: u32

@(private)
Entry_Kind :: enum u32 {
	Invalid,
	Literal,
	Length,
	End,
	Sub,
	Distance,
	Code_Length,
}

@(private)
entry :: #force_inline proc "contextless" (kind: Entry_Kind, value: u32, extra: u32 = 0) -> Entry {
	return value << 16 | u32(kind) << 12 | extra << 8
}
@(private)
entry_bits :: #force_inline proc "contextless" (e: Entry) -> u8 {return u8(e)}
@(private)
entry_extra :: #force_inline proc "contextless" (e: Entry) -> u8 {return u8(e >> 8) & 0xf}
@(private)
entry_kind :: #force_inline proc "contextless" (e: Entry) -> Entry_Kind {return Entry_Kind(e >> 12 & 0xf)}
@(private)
entry_value :: #force_inline proc "contextless" (e: Entry) -> int {return int(e >> 16)}

@(private, rodata)
LENGTH_BASE := [29]u16{3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258}
@(private, rodata)
LENGTH_EXTRA := [29]u8{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
@(private, rodata)
DISTANCE_BASE := [30]u16{1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577}
@(private, rodata)
DISTANCE_EXTRA := [30]u8{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}
@(private, rodata)
PRECODE_ORDER := [PRECODE_SYMBOLS]u8{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

Inflate_Decoder_Phase :: enum u8 {
	Uninitialized,
	Block,
	Stored_Length,
	Stored_Copy,
	Dynamic_Header,
	Precode_Lengths,
	Build_Precode,
	Code_Lengths,
	Repeat_Lengths,
	Build_Tables,
	Build_Fixed,
	Symbol,
	Literal,
	Length_Extra,
	Distance,
	Distance_Extra,
	Copy,
	End,
	Failed,
}

@(private)
Alphabet :: enum u8 {
	Precode,
	Literal,
	Distance,
}

// Fixed storage: no allocator, borrowed input, or complete-output buffer. History
// and parsing state belong exclusively to the caller, including between steps.
Inflate_Decoder :: struct {
	phase:             Inflate_Decoder_Phase,
	error:             Decode_Error,
	final_declared:    bool,
	last_block:        bool,
	// The tables hold the fixed codes.
	fixed_loaded:      bool,
	bit_count:         u8,
	// Bits to read after the code in hand, and the byte waiting for output room.
	extra_bits:        u8,
	literal:           u8,
	repeat_symbol:     u8,
	bit_buffer:        u64,
	encoded_bytes:     u64,
	decoded_bytes:     u64,
	max_encoded_bytes: u64,
	max_decoded_bytes: u64,
	literal_count:     int,
	distance_count:    int,
	precode_count:     int,
	index:             int,
	// Bytes left of a stored block or a match, and the match distance.
	remaining:         int,
	distance:          int,
	// The last bytes produced by earlier steps, as a ring. A step reads its own
	// output from `output` and adds it here when it returns.
	history_at:        int,
	history_size:      int,
	history:           [INFLATE_WINDOW_SIZE]u8,
	literals:          [LITERAL_TABLE_SIZE]Entry,
	distances:         [DISTANCE_TABLE_SIZE]Entry,
	precodes:          [PRECODE_TABLE_SIZE]Entry,
	lengths:           [LITERAL_SYMBOLS + DISTANCE_SYMBOLS]u8,
	precode_lengths:   [PRECODE_SYMBOLS]u8,
}

// Initialization also resets a terminal decoder. Zero byte ceilings are valid
// (notably for an empty member after an aggregate decoded budget is exhausted).
inflate_decoder_init :: proc(d: ^Inflate_Decoder, max_encoded_bytes, max_decoded_bytes: u64) -> Decode_Error {
	if d == nil {
		return .Invalid_State
	}
	// Only the scalars need a value: the history is read through `history_size`
	// and every table is built before it is read.
	d.phase = .Block
	d.error = .None
	d.final_declared = false
	d.last_block = false
	d.fixed_loaded = false
	d.bit_count = 0
	d.extra_bits = 0
	d.literal = 0
	d.repeat_symbol = 0
	d.bit_buffer = 0
	d.encoded_bytes = 0
	d.decoded_bytes = 0
	d.max_encoded_bytes = max_encoded_bytes
	d.max_decoded_bytes = max_decoded_bytes
	d.literal_count = 0
	d.distance_count = 0
	d.precode_count = 0
	d.index = 0
	d.remaining = 0
	d.distance = 0
	d.history_at = 0
	d.history_size = 0
	return .None
}

// Raw DEFLATE stops exactly at its final block, leaving following bytes
// unconsumed. Done does not require final_input (envelope decoders need the
// trailer). final_input means this slice contains all remaining input; callers
// resubmit its unconsumed suffix with final_input=true after backpressure/work
// yields. Once declared, final_input cannot be withdrawn. Errors are terminal;
// invalid arguments/overlap are rejected without changing state or buffers.
//
// One work unit is a bounded parser action, a decoded symbol, an output byte or
// a table construction phase; `work_limit` must be 1 through `DECODE_MAX_WORK`.
// A larger budget lets the fast loop run longer between returns.
inflate_decoder_step :: proc(d: ^Inflate_Decoder, input, output: []u8, final_input: bool, work_limit := 4096) -> (r: Decode_Result) {
	r.status = .Progress

	if d == nil || d.phase == .Uninitialized {
		r.err = .Invalid_State
		return
	}
	if work_limit <= 0 || work_limit > DECODE_MAX_WORK {
		r.err = .Invalid_Config
		return
	}
	if decode_buffers_overlap(input, output) {
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

	inflate_run(d, input, output, final_input, work_limit, &r)
	inflate_remember(d, output[:r.produced])
	return
}

@(private)
inflate_run :: proc(d: ^Inflate_Decoder, input, output: []u8, final_input: bool, work_limit: int, r: ^Decode_Result) {
	for r.work < work_limit {
		if d.phase == .Symbol {
			inflate_fast(d, input, output, work_limit, r)
			if r.err != .None {
				inflate_fail(d, r)
				return
			}
			if d.phase == .End {
				r.status = .Done
				return
			}
			if r.work >= work_limit {
				return
			}
		}

		r.work += 1
		need_input := false

		#partial switch d.phase {
		case .Block:
			value, ok := inflate_bits(d, input, r, 3)
			if !ok {
				need_input = true
				break
			}
			d.last_block = value & 1 != 0
			switch value >> 1 {
			case 0:
				// A stored block starts at the next byte boundary.
				d.bit_buffer = 0
				d.bit_count = 0
				d.phase = .Stored_Length
			case 1:
				d.phase = .Symbol if d.fixed_loaded else .Build_Fixed
			case 2:
				d.phase = .Dynamic_Header
			case 3:
				r.err = .Malformed
			}
		case .Stored_Length:
			value, ok := inflate_bits(d, input, r, 32)
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
			if r.consumed == len(input) {
				need_input = true
				break
			}
			if d.encoded_bytes == d.max_encoded_bytes {
				r.err = .Encoded_Limit
				break
			}
			n := min(d.remaining, len(input) - r.consumed, len(output) - r.produced, work_limit - r.work + 1)
			n = int(min(u64(n), d.max_encoded_bytes - d.encoded_bytes, d.max_decoded_bytes - d.decoded_bytes))
			copy(output[r.produced:][:n], input[r.consumed:][:n])
			r.consumed += n; r.produced += n; r.work += n - 1
			d.encoded_bytes += u64(n); d.decoded_bytes += u64(n)
			d.remaining -= n
		case .Dynamic_Header:
			value, ok := inflate_bits(d, input, r, 14)
			if !ok {
				need_input = true
				break
			}
			d.literal_count = int(value & 31) + 257
			d.distance_count = int(value >> 5 & 31) + 1
			d.precode_count = int(value >> 10 & 15) + 4
			if d.literal_count > 286 || d.distance_count > 30 {
				r.err = .Malformed
				break
			}
			d.precode_lengths = {}
			d.index = 0
			d.phase = .Precode_Lengths
		case .Precode_Lengths:
			if d.index == d.precode_count {
				d.phase = .Build_Precode
				break
			}
			value, ok := inflate_bits(d, input, r, 3)
			if !ok {
				need_input = true
				break
			}
			d.precode_lengths[PRECODE_ORDER[d.index]] = u8(value)
			d.index += 1
		case .Build_Precode:
			if !inflate_build(d.precodes[:], d.precode_lengths[:], PRECODE_ROOT, .Precode) {
				r.err = .Malformed
				break
			}
			d.index = 0
			d.phase = .Code_Lengths
		case .Code_Lengths:
			if d.index == d.literal_count + d.distance_count {
				d.phase = .Build_Tables
				break
			}
			e, ok := inflate_code(d, d.precodes[:], PRECODE_ROOT, input, r)
			if !ok {
				need_input = r.err == .None
				break
			}
			if entry_kind(e) != .Code_Length {
				r.err = .Malformed
				break
			}
			symbol := entry_value(e)
			if symbol < 16 {
				d.lengths[d.index] = u8(symbol)
				d.index += 1
				break
			}
			if symbol == 16 && d.index == 0 {
				r.err = .Malformed
				break
			}
			d.repeat_symbol = u8(symbol)
			d.phase = .Repeat_Lengths
		case .Repeat_Lengths:
			width: u8 = 2
			base := 3
			switch d.repeat_symbol {
			case 17: width = 3
			case 18: width = 7; base = 11
			}
			value, ok := inflate_bits(d, input, r, width)
			if !ok {
				need_input = true
				break
			}
			count := int(value) + base
			if count > d.literal_count + d.distance_count - d.index {
				r.err = .Malformed
				break
			}
			length := d.lengths[d.index - 1] if d.repeat_symbol == 16 else 0
			for i in 0 ..< count {
				d.lengths[d.index + i] = length
			}
			d.index += count
			d.phase = .Code_Lengths
		case .Build_Tables:
			// A block that cannot end is not a block.
			if d.lengths[256] == 0 ||
			   !inflate_build(d.literals[:], d.lengths[:d.literal_count], LITERAL_ROOT, .Literal) ||
			   !inflate_build(d.distances[:], d.lengths[d.literal_count:][:d.distance_count], DISTANCE_ROOT, .Distance) {
				r.err = .Malformed
				break
			}
			d.fixed_loaded = false
			d.phase = .Symbol
		case .Build_Fixed:
			for i in 0 ..< 144 {d.lengths[i] = 8}
			for i in 144 ..< 256 {d.lengths[i] = 9}
			for i in 256 ..< 280 {d.lengths[i] = 7}
			for i in 280 ..< 288 {d.lengths[i] = 8}
			for i in 288 ..< 320 {d.lengths[i] = 5}
			_ = inflate_build(d.literals[:], d.lengths[:288], LITERAL_ROOT, .Literal)
			_ = inflate_build(d.distances[:], d.lengths[288:320], DISTANCE_ROOT, .Distance)
			d.fixed_loaded = true
			d.phase = .Symbol
		case .Symbol:
			e, ok := inflate_code(d, d.literals[:], LITERAL_ROOT, input, r)
			if !ok {
				need_input = r.err == .None
				break
			}
			#partial switch entry_kind(e) {
			case .Literal:
				d.literal = u8(entry_value(e))
				d.phase = .Literal
			case .End:
				d.phase = .End if d.last_block else .Block
			case .Length:
				d.remaining = entry_value(e)
				d.extra_bits = entry_extra(e)
				d.phase = .Length_Extra
			case:
				r.err = .Malformed
			}
		case .Literal:
			if d.decoded_bytes == d.max_decoded_bytes {
				r.err = .Decoded_Limit
				break
			}
			if r.produced == len(output) {
				r.status = .Need_Output
				return
			}
			output[r.produced] = d.literal
			r.produced += 1
			d.decoded_bytes += 1
			d.phase = .Symbol
		case .Length_Extra:
			value, ok := inflate_bits(d, input, r, d.extra_bits)
			if !ok {
				need_input = true
				break
			}
			d.remaining += int(value)
			d.phase = .Distance
		case .Distance:
			e, ok := inflate_code(d, d.distances[:], DISTANCE_ROOT, input, r)
			if !ok {
				need_input = r.err == .None
				break
			}
			if entry_kind(e) != .Distance {
				r.err = .Malformed
				break
			}
			d.distance = entry_value(e)
			d.extra_bits = entry_extra(e)
			d.phase = .Distance_Extra
		case .Distance_Extra:
			value, ok := inflate_bits(d, input, r, d.extra_bits)
			if !ok {
				need_input = true
				break
			}
			d.distance += int(value)
			if d.distance > d.history_size + r.produced {
				r.err = .Malformed
				break
			}
			d.phase = .Copy
		case .Copy:
			if d.remaining == 0 {
				d.phase = .Symbol
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
			n := min(d.remaining, len(output) - r.produced, work_limit - r.work + 1)
			n = int(min(u64(n), d.max_decoded_bytes - d.decoded_bytes))
			inflate_copy(d, output, r.produced, d.distance, n)
			r.produced += n; r.work += n - 1
			d.decoded_bytes += u64(n)
			d.remaining -= n
		}

		if r.err != .None {
			inflate_fail(d, r)
			return
		}
		if need_input {
			if final_input {
				r.err = .Truncated
				inflate_fail(d, r)
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
}

@(private)
inflate_fail :: proc(d: ^Inflate_Decoder, r: ^Decode_Result) {
	d.error = r.err
	d.phase = .Failed
}

// Adds what this step produced to the history later steps copy from.
@(private)
inflate_remember :: proc(d: ^Inflate_Decoder, produced: []u8) {
	n := len(produced)
	if n == 0 {
		return
	}
	if n >= INFLATE_WINDOW_SIZE {
		copy(d.history[:], produced[n - INFLATE_WINDOW_SIZE:])
		d.history_at = 0
		d.history_size = INFLATE_WINDOW_SIZE
		return
	}
	first := min(n, INFLATE_WINDOW_SIZE - d.history_at)
	copy(d.history[d.history_at:], produced[:first])
	copy(d.history[:], produced[first:])
	d.history_at = (d.history_at + n) & WINDOW_MASK
	d.history_size = min(d.history_size + n, INFLATE_WINDOW_SIZE)
}

// Copies `count` bytes of a match to output[at:]. Its source starts `distance`
// bytes back: in the history while that reaches before this step's output, then
// in the output itself. The caller has checked the distance and the room.
@(private)
inflate_copy :: proc(d: ^Inflate_Decoder, output: []u8, at, distance, count: int) #no_bounds_check {
	done := 0
	if distance > at {
		before := distance - at
		from := d.history_at - before
		done = min(count, before)
		for i in 0 ..< done {
			output[at + i] = d.history[(from + i) & WINDOW_MASK]
		}
	}
	// The rest overlaps what is being written whenever distance < count.
	for i in done ..< count {
		output[at + i] = output[at + i - distance]
	}
}

// Moves the next input byte into the bit buffer, if there is one within the encoded ceiling.
@(private)
inflate_pull :: #force_inline proc(d: ^Inflate_Decoder, input: []u8, r: ^Decode_Result) -> bool {
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

// Takes `count` bits, pulling a byte only while there are too few. Fewer than
// eight bits are left behind, so nothing past this value has been read.
@(private)
inflate_bits :: proc(d: ^Inflate_Decoder, input: []u8, r: ^Decode_Result, count: u8) -> (value: u32, ok: bool) {
	for d.bit_count < count {
		if !inflate_pull(d, input, r) {
			return 0, false
		}
	}
	value = u32(d.bit_buffer & (u64(1) << count - 1))
	d.bit_buffer >>= count
	d.bit_count -= count
	return value, true
}

// Decodes one code. The bits in hand, padded with zeros, index the table: the
// entry found is the code they begin, and it is the code once it needs no more
// bits than are in hand. Only then is another byte left unread, so a code is
// never read past its last bit. Not ok with no error set means more input.
@(private)
inflate_code :: proc(d: ^Inflate_Decoder, table: []Entry, $ROOT: uint, input: []u8, r: ^Decode_Result) -> (e: Entry, ok: bool) #no_bounds_check {
	for {
		e = table[d.bit_buffer & (1 << ROOT - 1)]
		need := entry_bits(e)
		if entry_kind(e) == .Sub {
			e = table[entry_value(e) + int(d.bit_buffer >> ROOT & (u64(1) << entry_extra(e) - 1))]
			need = u8(ROOT) + entry_bits(e)
		}
		if need <= d.bit_count {
			d.bit_buffer >>= need
			d.bit_count -= need
			return e, true
		}
		if !inflate_pull(d, input, r) {
			return 0, false
		}
	}
}

// Decodes symbols for as long as a whole match fits the input in hand, the output
// room and the work budget, and leaves the rest to the careful path. It reads up
// to eight bytes ahead and returns every whole byte it did not use.
@(private)
inflate_fast :: proc(d: ^Inflate_Decoder, input, output: []u8, work_limit: int, r: ^Decode_Result) #no_bounds_check {
	// Neither ceiling can be crossed: the loop only sees what is left of them.
	in_end := int(min(u64(len(input) - r.consumed), d.max_encoded_bytes - d.encoded_bytes)) + r.consumed
	out_end := int(min(u64(len(output) - r.produced), d.max_decoded_bytes - d.decoded_bytes)) + r.produced
	// A refill loads eight bytes; a match writes up to MATCH_MAX bytes in blocks of eight.
	if in_end - r.consumed < 8 || out_end - r.produced < MATCH_MAX + 8 || work_limit - r.work < MATCH_MAX + 1 {
		return
	}

	ip, op, work := r.consumed, r.produced, r.work
	bits := d.bit_buffer
	count := u64(d.bit_count)
	source := raw_data(input)
	target := raw_data(output)
	literals := &d.literals
	distances := &d.distances
	available := d.history_size

	loop: for in_end - ip >= 8 && out_end - op >= MATCH_MAX + 8 && work_limit - work >= MATCH_MAX + 1 {
		// Top up to at least 56 bits. The eighth byte may be loaded without being
		// counted; the next refill loads it again in the same place.
		bits |= u64(intrinsics.unaligned_load((^u64le)(&source[ip]))) << count
		ip += int((63 - count) >> 3)
		count |= 56

		e := literals[bits & (1 << LITERAL_ROOT - 1)]
		if entry_kind(e) == .Sub {
			bits >>= LITERAL_ROOT; count -= LITERAL_ROOT
			e = literals[entry_value(e) + int(bits & (u64(1) << entry_extra(e) - 1))]
		}
		bits >>= entry_bits(e); count -= u64(entry_bits(e))

		if entry_kind(e) == .Literal {
			target[op] = u8(e >> 16)
			op += 1; work += 1
			// A literal took at most 15 of at least 56 bits: two more fit.
			for _ in 0 ..< 2 {
				e = literals[bits & (1 << LITERAL_ROOT - 1)]
				if entry_kind(e) != .Literal {
					break
				}
				bits >>= entry_bits(e); count -= u64(entry_bits(e))
				target[op] = u8(e >> 16)
				op += 1; work += 1
			}
			continue
		}
		if entry_kind(e) == .End {
			d.phase = .End if d.last_block else .Block
			break
		}
		if entry_kind(e) != .Length {
			r.err = .Malformed
			break
		}
		length := entry_value(e) + int(bits & (u64(1) << entry_extra(e) - 1))
		bits >>= entry_extra(e); count -= u64(entry_extra(e))

		e = distances[bits & (1 << DISTANCE_ROOT - 1)]
		if entry_kind(e) == .Sub {
			bits >>= DISTANCE_ROOT; count -= DISTANCE_ROOT
			e = distances[entry_value(e) + int(bits & (u64(1) << entry_extra(e) - 1))]
		}
		bits >>= entry_bits(e); count -= u64(entry_bits(e))
		if entry_kind(e) != .Distance {
			r.err = .Malformed
			break
		}
		distance := entry_value(e) + int(bits & (u64(1) << entry_extra(e) - 1))
		bits >>= entry_extra(e); count -= u64(entry_extra(e))

		if distance > available + op {
			r.err = .Malformed
			break
		}
		if distance >= 8 && distance <= op {
			// Blocks of eight may overlap their own output only behind the read.
			from := op - distance
			for i := 0; i < length; i += 8 {
				intrinsics.unaligned_store((^u64)(&target[op + i]), intrinsics.unaligned_load((^u64)(&target[from + i])))
			}
		} else {
			inflate_copy(d, output, op, distance, length)
		}
		op += length; work += length + 1
	}

	// Whole bytes still in the buffer were all loaded by this call: what the
	// careful path left behind was part of a code longer than those bits, and the
	// first symbol decoded here consumed it.
	ip -= int(count >> 3)
	count &= 7
	d.bit_buffer = bits & (u64(1) << count - 1)
	d.bit_count = u8(count)
	d.encoded_bytes += u64(ip - r.consumed)
	d.decoded_bytes += u64(op - r.produced)
	r.consumed, r.produced, r.work = ip, op, work
}

// Builds a two-level decoding table for a canonical Huffman code. The code must
// be complete; a literal or distance code may instead be a single code of one
// bit, and a distance code may be empty for a block of literals only.
@(private)
inflate_build :: proc(table: []Entry, lengths: []u8, $ROOT: uint, alphabet: Alphabet) -> bool #no_bounds_check {
	counts: [CODE_LENGTH_MAX + 1]int
	for length in lengths {
		counts[length] += 1
	}
	// A hole is known to be one only with all the bits of its level in hand.
	for &e in table[:1 << ROOT] {
		e = entry(.Invalid, 0) | Entry(ROOT)
	}
	if counts[0] == len(lengths) {
		return alphabet == .Distance
	}

	left, longest := 1, 0
	for length in 1 ..= CODE_LENGTH_MAX {
		left = left << 1 - counts[length]
		if left < 0 {
			return false
		}
		if counts[length] > 0 {
			longest = length
		}
	}
	if left > 0 && (alphabet == .Precode || longest != 1) {
		return false
	}

	next: [CODE_LENGTH_MAX + 1]u32
	code := u32(0)
	for length in 1 ..= CODE_LENGTH_MAX {
		code = (code + u32(counts[length - 1] if length > 1 else 0)) << 1
		next[length] = code
	}
	// Codes are read low bit first.
	reversed: [LITERAL_SYMBOLS]u16
	for length, symbol in lengths {
		if length != 0 {
			reversed[symbol] = intrinsics.reverse_bits(u16(next[length])) >> (16 - uint(length))
			next[length] += 1
		}
	}

	depth: [1 << ROOT]u8
	start: [1 << ROOT]u16
	if longest > int(ROOT) {
		for length, symbol in lengths {
			if uint(length) > ROOT {
				prefix := reversed[symbol] & u16(1 << ROOT - 1)
				depth[prefix] = max(depth[prefix], length - u8(ROOT))
			}
		}
		free := 1 << ROOT
		for prefix in 0 ..< 1 << ROOT {
			if depth[prefix] == 0 {
				continue
			}
			size := 1 << depth[prefix]
			if free + size > len(table) {
				return false
			}
			for &e in table[free:][:size] {
				e = entry(.Invalid, 0) | Entry(depth[prefix])
			}
			table[prefix] = entry(.Sub, u32(free), u32(depth[prefix])) | Entry(ROOT)
			start[prefix] = u16(free)
			free += size
		}
	}

	for length, symbol in lengths {
		if length == 0 {
			continue
		}
		e: Entry
		switch alphabet {
		case .Precode:
			e = entry(.Code_Length, u32(symbol))
		case .Literal:
			switch {
			case symbol < 256:
				e = entry(.Literal, u32(symbol))
			case symbol == 256:
				e = entry(.End, 0)
			case symbol < 257 + len(LENGTH_BASE):
				e = entry(.Length, u32(LENGTH_BASE[symbol - 257]), u32(LENGTH_EXTRA[symbol - 257]))
			case:
				e = entry(.Invalid, 0)
			}
		case .Distance:
			if symbol < len(DISTANCE_BASE) {
				e = entry(.Distance, u32(DISTANCE_BASE[symbol]), u32(DISTANCE_EXTRA[symbol]))
			} else {
				e = entry(.Invalid, 0)
			}
		}
		if uint(length) <= ROOT {
			e |= Entry(length)
			for i := int(reversed[symbol]); i < 1 << ROOT; i += 1 << uint(length) {
				table[i] = e
			}
		} else {
			prefix := reversed[symbol] & u16(1 << ROOT - 1)
			e |= Entry(length) - Entry(ROOT)
			for i := int(reversed[symbol] >> ROOT); i < 1 << depth[prefix]; i += 1 << (uint(length) - ROOT) {
				table[int(start[prefix]) + i] = e
			}
		}
	}
	return true
}
