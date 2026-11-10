package compress_zlib

import "base:intrinsics"
import "core:compress"

Inflate_Phase :: enum {
	Uninitialized, Block, Stored_Length, Stored_Copy, Dynamic_Header,
	Code_Lengths, Build_Code_Lengths, Dynamic_Lengths, Repeat_Lengths,
	Build_Tables, Symbol, Literal, Length_Extra, Distance, Distance_Extra,
	Copy, End, Failed,
}

// Fixed storage: no allocator, feed borrow, or complete-output buffer. History
// and parsing state belong exclusively to the caller, including between steps.
Inflate_State :: struct {
	phase: Inflate_Phase,
	encoded_bytes, decoded_bytes: u64,
	max_encoded_bytes, max_decoded_bytes: u64,
	error: compress.Decode_Error,
	final_declared: bool,
	bits: u64,
	bit_count: u8,
	last_block: bool,
	history: [32768]u8,
	history_at, history_size: int,
	literal_table, distance_table, code_table: Huffman_Table,
	lengths: [320]u8,
	code_lengths: [19]u8,
	hlit, hdist, hclen, index: int,
	prefix: u16,
	prefix_bits: u8,
	repeat_symbol: u16,
	remaining, distance: int,
	extra_bits: u8,
	literal: u8,
}

// Initialization also resets a terminal decoder. Zero byte ceilings are valid
// (notably for an empty member after an aggregate decoded budget is exhausted).
inflate_init :: proc(s: ^Inflate_State, max_encoded_bytes, max_decoded_bytes: u64) -> compress.Decode_Error {
	if s == nil { return .Invalid_State }
	s^ = Inflate_State{phase = .Block, max_encoded_bytes = max_encoded_bytes,
		max_decoded_bytes = max_decoded_bytes}
	return .None
}

@(private)
inflate_bits :: proc(s: ^Inflate_State, input: []u8, r: ^compress.Decode_Result, n: u8) -> (u32, bool) {
	for s.bit_count < n {
		if r.consumed == len(input) { return 0, false }
		if s.encoded_bytes == s.max_encoded_bytes { r.err = .Encoded_Limit; return 0, false }
		s.bits |= u64(input[r.consumed]) << s.bit_count
		s.bit_count += 8
		r.consumed += 1
		s.encoded_bytes += 1
	}
	v := u32(s.bits & ((u64(1) << n)-1))
	s.bits >>= n
	s.bit_count -= n
	return v, true
}

// RFC 1951 permits a one-symbol literal/distance tree, and an unused
// empty distance tree. Code-length trees must be complete.
@(private)
inflate_build :: proc(t: ^Huffman_Table, lengths: []u8, codes: bool, distance := false) -> bool {
	counts: [16]int
	used := 0
	for n in lengths {
		if n > 15 { return false }
		if n != 0 { counts[n] += 1; used += 1 }
	}
	left := 1
	for n in 1..=15 {
		left = (left << 1)-counts[n]
		if left < 0 { return false }
	}
	if left != 0 && (codes || !(used == 1 && counts[1] == 1) && !(distance && used == 0)) {
		return false
	}
	return build_huffman(t, lengths) == nil
}

// Decode at most one code bit per call: arbitrarily partitioned input cannot
// cause speculative reads into a following gzip trailer.
@(private)
inflate_symbol :: proc(s: ^Inflate_State, t: ^Huffman_Table, input: []u8,
	r: ^compress.Decode_Result) -> (symbol: u16, ready: bool) {
	bit, ok := inflate_bits(s, input, r, 1)
	if !ok { return }
	s.prefix = (s.prefix << 1) | u16(bit)
	s.prefix_bits += 1
	n := int(s.prefix_bits)
	first := int(t.firstsymbol[n])
	count := 0
	if n < 16 { count = int(t.firstsymbol[n+1])-first }
	if n == 16 { count = 0 }
	delta := int(s.prefix)-int(t.firstcode[n])
	if delta >= 0 && delta < count {
		symbol = t.value[first+delta]
		s.prefix = 0; s.prefix_bits = 0
		return symbol, true
	}
	if n == 15 { r.err = .Malformed }
	return
}

@(private)
inflate_emit :: proc(s: ^Inflate_State, output: []u8, r: ^compress.Decode_Result, value: u8) -> bool {
	if s.decoded_bytes == s.max_decoded_bytes { r.err = .Decoded_Limit; return false }
	if r.produced == len(output) { r.status = .Need_Output; return false }
	output[r.produced] = value
	r.produced += 1
	s.decoded_bytes += 1
	s.history[s.history_at] = value
	s.history_at = (s.history_at+1) & 32767
	s.history_size = min(s.history_size+1, 32768)
	return true
}

// Raw DEFLATE stops exactly at its final block, leaving following bytes
// unconsumed. Done does not require final_input (envelope decoders need the
// trailer). final_input means this slice contains all remaining input; callers
// resubmit its unconsumed suffix with final_input=true after backpressure/work
// yields. Once declared, final_input cannot be withdrawn. Errors are terminal;
// invalid arguments/overlap are rejected without changing state or buffers.
inflate_step :: proc(s: ^Inflate_State, input, output: []u8, final_input: bool,
	work_limit := 4096) -> (r: compress.Decode_Result) {
	r.status = .Progress
	if s == nil || s.phase == .Uninitialized { r.err = .Invalid_State; return }
	if work_limit <= 0 || work_limit > compress.DECODE_MAX_WORK { r.err = .Invalid_Config; return }
	if compress.decode_buffers_overlap(input, output) { r.err = .Overlapping_Buffers; return }
	if s.phase == .Failed { r.err = s.error; return }
	if s.final_declared && !final_input { r.err = .Invalid_State; return }
	if s.phase == .End { r.status = .Done; return }
	s.final_declared = final_input
	for r.work < work_limit {
		r.work += 1
		need_input := false
		#partial switch s.phase {
		case .Block:
			v, ok := inflate_bits(s, input, &r, 3)
			if !ok { need_input = true; break }
			s.last_block = v & 1 != 0
			switch v >> 1 {
			case 0:
				s.bits = 0; s.bit_count = 0; s.phase = .Stored_Length
			case 1:
				if !inflate_build(&s.literal_table, Z_FIXED_LENGTH[:], false) ||
					!inflate_build(&s.distance_table, Z_FIXED_DIST[:], false, true) { r.err = .Malformed; break }
				s.phase = .Symbol
			case 2: s.phase = .Dynamic_Header
			case 3: r.err = .Malformed
			}
		case .Stored_Length:
			v, ok := inflate_bits(s, input, &r, 32)
			if !ok { need_input = true; break }
			if u16(v) != ~u16(v >> 16) { r.err = .Malformed; break }
			s.remaining = int(v & 0xffff); s.phase = .Stored_Copy
		case .Stored_Copy:
			if s.remaining == 0 {
				s.phase = .End if s.last_block else .Block
				break
			}
			if s.decoded_bytes == s.max_decoded_bytes { r.err = .Decoded_Limit; break }
			if r.produced == len(output) { r.status = .Need_Output; return }
			v, ok := inflate_bits(s, input, &r, 8)
			if !ok { need_input = true; break }
			if inflate_emit(s, output, &r, u8(v)) { s.remaining -= 1 }
		case .Dynamic_Header:
			v, ok := inflate_bits(s, input, &r, 14)
			if !ok { need_input = true; break }
			s.hlit = int(v & 31)+257; s.hdist = int((v >> 5) & 31)+1
			s.hclen = int((v >> 10) & 15)+4
			if s.hlit > 286 { r.err = .Malformed; break }
			s.code_lengths = {}; s.index = 0; s.phase = .Code_Lengths
		case .Code_Lengths:
			if s.index == s.hclen { s.phase = .Build_Code_Lengths; break }
			v, ok := inflate_bits(s, input, &r, 3)
			if !ok { need_input = true; break }
			s.code_lengths[Z_LENGTH_DEZIGZAG[s.index]] = u8(v); s.index += 1
		case .Build_Code_Lengths:
			if !inflate_build(&s.code_table, s.code_lengths[:], true) { r.err = .Malformed; break }
			s.index = 0; s.phase = .Dynamic_Lengths
		case .Dynamic_Lengths:
			if s.index == s.hlit+s.hdist { s.phase = .Build_Tables; break }
			v, ok := inflate_symbol(s, &s.code_table, input, &r)
			if !ok { need_input = r.consumed == len(input) && s.bit_count == 0; break }
			if v < 16 { s.lengths[s.index] = u8(v); s.index += 1 } else {
				if v > 18 || (v == 16 && s.index == 0) { r.err = .Malformed; break }
				s.repeat_symbol = v; s.phase = .Repeat_Lengths
			}
		case .Repeat_Lengths:
			n := u8(2) if s.repeat_symbol == 16 else u8(3) if s.repeat_symbol == 17 else u8(7)
			v, ok := inflate_bits(s, input, &r, n)
			if !ok { need_input = true; break }
			count := int(v)+3 if s.repeat_symbol != 18 else int(v)+11
			if count > s.hlit+s.hdist-s.index { r.err = .Malformed; break }
			value := u8(0)
			if s.repeat_symbol == 16 { value = s.lengths[s.index-1] }
			for i in 0..<count { s.lengths[s.index+i] = value }
			s.index += count; s.phase = .Dynamic_Lengths
		case .Build_Tables:
			if s.lengths[256] == 0 || !inflate_build(&s.literal_table, s.lengths[:s.hlit], false) ||
				!inflate_build(&s.distance_table, s.lengths[s.hlit:s.hlit+s.hdist], false, true) { r.err = .Malformed; break }
			s.phase = .Symbol
		case .Symbol:
			v, ok := inflate_symbol(s, &s.literal_table, input, &r)
			if !ok { need_input = r.consumed == len(input) && s.bit_count == 0; break }
			if v < 256 { s.literal = u8(v); s.phase = .Literal } else if v == 256 {
				s.phase = .End if s.last_block else .Block
				if s.phase == .End { s.bits = 0; s.bit_count = 0 }
			} else if v <= 285 {
				s.remaining = int(Z_LENGTH_BASE[v-257]); s.extra_bits = Z_LENGTH_EXTRA[v-257]
				s.phase = .Length_Extra
			} else { r.err = .Malformed }
		case .Literal:
			if !inflate_emit(s, output, &r, s.literal) {
				if r.err == .None { return }; break
			}
			s.phase = .Symbol
		case .Length_Extra:
			v, ok := inflate_bits(s, input, &r, s.extra_bits)
			if !ok { need_input = true; break }
			s.remaining += int(v); s.phase = .Distance
		case .Distance:
			v, ok := inflate_symbol(s, &s.distance_table, input, &r)
			if !ok { need_input = r.consumed == len(input) && s.bit_count == 0; break }
			if v > 29 { r.err = .Malformed; break }
			s.distance = int(Z_DIST_BASE[v]); s.extra_bits = Z_DIST_EXTRA[v]
			s.phase = .Distance_Extra
		case .Distance_Extra:
			v, ok := inflate_bits(s, input, &r, s.extra_bits)
			if !ok { need_input = true; break }
			s.distance += int(v)
			if s.distance > s.history_size { r.err = .Malformed; break }
			s.phase = .Copy
		case .Copy:
			if s.remaining == 0 { s.phase = .Symbol; break }
			value := s.history[(s.history_at-s.distance+32768) & 32767]
			if !inflate_emit(s, output, &r, value) {
				if r.err == .None { return }; break
			}
			s.remaining -= 1
		case .End: r.status = .Done; return
		case: r.err = .Invalid_State
		}
		if r.err != .None { s.error = r.err; s.phase = .Failed; return }
		if need_input {
			if final_input { r.err = .Truncated; s.error = r.err; s.phase = .Failed } else { r.status = .Need_Input }
			return
		}
		if s.phase == .End { r.status = .Done; return }
	}
	return
}

// The incremental decoder walks canonical codes one bit at a time. These
// tables and the canonical table builder were shared with the one-shot
// inflater until it moved to `core:compress/deflate`; they stay here as the
// decoder's own helpers.
Z_LENGTH_BASE := [31]u16{
	3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,
	67,83,99,115,131,163,195,227,258,0,0,
}

Z_LENGTH_EXTRA := [31]u8{
	0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0,
}

Z_DIST_BASE := [32]u16{
	1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,
	257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577,0,0,
}

Z_DIST_EXTRA := [32]u8{
	0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,0,0,
}

Z_LENGTH_DEZIGZAG := []u8{
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
}

Z_FIXED_LENGTH := [288]u8{
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
	9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
	9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
	9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,8,8,8,8,8,8,8,8,
}

Z_FIXED_DIST := [32]u8{
	5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
}

HUFFMAN_MAX_BITS :: 16
ZFAST_BITS       :: 9

Huffman_Table :: struct {
	fast:        [1 << ZFAST_BITS]u16,
	firstcode:   [17]u16,
	maxcode:     [17]int,
	firstsymbol: [17]u16,
	size:        [288]u8,
	value:       [288]u16,
}

z_bit_reverse :: #force_inline proc(n: u16, bits: u8) -> (r: u16) {
	assert(bits <= 16)
	r = intrinsics.reverse_bits(n)

	r >>= (16 - bits)
	return
}

build_huffman :: #force_no_inline proc(z: ^Huffman_Table, code_lengths: []u8) -> (err: compress.Error) {
	sizes:     [HUFFMAN_MAX_BITS+1]int
	next_code: [HUFFMAN_MAX_BITS+1]int

	k := int(0)

	z.fast = {}

	for v in code_lengths {
		sizes[v] += 1
	}
	sizes[0] = 0

	for i in 1 ..< HUFFMAN_MAX_BITS {
		if sizes[i] > (1 << uint(i)) {
			return .Huffman_Bad_Sizes
		}
	}
	code := int(0)

	for i in 1 ..= HUFFMAN_MAX_BITS {
		next_code[i]     = code
		z.firstcode[i]   = u16(code)
		z.firstsymbol[i] = u16(k)
		code = code + sizes[i]
		if sizes[i] != 0 {
			if code - 1 >= (1 << u16(i)) {
				return .Huffman_Bad_Code_Lengths
			}
		}
		z.maxcode[i] = code << (HUFFMAN_MAX_BITS - uint(i))
		code <<= 1
		k += int(sizes[i])
	}

	z.maxcode[HUFFMAN_MAX_BITS] = 0x10000 // Sentinel
	c: int

	for v, ci in code_lengths {
		if v != 0 {
			c = next_code[v] - int(z.firstcode[v]) + int(z.firstsymbol[v])
			fastv := u16((u16(v) << 9) | u16(ci))
			z.size[c]  = u8(v)
			z.value[c] = u16(ci)
			if v <= ZFAST_BITS {
				j := z_bit_reverse(u16(next_code[v]), v)
				for j < (1 << ZFAST_BITS) {
					z.fast[j] = fastv
					j += (1 << v)
				}
			}
			next_code[v] += 1
		}
	}
	return nil
}
