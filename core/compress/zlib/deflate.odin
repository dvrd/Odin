package compress_zlib

import "base:intrinsics"
import "core:compress"
import "core:math/bits"
import "core:mem"

// DEFLATE (RFC 1951) compression: hash-chain LZ77 with greedy or lazy matching,
// dynamic or fixed Huffman blocks, and a stored fallback, so the output never
// exceeds the input by more than a few bytes.

Level :: enum u8 {
	Store   = 0,
	Fastest = 1,
	Fast    = 3,
	Default = 6,
	Best    = 9,
	// Cost-model driven optimal parsing; much slower, intended for data that
	// is compressed once and served many times.
	Optimal = 10,
}

WINDOW_SIZE :: 32768
MATCH_MIN :: 3
MATCH_MAX :: 258
HASH_BITS :: 15
HASH_SIZE :: 1 << HASH_BITS
TOKEN_MAX :: 1 << 15

LITERAL_SYMBOLS :: 286
DISTANCE_SYMBOLS :: 30

Strategy :: struct {
	good_length: int,
	max_lazy:    int,
	nice_length: int,
	max_chain:   int,
	lazy:        bool,
}

STRATEGIES := [10]Strategy {
	{},
	{4, 4, 8, 4, false},
	{4, 5, 16, 8, false},
	{4, 6, 32, 32, false},
	{4, 4, 16, 16, true},
	{8, 16, 32, 32, true},
	{8, 16, 128, 128, true},
	{8, 32, 128, 256, true},
	{32, 128, 258, 1024, true},
	{32, 258, 258, 4096, true},
}

CODE_LENGTH_ORDER := [19]u8{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

LENGTH_BASE := [29]u16 {
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
}

LENGTH_EXTRA := [29]u8{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}

DISTANCE_EXTRA := [30]u8 {
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
}

Token :: struct {
	distance: u16, // 0 marks a literal
	value:    u16, // literal byte or match length
}

Encoder :: struct {
	src:         []u8,
	out:         []u8,
	out_len:     int,
	accumulator: u64,
	acc_bits:    uint,
	strategy:    Strategy,
	head:        [HASH_SIZE]i32,
	prev:        [WINDOW_SIZE]i32,
	token_buffer: [TOKEN_MAX]Token,
	tokens:      []Token,
	token_count: int,
	block_start: int,
	literal_freq:  [LITERAL_SYMBOLS]u32,
	distance_freq: [DISTANCE_SYMBOLS]u32,
	literal_len:   [LITERAL_SYMBOLS]u8,
	distance_len:  [DISTANCE_SYMBOLS]u8,
	literal_code:  [LITERAL_SYMBOLS]u16,
	distance_code: [DISTANCE_SYMBOLS]u16,
	huffman:       Huffman_Scratch,
}

deflate_bound :: proc(size: int) -> int {
	return size + 5 * (size / 16384 + 2) + 16
}

// Raw DEFLATE stream (no zlib or gzip framing).
deflate :: proc(src: []u8, level := Level.Default, allocator := context.allocator) -> (output: []u8, err: compress.Error) {
	encoder, allocation_error := new(Encoder, allocator)

	if allocation_error != nil {
		return nil, allocation_error
	}

	defer free(encoder, allocator)

	scratch: []u8
	scratch, allocation_error = make([]u8, deflate_bound(len(src)), allocator)

	if allocation_error != nil {
		return nil, allocation_error
	}

	defer delete(scratch, allocator)

	written := deflate_into(encoder, src, scratch, level, allocator) or_return
	output, allocation_error = make([]u8, written, allocator)

	if allocation_error != nil {
		return nil, allocation_error
	}

	copy(output, scratch[:written])

	return output, nil
}

// Compresses into `dst`, which must hold at least `deflate_bound(len(src))` bytes.
deflate_into :: proc(
	e: ^Encoder,
	src, dst: []u8,
	level: Level,
	allocator := context.allocator,
) -> (
	written: int,
	err: compress.Error,
) {
	assert(len(dst) >= deflate_bound(len(src)))

	e.tokens = e.token_buffer[:]

	e.src = src
	e.out = dst
	e.out_len = 0
	e.accumulator = 0
	e.acc_bits = 0
	e.token_count = 0
	e.block_start = 0

	switch {
	case level == .Store:
		write_stored(e, 0, len(src), true)
	case level == .Optimal:
		optimal_parse(e, allocator) or_return
	case:
		setup_strategy(e, level)
		mem.set(&e.head, 0xff, size_of(e.head))

		if e.strategy.lazy {
			parse_lazy(e)
		} else {
			parse_greedy(e)
		}
	}

	finish_bits(e)

	return e.out_len, nil
}

@(private)
setup_strategy :: proc(e: ^Encoder, level: Level) {
	index := clamp(int(level), 1, 9)
	e.strategy = STRATEGIES[index]
}

// ---------------------------------------------------------------- bit output

@(private)
put_bits :: #force_inline proc(e: ^Encoder, value: u32, count: uint) {
	e.accumulator |= u64(value) << e.acc_bits
	e.acc_bits += count

	for e.acc_bits >= 8 {
		e.out[e.out_len] = u8(e.accumulator)
		e.out_len += 1
		e.accumulator >>= 8
		e.acc_bits -= 8
	}
}

@(private)
finish_bits :: proc(e: ^Encoder) {
	if e.acc_bits > 0 {
		e.out[e.out_len] = u8(e.accumulator)
		e.out_len += 1
		e.accumulator = 0
		e.acc_bits = 0
	}
}

@(private)
align_bits :: proc(e: ^Encoder) {
	if e.acc_bits > 0 {
		put_bits(e, 0, 8 - e.acc_bits)
	}
}

// -------------------------------------------------------- symbol arithmetic

@(private)
length_symbol :: #force_inline proc(length: int) -> (symbol: int, extra_bits: uint, extra: u32) {
	offset := u32(length - MATCH_MIN)

	if offset < 8 {
		return int(offset), 0, 0
	}

	if offset == 255 {
		return 28, 0, 0
	}

	shift := uint(bits.len_u32(offset) - 3)
	symbol = int(4 * u32(shift) + 4 + ((offset >> shift) & 3))
	extra_bits = shift
	extra = offset & ((1 << shift) - 1)

	return
}

@(private)
distance_symbol :: #force_inline proc(distance: int) -> (symbol: int, extra_bits: uint, extra: u32) {
	value := u32(distance - 1)

	if value < 4 {
		return int(value), 0, 0
	}

	top := uint(bits.len_u32(value) - 1)
	symbol = int(2 * top + uint((value >> (top - 1)) & 1))
	extra_bits = top - 1
	extra = value & ((1 << extra_bits) - 1)

	return
}

// ------------------------------------------------------------- block output

@(private)
emit_literal :: #force_inline proc(e: ^Encoder, byte: u8) {
	e.tokens[e.token_count] = {0, u16(byte)}
	e.token_count += 1
}

@(private)
emit_match :: #force_inline proc(e: ^Encoder, length, distance: int) {
	e.tokens[e.token_count] = {u16(distance), u16(length)}
	e.token_count += 1
}

// Writes the pending tokens as one block covering src[block_start:end].
@(private)
flush_block :: proc(e: ^Encoder, end: int, final: bool) {
	if e.token_count == 0 && !final {
		return
	}

	header := Dynamic_Header{}
	dynamic_cost, fixed_cost, stored_cost := measure_block(e, end - e.block_start, &header)

	switch {
	case stored_cost <= dynamic_cost && stored_cost <= fixed_cost:
		write_stored(e, e.block_start, end, final)
	case fixed_cost <= dynamic_cost:
		put_bits(e, final ? 1 : 0, 1)
		put_bits(e, 1, 2)
		set_fixed_codes(e)
		write_tokens(e)
	case:
		put_bits(e, final ? 1 : 0, 1)
		put_bits(e, 2, 2)
		write_dynamic_header(e, &header)
		huffman_codes(e.literal_len[:], e.literal_code[:])
		huffman_codes(e.distance_len[:], e.distance_code[:])
		write_tokens(e)
	}

	e.token_count = 0
	e.block_start = end
}

// Costs in bits of writing the pending tokens as each block type. Leaves the
// dynamic code lengths and `header` ready for the dynamic encoding.
@(private)
measure_block :: proc(e: ^Encoder, span: int, header: ^Dynamic_Header) -> (dynamic_cost, fixed_cost, stored_cost: u64) {
	for index in 0 ..< LITERAL_SYMBOLS {
		e.literal_freq[index] = 0
	}

	for index in 0 ..< DISTANCE_SYMBOLS {
		e.distance_freq[index] = 0
	}

	extra_bit_total: u64

	for token in e.tokens[:e.token_count] {
		if token.distance == 0 {
			e.literal_freq[token.value] += 1
			continue
		}

		length_code, length_extra_bits, _ := length_symbol(int(token.value))
		distance_code, distance_extra_bits, _ := distance_symbol(int(token.distance))
		e.literal_freq[257 + length_code] += 1
		e.distance_freq[distance_code] += 1
		extra_bit_total += u64(length_extra_bits) + u64(distance_extra_bits)
	}

	e.literal_freq[256] = 1

	// Dynamic Huffman cost.
	ensure_two_symbols(e.literal_freq[:])
	ensure_two_symbols(e.distance_freq[:])
	huffman_lengths(&e.huffman, e.literal_freq[:], 15, e.literal_len[:])
	huffman_lengths(&e.huffman, e.distance_freq[:], 15, e.distance_len[:])

	plan_dynamic_header(e, header)

	body: u64 = extra_bit_total

	for symbol in 0 ..< LITERAL_SYMBOLS {
		body += u64(e.literal_freq[symbol]) * u64(e.literal_len[symbol])
	}

	for symbol in 0 ..< DISTANCE_SYMBOLS {
		body += u64(e.distance_freq[symbol]) * u64(e.distance_len[symbol])
	}

	dynamic_cost = u64(3 + 14) + header.bits + body

	fixed_body: u64 = extra_bit_total

	for symbol in 0 ..< LITERAL_SYMBOLS {
		fixed_body += u64(e.literal_freq[symbol]) * u64(fixed_literal_length(symbol))
	}

	for symbol in 0 ..< DISTANCE_SYMBOLS {
		fixed_body += u64(e.distance_freq[symbol]) * 5
	}

	fixed_cost = u64(3) + fixed_body

	stored_chunks := max(1, (span + 65534) / 65535)
	stored_cost = u64(span) * 8 + u64(stored_chunks) * 40 + 7

	return
}

@(private)
ensure_two_symbols :: proc(frequencies: []u32) {
	nonzero := 0

	for frequency in frequencies {
		if frequency != 0 {
			nonzero += 1
		}
	}

	for index := 0; nonzero < 2 && index < len(frequencies); index += 1 {
		if frequencies[index] == 0 {
			frequencies[index] = 1
			nonzero += 1
		}
	}
}

@(private)
fixed_literal_length :: proc(symbol: int) -> int {
	switch {
	case symbol <= 143:
		return 8
	case symbol <= 255:
		return 9
	case symbol <= 279:
		return 7
	}

	return 8
}

@(private)
set_fixed_codes :: proc(e: ^Encoder) {
	// Symbols 286 and 287 never occur but take part in code assignment.
	full: [288]u8
	codes: [288]u16

	for symbol in 0 ..< 288 {
		full[symbol] = u8(fixed_literal_length(symbol))
	}

	huffman_codes(full[:], codes[:])

	for symbol in 0 ..< LITERAL_SYMBOLS {
		e.literal_len[symbol] = full[symbol]
		e.literal_code[symbol] = codes[symbol]
	}

	for symbol in 0 ..< DISTANCE_SYMBOLS {
		e.distance_len[symbol] = 5
		e.distance_code[symbol] = u16(bits.reverse_bits(u32(symbol)) >> 27)
	}
}

@(private)
write_tokens :: proc(e: ^Encoder) {
	for token in e.tokens[:e.token_count] {
		if token.distance == 0 {
			put_bits(e, u32(e.literal_code[token.value]), uint(e.literal_len[token.value]))
			continue
		}

		length_code, length_extra_bits, length_extra := length_symbol(int(token.value))
		symbol := 257 + length_code
		put_bits(e, u32(e.literal_code[symbol]), uint(e.literal_len[symbol]))
		put_bits(e, length_extra, length_extra_bits)

		distance_code, distance_extra_bits, distance_extra := distance_symbol(int(token.distance))
		put_bits(e, u32(e.distance_code[distance_code]), uint(e.distance_len[distance_code]))
		put_bits(e, distance_extra, distance_extra_bits)
	}

	put_bits(e, u32(e.literal_code[256]), uint(e.literal_len[256]))
}

@(private)
write_stored :: proc(e: ^Encoder, start, end: int, final: bool) {
	position := start

	for {
		chunk := min(end - position, 65535)
		last := position + chunk >= end

		put_bits(e, final && last ? 1 : 0, 1)
		put_bits(e, 0, 2)
		align_bits(e)
		put_bits(e, u32(chunk), 16)
		put_bits(e, u32(~u16(chunk)), 16)

		copy(e.out[e.out_len:][:chunk], e.src[position:][:chunk])
		e.out_len += chunk
		position += chunk

		if last {
			break
		}
	}
}

// ------------------------------------------------------- dynamic block header

Dynamic_Header :: struct {
	literal_count:  int,
	distance_count: int,
	code_count:     int,
	run_symbols:    [320]u8,
	run_extra:      [320]u8,
	run_total:      int,
	code_freq:      [19]u32,
	code_len:       [19]u8,
	code_code:      [19]u16,
	bits:           u64,
}

@(private)
plan_dynamic_header :: proc(e: ^Encoder, header: ^Dynamic_Header) {
	header.literal_count = LITERAL_SYMBOLS

	for header.literal_count > 257 && e.literal_len[header.literal_count - 1] == 0 {
		header.literal_count -= 1
	}

	header.distance_count = DISTANCE_SYMBOLS

	for header.distance_count > 1 && e.distance_len[header.distance_count - 1] == 0 {
		header.distance_count -= 1
	}

	lengths: [LITERAL_SYMBOLS + DISTANCE_SYMBOLS]u8
	total := header.literal_count + header.distance_count

	for index in 0 ..< header.literal_count {
		lengths[index] = e.literal_len[index]
	}

	for index in 0 ..< header.distance_count {
		lengths[header.literal_count + index] = e.distance_len[index]
	}

	header.run_total = 0

	for index := 0; index < total; {
		value := lengths[index]
		run := 1

		for index + run < total && lengths[index + run] == value {
			run += 1
		}

		index += run

		if value == 0 {
			for run >= 11 {
				take := min(run, 138)
				push_run(header, 18, u8(take - 11))
				run -= take
			}

			if run >= 3 {
				push_run(header, 17, u8(run - 3))
				run = 0
			}

			for _ in 0 ..< run {
				push_run(header, 0, 0)
			}

			continue
		}

		push_run(header, value, 0)
		run -= 1

		for run >= 3 {
			take := min(run, 6)
			push_run(header, 16, u8(take - 3))
			run -= take
		}

		for _ in 0 ..< run {
			push_run(header, value, 0)
		}
	}

	for index in 0 ..< 19 {
		header.code_freq[index] = 0
	}

	for index in 0 ..< header.run_total {
		header.code_freq[header.run_symbols[index]] += 1
	}

	ensure_two_symbols(header.code_freq[:])
	huffman_lengths(&e.huffman, header.code_freq[:], 7, header.code_len[:])
	huffman_codes(header.code_len[:], header.code_code[:])

	header.code_count = 19

	for header.code_count > 4 && header.code_len[CODE_LENGTH_ORDER[header.code_count - 1]] == 0 {
		header.code_count -= 1
	}

	header.bits = u64(3 * header.code_count)

	for index in 0 ..< header.run_total {
		symbol := header.run_symbols[index]
		header.bits += u64(header.code_len[symbol])

		switch symbol {
		case 16:
			header.bits += 2
		case 17:
			header.bits += 3
		case 18:
			header.bits += 7
		}
	}
}

@(private)
push_run :: proc(header: ^Dynamic_Header, symbol, extra: u8) {
	header.run_symbols[header.run_total] = symbol
	header.run_extra[header.run_total] = extra
	header.run_total += 1
}

@(private)
write_dynamic_header :: proc(e: ^Encoder, header: ^Dynamic_Header) {
	put_bits(e, u32(header.literal_count - 257), 5)
	put_bits(e, u32(header.distance_count - 1), 5)
	put_bits(e, u32(header.code_count - 4), 4)

	for index in 0 ..< header.code_count {
		put_bits(e, u32(header.code_len[CODE_LENGTH_ORDER[index]]), 3)
	}

	for index in 0 ..< header.run_total {
		symbol := header.run_symbols[index]
		put_bits(e, u32(header.code_code[symbol]), uint(header.code_len[symbol]))

		switch symbol {
		case 16:
			put_bits(e, u32(header.run_extra[index]), 2)
		case 17:
			put_bits(e, u32(header.run_extra[index]), 3)
		case 18:
			put_bits(e, u32(header.run_extra[index]), 7)
		}
	}
}

// ---------------------------------------------------------------- match finder

@(private)
hash3 :: #force_inline proc(src: []u8, position: int) -> int {
	value := u32(src[position]) | u32(src[position + 1]) << 8 | u32(src[position + 2]) << 16

	return int((value * 0x1e35a7bd) >> (32 - HASH_BITS))
}

@(private)
insert_position :: #force_inline proc(e: ^Encoder, position: int) -> int {
	hash := hash3(e.src, position)
	head := int(e.head[hash])
	e.prev[position & (WINDOW_SIZE - 1)] = i32(head)
	e.head[hash] = i32(position)

	return head
}

@(private)
match_length :: #force_inline proc(src: []u8, a, b, limit: int) -> int {
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

// Longest match for `position` among earlier positions on its hash chain that
// is longer than `above`. Returns length 0 when none qualifies.
@(private)
find_match :: proc(e: ^Encoder, position, candidate_head, above, chain_limit: int) -> (length, distance: int) {
	limit := min(MATCH_MAX, len(e.src) - position)

	if limit < MATCH_MIN || above >= limit {
		return 0, 0
	}

	best := above
	candidate := candidate_head
	chain := chain_limit
	nice := min(e.strategy.nice_length, limit)

	for candidate >= 0 && chain > 0 {
		offset := position - candidate

		if offset <= 0 || offset > WINDOW_SIZE {
			break
		}

		if e.src[candidate + best] == e.src[position + best] {
			found := match_length(e.src, candidate, position, limit)

			if found > best {
				best = found
				length = found
				distance = offset

				if found >= nice {
					break
				}
			}
		}

		next := int(e.prev[candidate & (WINDOW_SIZE - 1)])

		if next >= candidate {
			break
		}

		candidate = next
		chain -= 1
	}

	return length, distance
}

// ------------------------------------------------------------------- parsers

@(private)
parse_greedy :: proc(e: ^Encoder) {
	src := e.src
	size := len(src)
	position := 0

	for position < size {
		length, distance := 0, 0

		if position + MATCH_MIN <= size {
			head := insert_position(e, position)
			length, distance = find_match(e, position, head, MATCH_MIN - 1, e.strategy.max_chain)
		}

		if length >= MATCH_MIN {
			emit_match(e, length, distance)

			if length <= e.strategy.max_lazy {
				for covered in 1 ..< length {
					if position + covered + MATCH_MIN <= size {
						insert_position(e, position + covered)
					}
				}
			}

			position += length
		} else {
			emit_literal(e, src[position])
			position += 1
		}

		if e.token_count == len(e.tokens) {
			flush_block(e, position, false)
		}
	}

	flush_block(e, size, true)
}

@(private)
parse_lazy :: proc(e: ^Encoder) {
	lazy_tokens(e)
	flush_block(e, len(e.src), true)
}

// Lazy parse of the whole input into e.tokens, flushing full buffers only.
@(private)
lazy_tokens :: proc(e: ^Encoder) {
	src := e.src
	size := len(src)
	position := 0
	previous_length, previous_distance := 0, 0

	// A match found at `position - 1` waits one step to see if `position` beats it.
	pending := false

	for position < size {
		length, distance := 0, 0

		if position + MATCH_MIN <= size {
			head := insert_position(e, position)

			if previous_length < e.strategy.max_lazy {
				chain := e.strategy.max_chain

				if previous_length >= e.strategy.good_length {
					chain >>= 2
				}

				length, distance = find_match(e, position, head, max(previous_length, MATCH_MIN - 1), chain)

				if length == MATCH_MIN && distance > 4096 {
					length = 0
				}
			}
		}

		if pending && previous_length >= MATCH_MIN && length <= previous_length {
			emit_match(e, previous_length, previous_distance)

			// Positions inside the match still need hash entries.
			end := position - 1 + previous_length

			for covered in position + 1 ..< end {
				if covered + MATCH_MIN <= size {
					insert_position(e, covered)
				}
			}

			position = end
			pending = false
			previous_length, previous_distance = 0, 0

			if e.token_count == len(e.tokens) {
				flush_block(e, position, false)
			}

			continue
		}

		if pending {
			emit_literal(e, src[position - 1])

			if e.token_count == len(e.tokens) {
				flush_block(e, position, false)
			}
		}

		pending = true
		previous_length, previous_distance = length, distance
		position += 1
	}

	if pending {
		if previous_length >= MATCH_MIN {
			emit_match(e, previous_length, previous_distance)
		} else {
			emit_literal(e, src[size - 1])
		}
	}
}

