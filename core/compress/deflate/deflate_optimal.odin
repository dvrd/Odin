package compress_deflate

import "base:intrinsics"
import "core:compress"
import "core:hash"
import "core:math"

/*
Maximum compression on top of the one-shot compressor, for data that is compressed
once and served many times: a few percent smaller than `Deflate_Level.Best`, and
well over an order of magnitude slower.

The input is taken in chunks. For each one every match candidate of every position is
collected once, a lazy parse chooses the block boundaries, and each block is then parsed
repeatedly as a shortest path under an entropy model fitted to the previous parse,
keeping the cheapest exact encoding. Blocks are costed and written by the same Huffman
builder and block writer as every other level, so the output obeys `deflate_bound`.
*/

// Input bytes parsed together; blocks never span two chunks. A multiple of
// `DEFLATE_BLOCK_MAX`, which keeps the output within `deflate_bound`.
DEFLATE_OPTIMAL_CHUNK      :: 4 * DEFLATE_BLOCK_MAX
// Match candidates kept per chunk.
DEFLATE_OPTIMAL_PAIRS      :: 8 * DEFLATE_OPTIMAL_CHUNK
DEFLATE_OPTIMAL_CHAIN      :: 1024
DEFLATE_OPTIMAL_ITERATIONS :: 10
// Blocks per chunk, and the fewest sequences a block needs to be split further.
DEFLATE_OPTIMAL_BLOCKS     :: 96
DEFLATE_OPTIMAL_SPLIT_MIN  :: 1024
// A three-byte match further away than this costs more than its literals.
DEFLATE_OPTIMAL_MATCH3_DISTANCE :: 4096

Deflate_Optimal_Pair :: struct {
	length:   u16,
	distance: u16,
}

Deflate_Optimal_Model :: struct {
	literal_stats:  [DEFLATE_LITERAL_SYMBOLS]f32,
	distance_stats: [DEFLATE_DISTANCE_SYMBOLS]f32,
	literal_cost:   [256]f32,
	length_cost:    [DEFLATE_MATCH_MAX + 1]f32,
	distance_cost:  [DEFLATE_DISTANCE_SYMBOLS]f32,
}

// This struct is ~20MiB: allocate it with `new` rather than on the stack.
Deflate_Optimal :: struct {
	deflate:       Deflate,
	model:         Deflate_Optimal_Model,
	// `pairs[pair_start[p]:pair_start[p + 1]]` are the matches of the chunk's position `p`:
	// strictly longer lengths, each at the smallest distance that reaches it.
	pair_start:    [DEFLATE_OPTIMAL_CHUNK + 1]u32,
	// Where each sequence of `lazy` starts, to turn sequence splits into byte spans.
	offsets:       [DEFLATE_OPTIMAL_CHUNK + 1]i32,
	step_length:   [DEFLATE_OPTIMAL_CHUNK + 1]u16,
	step_distance: [DEFLATE_OPTIMAL_CHUNK + 1]u16,
	cost:          [DEFLATE_OPTIMAL_CHUNK + 1]f64,
	lazy:          [DEFLATE_OPTIMAL_CHUNK]Deflate_Sequence,
	current:       [DEFLATE_OPTIMAL_CHUNK]Deflate_Sequence,
	best:          [DEFLATE_OPTIMAL_CHUNK]Deflate_Sequence,
	pairs:         [DEFLATE_OPTIMAL_PAIRS]Deflate_Optimal_Pair,
}

Deflate_Optimal_To_Slice :: #type proc(s: ^Deflate_Optimal, output, input: []u8) -> (written: int, err: Error)

deflate_optimal_raw  :: proc{deflate_optimal_raw_to_slice,  deflate_optimal_raw_to_dynamic}
deflate_optimal_zlib :: proc{deflate_optimal_zlib_to_slice, deflate_optimal_zlib_to_dynamic}
deflate_optimal_gzip :: proc{deflate_optimal_gzip_to_slice, deflate_optimal_gzip_to_dynamic}

deflate_optimal_raw_to_dynamic :: proc(output: ^[dynamic]u8, input: []u8, allocator := context.allocator) -> (err: Error) {
	context.allocator = allocator

	return deflate_optimal_to_dynamic(output, input, deflate_bound(len(input)), deflate_optimal_raw_to_slice)
}

deflate_optimal_zlib_to_dynamic :: proc(output: ^[dynamic]u8, input: []u8, allocator := context.allocator) -> (err: Error) {
	context.allocator = allocator

	return deflate_optimal_to_dynamic(output, input, deflate_bound(len(input)), deflate_optimal_zlib_to_slice)
}

deflate_optimal_gzip_to_dynamic :: proc(output: ^[dynamic]u8, input: []u8, allocator := context.allocator) -> (err: Error) {
	context.allocator = allocator

	return deflate_optimal_to_dynamic(output, input, deflate_gzip_bound(len(input)), deflate_optimal_gzip_to_slice)
}

deflate_optimal_raw_to_slice :: proc(s: ^Deflate_Optimal, output, input: []u8) -> (written: int, err: Error) {
	deflate_check_arguments(s, len(output), deflate_bound(len(input))) or_return

	s.deflate.bit_buffer = 0
	s.deflate.bit_count  = 0

	return deflate_optimal_compress(s, output, input), nil
}

deflate_optimal_zlib_to_slice :: proc(s: ^Deflate_Optimal, output, input: []u8) -> (written: int, err: Error) {
	deflate_check_arguments(s, len(output), deflate_bound(len(input))) or_return

	q := output
	s.deflate.bit_buffer = 0
	s.deflate.bit_count  = 0
	deflate_put_bits(&q, &s.deflate, 0x78, 8) // deflate, 32k window
	deflate_put_bits(&q, &s.deflate, 0xda, 8) // maximum compression
	q = q[deflate_optimal_compress(s, q, input):]

	checksum := hash.adler32(input)

	for shift := u32(24); ; shift -= 8 {
		deflate_put_bits(&q, &s.deflate, i32((checksum >> shift) & 0xff), 8)

		if shift == 0 {
			break
		}
	}

	return len(output) - len(q), nil
}

deflate_optimal_gzip_to_slice :: proc(s: ^Deflate_Optimal, output, input: []u8) -> (written: int, err: Error) {
	deflate_check_arguments(s, len(output), deflate_gzip_bound(len(input))) or_return

	header := Gzip_Header{
		magic              = .GZIP,
		compression_method = .DEFLATE,
		xfl                = .Maximum_Compression,
		os                 = .Unknown,
	}
	intrinsics.unaligned_store((^Gzip_Header)(raw_data(output)), header)
	q := output[size_of(Gzip_Header):]

	s.deflate.bit_buffer = 0
	s.deflate.bit_count  = 0
	q = q[deflate_optimal_compress(s, q, input):]

	trailer := Gzip_Trailer{
		crc32 = u32le(hash.crc32(input)),
		size  = u32le(u32(len(input))),
	}
	intrinsics.unaligned_store((^Gzip_Trailer)(raw_data(q)), trailer)
	q = q[size_of(Gzip_Trailer):]

	return len(output) - len(q), nil
}

@(private)
deflate_optimal_to_dynamic :: proc(output: ^[dynamic]u8, input: []u8, bound: int, compressor: Deflate_Optimal_To_Slice) -> (err: Error) {
	if output == nil || bound < 0 {
		return General_Error.Incompatible_Options
	}

	if bound > compress.COMPRESS_OUTPUT_ALLOCATE_MAX {
		return General_Error.Output_Too_Short
	}

	s := new(Deflate_Optimal) or_return
	defer free(s)

	non_zero_resize(output, bound) or_return

	written: int
	written, err = compressor(s, output[:], input)
	non_zero_resize(output, written)

	return
}

@(private)
deflate_optimal_compress :: proc(s: ^Deflate_Optimal, output: []u8, input: []u8) -> int #no_bounds_check {
	d := &s.deflate
	q := output
	total := len(input)
	window := input
	base := 0
	i, hash_base: i32

	d.sequence_count = 0
	d.frequencies    = {}
	d.hash_head      = {}

	for {
		if i >= DEFLATE_SLIDE_SIZE {
			delta := (i - DEFLATE_WINDOW_SIZE) &~ DEFLATE_WINDOW_MASK
			hash_base -= delta
			base      += int(delta)
			i         -= delta
			window     = input[base:]
		}

		chunk_end := i + i32(min(total - base - int(i), DEFLATE_OPTIMAL_CHUNK))
		is_last := base + int(chunk_end) == total

		hash_base = deflate_optimal_collect(s, window, i, chunk_end, hash_base)
		deflate_optimal_chunk(&q, s, window, i, chunk_end, is_last)
		i = chunk_end

		if is_last {
			break
		}
	}

	if d.bit_count != 0 {
		deflate_put_bits(&q, d, 0x00, 8 - d.bit_count)
	}

	return len(output) - len(q)
}

// Splits `window[begin:end]` into blocks and writes each one at its cheapest parse.
@(private)
deflate_optimal_chunk :: proc(destination: ^[]u8, s: ^Deflate_Optimal, window: []u8, begin, end: i32, is_last: bool) #no_bounds_check {
	d := &s.deflate

	if begin == end {
		deflate_flush(destination, d, is_last, window, begin, end, nil)
		return
	}

	lazy_count := deflate_optimal_lazy(s, window, begin, end)
	splits: [DEFLATE_OPTIMAL_BLOCKS + 1]i32
	split_count := deflate_optimal_split(s, window, lazy_count, splits[:])
	frequencies, best_frequencies: Deflate_Frequency

	for block in 0 ..< split_count - 1 {
		first := splits[block]
		last := splits[block + 1]
		block_begin := s.offsets[first]
		block_end := s.offsets[last]
		span := block_end - block_begin

		best_count := last - first
		copy(s.best[:best_count], s.lazy[first:last])
		best_frequencies = {}
		deflate_optimal_count(&best_frequencies, window, s.best[:best_count])
		best_cost := deflate_block_cost(&best_frequencies, span, false)

		deflate_optimal_model_reset(&s.model)
		deflate_optimal_model_count(&s.model, window, s.best[:best_count])

		for iteration in 0 ..< DEFLATE_OPTIMAL_ITERATIONS {
			deflate_optimal_model_costs(&s.model)
			count := deflate_optimal_shortest_path(s, window, begin, block_begin, block_end)

			frequencies = {}
			deflate_optimal_count(&frequencies, window, s.current[:count])
			cost := deflate_block_cost(&frequencies, span, false)

			if cost < best_cost {
				best_cost = cost
				best_count = count
				best_frequencies = frequencies
				copy(s.best[:count], s.current[:count])
			}

			// Blend with earlier statistics once the model has had a few clean
			// rounds, which damps oscillation between two parses.
			if iteration >= 3 {
				deflate_optimal_model_halve(&s.model)
			} else {
				deflate_optimal_model_reset(&s.model)
			}

			deflate_optimal_model_count(&s.model, window, s.current[:count])
		}

		assert(len(destination^) >= int(span) + 5 * int(deflate_round_up_divide(span, DEFLATE_RAW_BLOCK_SIZE)) + 8)
		d.frequencies = best_frequencies
		deflate_flush(destination, d, is_last && block_end == end, window, block_begin, block_end, s.best[:best_count])
	}
}

@(private)
deflate_optimal_count :: proc(frequencies: ^Deflate_Frequency, window: []u8, sequences: []Deflate_Sequence) #no_bounds_check {
	for sequence in sequences {
		deflate_count_sequence(frequencies, window, sequence, false)
	}
}

@(private)
deflate_optimal_hash :: #force_inline proc(b: []u8) -> u32 #no_bounds_check {
	n := u32(b[0]) | u32(b[1]) << 8 | u32(b[2]) << 16

	return (n * 0x1e35a7bd) >> (32 - DEFLATE_HASH_BITS)
}

// Length of the common prefix of `window[a:]` and `window[b:]`, at most `limit`.
@(private)
deflate_optimal_match_length :: #force_inline proc(window: []u8, a, b, limit: i32) -> (length: i32) #no_bounds_check {
	for length + 8 <= limit {
		difference := deflate_load_u64(window[a + length:]) ~ deflate_load_u64(window[b + length:])

		if difference != 0 {
			return length + deflate_first_difference(difference)
		}

		length += 8
	}

	for length < limit && window[a + length] == window[b + length] {
		length += 1
	}

	return length
}

// Finds the match candidates of every position of `window[begin:end]` with three-byte
// hash chains in the compressor's own tables. Returns the hash base to continue from.
@(private)
deflate_optimal_collect :: proc(s: ^Deflate_Optimal, window: []u8, begin, end: i32, hash_base: i32) -> i32 #no_bounds_check {
	d := &s.deflate
	hash_base := hash_base
	pair_count: u32

	for position in begin ..< end {
		s.pair_start[position - begin] = pair_count
		limit := min(end - position, DEFLATE_MATCH_MAX)

		if limit < DEFLATE_MATCH3_MIN {
			continue
		}

		if position - hash_base >= DEFLATE_HASH_SLIDE_AT {
			deflate_slide(d, false)
			hash_base += DEFLATE_HASH_SLIDE
		}

		h := deflate_optimal_hash(window[position:])
		candidate := deflate_unwrap_position(hash_base, d.hash_head[h])
		d.hash_chain[position & DEFLATE_WINDOW_MASK] = d.hash_head[h]
		d.hash_head[h] = u16(position - hash_base + 1)

		// Every later position of the chunk keeps room for one match.
		room := u32(DEFLATE_OPTIMAL_PAIRS) - pair_count - u32(end - position - 1)
		first := pair_count
		oldest := max(position - DEFLATE_WINDOW_SIZE, DEFLATE_NO_POSITION)
		best: i32 = DEFLATE_MATCH3_MIN - 1

		for chain := DEFLATE_OPTIMAL_CHAIN; candidate > oldest && chain > 0; chain -= 1 {
			if window[candidate + best] == window[position + best] {
				found := deflate_optimal_match_length(window, candidate, position, limit)

				if found > best {
					if pair_count - first == room {
						pair_count -= 1
					}

					s.pairs[pair_count] = {u16(found), u16(position - candidate)}
					pair_count += 1
					best = found

					if found >= limit {
						break
					}
				}
			}

			next := deflate_unwrap_position(hash_base, d.hash_chain[candidate & DEFLATE_WINDOW_MASK])

			if next >= candidate {
				break
			}

			candidate = next
		}
	}

	s.pair_start[end - begin] = pair_count

	return hash_base
}

// The longest match of the chunk's position `index`, or a zero length.
@(private)
deflate_optimal_longest :: #force_inline proc(s: ^Deflate_Optimal, index: i32) -> Deflate_Optimal_Pair #no_bounds_check {
	if s.pair_start[index] == s.pair_start[index + 1] {
		return {}
	}

	pair := s.pairs[s.pair_start[index + 1] - 1]

	if pair.length == DEFLATE_MATCH3_MIN && pair.distance > DEFLATE_OPTIMAL_MATCH3_DISTANCE {
		return {}
	}

	return pair
}

// Lazy parse of `window[begin:end]` into `s.lazy`, one literal per sequence.
// Returns the number of sequences.
@(private)
deflate_optimal_lazy :: proc(s: ^Deflate_Optimal, window: []u8, begin, end: i32) -> (count: i32) #no_bounds_check {
	position := begin

	for position < end {
		pair := deflate_optimal_longest(s, position - begin)
		s.offsets[count] = position

		if pair.length != 0 && position + 1 < end && deflate_optimal_longest(s, position + 1 - begin).length > pair.length {
			pair.length = 0
		}

		if pair.length == 0 {
			s.lazy[count] = {distance = position, length = 1}
			position += 1
		} else {
			s.lazy[count] = {distance = -i32(pair.distance), length = i32(pair.length)}
			position += i32(pair.length)
		}

		count += 1
	}

	s.offsets[count] = end

	return count
}

// ------------------------------------------------------------ block splitting

// Bits of `s.lazy[first:last]` written as one block.
@(private)
deflate_optimal_range_cost :: proc(s: ^Deflate_Optimal, window: []u8, first, last: i32) -> i64 #no_bounds_check {
	frequencies: Deflate_Frequency
	deflate_optimal_count(&frequencies, window, s.lazy[first:last])

	return i64(deflate_block_cost(&frequencies, s.offsets[last] - s.offsets[first], false))
}

// Splits the lazy parse where two blocks cost less than one. `splits` receives
// sequence indexes including both ends; returns how many were written.
@(private)
deflate_optimal_split :: proc(s: ^Deflate_Optimal, window: []u8, lazy_count: i32, splits: []i32) -> (count: int) {
	done: [DEFLATE_OPTIMAL_BLOCKS + 1]bool
	splits[0] = 0
	splits[1] = lazy_count
	count = 2

	for count < len(splits) {
		// Largest block that has not been proven unsplittable.
		chosen := -1
		chosen_size: i32 = DEFLATE_OPTIMAL_SPLIT_MIN

		for index in 0 ..< count - 1 {
			size := splits[index + 1] - splits[index]

			if !done[index] && size >= chosen_size {
				chosen = index
				chosen_size = size
			}
		}

		if chosen < 0 {
			break
		}

		first := splits[chosen]
		last := splits[chosen + 1]
		whole := deflate_optimal_range_cost(s, window, first, last)
		at, parts := deflate_optimal_best_split(s, window, first, last)

		if at <= first || at >= last || parts >= whole {
			done[chosen] = true
			continue
		}

		for index := count; index > chosen + 1; index -= 1 {
			splits[index] = splits[index - 1]
			done[index] = done[index - 1]
		}

		splits[chosen + 1] = at
		done[chosen + 1] = false
		count += 1
	}

	return count
}

// Narrowing search over evenly spaced candidates for the cheapest two-way split.
@(private)
deflate_optimal_best_split :: proc(s: ^Deflate_Optimal, window: []u8, first, last: i32) -> (at: i32, cost: i64) {
	low := first + 1
	high := last - 1
	cost = max(i64)
	at = first

	for high - low >= 9 {
		step := (high - low) / 10
		best_index: i32
		best_cost := max(i64)

		for index in i32(1) ..= 9 {
			point := low + index * step
			value := deflate_optimal_range_cost(s, window, first, point) + deflate_optimal_range_cost(s, window, point, last)

			if value < best_cost {
				best_cost = value
				best_index = index
			}
		}

		point := low + best_index * step

		if best_cost < cost {
			cost = best_cost
			at = point
		}

		low = max(low, point - step)
		high = min(high, point + step)

		if step <= 1 {
			break
		}
	}

	return at, cost
}

// ---------------------------------------------------------------- cost model

@(private)
deflate_optimal_model_reset :: proc(model: ^Deflate_Optimal_Model) {
	model.literal_stats = {}
	model.distance_stats = {}
}

@(private)
deflate_optimal_model_halve :: proc(model: ^Deflate_Optimal_Model) {
	for &value in model.literal_stats {
		value *= 0.5
	}

	for &value in model.distance_stats {
		value *= 0.5
	}
}

@(private)
deflate_optimal_model_count :: proc(model: ^Deflate_Optimal_Model, window: []u8, sequences: []Deflate_Sequence) #no_bounds_check {
	match_codes: Deflate_Match_Codes

	for sequence in sequences {
		if sequence.distance >= 0 {
			for c in window[sequence.distance:][:sequence.length] {
				model.literal_stats[c] += 1
			}

			continue
		}

		deflate_match_codes(&match_codes, -sequence.distance, sequence.length, false)
		model.literal_stats[match_codes.length_code] += 1
		model.distance_stats[match_codes.distance_code] += 1
	}

	model.literal_stats[DEFLATE_END_OF_BLOCK] += 1
}

@(private)
deflate_optimal_model_costs :: proc(model: ^Deflate_Optimal_Model) {
	literal_total: f32

	for value in model.literal_stats {
		literal_total += value
	}

	distance_total: f32

	for value in model.distance_stats {
		distance_total += value
	}

	literal_log := math.log2(max(literal_total, 1))
	distance_log := math.log2(max(distance_total, 1))

	for symbol in 0 ..< 256 {
		model.literal_cost[symbol] = deflate_optimal_symbol_cost(model.literal_stats[symbol], literal_log)
	}

	for length in DEFLATE_MATCH3_MIN ..= DEFLATE_MATCH_MAX {
		slot := DEFLATE_LENGTH_SLOT[length]
		model.length_cost[length] = deflate_optimal_symbol_cost(model.literal_stats[257 + int(slot)], literal_log) + f32(DEFLATE_LENGTH_EXTRA_BITS[slot])
	}

	for symbol in 0 ..< DEFLATE_DISTANCE_SYMBOLS {
		model.distance_cost[symbol] = deflate_optimal_symbol_cost(model.distance_stats[symbol], distance_log) + f32(DEFLATE_DISTANCE_EXTRA_BITS[symbol])
	}
}

// Bits for a symbol seen `count` times; an unseen symbol costs as if seen once.
@(private)
deflate_optimal_symbol_cost :: #force_inline proc(count, total_log: f32) -> f32 {
	if count < 1 {
		return total_log
	}

	return total_log - math.log2(count)
}

// ------------------------------------------------------------ shortest path

// Cheapest sequences for `window[block_begin:block_end]` under the model, written
// to `s.current`; `chunk_begin` is the position `s.pair_start` counts from.
// Returns the number of sequences.
@(private)
deflate_optimal_shortest_path :: proc(s: ^Deflate_Optimal, window: []u8, chunk_begin, block_begin, block_end: i32) -> (count: i32) #no_bounds_check {
	model := &s.model
	span := block_end - block_begin
	match_codes: Deflate_Match_Codes

	for index in 1 ..= span {
		s.cost[index] = max(f64)
	}

	s.cost[0] = 0

	for offset in 0 ..< span {
		base := s.cost[offset]
		position := block_begin + offset
		literal := base + f64(model.literal_cost[window[position]])

		if literal < s.cost[offset + 1] {
			s.cost[offset + 1] = literal
			s.step_length[offset + 1] = 1
			s.step_distance[offset + 1] = 0
		}

		room := span - offset
		covered: i32 = DEFLATE_MATCH3_MIN - 1
		index := position - chunk_begin

		for pair in s.pairs[s.pair_start[index]:s.pair_start[index + 1]] {
			top := min(i32(pair.length), room)

			if top <= covered {
				break
			}

			deflate_match_codes(&match_codes, i32(pair.distance), DEFLATE_MATCH3_MIN, false)
			with_distance := base + f64(model.distance_cost[match_codes.distance_code])

			for length in covered + 1 ..= top {
				candidate := with_distance + f64(model.length_cost[length])

				if candidate < s.cost[offset + length] {
					s.cost[offset + length] = candidate
					s.step_length[offset + length] = u16(length)
					s.step_distance[offset + length] = pair.distance
				}
			}

			covered = top
		}
	}

	// Walk back from the end, then reverse into forward order.
	for offset := span; offset > 0; {
		length := i32(s.step_length[offset])
		offset -= length

		if length == 1 {
			s.current[count] = {distance = block_begin + offset, length = 1}
		} else {
			s.current[count] = {distance = -i32(s.step_distance[offset + length]), length = length}
		}

		count += 1
	}

	for low, high := i32(0), count - 1; low < high; low, high = low + 1, high - 1 {
		s.current[low], s.current[high] = s.current[high], s.current[low]
	}

	return count
}
