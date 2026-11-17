package compress_zlib

import "core:compress"
import "core:math"
import "core:mem"

// Level.Optimal: choose block boundaries on a first lazy parse, then for each
// block iterate a shortest-path parse under an entropy cost model fitted to the
// previous iteration's symbols, keeping the cheapest exact encoding.

OPTIMAL_CHAIN :: 1024
OPTIMAL_ITERATIONS :: 10
OPTIMAL_BLOCKS_MAX :: 96
OPTIMAL_SPLIT_MIN :: 1024

Match_Pair :: struct {
	length:   u16,
	distance: u16,
}

Optimal_Model :: struct {
	literal_stats:  [LITERAL_SYMBOLS]f32,
	distance_stats: [DISTANCE_SYMBOLS]f32,
	literal_cost:   [256]f32,
	length_cost:    [MATCH_MAX + 1]f32,
	distance_cost:  [DISTANCE_SYMBOLS]f32,
}

@(private)
optimal_parse :: proc(e: ^Encoder, allocator: mem.Allocator) -> compress.Error {
	src := e.src
	size := len(src)

	if size == 0 {
		flush_block(e, 0, true)
		return nil
	}

	setup_strategy(e, .Best)
	mem.set(&e.head, 0xff, size_of(e.head))

	lazy := make([]Token, size + 1, allocator) or_return
	defer delete(lazy, allocator)

	e.tokens = lazy
	e.token_count = 0
	lazy_tokens(e)
	lazy_count := e.token_count

	// Source offset where each lazy token starts, to turn token splits into byte spans.
	offsets := make([]u32, lazy_count + 1, allocator) or_return
	defer delete(offsets, allocator)

	position := 0

	for token, index in lazy[:lazy_count] {
		offsets[index] = u32(position)
		position += 1 if token.distance == 0 else int(token.value)
	}

	offsets[lazy_count] = u32(position)

	splits: [OPTIMAL_BLOCKS_MAX + 1]int
	split_count := split_blocks(e, lazy[:lazy_count], offsets, splits[:])

	// Every match candidate of every position, found once and reused by all iterations.
	pair_start := make([]u32, size + 1, allocator) or_return
	defer delete(pair_start, allocator)

	pairs := make([dynamic]Match_Pair, 0, size, allocator) or_return
	defer delete(pairs)

	collect_matches(e, pair_start, &pairs) or_return

	span_max := 0

	for index in 0 ..< split_count - 1 {
		span_max = max(span_max, int(offsets[splits[index + 1]]) - int(offsets[splits[index]]))
	}

	cost := make([]f64, span_max + 1, allocator) or_return
	defer delete(cost, allocator)

	step_length := make([]u16, span_max + 1, allocator) or_return
	defer delete(step_length, allocator)

	step_distance := make([]u16, span_max + 1, allocator) or_return
	defer delete(step_distance, allocator)

	current := make([]Token, span_max + 1, allocator) or_return
	defer delete(current, allocator)

	best := make([]Token, span_max + 1, allocator) or_return
	defer delete(best, allocator)

	model := new(Optimal_Model, allocator) or_return
	defer free(model, allocator)

	header := Dynamic_Header{}

	for block in 0 ..< split_count - 1 {
		first_token := splits[block]
		last_token := splits[block + 1]
		start := int(offsets[first_token])
		end := int(offsets[last_token])
		span := end - start

		best_count := last_token - first_token
		copy(best[:best_count], lazy[first_token:last_token])

		e.tokens = best
		e.token_count = best_count
		best_cost := cheapest(measure_block(e, span, &header))

		model_reset(model)
		model_count(model, best[:best_count], 1)

		for iteration in 0 ..< OPTIMAL_ITERATIONS {
			model_costs(model)
			count := shortest_path(src, start, end, pair_start, pairs[:], model, cost, step_length, step_distance, current)

			e.tokens = current
			e.token_count = count
			current_cost := cheapest(measure_block(e, span, &header))

			if current_cost < best_cost {
				best_cost = current_cost
				best_count = count
				copy(best[:count], current[:count])
			}

			// Blend with earlier statistics once the model has had a few clean
			// rounds, which damps oscillation between two parses.
			if iteration >= 3 {
				for &value in model.literal_stats {
					value *= 0.5
				}

				for &value in model.distance_stats {
					value *= 0.5
				}
			} else {
				model_reset(model)
			}

			model_count(model, current[:count], 1)
		}

		e.tokens = best
		e.token_count = best_count
		e.block_start = start
		flush_block(e, end, end == size)
	}

	e.tokens = e.token_buffer[:]
	e.token_count = 0

	return nil
}

@(private)
cheapest :: proc(dynamic_cost, fixed_cost, stored_cost: u64) -> u64 {
	return min(dynamic_cost, fixed_cost, stored_cost)
}

// ---------------------------------------------------------------- cost model

@(private)
model_reset :: proc(model: ^Optimal_Model) {
	model.literal_stats = {}
	model.distance_stats = {}
}

@(private)
model_count :: proc(model: ^Optimal_Model, tokens: []Token, weight: f32) {
	for token in tokens {
		if token.distance == 0 {
			model.literal_stats[token.value] += weight
			continue
		}

		length_code, _, _ := length_symbol(int(token.value))
		distance_code, _, _ := distance_symbol(int(token.distance))
		model.literal_stats[257 + length_code] += weight
		model.distance_stats[distance_code] += weight
	}

	model.literal_stats[256] += weight
}

@(private)
model_costs :: proc(model: ^Optimal_Model) {
	literal_total: f32

	for value in model.literal_stats {
		literal_total += value
	}

	distance_total: f32

	for value in model.distance_stats {
		distance_total += value
	}

	literal_total = max(literal_total, 1)
	distance_total = max(distance_total, 1)
	literal_log := math.log2(literal_total)
	distance_log := math.log2(distance_total)

	for symbol in 0 ..< 256 {
		model.literal_cost[symbol] = symbol_cost(model.literal_stats[symbol], literal_log)
	}

	for length in MATCH_MIN ..= MATCH_MAX {
		code, extra_bits, _ := length_symbol(length)
		model.length_cost[length] = symbol_cost(model.literal_stats[257 + code], literal_log) + f32(extra_bits)
	}

	for symbol in 0 ..< DISTANCE_SYMBOLS {
		model.distance_cost[symbol] =
			symbol_cost(model.distance_stats[symbol], distance_log) + f32(DISTANCE_EXTRA[symbol])
	}
}

// Bits for a symbol seen `count` times; an unseen symbol costs as if seen once.
@(private)
symbol_cost :: #force_inline proc(count, total_log: f32) -> f32 {
	if count < 1 {
		return total_log
	}

	return total_log - math.log2(count)
}

// ------------------------------------------------------------ shortest path

// Cheapest token sequence for src[start:end] under `model`; returns its length.
@(private)
shortest_path :: proc(
	src: []u8,
	start, end: int,
	pair_start: []u32,
	pairs: []Match_Pair,
	model: ^Optimal_Model,
	cost: []f64,
	step_length, step_distance: []u16,
	tokens: []Token,
) -> int {
	span := end - start

	for index in 1 ..= span {
		cost[index] = max(f64)
	}

	cost[0] = 0

	for offset in 0 ..< span {
		base := cost[offset]
		position := start + offset

		literal := base + f64(model.literal_cost[src[position]])

		if literal < cost[offset + 1] {
			cost[offset + 1] = literal
			step_length[offset + 1] = 1
			step_distance[offset + 1] = 0
		}

		room := span - offset
		covered := MATCH_MIN - 1

		for pair in pairs[pair_start[position]:pair_start[position + 1]] {
			top := min(int(pair.length), room)

			if top <= covered {
				break
			}

			code, _, _ := distance_symbol(int(pair.distance))
			with_distance := base + f64(model.distance_cost[code])

			for length in covered + 1 ..= top {
				candidate := with_distance + f64(model.length_cost[length])

				if candidate < cost[offset + length] {
					cost[offset + length] = candidate
					step_length[offset + length] = u16(length)
					step_distance[offset + length] = pair.distance
				}
			}

			covered = top
		}
	}

	// Walk back from the end, then reverse into forward order.
	count := 0

	for offset := span; offset > 0; {
		length := int(step_length[offset])

		if length == 1 {
			tokens[count] = {0, u16(src[start + offset - 1])}
		} else {
			tokens[count] = {step_distance[offset], u16(length)}
		}

		count += 1
		offset -= length
	}

	for low, high := 0, count - 1; low < high; low, high = low + 1, high - 1 {
		tokens[low], tokens[high] = tokens[high], tokens[low]
	}

	return count
}

// For each position, the matches worth considering: strictly longer lengths at
// the smallest distance that reaches them.
@(private)
collect_matches :: proc(e: ^Encoder, pair_start: []u32, pairs: ^[dynamic]Match_Pair) -> compress.Error {
	src := e.src
	size := len(src)

	mem.set(&e.head, 0xff, size_of(e.head))

	for position in 0 ..< size {
		pair_start[position] = u32(len(pairs))
		limit := min(MATCH_MAX, size - position)

		if limit < MATCH_MIN {
			continue
		}

		candidate := insert_position(e, position)
		best := MATCH_MIN - 1

		for chain := OPTIMAL_CHAIN; candidate >= 0 && chain > 0; chain -= 1 {
			offset := position - candidate

			if offset <= 0 || offset > WINDOW_SIZE {
				break
			}

			if src[candidate + best] == src[position + best] {
				found := match_length(src, candidate, position, limit)

				if found > best {
					_, append_error := append(pairs, Match_Pair{u16(found), u16(offset)})

					if append_error != nil {
						return append_error
					}

					best = found

					if found >= limit {
						break
					}
				}
			}

			next := int(e.prev[candidate & (WINDOW_SIZE - 1)])

			if next >= candidate {
				break
			}

			candidate = next
		}
	}

	pair_start[size] = u32(len(pairs))

	return nil
}

// ------------------------------------------------------------ block splitting

// Splits the lazy token stream where two blocks cost less than one. `splits`
// receives token indexes including both ends; returns how many were written.
@(private)
split_blocks :: proc(e: ^Encoder, tokens: []Token, offsets: []u32, splits: []int) -> int {
	splits[0] = 0
	splits[1] = len(tokens)
	count := 2
	done: [OPTIMAL_BLOCKS_MAX + 1]bool

	for count < len(splits) {
		// Largest block that has not been proven unsplittable.
		chosen := -1
		chosen_size := OPTIMAL_SPLIT_MIN

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
		whole := range_cost(e, tokens, offsets, first, last)
		at, parts := best_split(e, tokens, offsets, first, last)

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

@(private)
range_cost :: proc(e: ^Encoder, tokens: []Token, offsets: []u32, first, last: int) -> u64 {
	header := Dynamic_Header{}
	e.tokens = tokens[first:last]
	e.token_count = last - first

	return cheapest(measure_block(e, int(offsets[last]) - int(offsets[first]), &header))
}

// Narrowing search over evenly spaced candidates for the cheapest two-way split.
@(private)
best_split :: proc(e: ^Encoder, tokens: []Token, offsets: []u32, first, last: int) -> (at: int, cost: u64) {
	low := first + 1
	high := last - 1
	cost = max(u64)
	at = first

	for high - low >= 9 {
		step := (high - low) / 10
		best_index := 0
		best_cost := max(u64)

		for index in 1 ..= 9 {
			point := low + index * step
			value := range_cost(e, tokens, offsets, first, point) + range_cost(e, tokens, offsets, point, last)

			if value < best_cost {
				best_cost = value
				best_index = index
			}
		}

		if best_cost < cost {
			cost = best_cost
			at = low + best_index * step
		}

		point := low + best_index * step
		low = max(low, point - step)
		high = min(high, point + step)

		if step <= 1 {
			break
		}
	}

	return at, cost
}
