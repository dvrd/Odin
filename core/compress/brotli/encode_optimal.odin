package compress_brotli

import "base:runtime"
import "core:math"

// Level.Optimal: every match of a block is cached once, then the block is
// parsed as a shortest path under a bit-cost model taken from the previous
// parse, a few times over.

Cached_Match :: struct {
	length:   u32,
	distance: u32,
}

Node :: struct {
	cost:     f64,
	// Copy that arrives here; length 0 means a literal.
	length:   u32,
	distance: u32,
	// Literals since the last copy on the cheapest path.
	run:      u32,
	ring:     Ring,
}

Model :: struct {
	command:  [COMMAND_ALPHABET]f32,
	distance: [DISTANCE_CONTEXTS][DISTANCE_ALPHABET]f32,
}

Optimal :: struct {
	nodes:        []Node,
	matches:      [dynamic]Cached_Match,
	match_start:  []u32,
	literal_cost: []f32,
	path:         [dynamic]u32,
	model:        Model,
	tree_cost:    [LITERAL_CONTEXTS][LITERAL_ALPHABET]f32,
}

@(private)
optimal_make :: proc(block_max: int, allocator: runtime.Allocator) -> (o: ^Optimal, err: runtime.Allocator_Error) {
	o = new(Optimal, allocator) or_return
	o.nodes = make([]Node, block_max + 1, allocator) or_return
	o.match_start = make([]u32, block_max + 1, allocator) or_return
	o.literal_cost = make([]f32, block_max, allocator) or_return
	o.matches = make([dynamic]Cached_Match, allocator) or_return
	o.path = make([dynamic]u32, allocator) or_return

	return o, nil
}

@(private)
optimal_destroy :: proc(o: ^Optimal, allocator: runtime.Allocator) {
	if o == nil {
		return
	}

	delete(o.nodes, allocator)
	delete(o.match_start, allocator)
	delete(o.literal_cost, allocator)
	delete(o.matches)
	delete(o.path)
	free(o, allocator)
}

// Parses src[start:end] into e.commands and leaves `block` gathered for them.
@(private)
parse_optimal :: proc(e: ^Encoder, o: ^Optimal, block: ^Meta_Block, start, end: int) -> runtime.Allocator_Error {
	ring := e.ring
	collect_matches(e, o, start, end) or_return

	// First model: every byte as a literal, flat command and distance costs.
	push_command(e, end, end - start, 0, 0) or_return
	gather(e, block, start, end)
	set_model(e, o, block, start, end, true)

	for iteration in 0 ..< OPTIMAL_ITERATIONS {
		clear(&e.commands)
		e.ring = ring
		shortest_path(e, o, start, end) or_return
		gather(e, block, start, end)

		if iteration + 1 < OPTIMAL_ITERATIONS {
			set_model(e, o, block, start, end, false)
		}
	}

	return nil
}

// Caches, per position, the matches of strictly increasing length found by
// walking the hash chain from the nearest candidate outwards.
@(private)
collect_matches :: proc(e: ^Encoder, o: ^Optimal, start, end: int) -> runtime.Allocator_Error {
	src := e.src
	clear(&o.matches)

	for position := start; position < end; position += 1 {
		o.match_start[position - start] = u32(len(o.matches))
		limit := end - position

		if limit < 4 {
			continue
		}

		reach := min(position, e.window_max)
		best := 3
		nearest := 0
		candidate := e.head[hash4(src, position) >> e.hash_shift]

		for chain := OPTIMAL_CHAIN; candidate != NIL && chain > 0; chain -= 1 {
			distance := position - int(candidate)

			if distance > reach {
				break
			}

			if src[int(candidate) + best] == src[position + best] {
				length := common_length(src, int(candidate), position, limit)

				if length > best {
					append(&o.matches, Cached_Match{u32(length), u32(distance)}) or_return
					best = length
					nearest = distance

					if length >= limit || length >= OPTIMAL_LONG {
						break
					}
				}
			}

			candidate = e.chain[candidate]
		}

		insert_hash(e, position)

		if best < OPTIMAL_LONG {
			continue
		}

		// Inside a long match the same distance keeps matching; skip the search.
		for stop := position + best - OPTIMAL_LONG; position < stop; {
			position += 1
			best -= 1
			o.match_start[position - start] = u32(len(o.matches))
			append(&o.matches, Cached_Match{u32(best), u32(nearest)}) or_return
			insert_hash(e, position)
		}
	}

	o.match_start[end - start] = u32(len(o.matches))

	return nil
}

@(private)
symbol_costs :: proc(histogram: []u32, costs: []f32, fallback: f32) {
	total: u64

	for frequency in histogram {
		total += u64(frequency)
	}

	if total == 0 {
		for &cost in costs {
			cost = fallback
		}

		return
	}

	scale := math.log2(f64(total))
	missing := f32(scale + 1.5)

	for frequency, symbol in histogram {
		costs[symbol] = missing if frequency == 0 else f32(scale - math.log2(f64(frequency)))
	}
}

@(private)
set_model :: proc(e: ^Encoder, o: ^Optimal, block: ^Meta_Block, start, end: int, flat: bool) {
	src := e.src

	for tree in 0 ..< block.literal_trees {
		symbol_costs(block.literal_histogram[tree][:], o.tree_cost[tree][:], 8)
	}

	for position in start ..< end {
		tree := block.literal_map[literal_context(src, position)]
		o.literal_cost[position - start] = o.tree_cost[tree][src[position]]
	}

	if flat {
		for &cost, symbol in o.model.command {
			cost = 5.5 if symbol < 128 else 7
		}

		for &costs in o.model.distance {
			for &cost, symbol in costs {
				cost = 4 if symbol < 16 else 4.5
			}
		}

		return
	}

	symbol_costs(block.command_histogram[:], o.model.command[:], 8)

	for &costs, slot in o.model.distance {
		symbol_costs(block.distance_histogram[block.distance_map[slot]][:], costs[:], 6)
	}
}

// Offers copies of length low..=high at `distance` from node `at`.
@(private)
relax :: proc(o: ^Optimal, at, low, high, distance: int, dictionary: bool) {
	node := &o.nodes[at]
	ring := node.ring
	symbol, extra_bits, _ := distance_symbol(&ring, distance)

	if symbol != 0 && !dictionary {
		ring_push(&ring, distance)
	}

	insert := insert_code(int(node.run))
	base := node.cost + f64(INSERT_EXTRA[insert])
	copy := copy_code(low)

	for length in low ..= high {
		if copy < 23 && u32(length) >= COPY_BASE[copy + 1] {
			copy += 1
		}

		implicit := symbol == 0 && insert < 8 && copy < 16
		cell := COMMAND_CELLS[insert >> 3][copy >> 3]

		if implicit {
			cell -= 2
		}

		cost := base + f64(o.model.command[cell << 6 | (insert & 7) << 3 | copy & 7]) + f64(COPY_EXTRA[copy])

		if !implicit {
			cost += f64(o.model.distance[distance_context(u32(length))][symbol]) + f64(extra_bits)
		}

		target := &o.nodes[at + length]

		if cost < target.cost {
			target^ = {cost, u32(length), u32(distance), 0, ring}
		}
	}
}

@(private)
shortest_path :: proc(e: ^Encoder, o: ^Optimal, start, end: int) -> runtime.Allocator_Error {
	src := e.src
	count := end - start
	nodes := o.nodes[:count + 1]

	for &node in nodes {
		node.cost = math.INF_F64
	}

	nodes[0] = {
		ring = e.ring,
	}

	for at := 0; at < count; at += 1 {
		node := nodes[at]
		position := start + at
		limit := count - at
		literal := node.cost + f64(o.literal_cost[at])

		if literal < nodes[at + 1].cost {
			nodes[at + 1] = {literal, 0, 0, node.run + 1, node.ring}
		}

		if limit < 2 {
			continue
		}

		reach := min(position, e.window_max)
		cached := o.matches[o.match_start[at]:o.match_start[at + 1]]

		if len(cached) > 0 && cached[len(cached) - 1].length >= OPTIMAL_LONG {
			longest := cached[len(cached) - 1]
			relax(o, at, int(longest.length), int(longest.length), int(longest.distance), false)
			at += int(longest.length) - 1

			continue
		}

		for recent in node.ring {
			distance := int(recent)

			if distance > reach {
				continue
			}

			length := common_length(src, position - distance, position, min(limit, OPTIMAL_LONG))

			if length >= 2 {
				relax(o, at, 2, length, distance, false)
			}
		}

		shortest := 4

		for match in cached {
			relax(o, at, shortest, int(match.length), int(match.distance), false)
			shortest = int(match.length) + 1
		}

		words: [8]Match

		for word in words[:dictionary_matches(e, position, limit, words[:])] {
			relax(o, at, word.length, word.length, reach + word.distance, true)
		}
	}

	clear(&o.path)

	for at := count; at > 0; {
		length := int(nodes[at].length)

		if length == 0 {
			at -= 1
			continue
		}

		append(&o.path, u32(at)) or_return
		at -= length
	}

	literal_start := start

	for index := len(o.path) - 1; index >= 0; index -= 1 {
		node := nodes[o.path[index]]
		position := start + int(o.path[index]) - int(node.length)
		push_command(e, position, position - literal_start, int(node.length), int(node.distance)) or_return
		literal_start = position + int(node.length)
	}

	if literal_start < end {
		push_command(e, end, end - literal_start, 0, 0) or_return
	}

	return nil
}
