package compress_brotli

import "base:runtime"
import "core:math"

// Levels 10 and 11: every match of a block is cached once, then the block is
// parsed as a shortest path under a bit-cost model taken from the previous
// parse, a few times over.

Cached_Match :: struct {
	// Bytes covered, and the copy length that codes them: they differ for a
	// transformed static dictionary word.
	length:      u32,
	copy_length: u32,
	distance:    u32,
}

Node :: struct {
	// Cheapest cost of a command that ends here; infinite when none does.
	cost:        f64,
	insert:      u32,
	length:      u32,
	copy_length: u32,
	distance:    u32,
	// Recent distances after that command.
	ring:        Ring,
}

// A position commands may start from: the end of a cheap command.
Start :: struct {
	position: int,
	// Cost of its node less the literal cost of everything before it.
	relative: f64,
	ring:     Ring,
}

Model :: struct {
	command:     [COMMAND_ALPHABET]f32,
	// Cheapest command symbol.
	command_min: f32,
	distance:    [DISTANCE_CONTEXTS][DISTANCE_ALPHABET]f32,
	postfix:     uint,
	direct:      uint,
}

Word_Class :: enum u8 {
	Plain,
	Capital,
	Upper,
}

// Dictionary transforms that share a prefix and a letter case.
Transform_Group :: struct {
	prefix: string,
	class:  Word_Class,
	first:  u8,
	count:  u8,
}

// Literal estimates run low: they come from histograms that the next parse
// thins out. Measured on text, markup, JSON and binaries.
LITERAL_BIAS :: 1.1
TREE_BUCKET_BITS :: 17
TREE_DEPTH :: 64
// Trees order positions by their next TREE_COMPARE bytes.
TREE_COMPARE :: 128
// Positions before the current one scanned for two and three byte matches.
NEAR_RANGE :: 64
STARTS_MAX :: 8
// Starts tried with the recent distances, and with the cached matches.
STARTS_RECENT :: 5
STARTS_MATCHED :: 2
COPY_CODE_TABLE :: 2120
// Longest text a transformed dictionary word can cover.
DICTIONARY_COVER_MAX :: 37

Optimal :: struct {
	nodes:        []Node,
	matches:      [dynamic]Cached_Match,
	match_start:  []u32,
	literal_cost: []f32,
	// literal_sum[i]: cost of the first i literals of the block.
	literal_sum:  []f64,
	// Ends of the commands on the cheapest path, last first.
	path:         [dynamic]u32,
	model:        Model,
	tree_cost:    [LITERAL_CONTEXTS][LITERAL_ALPHABET]f32,
	// Binary trees of positions, one per hash bucket; forest holds the two
	// children of every window position.
	roots:        []u32,
	forest:       []u32,
	forest_mask:  int,
	copy_codes:   [COPY_CODE_TABLE]u8,
	groups:       [TRANSFORM_COUNT]Transform_Group,
	members:      [TRANSFORM_COUNT]u8,
	group_count:  int,
}

optimal_make :: proc(e: ^Encoder, block_max: int, allocator: runtime.Allocator) -> (o: ^Optimal, err: runtime.Allocator_Error) {
	o = new(Optimal, allocator) or_return

	window := 1 << WINDOW_BITS_MIN

	for window < min(len(e.src), e.window_max + 1) {
		window <<= 1
	}

	o.forest_mask = window - 1
	o.forest = make([]u32, 2 * window, allocator) or_return
	o.roots = make([]u32, 1 << TREE_BUCKET_BITS, allocator) or_return

	for &root in o.roots {
		root = NIL
	}

	o.nodes = make([]Node, block_max + 1, allocator) or_return
	o.match_start = make([]u32, block_max + 1, allocator) or_return
	o.literal_cost = make([]f32, block_max, allocator) or_return
	o.literal_sum = make([]f64, block_max + 1, allocator) or_return
	o.matches = make([dynamic]Cached_Match, allocator) or_return
	o.path = make([dynamic]u32, allocator) or_return

	for length in 0 ..< COPY_CODE_TABLE {
		o.copy_codes[length] = u8(copy_code(max(length, 2)))
	}

	group_transforms(o)

	return o, nil
}

optimal_destroy :: proc(o: ^Optimal, allocator: runtime.Allocator) {
	if o == nil {
		return
	}

	delete(o.forest, allocator)
	delete(o.roots, allocator)
	delete(o.nodes, allocator)
	delete(o.match_start, allocator)
	delete(o.literal_cost, allocator)
	delete(o.literal_sum, allocator)
	delete(o.matches)
	delete(o.path)
	free(o, allocator)
}

// Groups the transforms that keep a whole word by prefix and letter case.
group_transforms :: proc(o: ^Optimal) {
	grouped: [TRANSFORM_COUNT]bool
	members := 0

	for transform, id in TRANSFORMS {
		class, whole := word_class(transform.kind)

		if !whole || grouped[id] {
			continue
		}

		group := Transform_Group{transform.prefix, class, u8(members), 0}

		for other, other_id in TRANSFORMS[id:] {
			other_class, other_whole := word_class(other.kind)

			if other_whole && other_class == class && other.prefix == transform.prefix {
				grouped[id + other_id] = true
				o.members[members] = u8(id + other_id)
				members += 1
				group.count += 1
			}
		}

		o.groups[o.group_count] = group
		o.group_count += 1
	}
}

word_class :: proc(kind: u8) -> (class: Word_Class, whole: bool) {
	switch Transform_Kind(kind) {
	case .Identity:
		return .Plain, true
	case .Uppercase_First:
		return .Capital, true
	case .Uppercase_All:
		return .Upper, true
	case .Omit_Last_1, .Omit_Last_9, .Omit_First_1, .Omit_First_9:
	}

	return .Plain, false
}

// Parses src[start:end] into e.commands.
parse_optimal :: proc(e: ^Encoder, o: ^Optimal, block: ^Meta_Block, start, end: int) -> runtime.Allocator_Error {
	ring := e.ring
	collect_matches(e, o, start, end) or_return

	// First model: every byte as a literal, flat command and distance costs.
	push_command(e, end, end - start, 0, 0, 0) or_return
	gather(e, block, start, end, false) or_return
	set_model(e, o, block, start, end, true)
	iterations := OPTIMAL_ITERATIONS if e.level >= .Optimal else OPTIMAL_ITERATIONS - 1

	for iteration in 0 ..< iterations {
		clear(&e.commands)
		e.ring = ring
		shortest_path(e, o, start, end) or_return

		// The caller models the final parse together with its neighbours.
		if iteration + 1 < iterations {
			gather(e, block, start, end, false) or_return
			set_model(e, o, block, start, end, false)
		}
	}

	return nil
}

// ------------------------------------------------------------- match finding

is_upper :: #force_inline proc(value: u8) -> bool {
	return value >= 'A' && value <= 'Z'
}

is_lower :: #force_inline proc(value: u8) -> bool {
	return value >= 'a' && value <= 'z'
}

to_lower :: #force_inline proc(value: u8) -> u8 {
	return value | 0x20 if is_upper(value) else value
}

// Byte `index` of a dictionary word as text of the given case shows it.
cased :: #force_inline proc(value: u8, index: int, class: Word_Class) -> u8 {
	if is_lower(value) && (class == .Upper || class == .Capital && index == 0) {
		return value ~ 0x20
	}

	return value
}

starts_with :: #force_inline proc(src: []u8, position, limit: int, text: string) -> bool #no_bounds_check {
	if len(text) > limit {
		return false
	}

	for index in 0 ..< len(text) {
		if src[position + index] != text[index] {
			return false
		}
	}

	return true
}

offer_word :: #force_inline proc(found: ^[DICTIONARY_COVER_MAX + 1]Cached_Match, covered, size, distance: int) {
	slot := &found[covered]

	if slot.distance == 0 || u32(distance) < slot.distance {
		slot^ = {u32(covered), u32(size), u32(distance)}
	}
}

// Every way a static dictionary word, transformed or not, spells the text at
// `position`: the cheapest reference for each covered length.
dictionary_matches :: proc(o: ^Optimal, src: []u8, position, limit, reach: int, found: ^[DICTIONARY_COVER_MAX + 1]Cached_Match) #no_bounds_check {
	for group in o.groups[:o.group_count] {
		lead := len(group.prefix)

		if lead + 4 > limit || !starts_with(src, position, limit, group.prefix) {
			continue
		}

		at := position + lead
		room := limit - lead

		if group.class != .Plain && !is_upper(src[at]) {
			continue
		}

		key: u32

		for index in 0 ..< 4 {
			value := src[at + index]

			if group.class == .Upper || group.class == .Capital && index == 0 {
				value = to_lower(value)
			}

			key |= u32(value) << uint(8 * index)
		}

		word := WORD_HEAD[(key * 0x1e35a7bd) >> (32 - DICTIONARY_HASH_BITS)]

		for steps := 0; word != DICTIONARY_NONE && steps < 64; steps += 1 {
			size := int(WORD_LENGTH[word])
			index := int(word) - int(DICTIONARY_FIRST[size])
			offset := int(DICTIONARY_OFFSET[size]) + index * size
			word = WORD_NEXT[word]
			matched := 0

			for matched < min(size, room) {
				value := DICTIONARY[offset + matched]

				// Bytes from 0xc0 up make the uppercase transforms touch
				// their neighbours: leave those words to the plain form.
				if group.class != .Plain && value >= 0xc0 || src[at + matched] != cased(value, matched, group.class) {
					break
				}

				matched += 1
			}

			base := reach + 1 + index
			omit := size - matched

			if lead == 0 && group.class == .Plain && omit >= 1 && omit <= 9 && matched >= 4 {
				offer_word(found, matched, size, base + int(OMIT_LAST_TRANSFORM[omit]) << DICTIONARY_SIZE_BITS[size])
			}

			if omit != 0 {
				continue
			}

			for id in o.members[group.first:][:group.count] {
				suffix := TRANSFORMS[id].suffix

				if starts_with(src, at + size, room - size, suffix) {
					offer_word(found, lead + size + len(suffix), size, base + int(id) << DICTIONARY_SIZE_BITS[size])
				}
			}
		}
	}
}

// Stores `position` in its tree and, when `collect`, appends the matches
// longer than `best` met on the way down, nearest first per length.
tree_search :: proc(e: ^Encoder, o: ^Optimal, position, limit, best: int, collect: bool) -> (longest: int, err: runtime.Allocator_Error) #no_bounds_check {
	src := e.src
	longest = best
	reach := min(position, e.window_max)
	compare := min(limit, TREE_COMPARE)
	// Only positions with a full comparison length enter the trees.
	store := limit >= TREE_COMPARE
	key := hash4(src, position) >> (32 - TREE_BUCKET_BITS)
	candidate := o.roots[key]
	left := 2 * (position & o.forest_mask)
	right := left + 1
	left_length := 0
	right_length := 0

	if store {
		o.roots[key] = u32(position)
	}

	for depth := TREE_DEPTH; ; depth -= 1 {
		distance := position - int(candidate)

		if candidate == NIL || distance <= 0 || distance > reach || depth == 0 {
			if store {
				o.forest[left] = NIL
				o.forest[right] = NIL
			}

			break
		}

		other := int(candidate)
		length := min(left_length, right_length)
		length += common_length(src, other + length, position + length, limit - length)
		children := 2 * (other & o.forest_mask)

		if collect && length > longest {
			longest = length
			append(&o.matches, Cached_Match{u32(length), u32(length), u32(distance)}) or_return
		}

		if length >= compare {
			if store {
				o.forest[left] = o.forest[children]
				o.forest[right] = o.forest[children + 1]
			}

			break
		}

		if src[position + length] > src[other + length] {
			left_length = length

			if store {
				o.forest[left] = candidate
			}

			left = children + 1
			candidate = o.forest[left]
		} else {
			right_length = length

			if store {
				o.forest[right] = candidate
			}

			right = children
			candidate = o.forest[right]
		}
	}

	return
}

// Caches, per position, its matches by increasing length: the nearest two and
// three byte ones, the tree's, then static dictionary words longer than those.
collect_matches :: proc(e: ^Encoder, o: ^Optimal, start, end: int) -> runtime.Allocator_Error #no_bounds_check {
	src := e.src
	clear(&o.matches)

	for position := start; position < end; position += 1 {
		o.match_start[position - start] = u32(len(o.matches))
		limit := end - position

		if limit < 4 {
			continue
		}

		reach := min(position, e.window_max)
		first := len(o.matches)
		best := 1

		for distance := 1; distance <= min(reach, NEAR_RANGE) && best <= 2; distance += 1 {
			other := position - distance

			if src[other] != src[position] || src[other + 1] != src[position + 1] {
				continue
			}

			length := common_length(src, other, position, limit)

			if length > best {
				best = length
				append(&o.matches, Cached_Match{u32(length), u32(length), u32(distance)}) or_return
			}
		}

		if best < limit {
			best = tree_search(e, o, position, limit, best, true) or_return
		}

		if best <= OPTIMAL_LONG {
			found: [DICTIONARY_COVER_MAX + 1]Cached_Match
			dictionary_matches(o, src, position, limit, reach, &found)

			for word in found[min(max(best + 1, 4), len(found)):] {
				if word.distance != 0 {
					append(&o.matches, word) or_return
				}
			}

			continue
		}

		// A long match is taken whole: keep it alone and only index its tail.
		o.matches[first] = o.matches[len(o.matches) - 1]
		resize(&o.matches, first + 1) or_return
		stop := position + best
		tail := max(position + 1, stop - TREE_COMPARE / 2)

		for position += 1; position < stop; position += 1 {
			o.match_start[position - start] = u32(len(o.matches))

			if position >= tail && end - position >= TREE_COMPARE {
				tree_search(e, o, position, end - position, 0, false) or_return
			}
		}

		position -= 1
	}

	o.match_start[end - start] = u32(len(o.matches))

	return nil
}

// ---------------------------------------------------------------- cost model

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

set_model :: proc(e: ^Encoder, o: ^Optimal, block: ^Meta_Block, start, end: int, flat: bool) {
	src := e.src

	for tree in 0 ..< block.literal_trees {
		symbol_costs(block.literal_histogram[tree * LITERAL_ALPHABET:][:LITERAL_ALPHABET], o.tree_cost[tree][:], 8)
	}

	for position in start ..< end {
		tree := block.literal_map[literal_context(src, position, block.mode)]
		o.literal_cost[position - start] = o.tree_cost[tree][src[position]] * LITERAL_BIAS
		o.literal_sum[position - start + 1] = o.literal_sum[position - start] + f64(o.literal_cost[position - start])
	}

	o.model.postfix = block.postfix
	o.model.direct = block.direct

	if flat {
		for &cost, symbol in o.model.command {
			cost = 5.5 if symbol < 128 else 7
		}

		o.model.command_min = 5.5

		for &costs in o.model.distance {
			for &cost, symbol in costs {
				cost = 4 if symbol < 16 else 4.5
			}
		}

		return
	}

	symbol_costs(block.command_histogram[:COMMAND_ALPHABET], o.model.command[:], 8)
	o.model.command_min = math.INF_F32

	for cost in o.model.command {
		o.model.command_min = min(o.model.command_min, cost)
	}

	for &costs, slot in o.model.distance {
		symbol_costs(block.distance_histogram[int(block.distance_map[slot]) * DISTANCE_ALPHABET:][:DISTANCE_ALPHABET], costs[:], 6)
	}
}

// ------------------------------------------------------------- shortest path

// Bits of the command symbol and the copy length's extra bits.
command_cost :: #force_inline proc(o: ^Optimal, insert, copy: int, implicit: bool) -> f32 #no_bounds_check {
	cell := COMMAND_CELLS[insert >> 3][copy >> 3]

	if implicit {
		cell -= 2
	}

	return o.model.command[cell << 6 | (insert & 7) << 3 | copy & 7] + f32(COPY_EXTRA[copy])
}

copy_code_of :: #force_inline proc(o: ^Optimal, length: int) -> int #no_bounds_check {
	return int(o.copy_codes[length]) if length < COPY_CODE_TABLE else 23
}

// Keeps the STARTS_MAX cheapest starts, cheapest first.
push_start :: proc(starts: ^[STARTS_MAX]Start, count: ^int, start: Start) {
	// A new start always enters; when full it replaces the dearest one.
	slot := min(count^, STARTS_MAX - 1)

	for slot > 0 && starts[slot - 1].relative > start.relative {
		starts[slot] = starts[slot - 1]
		slot -= 1
	}

	starts[slot] = start
	count^ = min(count^ + 1, STARTS_MAX)
}

// Offers, from every start, the copies that begin at node `at`.
relax :: proc(e: ^Encoder, o: ^Optimal, starts: []Start, at, position, limit: int, cached: []Cached_Match) #no_bounds_check {
	src := e.src
	reach := min(position, e.window_max)
	nodes := o.nodes

	// Below the top level only the cheapest start is extended.
	recent := STARTS_RECENT if e.level >= .Optimal else 1
	matched := STARTS_MATCHED if e.level >= .Optimal else 1

	for start, rank in starts[:min(len(starts), recent)] {
		run := at - start.position
		insert := insert_code(run)
		arrival := start.relative + o.literal_sum[at]
		base := arrival + f64(INSERT_EXTRA[insert])

		// Shortest copy that could still beat what already reaches the nodes
		// ahead: the cheapest command, one more bit per length-code bucket.
		floor := arrival + f64(o.model.command_min)
		shortest := 2
		bucket := 4
		bucket_end := 10

		for shortest <= limit && nodes[at + shortest].cost <= floor {
			shortest += 1

			if shortest == bucket_end {
				floor += 1
				bucket_end += bucket
				bucket *= 2
			}
		}

		best := shortest - 1

		for index in 0 ..< 16 {
			if best >= limit {
				break
			}

			distance := int(start.ring[CACHE_INDEX[index]]) + int(CACHE_OFFSET[index])

			if distance <= 0 || distance > reach || index != 0 && distance == int(start.ring[0]) {
				continue
			}

			if src[position + best] != src[position - distance + best] {
				continue
			}

			length := common_length(src, position - distance, position, limit)
			ring := start.ring

			if index != 0 {
				ring_push(&ring, distance)
			}

			low := best + 1

			if length > OPTIMAL_LONG {
				low = length
			}

			for size in low ..= length {
				copy := copy_code_of(o, size)
				implicit := index == 0 && insert < 8 && copy < 16
				cost := base + f64(command_cost(o, insert, copy, implicit))

				if !implicit {
					cost += f64(o.model.distance[distance_context(u32(size))][index])
				}

				target := &nodes[at + size]

				if cost < target.cost {
					target^ = {cost, u32(run), u32(size), u32(size), u32(distance), ring}
				}
			}

			best = max(best, length)
		}

		if rank >= matched {
			continue
		}

		size := shortest

		for match in cached {
			distance := int(match.distance)
			word := distance > reach
			top := int(match.length)
			symbol, extra_bits, _ := distance_prefix(u32(distance) + 15, o.model.postfix, o.model.direct)
			ring := start.ring

			if !word {
				ring_push(&ring, distance)
			}

			if size < top && (word || top > OPTIMAL_LONG) {
				size = top
			}

			for ; size <= top; size += 1 {
				coded := int(match.copy_length) if word else size
				cost :=
					base +
					f64(command_cost(o, insert, copy_code_of(o, coded), false)) +
					f64(o.model.distance[distance_context(u32(coded))][symbol]) +
					f64(extra_bits)
				target := &nodes[at + size]

				if cost < target.cost {
					target^ = {cost, u32(run), u32(size), u32(coded), u32(distance), ring}
				}
			}
		}
	}
}

shortest_path :: proc(e: ^Encoder, o: ^Optimal, start, end: int) -> runtime.Allocator_Error #no_bounds_check {
	count := end - start
	nodes := o.nodes[:count + 1]

	for &node in nodes {
		node.cost = math.INF_F64
	}

	nodes[0] = {ring = e.ring}
	starts: [STARTS_MAX]Start
	started := 0
	skip := 0

	for at in 0 ..< count {
		node := &nodes[at]

		// Only ends of commands that beat plain literals are worth starting from.
		if node.cost <= o.literal_sum[at] {
			push_start(&starts, &started, {at, node.cost - o.literal_sum[at], node.ring})
		}

		if skip > 0 {
			skip -= 1
			continue
		}

		limit := count - at

		if limit < 2 {
			continue
		}

		cached := o.matches[o.match_start[at]:o.match_start[at + 1]]
		relax(e, o, starts[:started], at, start + at, limit, cached)

		// A long match is taken whole: nothing inside it starts a copy.
		if len(cached) == 1 && int(cached[0].length) > OPTIMAL_LONG {
			skip = int(cached[0].length) - 1
		}
	}

	// The block ends with whatever literals follow the cheapest last command.
	last := 0
	cheapest := math.INF_F64

	for node, at in nodes {
		total := node.cost + o.literal_sum[count] - o.literal_sum[at]

		if total <= cheapest {
			cheapest = total
			last = at
		}
	}

	clear(&o.path)

	for at := last; at > 0; {
		append(&o.path, u32(at)) or_return
		at -= int(nodes[at].length) + int(nodes[at].insert)
	}

	for index := len(o.path) - 1; index >= 0; index -= 1 {
		at := int(o.path[index])
		node := nodes[at]
		position := start + at - int(node.length)
		omit := int(node.copy_length) - int(node.length)
		push_command(e, position, int(node.insert), int(node.copy_length), int(node.distance), omit) or_return
	}

	if last < count {
		push_command(e, end, count - last, 0, 0, 0) or_return
	}

	return nil
}
