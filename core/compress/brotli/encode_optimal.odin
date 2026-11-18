package compress_brotli

import "base:intrinsics"
import "base:runtime"
import "core:math"
import "core:math/bits"

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

// The cheapest command that ends at a position.
Node :: struct {
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
	// Command symbol and copy extra bits by insert and copy code, and the same
	// for the symbols that stand for the last distance as well.
	pair:        [INSERT_CODES][COPY_CODES]f32,
	implicit:    [IMPLICIT_INSERT_CODES][IMPLICIT_COPY_CODES]f32,
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
// Starts tried with the recent distances, and with the cached matches.
STARTS_RECENT :: 5
STARTS_MATCHED :: 2
INSERT_CODES :: 24
COPY_CODES :: 24
// Codes below these share symbols that carry the last distance.
IMPLICIT_INSERT_CODES :: 8
IMPLICIT_COPY_CODES :: 16
COPY_CODE_TABLE :: 2120
// Longest text a transformed dictionary word can cover.
DICTIONARY_COVER_MAX :: 37

Optimal :: struct {
	nodes:        []Node,
	// costs[i]: cost of the cheapest command that ends at i, infinite when
	// none does. Kept apart from the nodes: it is read far more than they are.
	costs:        []f64,
	scanned:      Scanned,
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
	// Per byte, the groups whose prefix may start with it, as bits.
	group_leads:  [256]u16,
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
	o.costs = make([]f64, block_max + 1, allocator) or_return
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
	delete(o.costs, allocator)
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

	assert(o.group_count <= 16)

	for &leads, value in o.group_leads {
		for group, index in o.groups[:o.group_count] {
			if len(group.prefix) == 0 || group.prefix[0] == u8(value) {
				leads |= 1 << uint(index)
			}
		}
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

// Words found per covered length, and the lengths that have one.
Found_Words :: struct {
	lengths: u64,
	words:   [DICTIONARY_COVER_MAX + 1]Cached_Match,
}

// Bytes two texts start with alike, `limit` at most.
shared_length :: #force_inline proc(a, b: [^]u8, limit: int) -> int #no_bounds_check {
	length := 0

	when ODIN_ENDIAN == .Little {
		for length + 8 <= limit {
			difference := intrinsics.unaligned_load((^u64)(&a[length])) ~ intrinsics.unaligned_load((^u64)(&b[length]))

			if difference != 0 {
				return length + int(intrinsics.count_trailing_zeros(difference)) >> 3
			}

			length += 8
		}
	}

	for length < limit && a[length] == b[length] {
		length += 1
	}

	return length
}

offer_word :: #force_inline proc(found: ^Found_Words, covered, size, distance: int) {
	slot := &found.words[covered]
	had := found.lengths & (1 << uint(covered)) != 0

	if !had || u32(distance) < slot.distance {
		slot^ = {u32(covered), u32(size), u32(distance)}
		found.lengths |= 1 << uint(covered)
	}
}

// Every way a static dictionary word, transformed or not, spells the text at
// `position`: the cheapest reference for each covered length.
dictionary_matches :: proc(o: ^Optimal, src: []u8, position, limit, reach: int, found: ^Found_Words) #no_bounds_check {
	for leads := o.group_leads[src[position]]; leads != 0; leads &= leads - 1 {
		group := o.groups[intrinsics.count_trailing_zeros(leads)]
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

		hash := key * 0x1e35a7bd
		filter := hash >> (32 - DICTIONARY_FILTER_BITS)

		// Text as it stands is what a word has to start with, and most
		// of it starts none. A change of case can meet a word the filter
		// does not know under these four bytes: those go and look.
		if group.class == .Plain && DICTIONARY_FILTER[filter >> 6] & (1 << (filter & 63)) == 0 {
			continue
		}

		word := WORD_HEAD[hash >> (32 - DICTIONARY_HASH_BITS)]

		for steps := 0; word != DICTIONARY_NONE && steps < 64; steps += 1 {
			size := int(WORD_LENGTH[word])
			index := int(word) - int(DICTIONARY_FIRST[size])
			offset := int(DICTIONARY_OFFSET[size]) + index * size
			word = WORD_NEXT[word]
			matched := 0

			// A word as it stands goes by eight bytes at a time.
			if group.class == .Plain {
				matched = shared_length(raw_data(src)[at:], raw_data(DICTIONARY)[offset:], min(size, room))
			}

			for group.class != .Plain && matched < min(size, room) {
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
		children := 2 * (other & o.forest_mask)

		length := min(left_length, right_length)
		length += common_length(src, other + length, position + length, limit - length)

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

// Appends the nearest match of two bytes and the nearest longer one within
// NEAR_RANGE of `position`, and returns the length of the longer, 1 for none.
near_matches :: proc(o: ^Optimal, src: []u8, position, limit: int) -> (best: int, err: runtime.Allocator_Error) #no_bounds_check {
	best = 1
	distance := 1

	when ODIN_ENDIAN == .Little {
		// Eight distances at a time while the words stay inside the text:
		// byte k of them belongs to distance + 7 - k.
		if position >= NEAR_RANGE {
			first := u64(src[position]) * BYTE_ONES
			second := u64(src[position + 1]) * BYTE_ONES

			for ; distance <= NEAR_RANGE && best <= 2; distance += 8 {
				before := intrinsics.unaligned_load((^u64)(&src[position - distance - 7]))
				after := intrinsics.unaligned_load((^u64)(&src[position - distance - 6]))
				pairs := zero_bytes(before ~ first) & zero_bytes(after ~ second)

				for pairs != 0 && best <= 2 {
					slot := bits.len(uint(pairs)) - 1
					pairs &~= 1 << uint(slot)
					near := distance + 7 - slot
					length := common_length(src, position - near, position, limit)

					if length > best {
						best = length
						append(&o.matches, Cached_Match{u32(length), u32(length), u32(near)}) or_return
					}
				}
			}

			return
		}
	}

	for ; distance <= min(position, NEAR_RANGE) && best <= 2; distance += 1 {
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
		best := near_matches(o, src, position, limit) or_return

		if best < limit {
			best = tree_search(e, o, position, limit, best, true) or_return
		}

		if best <= OPTIMAL_LONG {
			found: Found_Words = ---
			found.lengths = 0
			dictionary_matches(o, src, position, limit, reach, &found)
			shortest := uint(min(max(best + 1, 4), len(found.words)))

			for lengths := found.lengths >> shortest << shortest; lengths != 0; lengths &= lengths - 1 {
				append(&o.matches, found.words[intrinsics.count_trailing_zeros(lengths)]) or_return
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

		pair_costs(&o.model)

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

	pair_costs(&o.model)
}

// Tabulates the command costs the shortest path asks for per copy length.
pair_costs :: proc(model: ^Model) {
	for insert in 0 ..< INSERT_CODES {
		for copy in 0 ..< COPY_CODES {
			model.pair[insert][copy] = command_cost(model, insert, copy, false)
		}
	}

	for insert in 0 ..< IMPLICIT_INSERT_CODES {
		for copy in 0 ..< IMPLICIT_COPY_CODES {
			model.implicit[insert][copy] = command_cost(model, insert, copy, true)
		}
	}
}

// ------------------------------------------------------------- shortest path

// Bits of the command symbol and the copy length's extra bits.
command_cost :: proc(model: ^Model, insert, copy: int, implicit: bool) -> f32 {
	cell := COMMAND_CELLS[insert >> 3][copy >> 3]

	if implicit {
		cell -= 2
	}

	return model.command[cell << 6 | (insert & 7) << 3 | copy & 7] + f32(COPY_EXTRA[copy])
}

copy_code_of :: #force_inline proc(o: ^Optimal, length: int) -> int #no_bounds_check {
	return int(o.copy_codes[length]) if length < COPY_CODE_TABLE else 23
}

// Longest copy of a copy code.
copy_code_last :: #force_inline proc(copy: int) -> int #no_bounds_check {
	return int(COPY_BASE[copy]) + 1 << COPY_EXTRA[copy] - 1
}

// Offers the nodes that copies of first..=last bytes from `at` reach a command
// of `cost` bits: one copy code, so one cost, for all of them. `omit` is what a
// dictionary word's copy length has over the bytes it covers.
offer_sizes :: #force_inline proc(o: ^Optimal, at, first, last: int, cost: f64, run, distance, omit: int, ring: Ring) #no_bounds_check {
	for size in first ..= last {
		if cost < o.costs[at + size] {
			o.costs[at + size] = cost
			o.nodes[at + size] = {u32(run), u32(size), u32(size + omit), u32(distance), ring}
		}
	}
}

// Keeps the cheapest starts, as many as `starts` holds, cheapest first and
// the older first among equals.
push_start :: #force_inline proc(starts: []Start, count: ^int, start: Start) #no_bounds_check {
	slot := count^

	if slot == len(starts) {
		// Full: only a start cheaper than the dearest enters, in its place.
		slot -= 1

		if starts[slot].relative <= start.relative {
			return
		}
	} else {
		count^ += 1
	}

	for slot > 0 && starts[slot - 1].relative > start.relative {
		starts[slot] = starts[slot - 1]
		slot -= 1
	}

	starts[slot] = start
}

BYTE_ONES :: 0x0101010101010101
BYTE_LOWS :: 0x7f7f7f7f7f7f7f7f
RECENT_ALL :: 0xffff

// Recent-distance candidates of the seven bytes around the newest distance,
// farthest first, as bits by candidate number.
RECENT_ORDER: [128]u16

@(init)
fill_recent_order :: proc "contextless" () {
	for set in 0 ..< len(RECENT_ORDER) {
		for candidate in 0 ..< 16 {
			slot := 3 - int(CACHE_OFFSET[candidate])

			if CACHE_INDEX[candidate] == 0 && set & (1 << uint(slot)) != 0 {
				RECENT_ORDER[set] |= 1 << uint(candidate)
			}
		}
	}
}

// One bit per byte of `word` that is zero, the first byte lowest.
zero_bytes :: #force_inline proc(word: u64) -> int {
	flags := ~((word & BYTE_LOWS + BYTE_LOWS) | word | BYTE_LOWS)

	return int((flags >> 7) * 0x0102040810204080 >> 56)
}

// The recent-distance candidates, as bits by number, that have `best` bytes
// in the byte the text has there: only those can go past `best`. Sixteen
// candidates are seven bytes around each of the two newest distances and one
// at each of the older two, so two words and two bytes answer for all. Every
// candidate when a word would reach outside the text.
recent_candidates :: #force_inline proc(src: []u8, ring: ^Ring, position, best: int) -> int #no_bounds_check {
	when ODIN_ENDIAN == .Little {
		first := int(ring[0])
		second := int(ring[1])
		third := int(ring[2])
		fourth := int(ring[3])

		if first < 5 || first + 3 > position || second < 5 || second + 3 > position {
			return RECENT_ALL
		}

		if third < 1 || third > position || fourth < 1 || fourth > position {
			return RECENT_ALL
		}

		at := position + best
		value := src[at]
		spread := u64(value) * BYTE_ONES
		near := int(RECENT_ORDER[zero_bytes(intrinsics.unaligned_load((^u64)(&src[at - first - 3])) ~ spread) & 127])
		far := int(RECENT_ORDER[zero_bytes(intrinsics.unaligned_load((^u64)(&src[at - second - 3])) ~ spread) & 127])
		// The second newest distance has candidate 1 and, for its
		// neighbours, 10 to 15 where the newest has 4 to 9.
		set := near | (far & 1) << 1 | (far >> 4) << 10

		if src[at - third] == value {
			set |= 1 << 2
		}

		if src[at - fourth] == value {
			set |= 1 << 3
		}

		return set
	} else {
		return RECENT_ALL
	}
}

// What the copies offered from one start at one node have in common.
Offer :: struct {
	at:       int,
	position: int,
	limit:    int,
	reach:    int,
	run:      int,
	insert:   int,
	// Cost up to the copy: the start, the literals and their extra bits.
	base:     f64,
	ring:     Ring,
}

// Offers the copies at the recent distances that are longer than `best`.
recent_copies :: #force_inline proc(src: []u8, o: ^Optimal, offer: ^Offer, best: int) #no_bounds_check {
	best := best
	model := &o.model
	at := offer.at
	position := offer.position
	limit := offer.limit
	insert := offer.insert
	pair := &model.pair[insert]

	if best >= limit {
		return
	}

	candidates := recent_candidates(src, &offer.ring, position, best)

	for candidates != 0 {
		index := int(intrinsics.count_trailing_zeros(candidates))
		candidates &= candidates - 1
		distance := int(offer.ring[CACHE_INDEX[index]]) + int(CACHE_OFFSET[index])

		if distance <= 0 || distance > offer.reach || index != 0 && distance == int(offer.ring[0]) {
			continue
		}

		if src[position + best] != src[position - distance + best] {
			continue
		}

		length := common_length(src, position - distance, position, limit)
		ring := offer.ring

		if index != 0 {
			ring_push(&ring, distance)
		}

		size := best + 1
		last_distance := index == 0 && insert < IMPLICIT_INSERT_CODES

		if length > OPTIMAL_LONG {
			size = length
		}

		for size <= length {
			copy := copy_code_of(o, size)
			last := min(length, copy_code_last(copy))
			cost := offer.base

			if last_distance && copy < IMPLICIT_COPY_CODES {
				cost += f64(model.implicit[insert][copy])
			} else {
				cost += f64(pair[copy])
				cost += f64(model.distance[distance_context(u32(size))][index])
			}

			offer_sizes(o, at, size, last, cost, offer.run, distance, 0, ring)
			size = last + 1
		}

		if length <= best {
			continue
		}

		best = length

		if best >= limit {
			break
		}

		// Later candidates have to pass at the new length.
		candidates &= recent_candidates(src, &offer.ring, position, best)
	}
}

// Offers the cached matches of the node at their lengths from `shortest` up.
cached_copies :: #force_inline proc(o: ^Optimal, offer: ^Offer, shortest: int, cached: []Cached_Match) #no_bounds_check {
	model := &o.model
	pair := &model.pair[offer.insert]
	size := shortest

	for match in cached {
		top := int(match.length)

		// Nothing left to offer: the lengths it has are taken or ruled out.
		if top < size {
			continue
		}

		distance := int(match.distance)
		word := distance > offer.reach
		symbol, extra_bits, _ := distance_prefix(u32(distance) + 15, model.postfix, model.direct)
		ring := offer.ring

		if !word {
			ring_push(&ring, distance)
		}

		if size < top && (word || top > OPTIMAL_LONG) {
			size = top
		}

		// A word is one copy, whose length says which word.
		omit := int(match.copy_length) - top if word else 0

		for size <= top {
			coded := size + omit
			copy := copy_code_of(o, coded)
			last := top if word else min(top, copy_code_last(copy))
			cost := offer.base + f64(pair[copy]) + f64(model.distance[distance_context(u32(coded))][symbol]) + f64(extra_bits)
			offer_sizes(o, offer.at, size, last, cost, offer.run, distance, omit, ring)
			size = last + 1
		}
	}
}

// The scan for the shortest copy from a node that could still beat what
// already reaches the nodes ahead: lengths below `shortest` cannot. The bound
// is the cheapest command, one more bit per length-code bucket.
Scan :: struct {
	shortest:   int,
	bucket:     int,
	bucket_end: int,
	// Bits the bound has gained so far.
	raises:     int,
}

// The scan of the cheapest start at the node before, kept to go on from.
Scanned :: struct {
	at:       int,
	// Its bound for the shortest copies.
	floor:    f64,
	shortest: int,
}

scan_raise :: #force_inline proc(scan: ^Scan, floor: ^f64) {
	floor^ += 1
	scan.raises += 1
	scan.bucket_end += scan.bucket
	scan.bucket *= 2
}

// Starts the scan at node `at` from what the node before found, when the
// bound has not come down since: a node that was within the bound one byte
// further from there is within it now, costs only ever falling, unless it
// was the first of its bucket then, where the bound had one bit more. Those
// few are looked at; the scan goes on after the last node known.
scan_resume :: #force_inline proc(o: ^Optimal, scan: ^Scan, at: int, floor: ^f64) #no_bounds_check {
	if o.scanned.at + 1 != at || floor^ < o.scanned.floor {
		return
	}

	known := max(o.scanned.shortest - 1, scan.shortest)

	for scan.bucket_end <= known {
		if o.costs[at + scan.bucket_end - 1] > floor^ {
			known = scan.bucket_end - 1

			break
		}

		scan_raise(scan, floor)
	}

	scan.shortest = known
}

// Offers, from every start, the copies that begin at node `at`.
relax :: proc(e: ^Encoder, o: ^Optimal, starts: []Start, at, position, limit: int, cached: []Cached_Match) #no_bounds_check {
	costs := o.costs

	// Below the top level only the cheapest start is extended.
	matched := STARTS_MATCHED if e.level >= .Optimal else 1

	// The starts come cheapest first, so no start's bound lies below that of
	// the one before it and each scan goes on where the last one stopped.
	scan := Scan{2, 4, 10, 0}

	for start, rank in starts {
		run := at - start.position
		insert := insert_code(run)
		arrival := start.relative + o.literal_sum[at]
		lowest := arrival + f64(o.model.command_min)
		floor := lowest

		// One at a time, as the scan itself adds them: the sums must agree.
		for _ in 0 ..< scan.raises {
			floor += 1
		}

		if rank == 0 {
			scan_resume(o, &scan, at, &floor)
		}

		for scan.shortest <= limit && costs[at + scan.shortest] <= floor {
			scan.shortest += 1

			if scan.shortest == scan.bucket_end {
				scan_raise(&scan, &floor)
			}
		}

		if rank == 0 {
			o.scanned = {at, lowest, scan.shortest}
		}

		offer := Offer{at, position, limit, min(position, e.window_max), run, insert, arrival + f64(INSERT_EXTRA[insert]), start.ring}
		recent_copies(e.src, o, &offer, scan.shortest - 1)

		if rank < matched {
			cached_copies(o, &offer, scan.shortest, cached)
		}
	}
}

shortest_path :: proc(e: ^Encoder, o: ^Optimal, start, end: int) -> runtime.Allocator_Error #no_bounds_check {
	count := end - start
	nodes := o.nodes[:count + 1]
	costs := o.costs[:count + 1]

	for &cost in costs {
		cost = math.INF_F64
	}

	costs[0] = 0
	nodes[0] = {ring = e.ring}
	o.scanned = {at = -2}
	// Below the top level only the cheapest start is extended.
	starts: [STARTS_RECENT]Start
	kept := STARTS_RECENT if e.level >= .Optimal else 1
	started := 0
	skip := 0

	for at in 0 ..< count {
		// Only ends of commands that beat plain literals are worth starting from.
		if costs[at] <= o.literal_sum[at] {
			push_start(starts[:kept], &started, {at, costs[at] - o.literal_sum[at], nodes[at].ring})
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

	for cost, at in costs {
		total := cost + o.literal_sum[count] - o.literal_sum[at]

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
