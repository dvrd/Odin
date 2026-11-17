package compress_zlib

import "core:math/bits"

// Optimal length-limited prefix codes by package-merge, and canonical code
// assignment. Shared by every DEFLATE block the encoder emits.

HUFFMAN_NODES_MAX :: 10240
HUFFMAN_SYMBOLS_MAX :: 320

Huffman_Node :: struct {
	weight: u64,
	left:   i32,
	right:  i32,
	symbol: i32,
}

Huffman_Scratch :: struct {
	nodes:      [HUFFMAN_NODES_MAX]Huffman_Node,
	list_a:     [HUFFMAN_SYMBOLS_MAX * 2]i32,
	list_b:     [HUFFMAN_SYMBOLS_MAX * 2]i32,
	order:      [HUFFMAN_SYMBOLS_MAX]i32,
	node_count: int,
}

// Fills `lengths` so that no code is longer than `limit` and the weighted
// length sum is minimal. Unused symbols get length 0. A single used symbol gets
// length 1, so callers that need a complete code must give it a partner.
huffman_lengths :: proc(scratch: ^Huffman_Scratch, frequencies: []u32, limit: int, lengths: []u8) {
	assert(len(frequencies) == len(lengths))
	assert(len(frequencies) <= HUFFMAN_SYMBOLS_MAX)

	for index in 0 ..< len(lengths) {
		lengths[index] = 0
	}

	used := 0

	for frequency, symbol in frequencies {
		if frequency != 0 {
			scratch.order[used] = i32(symbol)
			used += 1
		}
	}

	if used == 0 {
		return
	}

	if used == 1 {
		lengths[scratch.order[0]] = 1
		return
	}

	assert(used <= 1 << uint(limit))

	order := scratch.order[:used]
	sort_symbols(order, frequencies)

	scratch.node_count = 0

	for symbol in order {
		scratch.nodes[scratch.node_count] = {
			weight = u64(frequencies[symbol]),
			left   = -1,
			right  = -1,
			symbol = symbol,
		}
		scratch.node_count += 1
	}

	current := scratch.list_a[:used]

	for index in 0 ..< used {
		current[index] = i32(index)
	}

	current_count := used
	use_a := true

	for _ in 1 ..< limit {
		next := scratch.list_b[:] if use_a else scratch.list_a[:]
		next_count := 0
		package_index := 0
		leaf_index := 0
		package_total := current_count / 2

		// Merge the original leaves with the packages built from `current`.
		package_first := scratch.node_count

		for pair in 0 ..< package_total {
			left := current[pair * 2]
			right := current[pair * 2 + 1]
			scratch.nodes[scratch.node_count] = {
				weight = scratch.nodes[left].weight + scratch.nodes[right].weight,
				left   = left,
				right  = right,
				symbol = -1,
			}
			scratch.node_count += 1
		}

		for leaf_index < used || package_index < package_total {
			take_leaf := false

			if leaf_index < used && package_index < package_total {
				take_leaf = scratch.nodes[leaf_index].weight <= scratch.nodes[package_first + package_index].weight
			} else if leaf_index < used {
				take_leaf = true
			}

			if take_leaf {
				next[next_count] = i32(leaf_index)
				leaf_index += 1
			} else {
				next[next_count] = i32(package_first + package_index)
				package_index += 1
			}

			next_count += 1
		}

		current = next[:next_count]
		current_count = next_count
		use_a = !use_a
	}

	selected := 2 * used - 2

	for index in 0 ..< selected {
		count_leaves(scratch, current[index], lengths)
	}
}

@(private)
count_leaves :: proc(scratch: ^Huffman_Scratch, index: i32, lengths: []u8) {
	node := scratch.nodes[index]

	if node.symbol >= 0 {
		lengths[node.symbol] += 1
		return
	}

	count_leaves(scratch, node.left, lengths)
	count_leaves(scratch, node.right, lengths)
}

// Insertion sort by (frequency, symbol); alphabets here have at most ~300 entries.
@(private)
sort_symbols :: proc(order: []i32, frequencies: []u32) {
	for index in 1 ..< len(order) {
		value := order[index]
		position := index

		for position > 0 {
			other := order[position - 1]

			if frequencies[other] < frequencies[value] || frequencies[other] == frequencies[value] && other < value {
				break
			}

			order[position] = other
			position -= 1
		}

		order[position] = value
	}
}

// Canonical codes, already bit-reversed for the LSB-first DEFLATE bit order.
huffman_codes :: proc(lengths: []u8, codes: []u16) {
	counts: [16]u32
	first: [16]u32

	for length in lengths {
		counts[length] += 1
	}

	counts[0] = 0
	code: u32

	for length in 1 ..= 15 {
		code = (code + counts[length - 1]) << 1
		first[length] = code
	}

	for length, symbol in lengths {
		if length == 0 {
			codes[symbol] = 0
			continue
		}

		value := first[length]
		first[length] += 1
		codes[symbol] = u16(bits.reverse_bits(value) >> (32 - u32(length)))
	}
}
