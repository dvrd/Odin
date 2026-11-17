package compress_brotli

import "base:runtime"
import "core:math"

// A meta-block: the commands of e.commands split into block types per
// category, their histograms clustered into prefix codes, and the bit stream.

Category :: enum {
	Literal,
	Command,
	Distance,
}

// Consecutive runs of symbols of one category and the block type of each.
Split :: struct {
	types:   [dynamic]u8,
	lengths: [dynamic]u32,
	count:   int,
}

Cursor :: struct {
	index:     int,
	type:      int,
	remaining: u32,
	// Block type history for the switch code.
	last:      int,
	second:    int,
}

BLOCK_TYPE_ALPHABET :: 258

Meta_Block :: struct {
	// Literal context mode and distance parameters.
	mode:               int,
	postfix:            uint,
	direct:             uint,
	splits:             [Category]Split,
	streams:            [Category][dynamic]u16,
	// One histogram per (block type, context) until clustered; then one per tree.
	literal_histogram:  [dynamic]u32,
	command_histogram:  [dynamic]u32,
	distance_histogram: [dynamic]u32,
	literal_map:        [dynamic]u8,
	distance_map:       [dynamic]u8,
	literal_trees:      int,
	distance_trees:     int,
	literal_lengths:    [dynamic]u8,
	literal_codes:      [dynamic]u16,
	command_lengths:    [dynamic]u8,
	command_codes:      [dynamic]u16,
	distance_lengths:   [dynamic]u8,
	distance_codes:     [dynamic]u16,
	type_lengths:       [Category][BLOCK_TYPE_ALPHABET]u8,
	type_codes:         [Category][BLOCK_TYPE_ALPHABET]u16,
	count_lengths:      [Category][BLOCK_COUNT_ALPHABET]u8,
	count_codes:        [Category][BLOCK_COUNT_ALPHABET]u16,
}

@(private)
block_make :: proc(allocator: runtime.Allocator) -> (block: ^Meta_Block, err: runtime.Allocator_Error) {
	block = new(Meta_Block, allocator) or_return

	for &split in block.splits {
		split.types = make([dynamic]u8, allocator) or_return
		split.lengths = make([dynamic]u32, allocator) or_return
	}

	for &stream in block.streams {
		stream = make([dynamic]u16, allocator) or_return
	}

	block.literal_histogram = make([dynamic]u32, allocator) or_return
	block.command_histogram = make([dynamic]u32, allocator) or_return
	block.distance_histogram = make([dynamic]u32, allocator) or_return
	block.literal_map = make([dynamic]u8, allocator) or_return
	block.distance_map = make([dynamic]u8, allocator) or_return
	block.literal_lengths = make([dynamic]u8, allocator) or_return
	block.literal_codes = make([dynamic]u16, allocator) or_return
	block.command_lengths = make([dynamic]u8, allocator) or_return
	block.command_codes = make([dynamic]u16, allocator) or_return
	block.distance_lengths = make([dynamic]u8, allocator) or_return
	block.distance_codes = make([dynamic]u16, allocator) or_return

	return block, nil
}

@(private)
block_destroy :: proc(block: ^Meta_Block, allocator: runtime.Allocator) {
	if block == nil {
		return
	}

	for &split in block.splits {
		delete(split.types)
		delete(split.lengths)
	}

	for &stream in block.streams {
		delete(stream)
	}

	delete(block.literal_histogram)
	delete(block.command_histogram)
	delete(block.distance_histogram)
	delete(block.literal_map)
	delete(block.distance_map)
	delete(block.literal_lengths)
	delete(block.literal_codes)
	delete(block.command_lengths)
	delete(block.command_codes)
	delete(block.distance_lengths)
	delete(block.distance_codes)
	free(block, allocator)
}

@(private)
literal_context :: #force_inline proc(src: []u8, position, mode: int) -> int {
	p1 := int(src[position - 1]) if position > 0 else 0
	p2 := int(src[position - 2]) if position > 1 else 0

	return int(CONTEXT_LOOKUP[mode * 512 + p1] | CONTEXT_LOOKUP[mode * 512 + 256 + p2])
}

// Whether at least three quarters of `data` is well-formed UTF-8.
@(private)
mostly_utf8 :: proc(data: []u8) -> bool {
	valid := 0

	for index := 0; index < len(data); {
		lead := data[index]
		size := 1

		switch {
		case lead < 0x80:
		case lead >= 0xc2 && lead < 0xe0:
			size = 2
		case lead >= 0xe0 && lead < 0xf0:
			size = 3
		case lead >= 0xf0 && lead < 0xf5:
			size = 4
		case:
			index += 1
			continue
		}

		whole := index + size <= len(data)

		for tail := 1; whole && tail < size; tail += 1 {
			whole = data[index + tail] & 0xc0 == 0x80
		}

		if whole {
			valid += size
			index += size
		} else {
			index += 1
		}
	}

	return valid * 4 >= len(data) * 3
}

@(private)
distance_context :: #force_inline proc(copy_length: u32) -> int {
	return 3 if copy_length > 4 else int(copy_length) - 2
}

// True when the command's distance is carried by the command symbol itself.
@(private)
distance_is_implicit :: #force_inline proc(symbol: u16) -> bool {
	return symbol < 128
}

@(private)
cursor_start :: proc(split: ^Split) -> Cursor {
	return {type = int(split.types[0]), remaining = split.lengths[0], second = 1}
}

// Consumes one symbol; true when it is the first of a new block.
@(private)
cursor_step :: #force_inline proc(split: ^Split, cursor: ^Cursor) -> bool {
	switched := false

	if cursor.remaining == 0 {
		cursor.index += 1
		cursor.type = int(split.types[cursor.index])
		cursor.remaining = split.lengths[cursor.index]
		switched = true
	}

	cursor.remaining -= 1

	return switched
}

// Fills the histograms of e.commands over src[start:end], splitting each
// category into block types when `split` is set, and clusters them into trees.
@(private)
gather :: proc(e: ^Encoder, block: ^Meta_Block, start, end: int, split: bool) -> runtime.Allocator_Error {
	src := e.src
	block.mode = CONTEXT_MODE_UTF8
	block.postfix = 0
	block.direct = 0

	if e.parameters.modelled && !mostly_utf8(src[start:end]) {
		block.mode = CONTEXT_MODE_SIGNED
	}

	if e.parameters.split {
		choose_distance_parameters(e, block)
	}

	for &stream in block.streams {
		clear(&stream)
	}

	position := start

	for command in e.commands {
		append(&block.streams[.Command], command.symbol) or_return

		for _ in 0 ..< command.insert_length {
			append(&block.streams[.Literal], u16(src[position])) or_return
			position += 1
		}

		if command.copy_length > 0 && !distance_is_implicit(command.symbol) {
			prefix, _, _ := distance_prefix(command.code, block.postfix, block.direct)
			append(&block.streams[.Distance], prefix) or_return
		}

		position += int(command.copy_length) - int(command.omit)
	}

	assert(position == end)

	distance_alphabet := 16 + int(block.direct) + 48 << block.postfix
	alphabets := [Category]int{.Literal = LITERAL_ALPHABET, .Command = COMMAND_ALPHABET, .Distance = distance_alphabet}

	for category in Category {
		split_stream(e, block.streams[category][:], alphabets[category], category, &block.splits[category], split) or_return
	}

	distance_rows := block.splits[.Distance].count * DISTANCE_CONTEXTS
	command_rows := block.splits[.Command].count

	reset(&block.command_histogram, command_rows * COMMAND_ALPHABET) or_return
	reset(&block.distance_histogram, distance_rows * DISTANCE_ALPHABET) or_return
	resize(&block.distance_map, distance_rows) or_return

	commands := cursor_start(&block.splits[.Command])
	distances := cursor_start(&block.splits[.Distance])

	for command in e.commands {
		cursor_step(&block.splits[.Command], &commands)
		block.command_histogram[commands.type * COMMAND_ALPHABET + int(command.symbol)] += 1

		if command.copy_length > 0 && !distance_is_implicit(command.symbol) {
			cursor_step(&block.splits[.Distance], &distances)
			prefix, _, _ := distance_prefix(command.code, block.postfix, block.direct)
			row := distances.type * DISTANCE_CONTEXTS + distance_context(command.copy_length)
			block.distance_histogram[row * DISTANCE_ALPHABET + int(prefix)] += 1
		}
	}

	block.distance_trees = cluster(
		e,
		block.distance_histogram[:],
		DISTANCE_ALPHABET,
		distance_rows,
		block.distance_map[:],
		e.parameters.modelled,
	) or_return

	// Literal block types and literal contexts compete for the same
	// statistics: keep the split only when its trees are cheaper overall.
	split_cost := gather_literals(e, block, start) or_return

	if block.splits[.Literal].count > 1 {
		// Set the split result aside and model the literals unsplit.
		kept := block.splits[.Literal]
		kept_histogram := block.literal_histogram
		kept_map := block.literal_map
		kept_trees := block.literal_trees
		flat := Split{count = 1}
		flat.types = make([dynamic]u8, e.allocator) or_return
		flat.lengths = make([dynamic]u32, e.allocator) or_return
		block.literal_histogram = make([dynamic]u32, e.allocator) or_return
		block.literal_map = make([dynamic]u8, e.allocator) or_return
		append(&flat.types, 0) or_return
		append(&flat.lengths, u32(len(block.streams[.Literal]))) or_return
		block.splits[.Literal] = flat

		flat_cost := gather_literals(e, block, start) or_return

		if split_cost + f64(len(kept.types)) * SWITCH_BITS < flat_cost {
			kept, block.splits[.Literal] = block.splits[.Literal], kept
			kept_histogram, block.literal_histogram = block.literal_histogram, kept_histogram
			kept_map, block.literal_map = block.literal_map, kept_map
			block.literal_trees = kept_trees
		}

		delete(kept.types)
		delete(kept.lengths)
		delete(kept_histogram)
		delete(kept_map)
	}

	return nil
}

// Rough price of one block switch: a type code and a count code with extra bits.
SWITCH_BITS :: 14

// Literal histograms per (block type, context) for the current literal split,
// clustered into trees. Returns the estimated bits of all literals and trees.
@(private)
gather_literals :: proc(e: ^Encoder, block: ^Meta_Block, start: int) -> (cost: f64, err: runtime.Allocator_Error) {
	src := e.src
	rows := block.splits[.Literal].count * LITERAL_CONTEXTS
	reset(&block.literal_histogram, rows * LITERAL_ALPHABET) or_return
	resize(&block.literal_map, rows) or_return

	literals := cursor_start(&block.splits[.Literal])
	position := start

	for command in e.commands {
		for _ in 0 ..< command.insert_length {
			cursor_step(&block.splits[.Literal], &literals)
			row := literals.type * LITERAL_CONTEXTS + literal_context(src, position, block.mode)
			block.literal_histogram[row * LITERAL_ALPHABET + int(src[position])] += 1
			position += 1
		}

		position += int(command.copy_length) - int(command.omit)
	}

	block.literal_trees = cluster(
		e,
		block.literal_histogram[:],
		LITERAL_ALPHABET,
		rows,
		block.literal_map[:],
		e.parameters.modelled,
	) or_return

	for tree in 0 ..< block.literal_trees {
		cost += histogram_cost(block.literal_histogram[tree * LITERAL_ALPHABET:][:LITERAL_ALPHABET])
	}

	return cost, nil
}

// Resizes `array` to `size` zeroed elements.
@(private)
reset :: proc(array: ^[dynamic]$T, size: int) -> runtime.Allocator_Error {
	clear(array)

	return resize(array, size)
}

// Picks the NPOSTFIX and NDIRECT that code the explicit distances of
// e.commands in the fewest bits.
@(private)
choose_distance_parameters :: proc(e: ^Encoder, block: ^Meta_Block) {
	histogram: [DISTANCE_ALPHABET]u32
	best := max(f64)
	direct_high: uint

	for postfix in uint(0) ..= 3 {
		for ; direct_high < 16; direct_high += 1 {
			direct := direct_high << postfix
			histogram = {}
			extra: f64

			for command in e.commands {
				if command.copy_length > 0 && !distance_is_implicit(command.symbol) {
					prefix, extra_bits, _ := distance_prefix(command.code, postfix, direct)
					histogram[prefix] += 1
					extra += f64(extra_bits)
				}
			}

			cost := histogram_cost(histogram[:]) + extra

			if cost >= best {
				break
			}

			best = cost
			block.postfix = postfix
			block.direct = direct
		}

		if direct_high > 0 {
			direct_high -= 1
		}

		direct_high /= 2
	}
}

// --------------------------------------------------------------------- output

@(private)
block_count_symbol :: #force_inline proc(length: u32) -> int {
	for symbol := BLOCK_COUNT_ALPHABET - 1; symbol > 0; symbol -= 1 {
		if length >= BLOCK_COUNT_BASE[symbol] {
			return symbol
		}
	}

	return 0
}

// Block type code relative to the two previous types of the category.
@(private)
block_type_symbol :: #force_inline proc(cursor: ^Cursor) -> int {
	symbol := cursor.type + 2

	if cursor.type == cursor.last + 1 {
		symbol = 1
	} else if cursor.type == cursor.second {
		symbol = 0
	}

	cursor.second = cursor.last
	cursor.last = cursor.type

	return symbol
}

@(private)
write_block_count :: proc(e: ^Encoder, block: ^Meta_Block, category: Category, length: u32) {
	symbol := block_count_symbol(length)
	write_bits(&e.writer, u64(block.count_codes[category][symbol]), uint(block.count_lengths[category][symbol]))
	write_bits(&e.writer, u64(length - BLOCK_COUNT_BASE[symbol]), uint(BLOCK_COUNT_EXTRA[symbol]))
}

// Block type count of a category, then the codes for its switch commands and
// the length of its first block.
@(private)
write_split :: proc(e: ^Encoder, block: ^Meta_Block, category: Category) {
	split := &block.splits[category]
	write_variable_byte(&e.writer, split.count - 1)

	if split.count < 2 {
		return
	}

	type_histogram: [BLOCK_TYPE_ALPHABET]u32
	count_histogram: [BLOCK_COUNT_ALPHABET]u32
	cursor := Cursor{second = 1}

	for type, index in split.types {
		count_histogram[block_count_symbol(split.lengths[index])] += 1

		if index > 0 {
			cursor.type = int(type)
			type_histogram[block_type_symbol(&cursor)] += 1
		}
	}

	alphabet := split.count + 2
	build_and_write_code(e, type_histogram[:alphabet], block.type_lengths[category][:alphabet], block.type_codes[category][:alphabet])
	build_and_write_code(e, count_histogram[:], block.count_lengths[category][:], block.count_codes[category][:])
	write_block_count(e, block, category, split.lengths[0])
}

@(private)
write_switch :: #force_inline proc(e: ^Encoder, block: ^Meta_Block, category: Category, cursor: ^Cursor) {
	if cursor_step(&block.splits[category], cursor) {
		symbol := block_type_symbol(cursor)
		write_bits(&e.writer, u64(block.type_codes[category][symbol]), uint(block.type_lengths[category][symbol]))
		write_block_count(e, block, category, block.splits[category].lengths[cursor.index])
	}
}

// Builds and writes one prefix code per histogram row.
SMOOTH_LEVEL_MIN :: Level(4)

// Evens out neighbouring counts so that the code lengths built from them
// form runs, which the code-length code stores cheaply. Follows the
// reference encoder; arithmetic on averages is in 24.8 fixed point.
@(private)
smooth_for_rle :: proc(counts: []u32) {
	STREAK_LIMIT :: 1240
	length := len(counts)
	nonzeros := 0
	smallest := u32(1 << 30)

	for length > 0 && counts[length - 1] == 0 {
		length -= 1
	}

	for count in counts[:length] {
		if count != 0 {
			nonzeros += 1
			smallest = min(smallest, count)
		}
	}

	if nonzeros < 16 {
		return
	}

	if smallest < 4 && length - nonzeros < 6 {
		for index in 1 ..< length - 1 {
			if counts[index - 1] != 0 && counts[index] == 0 && counts[index + 1] != 0 {
				counts[index] = 1
			}
		}
	}

	if nonzeros < 28 {
		return
	}

	// Runs that already code well are left alone: five zeros, seven equals.
	good: [ALPHABET_MAX]bool
	symbol := counts[0]
	step := 0

	for index in 0 ..= length {
		if index < length && counts[index] == symbol {
			step += 1
			continue
		}

		if symbol == 0 && step >= 5 || symbol != 0 && step >= 7 {
			for back in 1 ..= step {
				good[index - back] = true
			}
		}

		step = 1

		if index != length {
			symbol = counts[index]
		}
	}

	stride := u64(0)
	sum := u64(0)
	limit := 256 * (u64(counts[0]) + u64(counts[1]) + u64(counts[2])) / 3 + 420

	for index in 0 ..= length {
		// Unsigned wrap-around: true when the count is far from the limit.
		ends :=
			index == length ||
			good[index] ||
			index != 0 && good[index - 1] ||
			256 * u64(counts[index]) - limit + STREAK_LIMIT >= 2 * STREAK_LIMIT

		if ends {
			if stride >= 4 || stride >= 3 && sum == 0 {
				count := max((sum + stride / 2) / stride, 1)

				if sum == 0 {
					count = 0
				}

				for back in 1 ..= int(stride) {
					counts[index - back] = u32(count)
				}
			}

			stride = 0
			sum = 0

			switch {
			case index + 2 < length:
				limit = 256 * (u64(counts[index]) + u64(counts[index + 1]) + u64(counts[index + 2])) / 3 + 420
			case index < length:
				limit = 256 * u64(counts[index])
			case:
				limit = 0
			}
		}

		stride += 1

		if index != length {
			sum += u64(counts[index])

			if stride >= 4 {
				limit = (256 * sum + stride / 2) / stride
			}

			if stride == 4 {
				limit += 120
			}
		}
	}
}

@(private)
write_codes :: proc(
	e: ^Encoder,
	histograms: []u32,
	stride, alphabet, rows: int,
	lengths: ^[dynamic]u8,
	codes: ^[dynamic]u16,
) -> runtime.Allocator_Error {
	resize(lengths, rows * stride) or_return
	resize(codes, rows * stride) or_return

	for row in 0 ..< rows {
		if e.level >= SMOOTH_LEVEL_MIN {
			smooth_for_rle(histograms[row * stride:][:alphabet])
		}

		build_and_write_code(
			e,
			histograms[row * stride:][:alphabet],
			lengths[row * stride:][:alphabet],
			codes[row * stride:][:alphabet],
		)
	}

	return nil
}

// Writes src[start:end] as one meta-block, stored when coding does not pay.
// `ring` is the recent-distance state from before the block was parsed.
@(private)
write_meta_block :: proc(
	e: ^Encoder,
	block: ^Meta_Block,
	start, end: int,
	last: bool,
	ring: Ring,
) -> runtime.Allocator_Error {
	w := &e.writer
	src := e.src
	length := end - start
	nibbles := 6 if length > 1 << 20 else 5 if length > 1 << 16 else 4
	mark_size := len(w.out)
	mark_accumulator := w.accumulator
	mark_count := w.count

	write_bits(w, 1 if last else 0, 1)

	if last {
		write_bits(w, 0, 1)
	}

	write_bits(w, u64(nibbles - 4), 2)
	write_bits(w, u64(length - 1), uint(nibbles * 4))

	if !last {
		write_bits(w, 0, 1)
	}

	for category in Category {
		write_split(e, block, category)
	}

	write_bits(w, u64(block.postfix), 2)
	write_bits(w, u64(block.direct >> block.postfix), 4)

	for _ in 0 ..< block.splits[.Literal].count {
		write_bits(w, u64(block.mode), 2)
	}

	write_context_map(e, block.literal_map[:], block.literal_trees)
	write_context_map(e, block.distance_map[:], block.distance_trees)

	distance_alphabet := 16 + int(block.direct) + 48 << block.postfix
	write_codes(
		e,
		block.literal_histogram[:],
		LITERAL_ALPHABET,
		LITERAL_ALPHABET,
		block.literal_trees,
		&block.literal_lengths,
		&block.literal_codes,
	) or_return
	write_codes(
		e,
		block.command_histogram[:],
		COMMAND_ALPHABET,
		COMMAND_ALPHABET,
		block.splits[.Command].count,
		&block.command_lengths,
		&block.command_codes,
	) or_return
	write_codes(
		e,
		block.distance_histogram[:],
		DISTANCE_ALPHABET,
		distance_alphabet,
		block.distance_trees,
		&block.distance_lengths,
		&block.distance_codes,
	) or_return

	literals := cursor_start(&block.splits[.Literal])
	commands := cursor_start(&block.splits[.Command])
	distances := cursor_start(&block.splits[.Distance])
	position := start

	for command in e.commands {
		write_switch(e, block, .Command, &commands)

		slot := commands.type * COMMAND_ALPHABET + int(command.symbol)
		insert := command.insert_code
		copy := command.copy_code
		write_bits(w, u64(block.command_codes[slot]), uint(block.command_lengths[slot]))
		write_bits(w, u64(command.insert_length - INSERT_BASE[insert]), uint(INSERT_EXTRA[insert]))
		write_bits(w, u64(max(command.copy_length, 2) - COPY_BASE[copy]), uint(COPY_EXTRA[copy]))

		for _ in 0 ..< command.insert_length {
			write_switch(e, block, .Literal, &literals)

			row := literals.type * LITERAL_CONTEXTS + literal_context(src, position, block.mode)
			slot = int(block.literal_map[row]) * LITERAL_ALPHABET + int(src[position])
			write_bits(w, u64(block.literal_codes[slot]), uint(block.literal_lengths[slot]))
			position += 1
		}

		if command.copy_length > 0 && !distance_is_implicit(command.symbol) {
			write_switch(e, block, .Distance, &distances)

			prefix, extra_bits, extra := distance_prefix(command.code, block.postfix, block.direct)
			row := distances.type * DISTANCE_CONTEXTS + distance_context(command.copy_length)
			slot = int(block.distance_map[row]) * DISTANCE_ALPHABET + int(prefix)
			write_bits(w, u64(block.distance_codes[slot]), uint(block.distance_lengths[slot]))
			write_bits(w, u64(extra), uint(extra_bits))
		}

		position += int(command.copy_length) - int(command.omit)
	}

	coded := (len(w.out) - mark_size) * 8 + int(w.count) - int(mark_count)

	if coded <= (length + 4) * 8 {
		return nil
	}

	// Stored meta-block; it cannot be the last one, so an empty one follows.
	resize(&w.out, mark_size) or_return
	w.accumulator = mark_accumulator
	w.count = mark_count
	e.ring = ring

	write_bits(w, 0, 1)
	write_bits(w, u64(nibbles - 4), 2)
	write_bits(w, u64(length - 1), uint(nibbles * 4))
	write_bits(w, 1, 1)
	flush_bits(w)
	append(&w.out, ..src[start:end]) or_return

	if last {
		write_bits(w, 3, 2)
	}

	return nil
}

// ------------------------------------------------------------ histogram costs

@(private)
entropy_bits :: proc(histogram: []u32) -> (total: u64, used: int, data_bits: f64) {
	weighted: f64

	for frequency in histogram {
		if frequency != 0 {
			total += u64(frequency)
			used += 1
			weighted += f64(frequency) * math.log2(f64(frequency))
		}
	}

	if total != 0 {
		data_bits = f64(total) * math.log2(f64(total)) - weighted
	}

	return
}

// Estimated bits to store a histogram's prefix code and all of its symbols.
@(private)
histogram_cost :: proc(histogram: []u32) -> f64 {
	total, used, data_bits := entropy_bits(histogram)

	switch used {
	case 0:
		return 0
	case 1:
		return 12
	case 2:
		return 20 + f64(total)
	}

	// The code lengths themselves: an estimate of their run-length coded size.
	depths: [18]u32
	scale := math.log2(f64(total))
	deepest := 1
	zeros := 0

	for frequency in histogram {
		if frequency == 0 {
			zeros += 1
			continue
		}

		for zeros >= 3 {
			depths[17] += 1
			data_bits += 3
			zeros >>= 3
		}

		depths[0] += u32(zeros)
		zeros = 0

		depth := clamp(int(scale - math.log2(f64(frequency)) + 0.5), 1, CODE_LENGTH_MAX)
		depths[depth] += 1
		deepest = max(deepest, depth)
	}

	_, _, depth_bits := entropy_bits(depths[:])

	return data_bits + depth_bits + f64(18 + 2 * deepest)
}

// ----------------------------------------------------------------- clustering

CLUSTER_BATCH :: 64
// Above this many candidates the final pass is linear instead of pairwise.
CLUSTER_PAIRWISE_MAX :: 256
CLUSTER_MAX :: 256

// Merges `rows` histograms of `stride` counters while that saves bits; row `r`
// then uses cluster `mapping[r]`, and the first `clusters` rows hold the merged
// histograms. Without `modelled` all rows share one cluster.
@(private)
cluster :: proc(
	e: ^Encoder,
	histograms: []u32,
	stride, rows: int,
	mapping: []u8,
	modelled: bool,
) -> (
	clusters: int,
	err: runtime.Allocator_Error,
) {
	if rows == 0 {
		return 1, nil
	}

	if !modelled || rows == 1 {
		for row in 1 ..< rows {
			for symbol in 0 ..< stride {
				histograms[symbol] += histograms[row * stride + symbol]
			}
		}

		for &tree in mapping[:rows] {
			tree = 0
		}

		return 1, nil
	}

	cost := make([]f64, rows, e.allocator) or_return
	defer delete(cost, e.allocator)

	parent := make([]i32, rows, e.allocator) or_return
	defer delete(parent, e.allocator)

	stats := make([]Row_Stats, rows, e.allocator) or_return
	defer delete(stats, e.allocator)

	survivors := make([dynamic]i32, 0, rows, e.allocator) or_return
	defer delete(survivors)

	numbers := make([]i32, rows, e.allocator) or_return
	defer delete(numbers, e.allocator)

	for row in 0 ..< rows {
		stats[row] = row_stats(histograms[row * stride:][:stride])
		cost[row] = stats_cost(stats[row])
		parent[row] = i32(row)
	}

	members: [CLUSTER_BATCH]i32

	for first := 0; first < rows; first += CLUSTER_BATCH {
		count := 0

		for row in first ..< min(first + CLUSTER_BATCH, rows) {
			if cost[row] != 0 {
				members[count] = i32(row)
				count += 1
			}
		}

		merge_group(e, histograms, stride, members[:count], cost, parent, stats) or_return

		for member in members[:count] {
			if parent[member] == member {
				append(&survivors, member) or_return
			}
		}
	}

	if len(survivors) <= CLUSTER_PAIRWISE_MAX {
		merge_group(e, histograms, stride, survivors[:], cost, parent, stats) or_return
	} else {
		merge_leaders(histograms, stride, survivors[:], cost, parent, stats)
	}

	// Number the clusters in order of first use and move them to the front; a
	// cluster never moves to a later row.
	clusters = 0

	for row in 0 ..< rows {
		if parent[row] == i32(row) && cost[row] != 0 {
			copy(histograms[clusters * stride:][:stride], histograms[row * stride:][:stride])
			numbers[row] = i32(clusters)
			clusters += 1
		}
	}

	for row in 0 ..< rows {
		root := row

		for parent[root] != i32(root) {
			root = int(parent[root])
		}

		// Rows that never occur are their own empty root and may use any cluster.
		mapping[row] = u8(numbers[root])
	}

	if clusters == 0 {
		for symbol in 0 ..< stride {
			histograms[symbol] = 0
		}

		return 1, nil
	}

	return clusters, nil
}

// What clustering needs of a histogram: symbol total, distinct symbols and
// the sum of n*log2(n) over its counters.
Row_Stats :: struct {
	total:    u64,
	used:     int,
	weighted: f64,
}

LOG2_TABLE_SIZE :: 4096

LOG2_TABLE: [LOG2_TABLE_SIZE]f32

@(init, private)
fill_log2_table :: proc "contextless" () {
	for index in 1 ..< LOG2_TABLE_SIZE {
		LOG2_TABLE[index] = f32(math.log2(f64(index)))
	}
}

@(private)
fast_log2 :: #force_inline proc(value: u64) -> f64 {
	return f64(LOG2_TABLE[value]) if value < LOG2_TABLE_SIZE else math.log2(f64(value))
}

@(private)
row_stats :: proc(histogram: []u32) -> (stats: Row_Stats) {
	for frequency in histogram {
		if frequency != 0 {
			stats.total += u64(frequency)
			stats.used += 1
			stats.weighted += f64(frequency) * fast_log2(u64(frequency))
		}
	}

	return
}

// Cheap estimate of a histogram's coded size for clustering decisions.
@(private)
stats_cost :: #force_inline proc(stats: Row_Stats) -> f64 {
	if stats.used == 0 {
		return 0
	}

	if stats.used == 1 {
		return 12
	}

	return f64(stats.total) * fast_log2(stats.total) - stats.weighted + 20 + 5 * f64(stats.used)
}

// Cost of rows `a` and `b` as one histogram; only symbols both rows use need
// their logarithms recomputed.
@(private)
merged_cost :: proc(histograms: []u32, stride: int, a, b: i32, stats: []Row_Stats) -> f64 #no_bounds_check {
	combined := Row_Stats {
		total    = stats[a].total + stats[b].total,
		used     = stats[a].used + stats[b].used,
		weighted = stats[a].weighted + stats[b].weighted,
	}

	first := histograms[int(a) * stride:][:stride]
	second := histograms[int(b) * stride:][:stride]

	for symbol in 0 ..< stride {
		x := u64(first[symbol])
		y := u64(second[symbol])

		if x != 0 && y != 0 {
			combined.used -= 1
			combined.weighted += f64(x + y) * fast_log2(x + y) - f64(x) * fast_log2(x) - f64(y) * fast_log2(y)
		}
	}

	return stats_cost(combined)
}

@(private)
merge_rows :: proc(histograms: []u32, stride: int, into, from: i32, cost: []f64, parent: []i32, stats: []Row_Stats) {
	for symbol in 0 ..< stride {
		histograms[int(into) * stride + symbol] += histograms[int(from) * stride + symbol]
	}

	parent[from] = into
	stats[into] = row_stats(histograms[int(into) * stride:][:stride])
	cost[into] = stats_cost(stats[into])
}

// Repeatedly merges the pair of `members` that saves the most bits.
@(private)
merge_group :: proc(
	e: ^Encoder,
	histograms: []u32,
	stride: int,
	members: []i32,
	cost: []f64,
	parent: []i32,
	stats: []Row_Stats,
) -> runtime.Allocator_Error {
	count := len(members)

	if count < 2 {
		return nil
	}

	gain := make([]f64, count * count, e.allocator) or_return
	defer delete(gain, e.allocator)

	alive := make([]bool, count, e.allocator) or_return
	defer delete(alive, e.allocator)

	for a in 0 ..< count {
		alive[a] = true

		for b in a + 1 ..< count {
			gain[a * count + b] =
				cost[members[a]] + cost[members[b]] - merged_cost(histograms, stride, members[a], members[b], stats)
		}
	}

	for {
		best: f64
		best_a, best_b := -1, -1

		for a in 0 ..< count {
			if !alive[a] {
				continue
			}

			for b in a + 1 ..< count {
				if alive[b] && gain[a * count + b] > best {
					best = gain[a * count + b]
					best_a, best_b = a, b
				}
			}
		}

		if best_a < 0 {
			return nil
		}

		merge_rows(histograms, stride, members[best_a], members[best_b], cost, parent, stats)
		alive[best_b] = false

		for other in 0 ..< count {
			if !alive[other] || other == best_a {
				continue
			}

			low, high := min(best_a, other), max(best_a, other)
			gain[low * count + high] =
				cost[members[low]] + cost[members[high]] - merged_cost(histograms, stride, members[low], members[high], stats)
		}
	}
}

// One pass for many candidates: each joins the kept cluster it saves the most
// bits with, or is kept itself while there is room.
@(private)
merge_leaders :: proc(histograms: []u32, stride: int, members: []i32, cost: []f64, parent: []i32, stats: []Row_Stats) {
	kept: [CLUSTER_MAX]i32
	count := 0

	for member in members {
		best: f64 = 0 if count < CLUSTER_MAX else min(f64)
		target := -1

		for index in 0 ..< count {
			gain := cost[kept[index]] + cost[member] - merged_cost(histograms, stride, kept[index], member, stats)

			if gain > best {
				best = gain
				target = index
			}
		}

		if target < 0 {
			kept[count] = member
			count += 1
			continue
		}

		merge_rows(histograms, stride, kept[target], member, cost, parent, stats)
	}
}

// ------------------------------------------------------------ block splitting

Split_Parameters :: struct {
	symbols_per_histogram: int,
	histograms_max:        int,
	stride:                int,
	switch_cost:           f32,
}

SPLIT_PARAMETERS := [Category]Split_Parameters {
	.Literal  = {544, 100, 70, 28.1},
	.Command  = {530, 50, 40, 13.5},
	.Distance = {544, 50, 40, 14.6},
}

SPLIT_LENGTH_MIN :: 128
SPLIT_HISTOGRAMS_FAST :: 16

// Splits `data` into blocks of similar statistics: a few sampled histograms
// are refined by assigning every symbol to the histogram that codes it most
// cheaply, with a price on switching, then similar histograms are merged.
@(private)
split_stream :: proc(
	e: ^Encoder,
	data: []u16,
	alphabet: int,
	category: Category,
	split: ^Split,
	enabled: bool,
) -> runtime.Allocator_Error {
	clear(&split.types)
	clear(&split.lengths)
	split.count = 1

	parameters := SPLIT_PARAMETERS[category]
	count := min(len(data) / parameters.symbols_per_histogram + 1, parameters.histograms_max)

	// Below the optimal levels a coarser split keeps the cost in proportion.
	if e.level < OPTIMAL_LEVEL_MIN {
		count = min(count, SPLIT_HISTOGRAMS_FAST)
	}

	if !enabled || len(data) < SPLIT_LENGTH_MIN || count < 2 {
		append(&split.types, 0) or_return
		append(&split.lengths, u32(len(data))) or_return

		return nil
	}

	size := len(data)
	histograms := make([]u32, count * alphabet, e.allocator) or_return
	defer delete(histograms, e.allocator)

	insert_cost := make([]f32, count * alphabet, e.allocator) or_return
	defer delete(insert_cost, e.allocator)

	cost := make([]f32, count, e.allocator) or_return
	defer delete(cost, e.allocator)

	signal_stride := (count + 7) >> 3
	signals := make([]u8, size * signal_stride, e.allocator) or_return
	defer delete(signals, e.allocator)

	ids := make([]u8, size, e.allocator) or_return
	defer delete(ids, e.allocator)

	renumbered := make([]i32, count, e.allocator) or_return
	defer delete(renumbered, e.allocator)

	// Initial histograms: one short sample per evenly spaced region.
	seed := u32(7)
	stride := parameters.stride
	region := size / count

	for index in 0 ..< count {
		position := size * index / count

		if index != 0 {
			seed *= 16807
			position += int(seed % u32(region))
		}

		position = min(position, size - stride - 1)

		for symbol in data[position:][:stride] {
			histograms[index * alphabet + int(symbol)] += 1
		}
	}

	samples := (2 * size / stride + 100 + count - 1) / count * count

	for sample in 0 ..< samples {
		seed *= 16807
		position := int(seed % u32(size - stride + 1))

		for symbol in data[position:][:stride] {
			histograms[(sample % count) * alphabet + int(symbol)] += 1
		}
	}

	iterations := 10 if e.level >= .Optimal else 2

	for _ in 0 ..< iterations {
		find_blocks(data, alphabet, count, parameters.switch_cost, histograms, insert_cost, cost, signals, ids)

		// Number the histograms still in use densely and rebuild them.
		for &slot in renumbered {
			slot = -1
		}

		used := 0

		for &id in ids {
			if renumbered[id] < 0 {
				renumbered[id] = i32(used)
				used += 1
			}

			id = u8(renumbered[id])
		}

		count = used

		for &counter in histograms[:count * alphabet] {
			counter = 0
		}

		for symbol, index in data {
			histograms[int(ids[index]) * alphabet + int(symbol)] += 1
		}
	}

	mapping := make([]u8, count, e.allocator) or_return
	defer delete(mapping, e.allocator)

	cluster(e, histograms, alphabet, count, mapping, true) or_return

	for &slot in renumbered {
		slot = -1
	}

	types := 0

	for index := 0; index < size; {
		id := mapping[ids[index]]
		run := 1

		for index + run < size && mapping[ids[index + run]] == id {
			run += 1
		}

		if renumbered[id] < 0 {
			renumbered[id] = i32(types)
			types += 1
		}

		append(&split.types, u8(renumbered[id])) or_return
		append(&split.lengths, u32(run)) or_return
		index += run
	}

	split.count = types

	return nil
}

// Assigns each symbol of `data` to one of `count` histograms: the cheapest
// path where changing histogram costs `switch_cost` bits.
@(private)
find_blocks :: proc(
	data: []u16,
	alphabet, count: int,
	switch_cost: f32,
	histograms: []u32,
	insert_cost, cost: []f32,
	signals, ids: []u8,
) #no_bounds_check {
	if count < 2 {
		for &id in ids {
			id = 0
		}

		return
	}

	signal_stride := (count + 7) >> 3

	for index in 0 ..< count {
		total: u64

		for frequency in histograms[index * alphabet:][:alphabet] {
			total += u64(frequency)
		}

		scale := f32(math.log2(f64(max(total, 1))))

		for frequency, symbol in histograms[index * alphabet:][:alphabet] {
			insert_cost[symbol * count + index] = scale + 2 if frequency == 0 else scale - f32(math.log2(f64(frequency)))
		}

		cost[index] = 0
	}

	for &signal in signals[:len(data) * signal_stride] {
		signal = 0
	}

	for symbol, position in data {
		costs := insert_cost[int(symbol) * count:][:count]
		// Separate simple loops so that each one vectorizes.
		for index in 0 ..< count {
			cost[index] += costs[index]
		}

		cheapest := cost[0]

		for index in 1 ..< count {
			cheapest = min(cheapest, cost[index])
		}

		choice := 0

		for cost[choice] != cheapest {
			choice += 1
		}

		ids[position] = u8(choice)
		price := switch_cost

		// Switching is cheaper while the histograms are still filling up.
		if position < 2000 {
			price *= 0.77 + 0.07 * f32(position) / 2000
		}

		row := signals[position * signal_stride:]

		for index in 0 ..< count {
			value := cost[index] - cheapest
			capped := value >= price
			cost[index] = price if capped else value
			row[index >> 3] |= u8(capped) << uint(index & 7)
		}
	}

	current := int(ids[len(data) - 1])

	for position := len(data) - 2; position >= 0; position -= 1 {
		if signals[position * signal_stride + current >> 3] & (1 << uint(current & 7)) != 0 {
			current = int(ids[position])
		}

		ids[position] = u8(current)
	}
}
