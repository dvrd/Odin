package compress_brotli

import "base:intrinsics"
import "base:runtime"
import "core:math/bits"


// Match finder and parser for levels 0..9: every hash bucket keeps its newest
// positions in a small ring, searched newest first after the recent distances.

Finder :: struct {
	counts:       []u16,
	buckets:      []u32,
	bucket_shift: u32,
	block_bits:   uint,
	// Recent distances probed before the bucket: 4, 10 or 16.
	cache_size:   int,
	// Static dictionary probes and hits; the dictionary is dropped when it
	// stops paying.
	lookups:      int,
	hits:         int,
}

Match :: struct {
	// Bytes covered; a dictionary word shortened by `omit` covers fewer bytes
	// than the copy length that names it.
	length:   int,
	distance: int,
	score:    int,
	omit:     int,
}

BUCKET_BITS_MIN :: 8
BUCKET_BITS_MAX :: 15

// A copy must beat this: four bytes at a distance below 2^15, more beyond.
SCORE_MIN :: 2020

// Transform that drops the last k bytes of a dictionary word, k = 0..9.
@(rodata)
OMIT_LAST_TRANSFORM := [10]u8{0, 12, 27, 23, 42, 63, 56, 48, 59, 64}

// Recent distance candidates in probe order: ring entry and offset.
@(rodata)
CACHE_INDEX := [16]u8{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1}

@(rodata)
CACHE_OFFSET := [16]i8{0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3}

finder_make :: proc(f: ^Finder, size: int, block_bits: uint, cache_size: int, allocator: runtime.Allocator) -> runtime.Allocator_Error {
	bucket_bits := clamp(bits.len_u32(u32(min(size, 1 << 30))) - 1, BUCKET_BITS_MIN, BUCKET_BITS_MAX)
	f.bucket_shift = u32(32 - bucket_bits)
	f.block_bits = block_bits
	f.cache_size = cache_size
	f.counts = make([]u16, 1 << uint(bucket_bits), allocator) or_return

	// Slots are only read up to their bucket's count: no need to clear them.
	slots, slots_error := runtime.mem_alloc_non_zeroed((4 << uint(bucket_bits)) << block_bits, align_of(u32), allocator)

	if slots_error != nil {
		return slots_error
	}

	f.buckets = ([^]u32)(raw_data(slots))[:(1 << uint(bucket_bits)) << block_bits]

	return nil
}

finder_destroy :: proc(f: ^Finder, allocator: runtime.Allocator) {
	delete(f.counts, allocator)
	delete(f.buckets, allocator)
}

finder_store :: #force_inline proc(f: ^Finder, src: []u8, position: int) #no_bounds_check {
	key := hash4(src, position) >> f.bucket_shift
	slot := u32(f.counts[key]) & (1 << f.block_bits - 1)
	f.buckets[key << f.block_bits + slot] = u32(position)
	f.counts[key] += 1
}

match_score :: #force_inline proc(length, distance: int) -> int {
	return 1920 + 135 * length - 30 * (bits.len_u32(u32(distance)) - 1)
}

// Best copy for `position` that ends by `end`, which must leave at least four
// bytes; score SCORE_MIN when nothing is worth it. Indexes `position`.
find_match :: proc(e: ^Encoder, position, end: int) -> Match #no_bounds_check {
	f := &e.finder
	src := e.src
	limit := end - position
	reach := min(position, e.window_max)
	best := Match{score = SCORE_MIN}

	for index in 0 ..< f.cache_size {
		distance := int(e.ring[CACHE_INDEX[index]]) + int(CACHE_OFFSET[index])

		if distance <= 0 || distance > reach {
			continue
		}

		if best.length < limit && src[position + best.length] != src[position - distance + best.length] {
			continue
		}

		length := common_length(src, position - distance, position, limit)

		if length >= 3 || length == 2 && index < 2 {
			score := 135 * length + 1935

			if index != 0 {
				score -= 39 + (0x1ca10 >> uint(index & 0xe)) & 0xe
			}

			if score > best.score {
				best = {length, distance, score, 0}
			}
		}
	}

	key := hash4(src, position) >> f.bucket_shift
	count := f.counts[key]
	mask := u16(1) << f.block_bits - 1
	bucket := f.buckets[key << f.block_bits:]

	for back in 1 ..= min(int(count), 1 << f.block_bits) {
		candidate := int(bucket[(count - u16(back)) & mask])
		distance := position - candidate

		if distance > reach {
			break
		}

		if best.length >= limit || src[candidate + best.length] != src[position + best.length] {
			continue
		}

		length := common_length(src, candidate, position, limit)

		if length >= 4 {
			score := match_score(length, distance)

			if score > best.score {
				best = {length, distance, score, 0}
			}
		}
	}

	bucket[count & mask] = u32(position)
	f.counts[key] = count + 1

	if e.parameters.modelled && best.score == SCORE_MIN && f.hits >= f.lookups >> 7 {
		f.lookups += 1
		word := dictionary_match(src, position, limit, reach)

		if word.score > best.score {
			best = word
			f.hits += 1
		}
	}

	return best
}

// ---------------------------------------------------------- static dictionary

// Start of the words of each length in DICTIONARY.
@(rodata)
DICTIONARY_OFFSET := [DICTIONARY_WORD_MAX + 1]u32 {
	0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864, 104704, 106752, 108928,
	113536, 115968, 118528, 119872, 121280, 122016,
}

// First word id of each length.
@(rodata)
DICTIONARY_FIRST := [DICTIONARY_WORD_MAX + 1]u16 {
	0, 0, 0, 0, 0, 1024, 2048, 4096, 6144, 7168, 8192, 9216, 10240, 11264, 11776, 12288, 12544, 12672, 12800, 13056,
	13184, 13312, 13376, 13440, 13472,
}

// Best static dictionary word, whole or with up to nine trailing bytes
// dropped, that src[position:] starts with.
dictionary_match :: proc(src: []u8, position, limit, reach: int) -> Match #no_bounds_check {
	best := Match{score = SCORE_MIN}
	word := WORD_HEAD[hash4(src, position) >> (32 - DICTIONARY_HASH_BITS)]

	for steps := 0; word != DICTIONARY_NONE && steps < 64; steps += 1 {
		size := int(WORD_LENGTH[word])
		index := int(word) - int(DICTIONARY_FIRST[size])
		offset := int(DICTIONARY_OFFSET[size]) + index * size
		word = WORD_NEXT[word]
		matched := 0

		for matched < min(size, limit) && src[position + matched] == DICTIONARY[offset + matched] {
			matched += 1
		}

		omit := size - matched

		if matched < 4 || omit > 9 {
			continue
		}

		distance := reach + 1 + index + int(OMIT_LAST_TRANSFORM[omit]) << DICTIONARY_SIZE_BITS[size]
		score := match_score(matched, distance)

		if score > best.score {
			best = {matched, distance, score, omit}
		}
	}

	return best
}

// -------------------------------------------------------------------- parsing

// Lazy parse of src[start:end] into e.commands.
parse_range :: proc(e: ^Encoder, start, end: int) -> runtime.Allocator_Error {
	f := &e.finder
	src := e.src
	position := start
	literal_start := start
	// Hashing needs four bytes.
	last := end - 4
	spree := 512 if e.level >= .Best else 64
	sparse_after := position + spree

	for position <= last {
		match := find_match(e, position, end)

		if match.score == SCORE_MIN {
			position += 1

			// After a long run without matches the data is probably
			// incompressible: look at fewer positions.
			if position > sparse_after {
				step := 4 if position > sparse_after + 4 * spree else 2
				stop := min(position + 4 * step, last)

				for ; position < stop; position += step {
					finder_store(f, src, position)
				}
			}

			continue
		}

		if e.parameters.lazy {
			// Give up to four literals when a later start scores clearly better.
			for _ in 0 ..< 4 {
				if position + 1 > last {
					break
				}

				next := find_match(e, position + 1, end)

				if next.score < match.score + 175 {
					break
				}

				position += 1
				match = next
			}
		}

		push_command(e, position, position - literal_start, match.length + match.omit, match.distance, match.omit) or_return

		// Index the copied bytes; of a short-period repeat only the tail, so
		// that its buckets do not fill with one pattern.
		first := position + 2
		stop := min(position + match.length, last + 1)

		if match.distance < match.length >> 2 {
			first = max(first, position + match.length - match.distance << 2)
		}

		for covered in first ..< stop {
			finder_store(f, src, covered)
		}

		sparse_after = position + 2 * match.length + spree
		position += match.length
		literal_start = position
	}

	if literal_start < end {
		push_command(e, end, end - literal_start, 0, 0, 0) or_return
	}

	return nil
}

// Misses before the step between probed positions grows by one, log2.
FAST_PATIENCE :: 5

// Shortest copy the fast levels take, and the bytes their hash covers: text
// packs better without the copies of four and five bytes, which cost about
// what they save, and there are fewer commands to find and write.
FAST_MATCH_MIN :: 6

#assert(FAST_MATCH_MIN <= size_of(u64))

// Most hash slots a fast level looks at per position.
FAST_SLOTS_MAX :: 2

// A command of the fast levels with its symbols worked out: the parser has
// time for that while it waits on memory, the writer has not.
Fast_Record :: struct {
	insert_length:   u32,
	copy_length:     u32,
	distance_extra:  u32,
	symbol:          u16,
	// Distance symbol plus one; zero when the command symbol stands for the
	// last distance.
	distance_symbol: u8,
	distance_bits:   u8,
}

Fast_Histograms :: struct {
	literal:  [LITERAL_ALPHABET]u32,
	command:  [COMMAND_ALPHABET]u32,
	distance: [PLAIN_DISTANCE_ALPHABET]u32,
}

// What is known about a position before it is looked at: its bytes, and the
// table's candidates with theirs.
Fast_Look :: struct {
	word:       u64,
	candidates: [FAST_SLOTS_MAX]int,
	words:      [FAST_SLOTS_MAX]u64,
}

// Table of the fast levels: a position per slot and no counts, about a slot
// per input byte up to 2^(15 + extra_bits). Zeroed, so that every slot
// points into the data from the start.
fast_finder_make :: proc(f: ^Finder, size: int, extra_bits: uint, allocator: runtime.Allocator) -> runtime.Allocator_Error {
	table_bits := clamp(bits.len_u32(u32(min(size, 1 << 30))), BUCKET_BITS_MIN, BUCKET_BITS_MAX + int(extra_bits))
	f.bucket_shift = u32(32 - table_bits)
	f.buckets = make([]u32, 1 << uint(table_bits), allocator) or_return

	return nil
}

// Room for the records of one block of `length` bytes; they are written
// before they are read.
fast_records_make :: proc(length: int, allocator: runtime.Allocator) -> ([]Fast_Record, runtime.Allocator_Error) {
	count := length / FAST_MATCH_MIN + 1
	memory, memory_error := runtime.mem_alloc_non_zeroed(count * size_of(Fast_Record), align_of(Fast_Record), allocator)

	if memory_error != nil {
		return nil, memory_error
	}

	return ([^]Fast_Record)(raw_data(memory))[:count], nil
}

fast_word :: #force_inline proc(src: []u8, position: int) -> u64 #no_bounds_check {
	return u64(intrinsics.unaligned_load((^u64le)(&src[position])))
}

fast_hash :: #force_inline proc(word: u64, shift: u32) -> u32 {
	return u32((word << (64 - 8 * FAST_MATCH_MIN)) * 0x1e35a7bd1e35a7bd >> (32 + shift))
}

// True when the two words start with the same FAST_MATCH_MIN bytes.
fast_same :: #force_inline proc(a, b: u64) -> bool {
	return (a ~ b) << (64 - 8 * FAST_MATCH_MIN) == 0
}

fast_slot :: #force_inline proc(word: u64, position: int, shift, mask: u32, $SLOTS: u32) -> u32 {
	return (fast_hash(word, shift) + u32(position >> 3) & (SLOTS - 1)) & mask
}

// Reads what the table holds for `position` and enters the position.
fast_look :: #force_inline proc(src: []u8, table: [^]u32, position: int, shift, mask: u32, $SLOTS: u32) -> (look: Fast_Look) #no_bounds_check {
	look.word = fast_word(src, position)
	key := fast_hash(look.word, shift)

	for slot in 0 ..< SLOTS {
		look.candidates[slot] = int(table[(key + slot) & mask])
		look.words[slot] = fast_word(src, look.candidates[slot])
	}

	table[fast_slot(look.word, position, shift, mask, SLOTS)] = u32(position)

	return
}

// Parses src[start:end] into `records`, counts their symbols and returns how
// many there are and how many literals follow the last copy. Levels 0 and 1:
// the last distance and one or two hash slots, copies of six bytes or more,
// positions inside copies mostly left out of the table, and ever longer
// steps while nothing matches.
//
// After a copy nothing can go on before the table and the candidate of the
// next position have been read, so those reads are started first and the
// bookkeeping of the copy is done while they are under way.
parse_fast :: proc(
	e: ^Encoder,
	start, end: int,
	records: []Fast_Record,
	histograms: ^Fast_Histograms,
	$SLOTS: u32,
) -> (
	total: int,
	trailing: int,
) #no_bounds_check {
	// Level 0 gives up on unmatched data sooner, enters fewer positions of a
	// copy and takes the last distance whenever it matches; level 1 keeps
	// looking unless it matches well.
	PATIENCE :: FAST_PATIENCE when SLOTS == 1 else FAST_PATIENCE + 1
	GOOD :: FAST_MATCH_MIN when SLOTS == 1 else 16
	TAIL :: 2 when SLOTS == 1 else 4

	src := e.src
	table := raw_data(e.finder.buckets)
	shift := e.finder.bucket_shift
	mask := u32(len(e.finder.buckets) - 1)
	window := uint(e.window_max)
	// A word is read at every position looked at.
	last := min(end - FAST_MATCH_MIN, len(src) - size_of(u64))
	position := start
	literal_start := start
	misses := 0
	last_distance := int(e.ring[0])
	look: Fast_Look

	if position <= last {
		look = fast_look(src, table, position, shift, mask, SLOTS)
	}

	for position <= last {
		length := 0
		distance := last_distance

		if distance <= position && fast_same(fast_word(src, position - distance), look.word) {
			length = common_length(src, position - distance, position, end - position)
		}

		if length < GOOD {
			for slot in 0 ..< SLOTS {
				candidate := look.candidates[slot]

				// An empty slot holds position zero, which is as good a
				// candidate as any other.
				if !fast_same(look.words[slot], look.word) || uint(position - candidate - 1) >= window {
					continue
				}

				found := common_length(src, candidate, position, end - position)

				// A new distance has to pay for itself.
				if found > length + (1 if length > 0 else 0) {
					length = found
					distance = position - candidate
				}
			}
		}

		if length == 0 {
			position += 1 + misses >> PATIENCE
			misses += 1

			if position <= last {
				look = fast_look(src, table, position, shift, mask, SLOTS)
			}

			continue
		}

		next := position + length

		if next <= last {
			for back in 1 ..= TAIL {
				table[fast_slot(fast_word(src, next - back), next - back, shift, mask, SLOTS)] = u32(next - back)
			}

			look = fast_look(src, table, next, shift, mask, SLOTS)
		}

		// Only the last distance gets a short code here: the other fifteen
		// cost more to look for than they save at this level.
		insert_length := position - literal_start
		repeated := distance == last_distance
		symbol := command_symbol(insert_code(insert_length), copy_code(length), repeated)
		histograms.command[symbol] += 1

		for value in src[literal_start:position] {
			histograms.literal[value] += 1
		}

		record := Fast_Record {
			insert_length = u32(insert_length),
			copy_length   = u32(length),
			symbol        = u16(symbol),
		}

		if !repeated {
			prefix, extra_bits, extra := distance_prefix(u32(distance) + 15, 0, 0)
			record.distance_symbol = u8(prefix) + 1
			record.distance_bits = extra_bits
			record.distance_extra = extra
		} else if !distance_is_implicit(u16(symbol)) {
			record.distance_symbol = 1
		}

		if record.distance_symbol != 0 {
			histograms.distance[record.distance_symbol - 1] += 1
		}

		records[total] = record
		total += 1
		last_distance = distance
		misses = 0
		position = next
		literal_start = next
	}

	e.ring[0] = i32(last_distance)

	return total, end - literal_start
}

// Pending output bits of the fast writer, which knows the size of what it
// writes beforehand and has the room reserved.
Fast_Bits :: struct {
	accumulator: u64,
	count:       uint,
	out:         uintptr,
}

// At most 56 bits may be pending after this. The counts are masked to what
// they can be, which spares the shifts their check for 64 and more.
fast_put :: #force_inline proc(b: ^Fast_Bits, value: u64, width: uint) {
	b.accumulator |= value << (b.count & 63)
	b.count += width
}

// Stores the whole bytes; up to 7 bits stay pending.
fast_flush :: #force_inline proc(b: ^Fast_Bits) {
	intrinsics.unaligned_store((^u64le)(rawptr(b.out)), u64le(b.accumulator))
	b.out += uintptr(b.count >> 3)
	b.accumulator >>= b.count & 56
	b.count &= 7
}

// Command symbol with its insert and copy extra bits, then the literals.
fast_command :: #force_inline proc(
	b: ^Fast_Bits,
	commands: ^[COMMAND_ALPHABET]u32,
	literals: ^[LITERAL_ALPHABET]u32,
	inserted: []u8,
	copy_length: u32,
	symbol: int,
) #no_bounds_check {
	cell := symbol >> 6
	insert := int(COMMAND_INSERT_CELL[cell]) + symbol >> 3 & 7
	copy := int(COMMAND_COPY_CELL[cell]) + symbol & 7
	entry := commands[symbol]
	fast_put(b, u64(entry & 0xffff), uint(entry >> 16))
	fast_put(b, u64(u32(len(inserted)) - INSERT_BASE[insert]), uint(INSERT_EXTRA[insert]))

	// Only the longest lengths have more extra bits than fit at once.
	if insert > 20 || copy > 20 {
		fast_flush(b)
	}

	fast_put(b, u64(copy_length - COPY_BASE[copy]), uint(COPY_EXTRA[copy]))
	fast_flush(b)
	index := 0

	for ; index + 2 <= len(inserted); index += 2 {
		first := literals[inserted[index]]
		second := literals[inserted[index + 1]]
		fast_put(b, u64(first & 0xffff), uint(first >> 16))
		fast_put(b, u64(second & 0xffff), uint(second >> 16))
		fast_flush(b)
	}

	if index < len(inserted) {
		entry = literals[inserted[index]]
		fast_put(b, u64(entry & 0xffff), uint(entry >> 16))
		fast_flush(b)
	}
}

// Parses src[start:end] and writes it as a meta-block with one prefix code
// per alphabet and no context modelling, or as stored bytes when smaller.
write_fast_meta_block :: proc(e: ^Encoder, records: []Fast_Record, start, end: int, last: bool) -> runtime.Allocator_Error #no_bounds_check {
	w := &e.writer
	src := e.src
	mark_size := len(w.out)
	mark_accumulator := w.accumulator
	mark_count := w.count
	ring := e.ring

	histograms: Fast_Histograms
	total, trailing: int

	if e.level == Level(0) {
		total, trailing = parse_fast(e, start, end, records, &histograms, 1)
	} else {
		total, trailing = parse_fast(e, start, end, records, &histograms, 2)
	}

	// The literals after the last copy: a command whose copy is never read.
	trailing_symbol := command_symbol(insert_code(trailing), 0, true)

	if trailing > 0 {
		histograms.command[trailing_symbol] += 1

		for value in src[end - trailing:end] {
			histograms.literal[value] += 1
		}
	}

	write_plain_header(w, end - start, last)

	literal_lengths: [LITERAL_ALPHABET]u8
	literal_codes: [LITERAL_ALPHABET]u16
	command_lengths: [COMMAND_ALPHABET]u8
	command_codes: [COMMAND_ALPHABET]u16
	distance_lengths: [PLAIN_DISTANCE_ALPHABET]u8
	distance_codes: [PLAIN_DISTANCE_ALPHABET]u16
	build_and_write_code(e, histograms.literal[:], literal_lengths[:], literal_codes[:], true)
	build_and_write_code(e, histograms.command[:], command_lengths[:], command_codes[:], true)
	build_and_write_code(e, histograms.distance[:], distance_lengths[:], distance_codes[:], true)

	// The counts and the codes give the exact size: data that does not
	// shrink is stored without being coded first.
	literal_table: [LITERAL_ALPHABET]u32
	command_table: [COMMAND_ALPHABET]u32
	coded := (len(w.out) - mark_size) * 8 + int(w.count) - int(mark_count)

	for &entry, value in literal_table {
		entry = u32(literal_codes[value]) | u32(literal_lengths[value]) << 16
		coded += int(histograms.literal[value]) * int(literal_lengths[value])
	}

	for &entry, symbol in command_table {
		cell := symbol >> 6
		extra := INSERT_EXTRA[int(COMMAND_INSERT_CELL[cell]) + symbol >> 3 & 7] + COPY_EXTRA[int(COMMAND_COPY_CELL[cell]) + symbol & 7]
		entry = u32(command_codes[symbol]) | u32(command_lengths[symbol]) << 16
		coded += int(histograms.command[symbol]) * int(command_lengths[symbol] + extra)
	}

	for count, symbol in histograms.distance {
		extra := (symbol - 14) >> 1 if symbol >= 16 else 0
		coded += int(count) * (int(distance_lengths[symbol]) + extra)
	}

	raw := (^runtime.Raw_Dynamic_Array)(&w.out)

	if coded > (end - start + 4) * 8 {
		e.ring = ring
		raw.len = mark_size
		w.accumulator = mark_accumulator
		w.count = mark_count

		return write_stored_meta_block(w, src[start:end], last)
	}

	if raw.len + coded / 8 + 16 > raw.cap {
		reserve(&w.out, max(raw.cap * 2, raw.len + coded / 8 + 16)) or_return
	}

	b := Fast_Bits{w.accumulator, w.count, uintptr(raw.data) + uintptr(raw.len)}
	fast_flush(&b)
	position := start

	for record in records[:total] {
		fast_command(&b, &command_table, &literal_table, src[position:][:record.insert_length], record.copy_length, int(record.symbol))

		if record.distance_symbol != 0 {
			prefix := record.distance_symbol - 1
			fast_put(&b, u64(distance_codes[prefix]), uint(distance_lengths[prefix]))
			fast_put(&b, u64(record.distance_extra), uint(record.distance_bits))
			fast_flush(&b)
		}

		position += int(record.insert_length) + int(record.copy_length)
	}

	if trailing > 0 {
		fast_command(&b, &command_table, &literal_table, src[position:end], 2, trailing_symbol)
	}

	raw.len = int(b.out - uintptr(raw.data))
	w.accumulator = b.accumulator
	w.count = b.count
	assert((len(w.out) - mark_size) * 8 + int(w.count) - int(mark_count) == coded)

	return nil
}
