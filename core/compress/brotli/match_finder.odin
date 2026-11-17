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

// Levels 0 and 1: the last distance and one or four hash slots, positions
// inside copies mostly left out of the table, and ever longer steps while
// nothing matches. The table is not cleared: a stale or random slot is
// rejected by comparing the bytes it points at.
parse_fast :: proc(e: ^Encoder, start, end: int) -> runtime.Allocator_Error #no_bounds_check {
	f := &e.finder
	src := e.src
	table := f.buckets
	position := start
	literal_start := start
	last := end - 4
	misses := 0

	shift := f.bucket_shift - u32(f.block_bits)
	mask := u32(len(table) - 1)
	sweep := u32(1) << f.block_bits
	// Level 0 looks no further once anything matches and gives up on
	// unmatched data sooner; level 1 probes four slots.
	patient := e.level > Level(0)
	patience: uint = FAST_PATIENCE + 1 if patient else FAST_PATIENCE
	good := 16 if patient else 4
	tail := 8 if patient else 2

	for position <= last {
		key := hash4(src, position) >> shift
		reach := min(position, e.window_max)
		head := intrinsics.unaligned_load((^u32)(&src[position]))
		distance := int(e.ring[0])
		length := 0

		if distance <= reach && intrinsics.unaligned_load((^u32)(&src[position - distance])) == head {
			length = common_length(src, position - distance, position, end - position)
		}

		if length < good {
			best := length

			for slot in 0 ..< sweep {
				candidate := int(table[(key + slot) & mask])

				if candidate >= position || position - candidate > reach {
					continue
				}

				if intrinsics.unaligned_load((^u32)(&src[candidate])) != head {
					continue
				}

				found := common_length(src, candidate, position, end - position)

				if found > best + (1 if best >= 4 else 0) {
					best = found
					distance = position - candidate
				}
			}

			length = best
		}

		table[(key + u32(position >> 3) & (sweep - 1)) & mask] = u32(position)

		if length < 4 {
			position += 1 + misses >> patience
			misses += 1
			continue
		}

		misses = 0

		// Only the last distance gets a short code here: the other fifteen
		// cost more to look for than they save at this level.
		insert := insert_code(position - literal_start)
		copy := copy_code(length)
		command := Command {
			insert_length = u32(position - literal_start),
			copy_length   = u32(length),
			distance      = u32(distance),
			code          = u32(distance) + 15,
			insert_code   = u8(insert),
			copy_code     = u8(copy),
		}

		if distance == int(e.ring[0]) {
			command.code = 0
		} else {
			ring_push(&e.ring, distance)
		}

		command.symbol = u16(command_symbol(insert, copy, command.code == 0))
		append(&e.commands, command) or_return
		position += length
		literal_start = position

		if position <= last {
			for back in 1 ..= min(tail, length - 1) {
				at := position - back
				table[(hash4(src, at) >> shift + u32(at >> 3) & (sweep - 1)) & mask] = u32(at)
			}
		}
	}

	if literal_start < end {
		push_command(e, end, end - literal_start, 0, 0, 0) or_return
	}

	return nil
}
