package compress_brotli

import "base:intrinsics"
import "base:runtime"
import "core:math/bits"


// Match finders and parsers for levels 0..9. Levels 5..9: every hash bucket
// keeps its newest positions in a ring, searched newest first after the
// recent distances; their finder and parser come last. The levels below have
// tables of their own.

Finder :: struct {
	// Positions ever entered per bucket of the levels 5..9.
	counts:       []u16,
	// Newest position per hash of four bytes, levels 5..9.
	short:        []u32,
	buckets:      []u32,
	bucket_shift: u32,
	block_bits:   uint,
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

// Tables of the levels 5..9: 2^block_bits positions per bucket in a ring and
// the number of positions ever entered beside it, and the newest position
// per four bytes. Slots are only read up to their bucket's count: no need to
// clear them.
finder_make :: proc(f: ^Finder, size: int, block_bits: uint, allocator: runtime.Allocator) -> runtime.Allocator_Error {
	bucket_bits := clamp(bits.len_u32(u32(min(size, 1 << 30))) - 1, BUCKET_BITS_MIN, DEEP_BUCKET_BITS_MAX)
	f.bucket_shift = u32(32 - bucket_bits)
	f.block_bits = block_bits
	f.counts = make([]u16, 1 << uint(bucket_bits), allocator) or_return
	f.short = make([]u32, 1 << SHORT_BITS, allocator) or_return
	slots, slots_error := runtime.mem_alloc_non_zeroed((4 << uint(bucket_bits)) << block_bits, 64, allocator)

	if slots_error != nil {
		return slots_error
	}

	f.buckets = ([^]u32)(raw_data(slots))[:(1 << uint(bucket_bits)) << block_bits]

	return nil
}

finder_destroy :: proc(f: ^Finder, allocator: runtime.Allocator) {
	delete(f.counts, allocator)
	delete(f.short, allocator)
	delete(f.buckets, allocator)
}

match_score :: #force_inline proc(length, distance: int) -> int {
	return 1920 + 135 * length - 30 * (bits.len_u32(u32(distance)) - 1)
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

// Bits of the hash of four bytes that tell whether a word may start with
// them: most bytes start none, and the table that says so is small enough to
// stay at hand, which the words and their chains are not.
DICTIONARY_FILTER_BITS :: 16

DICTIONARY_FILTER: [1 << DICTIONARY_FILTER_BITS / 64]u64

@(init)
fill_dictionary_filter :: proc "contextless" () #no_bounds_check {
	for size in DICTIONARY_WORD_MIN ..= DICTIONARY_WORD_MAX {
		for index in 0 ..< 1 << DICTIONARY_SIZE_BITS[size] {
			start := DICTIONARY[int(DICTIONARY_OFFSET[size]) + index * size:]
			value := u32(start[0]) | u32(start[1]) << 8 | u32(start[2]) << 16 | u32(start[3]) << 24
			// As hash4 has it.
			filter := value * 0x1e35a7bd >> (32 - DICTIONARY_FILTER_BITS)
			DICTIONARY_FILTER[filter >> 6] |= 1 << (filter & 63)
		}
	}
}

// Best static dictionary word, whole or with up to nine trailing bytes
// dropped, that src[position:] starts with.
dictionary_match :: proc(src: []u8, position, limit, reach: int) -> Match #no_bounds_check {
	best := Match{score = SCORE_MIN}
	hash := hash4(src, position)
	filter := hash >> (32 - DICTIONARY_FILTER_BITS)

	if DICTIONARY_FILTER[filter >> 6] & (1 << (filter & 63)) == 0 {
		return best
	}

	word := WORD_HEAD[hash >> (32 - DICTIONARY_HASH_BITS)]

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

// Misses before the step between probed positions grows by one, log2.
FAST_PATIENCE :: 5

// Shortest copy the fast levels take, and the bytes their hash covers: text
// packs better without the copies of four and five bytes, which cost about
// what they save, and there are fewer commands to find and write.
FAST_MATCH_MIN :: 6

#assert(FAST_MATCH_MIN <= size_of(u64))

// Most hash slots a fast level looks at per position.
FAST_SLOTS_MAX :: 2

// A command of the levels without modelling with its symbols worked out: the
// parser has time for that while it waits on memory, the writer has not.
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

// Room for the records of one block of `length` bytes whose copies are at
// least `shortest` long; they are written before they are read.
fast_records_make :: proc(length, shortest: int, allocator: runtime.Allocator) -> ([]Fast_Record, runtime.Allocator_Error) {
	count := length / shortest + 1
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

// ---------------------------------------------------------------- lazy levels

// Bytes the hash of the lazy levels covers, and so their shortest copy at a
// new distance: a copy of four bytes costs about what it saves on text and
// more than that on digits, and a longer hash keeps the buckets apart.
LAZY_HASH_BYTES :: 5

// The word of the next position is the word of this one shifted by a byte.
#assert(LAZY_HASH_BYTES < size_of(u64))

// Shortest copy of the lazy levels: two bytes at one of the last two
// distances.
LAZY_MATCH_MIN :: 2

// Most buckets of the lazy levels, log2.
LAZY_BUCKET_BITS_MAX :: 16

// A copy of LAZY_HASH_BYTES has to come from within 2^LAZY_SHORT_REACH_BITS:
// from further away its distance costs more than the literals would.
LAZY_SHORT_REACH_BITS :: 16

// Positions without a copy before the lazy levels look at fewer of them.
LAZY_SPREE :: 64

// A later start has to score this much more to be taken instead.
LAZY_GAIN :: 175

// Table of the lazy levels: 2^slot_bits positions per bucket, newest first,
// in 64-bit words so that a bucket is read and shifted along two positions at
// a time, and on cache lines of its own. Zeroed, so that every slot points
// into the data from the start.
lazy_finder_make :: proc(f: ^Finder, size: int, slot_bits: uint, allocator: runtime.Allocator) -> runtime.Allocator_Error {
	assert(slot_bits >= 1)

	bucket_bits := clamp(bits.len_u32(u32(min(size, 1 << 30))) - 1, BUCKET_BITS_MIN, LAZY_BUCKET_BITS_MAX)
	f.bucket_shift = u32(32 - bucket_bits)
	slots, slots_error := runtime.mem_alloc((4 << uint(bucket_bits)) << slot_bits, 64, allocator)

	if slots_error != nil {
		return slots_error
	}

	f.buckets = ([^]u32)(raw_data(slots))[:(1 << uint(bucket_bits)) << slot_bits]

	return nil
}

// Index of the first word of the bucket of `word` in a table of SLOTS
// positions per bucket.
lazy_bucket :: #force_inline proc(word: u64, shift: u32, $SLOTS: int) -> int {
	return int((word << (64 - 8 * LAZY_HASH_BYTES)) * 0x1e35a7bd1e35a7bd >> (32 + shift)) * (SLOTS / 2)
}

// True when the two words start with the same LAZY_HASH_BYTES bytes.
lazy_same :: #force_inline proc(a, b: u64) -> bool {
	return (a ~ b) << (64 - 8 * LAZY_HASH_BYTES) == 0
}

// Enters `position` at the head of the bucket of `word`, from which the
// oldest position drops out, and returns what the bucket held, newest first.
lazy_enter :: #force_inline proc(table: [^]u64, word: u64, position: int, shift: u32, $SLOTS: int) -> (candidates: [SLOTS]u32) #no_bounds_check {
	bucket := table[lazy_bucket(word, shift, SLOTS):]
	carry := u64(u32(position))

	for index in 0 ..< SLOTS / 2 {
		pair := bucket[index]
		bucket[index] = pair << 32 | carry
		carry = pair >> 32
		candidates[2 * index] = u32(pair)
		candidates[2 * index + 1] = u32(pair >> 32)
	}

	return
}

// Starts reading the bytes at the newest position the table has for `word`:
// they are compared as soon as its position is looked at.
lazy_prefetch :: #force_inline proc(src: []u8, table: [^]u64, word: u64, shift: u32, $SLOTS: int) #no_bounds_check {
	intrinsics.prefetch_read_data(&src[u32(table[lazy_bucket(word, shift, SLOTS)])], 3)
}

// Best copy for `position` that ends by `end` among the CACHE last distances
// and the bucket; score SCORE_MIN when nothing is worth it. A word is read at
// `position`, which is entered. `floor`, less than the bytes left, spares
// most candidates that are no longer than that their comparison.
lazy_find :: #force_inline proc(
	src: []u8,
	table: [^]u64,
	ring: ^Ring,
	position, end, window: int,
	shift: u32,
	floor: int,
	$SLOTS: int,
	$CACHE: int,
) -> (
	best: Match,
) #no_bounds_check {
	#assert(CACHE <= len(Ring))

	limit := end - position
	reach := min(position, window)
	word := fast_word(src, position)
	best = {length = floor, score = SCORE_MIN}

	for index in 0 ..< CACHE {
		distance := int(ring[index])
		// Two bytes are enough at the last two distances, three at the others.
		shortest := 2 if index < 2 else 3

		if distance > reach || (fast_word(src, position - distance) ~ word) << uint(64 - 8 * shortest) != 0 {
			continue
		}

		if best.length >= limit || src[position + best.length] != src[position - distance + best.length] {
			continue
		}

		length := common_length(src, position - distance, position, limit)
		score := 135 * length + 1935

		if index != 0 {
			score -= 39 + (0x1ca10 >> uint(index & 0xe)) & 0xe
		}

		if score > best.score {
			best = {length, distance, score, 0}
		}
	}

	candidates := lazy_enter(table, word, position, shift, SLOTS)
	lazy_prefetch(src, table, word >> 8, shift, SLOTS)

	for slot in 0 ..< SLOTS {
		candidate := int(candidates[slot])
		distance := position - candidate

		// An empty slot holds position zero, which is as good a candidate as
		// any other.
		if uint(distance - 1) >= uint(reach) || !lazy_same(fast_word(src, candidate), word) {
			continue
		}

		if best.length >= limit || src[candidate + best.length] != src[position + best.length] {
			continue
		}

		length := LAZY_HASH_BYTES + common_length(src, candidate + LAZY_HASH_BYTES, position + LAZY_HASH_BYTES, limit - LAZY_HASH_BYTES)

		if length == LAZY_HASH_BYTES && distance >> LAZY_SHORT_REACH_BITS != 0 {
			continue
		}

		score := match_score(length, distance)

		if score > best.score {
			best = {length, distance, score, 0}
		}
	}

	return best
}

// Parses src[start:end] into `records`, counts their symbols and returns how
// many there are and how many literals follow the last copy. Levels 2 to 4:
// the last CACHE distances and SLOTS positions per bucket, a copy given up
// for a clearly better one starting later, every position of a copy entered.
parse_lazy :: proc(
	e: ^Encoder,
	start, end: int,
	records: []Fast_Record,
	histograms: ^Fast_Histograms,
	$SLOTS: int,
	$CACHE: int,
) -> (
	total: int,
	trailing: int,
) #no_bounds_check {
	src := e.src
	table := ([^]u64)(raw_data(e.finder.buckets))
	shift := e.finder.bucket_shift
	window := e.window_max
	ring := e.ring
	// A word is read at every position looked at.
	last := min(end - LAZY_HASH_BYTES, len(src) - size_of(u64))
	position := start
	literal_start := start
	sparse_after := position + LAZY_SPREE

	for position <= last {
		match := lazy_find(src, table, &ring, position, end, window, shift, 0, SLOTS, CACHE)

		if match.score == SCORE_MIN {
			position += 1

			// After a long run without matches the data is probably
			// incompressible: look at fewer positions.
			if position > sparse_after {
				step := 4 if position > sparse_after + 4 * LAZY_SPREE else 2
				stop := min(position + 4 * step, last)

				for ; position < stop; position += step {
					_ = lazy_enter(table, fast_word(src, position), position, shift, SLOTS)
				}
			}

			continue
		}

		// Give up to four literals when a later start scores clearly better.
		// That takes a copy about as long as this one: shorter candidates
		// are not compared in full.
		for _ in 0 ..< 4 {
			if position + 1 > last || position + match.length >= end {
				break
			}

			next := lazy_find(src, table, &ring, position + 1, end, window, shift, match.length - 1, SLOTS, CACHE)

			if next.score < match.score + LAZY_GAIN {
				break
			}

			position += 1
			match = next
		}

		// Entered so far: the positions up to the one last looked at.
		first := position + 2

		// The copy may have begun among the literals before it, where the
		// table no longer or not yet had its source.
		for position > literal_start && match.distance < position && src[position - 1] == src[position - 1 - match.distance] {
			position -= 1
			match.length += 1
		}

		next := position + match.length

		if next <= last {
			lazy_prefetch(src, table, fast_word(src, next), shift, SLOTS)
		}

		// Index the copied bytes; of a short-period repeat only the tail, so
		// that its buckets do not fill with one pattern.
		stop := min(next, last + 1)

		if match.distance < match.length >> 2 {
			first = max(first, next - match.distance << 2)
		}

		for covered in first ..< stop {
			_ = lazy_enter(table, fast_word(src, covered), covered, shift, SLOTS)
		}

		insert_length := position - literal_start
		code := distance_code(&ring, match.distance)
		symbol := command_symbol(insert_code(insert_length), copy_code(match.length), code == 0)
		histograms.command[symbol] += 1

		for value in src[literal_start:position] {
			histograms.literal[value] += 1
		}

		record := Fast_Record {
			insert_length = u32(insert_length),
			copy_length   = u32(match.length),
			symbol        = u16(symbol),
		}

		if code != 0 {
			ring_push(&ring, match.distance)
		}

		if code != 0 || !distance_is_implicit(u16(symbol)) {
			prefix, extra_bits, extra := distance_prefix(code, 0, 0)
			record.distance_symbol = u8(prefix) + 1
			record.distance_bits = extra_bits
			record.distance_extra = extra
			histograms.distance[prefix] += 1
		}

		records[total] = record
		total += 1
		sparse_after = position + 2 * match.length + LAZY_SPREE
		position = next
		literal_start = next
	}

	e.ring = ring

	return total, end - literal_start
}

// ---------------------------------------------------------------- deep levels

// Bytes the hash of the deep levels covers, as that of the lazy levels.
DEEP_HASH_BYTES :: LAZY_HASH_BYTES

// Most buckets of the deep levels, log2: with fewer of them the positions
// they hold are told apart by reading their bytes, which takes longer than a
// larger table does.
DEEP_BUCKET_BITS_MAX :: 16

// Slots of the table of four bytes, log2: it tells of the short copies the
// buckets cannot see, and of them only the nearest is cheap enough to take.
SHORT_BITS :: 16

// A copy found by its first four bytes has to come from within this.
SHORT_REACH :: 1 << 10

// Lookups the static dictionary is given before it has to pay, and the
// lookups a hit pays for, log2: walking its chains costs several times what
// a bucket does.
DICTIONARY_TRIAL :: 512
DICTIONARY_HIT_BITS :: 5

// A word has to beat the literals by this much: its distance is costlier
// than its score tells.
DICTIONARY_MARGIN :: 135

// The tables of a Finder as the parser of the deep levels keeps them at hand.
Deep_Table :: struct {
	counts:     [^]u16,
	short:      [^]u32,
	buckets:    [^]u32,
	shift:      u32,
	block_bits: uint,
}

deep_table :: proc(f: ^Finder) -> Deep_Table {
	return {raw_data(f.counts), raw_data(f.short), raw_data(f.buckets), f.bucket_shift, f.block_bits}
}

deep_key :: #force_inline proc(word: u64, shift: u32) -> int {
	return int((word << (64 - 8 * DEEP_HASH_BYTES)) * 0x1e35a7bd1e35a7bd >> (32 + shift))
}

short_key :: #force_inline proc(word: u64) -> u32 {
	return u32(word) * 0x1e35a7bd >> (32 - SHORT_BITS)
}

// Enters `position` in the bucket of `word`, where it takes the place of the
// oldest position, and as the newest position of its first four bytes.
deep_enter :: #force_inline proc(t: Deep_Table, word: u64, position: int) #no_bounds_check {
	key := deep_key(word, t.shift)
	count := t.counts[key]
	t.buckets[key << t.block_bits + int(count & (1 << t.block_bits - 1))] = u32(position)
	t.counts[key] = count + 1
	t.short[short_key(word)] = u32(position)
}

// Starts reading the newest positions of the bucket of `word`: the cache
// line of the newest one and, in a bucket of more than one, the line before.
deep_prefetch :: #force_inline proc(t: Deep_Table, word: u64) #no_bounds_check {
	LINE :: 64 / size_of(u32)

	key := deep_key(word, t.shift)
	newest := t.counts[key] - 1
	mask := u16(1) << t.block_bits - 1
	intrinsics.prefetch_read_data(&t.buckets[key << t.block_bits + int(newest & mask)], 3)
	intrinsics.prefetch_read_data(&t.buckets[key << t.block_bits + int((newest - LINE) & mask)], 3)
}

// Best copy for `position` that ends by `end` among the CACHE recent
// distances, the bucket, the nearest position with the same four bytes and,
// when nothing else is found, the static dictionary; score SCORE_MIN when
// nothing is worth it. A word is read at `position`, which is entered.
// `floor`, less than the bytes left, spares most candidates that are no
// longer than that their comparison.
deep_find :: #force_inline proc(
	f: ^Finder,
	t: Deep_Table,
	src: []u8,
	ring: ^Ring,
	position, end, window: int,
	floor: int,
	$CACHE: int,
) -> (
	best: Match,
) #no_bounds_check {
	#assert(CACHE <= len(CACHE_INDEX))

	limit := end - position
	reach := min(position, window)
	word := fast_word(src, position)
	best = {length = floor, score = SCORE_MIN}

	for index in 0 ..< CACHE {
		distance := int(ring[CACHE_INDEX[index]]) + int(CACHE_OFFSET[index])
		// Two bytes are enough at the last two distances, three at the others.
		shortest := 2 if index < 2 else 3

		if uint(distance - 1) >= uint(reach) || (fast_word(src, position - distance) ~ word) << uint(64 - 8 * shortest) != 0 {
			continue
		}

		if best.length >= limit || src[position + best.length] != src[position - distance + best.length] {
			continue
		}

		length := common_length(src, position - distance, position, limit)
		score := 135 * length + 1935

		if index != 0 {
			score -= 39 + (0x1ca10 >> uint(index & 0xe)) & 0xe
		}

		if score > best.score {
			best = {length, distance, score, 0}
		}
	}

	key := deep_key(word, t.shift)
	count := t.counts[key]
	mask := u16(1) << t.block_bits - 1
	bucket := t.buckets[key << t.block_bits:]
	deep_prefetch(t, word >> 8)

	// Nothing is longer than a copy to the end.
	held := min(int(count), 1 << t.block_bits) if best.length < limit else 0

	for back in 1 ..= held {
		candidate := int(bucket[(count - u16(back)) & mask])
		distance := position - candidate

		// The older positions are further away still.
		if distance > reach {
			break
		}

		// Most candidates are told by one byte: where a longer copy has to
		// go on. Whether the bytes of the hash match is seen with the rest.
		if src[candidate + best.length] != src[position + best.length] {
			continue
		}

		length := common_length(src, candidate, position, limit)

		if length < DEEP_HASH_BYTES || length == DEEP_HASH_BYTES && distance >> LAZY_SHORT_REACH_BITS != 0 {
			continue
		}

		score := match_score(length, distance)

		if score > best.score {
			best = {length, distance, score, 0}

			// There is no byte after the end to tell a longer copy by.
			if length == limit {
				break
			}
		}
	}

	bucket[count & mask] = u32(position)
	t.counts[key] = count + 1
	near := &t.short[short_key(word)]

	if best.length < size_of(u32) {
		candidate := int(near^)
		distance := position - candidate

		// An empty slot holds position zero, which is as good a candidate as
		// any other.
		if uint(distance - 1) < uint(min(reach, SHORT_REACH)) && u32(fast_word(src, candidate)) == u32(word) {
			length := common_length(src, candidate, position, limit)
			score := match_score(length, distance)

			if score > best.score {
				best = {length, distance, score, 0}
			}
		}
	}

	near^ = u32(position)

	if best.score == SCORE_MIN && f.hits << DICTIONARY_HIT_BITS + DICTIONARY_TRIAL >= f.lookups {
		f.lookups += 1
		entry := dictionary_match(src, position, limit, reach)

		if entry.score > best.score + DICTIONARY_MARGIN {
			best = entry
			f.hits += 1
		}
	}

	return best
}

// Parses src[start:end] into e.commands. Levels 5 to 9: the CACHE recent
// distances, a bucket of positions and the static dictionary, a copy given up
// for a clearly better one starting later, every position of a copy entered.
parse_deep :: proc(e: ^Encoder, start, end: int, $CACHE: int) -> runtime.Allocator_Error #no_bounds_check {
	f := &e.finder
	t := deep_table(f)
	src := e.src
	window := e.window_max
	ring := e.ring
	// A word is read at every position looked at.
	last := min(end - DEEP_HASH_BYTES, len(src) - size_of(u64))
	position := start
	literal_start := start
	spree := 512 if e.level >= .Best else LAZY_SPREE
	sparse_after := position + spree

	for position <= last {
		match := deep_find(f, t, src, &ring, position, end, window, 0, CACHE)

		if match.score == SCORE_MIN {
			position += 1

			// After a long run without matches the data is probably
			// incompressible: look at fewer positions.
			if position > sparse_after {
				step := 4 if position > sparse_after + 4 * spree else 2
				stop := min(position + 4 * step, last)

				for ; position < stop; position += step {
					deep_enter(t, fast_word(src, position), position)
				}
			}

			continue
		}

		// Give up to four literals when a later start scores clearly better.
		// That takes a copy about as long as this one: shorter candidates
		// are not compared in full.
		for _ in 0 ..< 4 {
			if position + 1 > last || position + match.length >= end {
				break
			}

			next := deep_find(f, t, src, &ring, position + 1, end, window, match.length - 1, CACHE)

			if next.score < match.score + LAZY_GAIN {
				break
			}

			position += 1
			match = next
		}

		// Entered so far: the positions up to the one last looked at.
		first := position + 2
		// A dictionary word lies past the window.
		inside := match.distance <= min(position, window)

		// The copy may have begun among the literals before it, where the
		// table no longer or not yet had its source.
		for inside && position > literal_start && match.distance < position && src[position - 1] == src[position - 1 - match.distance] {
			position -= 1
			match.length += 1
		}

		next := position + match.length

		if next <= last {
			deep_prefetch(t, fast_word(src, next))
		}

		// Index the copied bytes; of a short-period repeat only the tail, so
		// that its buckets do not fill with one pattern.
		stop := min(next, last + 1)

		if match.distance < match.length >> 2 {
			first = max(first, next - match.distance << 2)
		}

		for covered in first ..< stop {
			deep_enter(t, fast_word(src, covered), covered)
		}

		if len(e.commands) == cap(e.commands) {
			reserve(&e.commands, 2 * cap(e.commands) + 16) or_return
		}

		// Room is there: the command goes in without a call.
		commands := (^runtime.Raw_Dynamic_Array)(&e.commands)
		([^]Command)(commands.data)[commands.len] = command_make(&ring, position - literal_start, match.length + match.omit, match.distance, match.omit, inside)
		commands.len += 1

		sparse_after = position + 2 * match.length + spree
		position = next
		literal_start = next
	}

	if literal_start < end {
		append(&e.commands, command_make(&ring, end - literal_start, 0, 0, 0, false)) or_return
	}

	e.ring = ring

	return nil
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

	#partial switch e.level {
	case Level(0):
		total, trailing = parse_fast(e, start, end, records, &histograms, 1)
	case Level(1):
		total, trailing = parse_fast(e, start, end, records, &histograms, 2)
	case Level(2):
		total, trailing = parse_lazy(e, start, end, records, &histograms, 2, 1)
	case Level(3):
		total, trailing = parse_lazy(e, start, end, records, &histograms, 4, 2)
	case:
		total, trailing = parse_lazy(e, start, end, records, &histograms, 8, 2)
	}

	// The literals after the last copy: a command whose copy is never read.
	trailing_symbol := command_symbol(insert_code(trailing), 0, true)

	if trailing > 0 {
		histograms.command[trailing_symbol] += 1

		for value in src[end - trailing:end] {
			histograms.literal[value] += 1
		}
	}

	// The codes may be built from counts evened out; the sizes come from
	// the true ones.
	counted := histograms

	if e.level >= SMOOTH_LEVEL_MIN {
		smooth_for_rle(histograms.literal[:])
		smooth_for_rle(histograms.command[:])
		smooth_for_rle(histograms.distance[:])
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
		coded += int(counted.literal[value]) * int(literal_lengths[value])
	}

	for &entry, symbol in command_table {
		cell := symbol >> 6
		extra := INSERT_EXTRA[int(COMMAND_INSERT_CELL[cell]) + symbol >> 3 & 7] + COPY_EXTRA[int(COMMAND_COPY_CELL[cell]) + symbol & 7]
		entry = u32(command_codes[symbol]) | u32(command_lengths[symbol]) << 16
		coded += int(counted.command[symbol]) * int(command_lengths[symbol] + extra)
	}

	for count, symbol in counted.distance {
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
