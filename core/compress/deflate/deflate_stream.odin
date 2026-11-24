package compress_deflate

import "base:intrinsics"
import "core:hash"

/*
Streaming compression on top of the one-shot compressor.

A `Deflate_Stream` accepts its input in arbitrary pieces, never allocates and hands
its output out through `deflate_stream_pull`, so a body produced on the fly can be
compressed with bounded state. It parses the same 64 KiB blocks with the same match
finder, block splitter and Huffman builder as `deflate_raw`, `deflate_zlib` and
`deflate_gzip`: without a `deflate_stream_flush` its output is byte for byte the
output of the one-shot procedure of the same framing and level.

	s := new(Deflate_Stream)
	deflate_stream_reset(s, .Gzip, .Level_6)
	for each piece {
		for len(piece) > 0 {
			piece = piece[deflate_stream_write(s, piece):]
			send(buffer[:deflate_stream_pull(s, buffer[:])])
		}
	}
	for !deflate_stream_finish(s) {
		send(buffer[:deflate_stream_pull(s, buffer[:])])
	}
	for deflate_stream_pending(s) > 0 {
		send(buffer[:deflate_stream_pull(s, buffer[:])])
	}
*/

// A block is parsed once this many bytes follow it, so that the positions at its end
// are hashed exactly as the one-shot compressor hashes them.
DEFLATE_STREAM_LOOKAHEAD   :: 8
DEFLATE_STREAM_INPUT_SIZE  :: 2 * DEFLATE_WINDOW_SIZE + DEFLATE_BLOCK_MAX + DEFLATE_STREAM_LOOKAHEAD
// What one block can occupy: its bytes stored, the bits left over by the block before it,
// and the framing around the first and the last block.
DEFLATE_STREAM_BLOCK_SLACK :: 16
DEFLATE_STREAM_OUTPUT_SIZE :: DEFLATE_BLOCK_MAX + 2 * DEFLATE_STREAM_BLOCK_SLACK + size_of(Gzip_Header) + size_of(Gzip_Trailer)

Deflate_Stream_Framing :: enum u8 {
	Raw,
	Zlib,
	Gzip,
}

// This struct is ~600kiB: allocate it with `new` rather than on the stack.
Deflate_Stream :: struct {
	deflate:       Deflate,
	framing:       Deflate_Stream_Framing,
	level:         Deflate_Level,
	// Parse position inside `input`; `input[:fill]` holds the window and the bytes not yet parsed.
	position:      i32,
	fill:          i32,
	hash_base:     i32,
	last_distance: i32,
	output_offset: int,
	output_length: int,
	checksum:      u32,
	total:         u64,
	produced:      int,
	// Zero means unbounded; otherwise producing more sets `overflow`.
	max_output:    int,
	synced:        bool,
	finished:      bool,
	overflow:      bool,
	input:         [DEFLATE_STREAM_INPUT_SIZE]u8,
	output:        [DEFLATE_STREAM_OUTPUT_SIZE]u8,
}

// The most a stream of `len` input bytes produces when it is never flushed.
// Each `deflate_stream_flush` can add up to `DEFLATE_STREAM_BLOCK_SLACK` bytes.
deflate_stream_bound :: proc(len: int, framing := Deflate_Stream_Framing.Gzip) -> int {
	if framing == .Gzip {
		return compress_gzip_bound(len)
	}

	return compress_raw_bound(len)
}

// Starts a new stream. Only the tables the parser reads before writing them are cleared,
// so a reset costs far less than zeroing the state.
deflate_stream_reset :: proc(s: ^Deflate_Stream, framing := Deflate_Stream_Framing.Gzip, level := Deflate_Level.Default, max_output := 0) {
	d := &s.deflate

	d.bit_buffer     = 0
	d.bit_count      = 0
	d.sequence_count = 0
	d.frequencies    = {}
	d.hash_head      = {}

	s.framing       = framing
	s.level         = clamp(level, Deflate_Level.Stored, Deflate_Level.Best)
	s.position      = 0
	s.fill          = 0
	s.hash_base     = 0
	s.last_distance = 0
	s.output_offset = 0
	s.output_length = 0
	s.checksum      = 1 if framing == .Zlib else 0
	s.total         = 0
	s.produced      = 0
	s.max_output    = max_output
	s.synced        = false
	s.finished      = false
	s.overflow      = false

	if s.level == .Level_10 {
		d.hash3_head            = {}
		d.codes.lengths.literal = DEFLATE_FIXED_LITERAL_LENGTH

		for &length in d.codes.lengths.distance {
			length = 5
		}
	}

	deflate_stream_put_header(s)
}

// Consumes a prefix of `input`. A full output buffer stops progress without failing:
// pull, then write the rest.
deflate_stream_write :: proc(s: ^Deflate_Stream, input: []u8) -> (consumed: int) {
	if s.finished || s.overflow {
		return 0
	}

	for {
		if deflate_stream_block_is_ready(s) {
			if !deflate_stream_put_block(s, DEFLATE_BLOCK_MAX, false) {
				break
			}

			continue
		}

		count := min(len(input) - consumed, len(s.input) - int(s.fill))

		if count == 0 {
			break
		}

		piece := input[consumed:][:count]
		copy(s.input[s.fill:], piece)
		deflate_stream_checksum(s, piece)

		s.fill   += i32(count)
		s.total  += u64(count)
		s.synced  = false
		consumed += count
	}

	return consumed
}

// Makes everything written so far decodable by the receiver: the buffered input is
// compressed and followed by an empty stored block. Returns false while the output
// buffer lacks room; pull and call again. Flushing costs ratio: use it only where the
// receiver must not wait for the next block.
deflate_stream_flush :: proc(s: ^Deflate_Stream) -> (flushed: bool) {
	if s.finished || s.overflow {
		return s.finished
	}

	if s.synced {
		return true
	}

	for s.fill > s.position {
		if !deflate_stream_put_block(s, min(s.fill - s.position, DEFLATE_BLOCK_MAX), false) {
			return false
		}
	}

	if !deflate_stream_reserve(s, DEFLATE_STREAM_BLOCK_SLACK) {
		return false
	}

	q := s.output[s.output_length:]
	room := len(q)
	deflate_store(&q, &s.deflate, false, s.input[:s.fill], s.position, s.position)
	deflate_stream_produce(s, room - len(q))
	s.synced = true

	return !s.overflow
}

// Compresses what is left and closes the stream. Returns false while the output
// buffer lacks room; pull and call again. Output can remain to be pulled afterwards.
deflate_stream_finish :: proc(s: ^Deflate_Stream) -> (finished: bool) {
	if s.finished || s.overflow {
		return s.finished
	}

	for s.fill - s.position > DEFLATE_BLOCK_MAX {
		if !deflate_stream_put_block(s, DEFLATE_BLOCK_MAX, false) {
			return false
		}
	}

	if !deflate_stream_put_block(s, s.fill - s.position, true) {
		return false
	}

	s.finished = !s.overflow

	return s.finished
}

// Moves compressed bytes out. Returns how many were copied into `output`.
deflate_stream_pull :: proc(s: ^Deflate_Stream, output: []u8) -> (count: int) {
	count = min(len(output), s.output_length - s.output_offset)

	if count <= 0 {
		return 0
	}

	copy(output, s.output[s.output_offset:][:count])
	s.output_offset += count

	if s.output_offset == s.output_length {
		s.output_offset = 0
		s.output_length = 0
	}

	return count
}

// Compressed bytes waiting for `deflate_stream_pull`.
deflate_stream_pending :: proc(s: ^Deflate_Stream) -> int {
	return s.output_length - s.output_offset
}

// True while `deflate_stream_write` can take input without a pull first.
deflate_stream_accepts_input :: proc(s: ^Deflate_Stream) -> bool {
	if s.finished || s.overflow {
		return false
	}

	return !deflate_stream_block_is_ready(s) || deflate_stream_has_room(s, DEFLATE_BLOCK_MAX)
}

// Compresses all of `input` as one stream into `output`, which must hold
// `deflate_stream_bound(len(input), framing)` bytes. The stream must have been reset.
deflate_stream_to_slice :: proc(s: ^Deflate_Stream, output, input: []u8) -> (written: int, err: Error) {
	if s == nil {
		return 0, General_Error.Incompatible_Options
	}

	rest := input

	for len(rest) > 0 {
		rest = rest[deflate_stream_write(s, rest):]
		written += deflate_stream_pull(s, output[written:])

		if s.overflow || s.finished || (written == len(output) && deflate_stream_pending(s) > 0) {
			return written, General_Error.Output_Too_Short
		}
	}

	for !deflate_stream_finish(s) {
		written += deflate_stream_pull(s, output[written:])

		if s.overflow || (written == len(output) && deflate_stream_pending(s) > 0) {
			return written, General_Error.Output_Too_Short
		}
	}

	written += deflate_stream_pull(s, output[written:])

	if deflate_stream_pending(s) > 0 {
		return written, General_Error.Output_Too_Short
	}

	return written, nil
}

@(private)
deflate_stream_block_is_ready :: proc(s: ^Deflate_Stream) -> bool {
	return s.fill - s.position >= DEFLATE_BLOCK_MAX + DEFLATE_STREAM_LOOKAHEAD
}

@(private)
deflate_stream_has_room :: proc(s: ^Deflate_Stream, span: i32) -> bool {
	free := len(s.output) - (s.output_length - s.output_offset)

	return free >= int(span) + 2 * DEFLATE_STREAM_BLOCK_SLACK
}

// Makes `count` contiguous bytes available after the pending output.
@(private)
deflate_stream_reserve :: proc(s: ^Deflate_Stream, count: int) -> bool {
	if len(s.output) - s.output_length >= count {
		return true
	}

	pending := s.output_length - s.output_offset

	if len(s.output) - pending < count {
		return false
	}

	copy(s.output[:pending], s.output[s.output_offset:s.output_length])
	s.output_offset = 0
	s.output_length = pending

	return true
}

// Accounts for `count` bytes appended to the output and applies the output cap.
@(private)
deflate_stream_produce :: proc(s: ^Deflate_Stream, count: int) {
	s.output_length += count
	s.produced      += count

	if s.max_output > 0 && s.produced > s.max_output {
		s.output_length -= min(s.produced - s.max_output, s.output_length - s.output_offset)
		s.overflow       = true
	}
}

@(private)
deflate_stream_checksum :: proc(s: ^Deflate_Stream, piece: []u8) {
	switch s.framing {
	case .Raw:
	case .Zlib:
		s.checksum = hash.adler32(piece, s.checksum)
	case .Gzip:
		s.checksum = hash.crc32(piece, s.checksum)
	}
}

@(private)
deflate_stream_put_header :: proc(s: ^Deflate_Stream) {
	switch s.framing {
	case .Raw:
	case .Zlib:
		s.output[0] = 0x78 // deflate, 32k window
		s.output[1] = 0x01 // fast compression
		deflate_stream_produce(s, 2)
	case .Gzip:
		header := Gzip_Header{
			magic              = .GZIP,
			compression_method = .DEFLATE,
			os                 = .Unknown,
		}

		#partial switch s.level {
		case .Fastest:
			header.xfl = .Fastest_Compression
		case .Level_9, .Level_10:
			header.xfl = .Maximum_Compression
		}

		intrinsics.unaligned_store((^Gzip_Header)(raw_data(s.output[:])), header)
		deflate_stream_produce(s, size_of(Gzip_Header))
	}
}

@(private)
deflate_stream_put_trailer :: proc(s: ^Deflate_Stream, q: ^[]u8) {
	switch s.framing {
	case .Raw:
	case .Zlib:
		q[0] = u8(s.checksum >> 24)
		q[1] = u8(s.checksum >> 16)
		q[2] = u8(s.checksum >> 8)
		q[3] = u8(s.checksum)
		q^ = q[4:]
	case .Gzip:
		trailer := Gzip_Trailer{
			crc32 = u32le(s.checksum),
			size  = u32le(u32(s.total)),
		}

		intrinsics.unaligned_store((^Gzip_Trailer)(raw_data(q^)), trailer)
		q^ = q[size_of(Gzip_Trailer):]
	}
}

// Parses and writes the next `span` input bytes as one block of the one-shot compressor
// (which the best level may split further). Returns false when the output lacks room.
@(private)
deflate_stream_put_block :: proc(s: ^Deflate_Stream, span: i32, is_last: bool) -> bool {
	if !deflate_stream_reserve(s, int(span) + 2 * DEFLATE_STREAM_BLOCK_SLACK) {
		return false
	}

	d := &s.deflate
	q := s.output[s.output_length:]
	room := len(q)
	window := s.input[:s.fill]
	block_end := s.position + span

	switch {
	case s.level == .Stored:
		deflate_store(&q, d, is_last, window, s.position, block_end)
	case s.level == .Level_1:
		deflate_stream_parse_quick(s, window, block_end)
		deflate_flush(&q, d, is_last, window, s.position, block_end, d.sequences[:d.sequence_count])
	case s.level == .Level_10:
		deflate_stream_parse(s, window, block_end, true)
		deflate_flush_split(&q, d, is_last, window, s.position, block_end)
	case:
		deflate_stream_parse(s, window, block_end, false)
		deflate_flush(&q, d, is_last, window, s.position, block_end, d.sequences[:d.sequence_count])
	}

	if is_last {
		if d.bit_count != 0 {
			deflate_put_bits(&q, d, 0x00, 8 - d.bit_count)
		}

		deflate_stream_put_trailer(s, &q)
	}

	s.position = block_end
	deflate_stream_produce(s, room - len(q))
	deflate_stream_slide(s)

	return true
}

// Drops the input no match can reach any more. The shift is a multiple of the window
// size, so a position keeps its slot in the hash chain.
@(private)
deflate_stream_slide :: proc(s: ^Deflate_Stream) {
	if s.position < 2 * DEFLATE_WINDOW_SIZE {
		return
	}

	delta := (s.position - DEFLATE_WINDOW_SIZE) &~ DEFLATE_WINDOW_MASK
	copy(s.input[:s.fill - delta], s.input[delta:s.fill])

	s.position  -= delta
	s.fill      -= delta
	s.hash_base -= delta
}

@(private)
deflate_stream_max_chain :: proc(level: Deflate_Level) -> i32 {
	switch {
	case level < .Level_9:
		return i32(1) << u32(level)
	case level == .Level_9:
		return 1 << 12
	}

	return 1 << 13
}

// Length of the common prefix of `window[a:]` and `window[b:]`, at most `limit`.
@(private)
deflate_stream_match_length :: #force_inline proc(window: []u8, a, b, limit: i32) -> (length: i32) #no_bounds_check {
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

@(private)
deflate_stream_insert :: #force_inline proc(d: ^Deflate, window: []u8, position, hash_base: i32) #no_bounds_check {
	h := deflate_hash32(window[position:], DEFLATE_HASH_BITS)

	d.hash_chain[position & DEFLATE_WINDOW_MASK] = d.hash_head[h]
	d.hash_head[h] = u16(position - hash_base + 1)
}

// The block parser of `deflate_compress_quick`, one block at a time.
@(private)
deflate_stream_parse_quick :: proc(s: ^Deflate_Stream, window: []u8, block_end: i32) #no_bounds_check {
	d := &s.deflate
	i := s.position
	hash_base := s.hash_base
	last_distance := s.last_distance
	literal_run: i32

	for i < block_end {
		if intrinsics.expect(i - hash_base >= DEFLATE_HASH_SLIDE_AT, false) {
			deflate_slide(d, false)
			hash_base += DEFLATE_HASH_SLIDE
		}

		left := block_end - i

		if left > DEFLATE_MATCH_MIN {
			h := deflate_hash32(window[i:], DEFLATE_HASH_BITS)
			candidate := deflate_unwrap_position(hash_base, d.hash_head[h])
			d.hash_head[h] = u16(i - hash_base + 1)

			if last_distance != 0 {
				if deflate_load_u32(window[i - last_distance:]) == deflate_load_u32(window[i:]) {
					candidate = i - last_distance
				}

				last_distance = 0
			}

			if candidate >= 0 && i - candidate < DEFLATE_WINDOW_SIZE && deflate_load_u32(window[candidate:]) == deflate_load_u32(window[i:]) {
				max_match := min(left, DEFLATE_MATCH_MAX)
				length := DEFLATE_MATCH_MIN + deflate_stream_match_length(window, candidate + DEFLATE_MATCH_MIN, i + DEFLATE_MATCH_MIN, max_match - DEFLATE_MATCH_MIN)

				if literal_run != 0 {
					deflate_add_sequence_field(d, i - literal_run, literal_run)
					literal_run = 0
				}

				deflate_add_sequence_field(d, candidate - i, length)
				deflate_register_match(d, i - candidate, length)
				last_distance = i - candidate
				i += length

				continue
			}
		}

		d.frequencies.literal[window[i]] += 1
		literal_run += 1
		i += 1
		last_distance = 0
	}

	if literal_run != 0 {
		deflate_add_sequence_field(d, i - literal_run, literal_run)
	}

	s.hash_base = hash_base
	s.last_distance = last_distance
}

// The block parser of `deflate_compress_level`, one block at a time.
@(private)
deflate_stream_parse :: proc(s: ^Deflate_Stream, window: []u8, block_end: i32, $BEST: bool) #no_bounds_check {
	d := &s.deflate
	level := s.level
	input_length := i32(len(window))
	max_chain := deflate_stream_max_chain(level)
	match_min: i32 = DEFLATE_MATCH3_MIN if BEST else DEFLATE_MATCH_MIN
	i := s.position
	hash_base := s.hash_base
	last_distance := s.last_distance
	literal_run, sequence_count: i32
	next: Deflate_Match
	have_next := false

	for i < block_end {
		if i - hash_base >= DEFLATE_HASH_SLIDE_AT {
			deflate_slide(d, BEST)
			hash_base += DEFLATE_HASH_SLIDE
		}

		m: Deflate_Match
		left := block_end - i
		max_match := min(left, DEFLATE_MATCH_MAX)
		nice_match := min(i32(DEFLATE_LEVEL_NICE[level]), max_match)
		run, step: i32 = 1, 1

		if have_next {
			m = next
			have_next = false
		} else if max_match > DEFLATE_MATCH_MIN {
			deflate_find_match(&m, d, max_chain, max_match, window, i, hash_base)

			if last_distance != 0 && m.length < max_match {
				length := deflate_stream_match_length(window, i - last_distance, i, max_match)

				if length > m.length && length >= DEFLATE_MATCH_MIN {
					m.length   = length
					m.distance = last_distance
				}
			}

			if BEST && m.length < DEFLATE_MATCH_MIN {
				deflate_find_match3(&m, d, max_match, window, i, hash_base)
			}
		}

		next_max := min(left - 1, DEFLATE_MATCH_MAX)

		if level >= DEFLATE_LEVEL_LAZY && m.length >= match_min && m.length + 1 < nice_match && next_max > DEFLATE_MATCH_MIN {
			lazy_chain := max_chain

			if level >= .Level_9 && m.length >= DEFLATE_GOOD_MATCH {
				lazy_chain >>= 2
			}

			next = {}
			deflate_find_match(&next, d, lazy_chain, next_max, window, i + 1, hash_base)

			if next.length > m.length {
				have_next = true
				m.length = 0
			}
		}

		if m.length >= match_min {
			if literal_run != 0 {
				deflate_add_sequence(d, &sequence_count, i - literal_run, literal_run)
				literal_run = 0
			}

			deflate_add_sequence(d, &sequence_count, -m.distance, m.length)
			deflate_register_match(d, m.distance, m.length)

			if level < .Level_3 {
				last_distance = m.distance

				if m.length >= nice_match {
					step = m.length
				} else {
					run = m.length
				}
			} else {
				run = m.length
			}
		} else {
			d.frequencies.literal[window[i]] += 1
			literal_run += 1
			last_distance = 0
		}

		advance := run * step

		if input_length - (i + advance) <= DEFLATE_MATCH_MIN {
			i += advance
			continue
		}

		for run > 0 {
			run -= 1
			deflate_stream_insert(d, window, i, hash_base)

			when BEST {
				d.hash3_head[deflate_hash24(window[i:])] = u16(i - hash_base + 1)
			}

			i += step
		}
	}

	if literal_run != 0 {
		deflate_add_sequence(d, &sequence_count, i - literal_run, literal_run)
	}

	d.sequence_count = sequence_count
	s.hash_base = hash_base
	s.last_distance = last_distance
}
