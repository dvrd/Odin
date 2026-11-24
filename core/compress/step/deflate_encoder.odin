package compress_step

import "base:runtime"
import "core:compress/deflate"
import "core:io"
import "core:mem"

/*
Pull-style DEFLATE, zlib and gzip encoding for a caller that produces a body in
pieces and sends it as the socket takes it.

The compression is `deflate.Writer`: its match finder, its block splitter and its
Huffman coder, reached through its public procedures only. The writer pushes what
it produces into a buffer held here, and the caller drains that buffer with
`deflate_encoder_pull` whenever it can send. Encoding never waits for anything, so
no call blocks.

	e: Deflate_Encoder
	deflate_encoder_init(&e, .Gzip, .Level_6) or_return
	defer deflate_encoder_destroy(&e)
	for each piece {
		for len(piece) > 0 {
			piece = piece[deflate_encoder_write(&e, piece):]
			send(buffer[:deflate_encoder_pull(&e, buffer[:])])
		}
	}
	for !deflate_encoder_finish(&e) {
		send(buffer[:deflate_encoder_pull(&e, buffer[:])])
	}
	for deflate_encoder_pending(&e) > 0 {
		send(buffer[:deflate_encoder_pull(&e, buffer[:])])
	}

All memory is taken once, in `deflate_encoder_init`; `deflate_encoder_reset` starts
another stream in the same memory. An encoder holds pointers into itself: do not
copy or move it between init and destroy.
*/

// The most input one `deflate_encoder_write` takes. The writer then emits at most
// one block, which is what bounds the buffer between writer and caller.
DEFLATE_ENCODER_WRITE_MAX :: deflate.DEFLATE_BLOCK_MAX

Deflate_Encoder :: struct {
	writer:     deflate.Writer,
	// One allocation: the writer's state and block buffer, its window, and the
	// output waiting to be pulled.
	memory:     []u8,
	state:      []u8,
	window:     []u8,
	sink:       []u8,
	arena:      mem.Arena,
	head, tail: int,
	produced:   i64,
	max_output: i64,
	err:        deflate.Error,
	allocator:  runtime.Allocator,
	finished:   bool,
	// The stream would have passed `max_output`. The encoder has failed.
	overflow:   bool,
}

// `format` is .Raw, .Zlib or .Gzip. A `max_output` above zero is a ceiling on the
// whole encoded stream; passing it fails the encoder, see `overflow`.
deflate_encoder_init :: proc(e: ^Deflate_Encoder, format: deflate.Format, level := deflate.Deflate_Level.Default, max_output := 0, allocator := context.allocator) -> (err: deflate.Error) {
	e^ = {}
	if format == .Raw64 {
		return deflate.General_Error.Incompatible_Options
	}
	block := deflate.compress_gzip_bound(deflate.DEFLATE_BLOCK_MAX)
	// The writer's state and its one-block output buffer, with room for alignment.
	state := size_of(deflate.Deflate) + block + 256
	// History, a block being gathered, a block of new input, and lookahead.
	window := 2 * deflate.DEFLATE_WINDOW_SIZE + 2 * deflate.DEFLATE_BLOCK_MAX + 4096
	// A flush or a finish emits what is gathered: under two blocks and a trailer.
	sink := 2 * block + 64

	e.memory = make([]u8, state + window + sink, allocator) or_return
	e.state = e.memory[:state]
	e.window = e.memory[state:][:window]
	e.sink = e.memory[state + window:]
	e.allocator = allocator
	return deflate_encoder_reset(e, format, level, max_output)
}

// Starts another stream in the memory of an initialized encoder.
deflate_encoder_reset :: proc(e: ^Deflate_Encoder, format: deflate.Format, level := deflate.Deflate_Level.Default, max_output := 0) -> (err: deflate.Error) {
	e.head, e.tail = 0, 0
	e.produced = 0
	e.max_output = i64(max_output)
	e.finished = false
	e.overflow = false
	if e.memory == nil || format == .Raw64 || max_output < 0 {
		e.err = deflate.General_Error.Incompatible_Options
		return e.err
	}
	// The writer allocates its state from this arena, so a reset allocates nothing.
	mem.arena_init(&e.arena, e.state)
	sink := io.Stream{procedure = deflate_encoder_sink, data = e}
	e.err = deflate.writer_init(&e.writer, sink, format, level, {buffer = e.window}, mem.arena_allocator(&e.arena))
	return e.err
}

deflate_encoder_destroy :: proc(e: ^Deflate_Encoder) {
	delete(e.memory, e.allocator)
	e^ = {}
}

// Takes a prefix of `input`. Zero while output waits to be pulled, after
// `deflate_encoder_finish`, and once the encoder has failed.
deflate_encoder_write :: proc(e: ^Deflate_Encoder, input: []u8) -> (consumed: int) {
	if !deflate_encoder_accepts_input(e) {
		return 0
	}
	consumed, e.err = deflate.writer_write(&e.writer, input[:min(len(input), DEFLATE_ENCODER_WRITE_MAX)])
	return
}

// Ends the current block on a byte boundary, so that everything written so far
// can be decoded from the output. False while output must be pulled first, and
// once the encoder has failed.
deflate_encoder_flush :: proc(e: ^Deflate_Encoder) -> (flushed: bool) {
	if !deflate_encoder_accepts_input(e) {
		return false
	}
	e.err = deflate.writer_flush(&e.writer)
	return e.err == nil
}

// Ends the stream. False while output must be pulled first; call again after
// pulling. Output can still be pending when it returns true.
deflate_encoder_finish :: proc(e: ^Deflate_Encoder) -> (finished: bool) {
	if e.finished {
		return true
	}
	if e.err != nil || e.head != e.tail {
		return false
	}
	e.err = deflate.writer_finish(&e.writer)
	e.finished = e.err == nil
	return e.finished
}

deflate_encoder_pull :: proc(e: ^Deflate_Encoder, output: []u8) -> (count: int) {
	count = copy(output, e.sink[e.head:e.tail])
	e.head += count
	if e.head == e.tail {
		e.head, e.tail = 0, 0
	}
	return
}

deflate_encoder_pending :: proc(e: ^Deflate_Encoder) -> int {
	return e.tail - e.head
}

deflate_encoder_accepts_input :: proc(e: ^Deflate_Encoder) -> bool {
	return e.err == nil && !e.finished && e.head == e.tail && e.memory != nil
}

// nil, or why the encoder stopped. A failed encoder takes no input and never finishes.
deflate_encoder_error :: proc(e: ^Deflate_Encoder) -> deflate.Error {
	return e.err
}

@(private)
deflate_encoder_sink :: proc(stream_data: rawptr, mode: io.Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From) -> (n: i64, err: io.Error) {
	e := (^Deflate_Encoder)(stream_data)
	#partial switch mode {
	case .Write:
		if e.max_output > 0 && e.produced + i64(len(p)) > e.max_output {
			e.overflow = true
			return 0, .Short_Write
		}
		if len(p) > len(e.sink) - e.tail {
			return 0, .Short_Write
		}
		copy(e.sink[e.tail:], p)
		e.tail += len(p)
		e.produced += i64(len(p))
		return i64(len(p)), nil
	case .Query:
		return io.query_utility({.Write, .Query})
	}
	return 0, .Empty
}
