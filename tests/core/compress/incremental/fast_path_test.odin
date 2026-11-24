package incremental_test

import "core:bytes"
import "core:compress/deflate"
import "core:compress/step"
import "core:testing"
import "core:time"

// The step decoder against streams from `core:compress/deflate`, with every
// buffer boundary moved around. Input, output and work budget change on each
// step, so the fast loop is entered and left at arbitrary points of a stream.

@(private = "file")
GUARD :: 64

@(private = "file")
random :: proc(state: ^u64) -> u64 {
	state^ ~= state^ << 13; state^ ~= state^ >> 7; state^ ~= state^ << 17
	return state^
}

// Sizes with a long tail: mostly small, sometimes far larger than a match.
@(private = "file")
random_size :: proc(state: ^u64, limit: int) -> int {
	switch random(state) % 8 {
	case 0: return 0
	case 1: return 1
	case 2, 3: return int(random(state) % 16)
	case 4, 5: return int(random(state) % 600)
	}
	return int(random(state) % u64(limit))
}

@(private = "file")
Corpus :: enum {
	Words,     // text-like: literals and short matches
	Runs,      // long runs: distances below eight, overlapping copies
	Noise,     // incompressible: stored blocks and literal-only blocks
	Far,       // repeats near the far edge of the window
}

@(private = "file")
make_corpus :: proc(kind: Corpus, size: int, seed: u64) -> []u8 {
	state := seed
	plain := make([]u8, size)
	switch kind {
	case .Words:
		words := [?]string{"the ", "stream ", "decoder ", "window ", "of ", "bytes ", "and ", "output ", "match ", "literal ", "a ", "table ", "\n"}
		for at := 0; at < size; {
			at += copy(plain[at:], words[random(&state) % len(words)])
			if random(&state) % 9 == 0 && at < size {
				plain[at] = u8('0' + random(&state) % 10); at += 1
			}
		}
	case .Runs:
		for at := 0; at < size; {
			period := 1 + int(random(&state) % 7)
			length := 1 + int(random(&state) % 900)
			for i in 0 ..< min(length, size - at) {
				plain[at + i] = u8('a' + (i % period) + int(random(&state) % 2) * 0)
			}
			at += length
			if at < size {
				plain[at] = u8(random(&state)); at += 1
			}
		}
	case .Noise:
		for &v in plain {v = u8(random(&state))}
	case .Far:
		block := 31_000 + int(seed % 1500)
		for &v, i in plain {
			v = u8(random(&state)) if i < block else plain[i - block]
			if i >= block && random(&state) % 211 == 0 {
				v = u8(random(&state))
			}
		}
	}
	return plain
}

// One decode with random step sizes. `tail` bytes follow the stream and must be
// left unread. Returns the error, or .None once the output equals `plain` and the
// stream ended exactly where it should.
@(private = "file")
drive_raw :: proc(t: ^testing.T, wire, plain: []u8, tail: int, state: ^u64, arena: []u8,
	max_encoded := u64(1) << 40, max_decoded := u64(1) << 40, corrupt := false) -> step.Decode_Error {
	d := new(step.Inflate_Decoder); defer free(d)
	testing.expect_value(t, step.inflate_decoder_init(d, max_encoded, max_decoded), step.Decode_Error.None)
	for &v in arena {v = 0xa5}
	room := len(arena) - 2 * GUARD
	at, produced := 0, 0
	stream := len(wire) - tail
	declared := false
	for round := 0; round < 4_000_000; round += 1 {
		in_n := min(random_size(state, 5000), len(wire) - at)
		if declared {
			// The final input was announced: every later step gets all of the rest.
			in_n = len(wire) - at
		}
		out_n := min(random_size(state, 70_000), room)
		work := 1 + random_size(state, step.DECODE_MAX_WORK)
		final := at + in_n == len(wire)
		declared = final
		output := arena[GUARD:][:out_n]
		r := step.inflate_decoder_step(d, wire[at:][:in_n], output, final, work)
		if r.consumed < 0 || r.consumed > in_n || r.produced < 0 || r.produced > out_n || r.work < 0 || r.work > work {
			testing.expectf(t, false, "step out of bounds: %v for in %d out %d work %d", r, in_n, out_n, work)
			return .Invalid_State
		}
		// Nothing outside the output slice is ever written.
		for v in arena[:GUARD] {
			if v != 0xa5 {testing.expect(t, false, "wrote before the output"); return .Invalid_State}
		}
		for v in arena[GUARD + out_n:][:GUARD] {
			if v != 0xa5 {testing.expect(t, false, "wrote past the output"); return .Invalid_State}
		}
		at += r.consumed
		if r.err != .None {
			return r.err
		}
		if !corrupt {
			if r.produced > len(plain) - produced || !bytes.equal(output[:r.produced], plain[produced:][:r.produced]) {
				testing.expectf(t, false, "output differs after %d bytes", produced)
				return .Invalid_State
			}
		}
		for &v in output {v = 0xa5}
		produced += r.produced
		switch r.status {
		case .Done:
			if !corrupt {
				testing.expect_value(t, at, stream)
				testing.expect_value(t, produced, len(plain))
				testing.expect(t, d.encoded_bytes == u64(at) && d.decoded_bytes == u64(produced))
			}
			return .None
		case .Need_Input:
			if r.consumed != in_n {
				testing.expect(t, false, "Need_Input with input left")
				return .Invalid_State
			}
			if final {
				testing.expect(t, false, "Need_Input after final input")
				return .Invalid_State
			}
		case .Need_Output:
			if r.produced != out_n {
				testing.expect(t, false, "Need_Output with room left")
				return .Invalid_State
			}
		case .Progress:
		}
	}
	testing.expect(t, false, "decoder did not finish")
	return .Invalid_State
}

@(test)
step_inflate_matches_deflate_across_random_step_boundaries :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Minute)
	arena := make([]u8, 70_000 + 2 * GUARD); defer delete(arena)
	state := u64(0x2545f4914f6cdd1d)
	levels := [?]deflate.Deflate_Level{.Stored, .Level_1, .Default, .Best}
	for kind in Corpus {
		plain := make_corpus(kind, 400_000 + int(kind) * 12_345, 0x9e3779b97f4a7c15 + u64(kind))
		defer delete(plain)
		for level in levels {
			wire: [dynamic]u8; defer delete(wire)
			if !testing.expect(t, deflate.compress_raw(&wire, plain, level) == nil) {
				return
			}
			// Bytes that follow the stream belong to someone else.
			tail := 16
			for i in 0 ..< tail {append(&wire, u8(0xf0 + i))}
			stream := len(wire) - tail
			for _ in 0 ..< 3 {
				e := drive_raw(t, wire[:], plain, tail, &state, arena)
				if !testing.expectf(t, e == .None, "%v at %v: %v", kind, level, e) {
					return
				}
			}
			// Each ceiling is exact: enough is enough, one byte less is refused.
			testing.expect_value(t, drive_raw(t, wire[:], plain, tail, &state, arena, u64(stream), u64(len(plain))), step.Decode_Error.None)
			testing.expect_value(t, drive_raw(t, wire[:], plain, tail, &state, arena, u64(stream), u64(len(plain) - 1)), step.Decode_Error.Decoded_Limit)
			testing.expect_value(t, drive_raw(t, wire[:], plain, tail, &state, arena, u64(stream - 1), u64(len(plain))), step.Decode_Error.Encoded_Limit)
			// A stream cut anywhere is truncated, never complete and never wrong.
			for _ in 0 ..< 12 {
				cut := int(random(&state) % u64(stream))
				testing.expect_value(t, drive_raw(t, wire[:cut], plain, 0, &state, arena), step.Decode_Error.Truncated)
			}
		}
	}
}

@(test)
step_inflate_survives_corrupt_streams_within_its_buffers :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Minute)
	arena := make([]u8, 70_000 + 2 * GUARD); defer delete(arena)
	state := u64(0x1b873593a5a5a5a5)
	for kind in Corpus {
		plain := make_corpus(kind, 120_000, 77 + u64(kind)); defer delete(plain)
		wire: [dynamic]u8; defer delete(wire)
		if !testing.expect(t, deflate.compress_raw(&wire, plain, .Default) == nil) {
			return
		}
		damaged := make([]u8, len(wire)); defer delete(damaged)
		rejected := 0
		for _ in 0 ..< 250 {
			copy(damaged, wire[:])
			for _ in 0 ..< 1 + int(random(&state) % 4) {
				damaged[random(&state) % u64(len(damaged))] ~= u8(1) << (random(&state) % 8)
			}
			// Any outcome is acceptable except leaving its buffers or not ending;
			// the decoded-byte ceiling bounds what a damaged stream can produce.
			e := drive_raw(t, damaged, plain, 0, &state, arena, u64(len(damaged)), u64(4 * len(plain)), true)
			if e != .None {
				rejected += 1
				testing.expect(t, e == .Malformed || e == .Truncated || e == .Decoded_Limit || e == .Encoded_Limit, "unexpected error kind")
			}
		}
		// Noise is stored, so a flipped bit is usually just a different byte.
		testing.expect(t, kind == .Noise || rejected > 0)
	}
}

@(test)
step_gzip_matches_deflate_for_large_bodies :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Minute)
	state := u64(0x7f4a7c159e3779b9)
	output := make([]u8, 65_536); defer delete(output)
	for kind in Corpus {
		plain := make_corpus(kind, 700_000, 1234 + u64(kind)); defer delete(plain)
		wire: [dynamic]u8; defer delete(wire)
		if !testing.expect(t, deflate.compress_gzip(&wire, plain) == nil) {
			return
		}
		d := new(step.Gzip_Decoder); defer free(d)
		testing.expect_value(t, step.inflate_gzip_decoder_init(d, {u64(len(wire)), u64(len(plain)), 8192, 1}), step.Decode_Error.None)
		at, produced := 0, 0
		done := false
		for _ in 0 ..< 2_000_000 {
			in_n := min(1 + int(random(&state) % 1500), len(wire) - at)
			r := step.inflate_gzip_decoder_step(d, wire[at:][:in_n], output, at + in_n == len(wire), step.DECODE_MAX_WORK)
			if !testing.expect_value(t, r.err, step.Decode_Error.None) {
				return
			}
			if !testing.expect(t, bytes.equal(output[:r.produced], plain[produced:][:r.produced])) {
				return
			}
			at += r.consumed; produced += r.produced
			if r.status == .Done {
				done = true
				break
			}
		}
		testing.expect(t, done && at == len(wire) && produced == len(plain))
	}
}
