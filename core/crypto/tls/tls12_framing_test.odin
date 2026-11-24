package tls

import "core:bytes"
import "core:mem"
import "core:testing"

@(test)
tls12_framing_fragmentation_and_coalesced_tail :: proc(t: ^testing.T) {
	flight := [?]u8{2, 0, 0, 5, 1, 2, 3, 4, 5, 11, 0, 0, 2, 6, 7, 14, 0, 0, 0}
	context.allocator = mem.panic_allocator()
	context.temp_allocator = mem.panic_allocator()
	for chunk in 1 ..= len(flight) {
		storage: [32]u8
		state, e := tls12_framing_init(storage[:])
		testing.expect_value(t, e, .None)
		at, index := 0, 0
		for at < len(flight) {
			end := min(at + chunk, len(flight))
			for at < end {
				consumed, message, error := tls12_framing_push(&state, flight[at:end])
				testing.expect_value(t, error, .None)
				testing.expect(t, consumed > 0)
				at += consumed
				if len(message) > 0 {
					bounds := [4]int{0, 9, 15, 19}
					testing.expect(t, index < 3)
					testing.expect(t, bytes.equal(message, flight[bounds[index]:bounds[index + 1]]))
					// A complete message cannot consume the following one.
					used, again, again_error := tls12_framing_push(&state, flight[at:end])
					testing.expect_value(t, used, 0)
					testing.expect_value(t, again_error, .None)
					testing.expect(t, raw_data(again) == raw_data(message))
					testing.expect_value(t, tls12_framing_next(&state), .None)
					index += 1
				}
			}
		}
		testing.expect_value(t, index, 3)
	}
}

@(test)
tls12_framing_bounds_alias_and_poison :: proc(t: ^testing.T) {
	storage: [16]u8
	state, e := tls12_framing_init(storage[:])
	testing.expect_value(t, e, .None)
	testing.expect_value(t, tls12_framing_next(&state), .Invalid_State)
	original := storage
	consumed, _, alias := tls12_framing_push(&state, storage[:4])
	testing.expect_value(t, alias, .Overlapping_Buffers)
	testing.expect_value(t, consumed, 0)
	testing.expect_value(t, storage, original)
	testing.expect_value(t, state.used, 0)
	input := [?]u8{11, 0xff, 0xff, 0xff, 1, 2, 3, 4}
	n, message, limit := tls12_framing_push(&state, input[:])
	testing.expect_value(t, n, 4)
	testing.expect_value(t, len(message), 0)
	testing.expect_value(t, limit, .Message_Oversized)
	after := storage
	n2, _, poison := tls12_framing_push(&state, input[4:])
	testing.expect_value(t, n2, 0)
	testing.expect_value(t, poison, .Message_Oversized)
	testing.expect_value(t, storage, after)
	testing.expect_value(t, tls12_framing_next(&state), .Invalid_State)
	_, small := tls12_framing_init(storage[:3])
	testing.expect_value(t, small, .Invalid_State)
	bad := TLS12_Handshake_Framer {
		storage = storage[:],
		used    = 5,
	}
	_, _, invalid := tls12_framing_push(&bad, input[:])
	testing.expect_value(t, invalid, .Invalid_State)
	_, _, nil_error := tls12_framing_push(nil, input[:])
	testing.expect_value(t, nil_error, .Invalid_State)
}

@(test)
tls12_framing_exact_capacity_and_input_independence :: proc(t: ^testing.T) {
	storage: [8]u8
	input := [?]u8{11, 0, 0, 4, 1, 2, 3, 4, 14, 0, 0, 0}
	state, e := tls12_framing_init(storage[:])
	testing.expect_value(t, e, .None)
	consumed, message, error := tls12_framing_push(&state, input[:])
	testing.expect_value(t, error, .None)
	testing.expect_value(t, consumed, 8)
	testing.expect(t, bytes.equal(message, input[:8]))
	for &b in input[:] {b = 0}
	testing.expect_value(t, message[4], u8(1))
	testing.expect_value(t, tls12_framing_next(&state), .None)
	_, _, empty := tls12_framing_push(&state, nil)
	testing.expect_value(t, empty, .None)
	// A fragmented header is retained; the caller's source can disappear.
	prefix := [?]u8{14, 0}
	_, partial, pe := tls12_framing_push(&state, prefix[:])
	testing.expect_value(t, pe, .None)
	testing.expect_value(t, len(partial), 0)
	prefix = {}
	suffix := [?]u8{0, 0}
	_, complete, ce := tls12_framing_push(&state, suffix[:])
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, len(complete), 4)
	testing.expect_value(t, complete[0], u8(14))
}

@(test)
tls12_framing_maximum_flight_and_capacity_rejection :: proc(t: ^testing.T) {
	allocator := context.allocator
	storage := make([]u8, MAX_CERTIFICATE_MESSAGE_SIZE + 1)
	defer delete(storage, allocator)
	context.allocator = mem.panic_allocator()
	context.temp_allocator = mem.panic_allocator()
	_, oversized := tls12_framing_init(storage)
	testing.expect_value(t, oversized, .Invalid_State)
	state, e := tls12_framing_init(storage[:MAX_CERTIFICATE_MESSAGE_SIZE])
	testing.expect_value(t, e, .None)
	record: [MAX_PLAINTEXT_SIZE + 4]u8
	remaining := MAX_CERTIFICATE_MESSAGE_SIZE
	first := true
	complete: []u8
	for remaining > 0 {
		for &b in record[:] {b = 0x5a}
		if first {
			body_size := MAX_CERTIFICATE_MESSAGE_SIZE - 4
			record[0], record[1], record[2], record[3] = 11, u8(body_size >> 16), u8(body_size >> 8), u8(body_size)
			first = false
		}
		n := min(MAX_PLAINTEXT_SIZE, remaining)
		provided := n
		if n == remaining {
			copy(record[n:], ([]u8{14, 0, 0, 0}))
			provided += 4
		}
		consumed, message, error := tls12_framing_push(&state, record[:provided])
		testing.expect_value(t, error, .None)
		testing.expect_value(t, consumed, n)
		remaining -= consumed
		if remaining > 0 {
			testing.expect_value(t, len(message), 0)
		} else {
			complete = message
			testing.expect_value(t, len(complete), MAX_CERTIFICATE_MESSAGE_SIZE)
			for b in complete[4:] {testing.expect_value(t, b, u8(0x5a))}
			testing.expect_value(t, tls12_framing_next(&state), .None)
			used, tail, tail_error := tls12_framing_push(&state, record[n:provided])
			testing.expect_value(t, tail_error, .None)
			testing.expect_value(t, used, 4)
			testing.expect(t, bytes.equal(tail, ([]u8{14, 0, 0, 0})))
		}
	}
	// Exactly one byte over the caller's cap is denied from the header alone.
	state, e = tls12_framing_init(storage[:MAX_CERTIFICATE_MESSAGE_SIZE])
	testing.expect_value(t, e, .None)
	body_size := MAX_CERTIFICATE_MESSAGE_SIZE - 3
	record[0], record[1], record[2], record[3] = 11, u8(body_size >> 16), u8(body_size >> 8), u8(body_size)
	before := storage[4]
	used, message, limit := tls12_framing_push(&state, record[:32])
	testing.expect_value(t, limit, .Message_Oversized)
	testing.expect_value(t, used, 4)
	testing.expect_value(t, len(message), 0)
	testing.expect_value(t, storage[4], before)
	forged := TLS12_Handshake_Framer {
		storage  = storage,
		used     = 4,
		expected = 4,
	}
	testing.expect_value(t, tls12_framing_next(&forged), .Invalid_State)
	forged = {
		storage  = storage[:16],
		used     = 0,
		expected = 8,
	}
	_, _, bad := tls12_framing_push(&forged, record[:1])
	testing.expect_value(t, bad, .Invalid_State)
}
