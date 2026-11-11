package tests

import "core:bytes"
import "core:mem"
import "core:net/quic"
import "core:net/quic/sim"
import "core:testing"

@(test)
packet_first_tie_and_invalid_storage :: proc(t: ^testing.T) {
	p: [1]sim.Packet_Slot
	b: [8]u8
	timers: [1]sim.Timer_Slot
	link: sim.Link
	owner := (cast([^]u8)&link)[:size_of(link)]
	testing.expect_value(t, sim.init(&link, p[:], owner, len(owner), timers[:]), .Overlap)
	timer_bytes := mem.slice_to_bytes(timers[:])
	testing.expect_value(
		t,
		sim.init(&link, p[:], timer_bytes, len(timer_bytes), timers[:]),
		.Overlap,
	)
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:]), .None)
	defer sim.destroy(&link)
	testing.expect_value(
		t,
		sim.send(&link, {}, {}, nil, {drop = true, duplicate = true}),
		.Invalid_Time,
	)
	testing.expect_value(t, sim.send(&link, {}, {}, nil, {duplicate_delay = 1}), .Invalid_Time)
	testing.expect_value(t, sim.send(&link, {}, {}, nil), .None)
	_, e := sim.schedule(&link, 1, 0)
	testing.expect_value(t, e, .None)
	packet, ok, se := sim.step(&link, 0, nil)
	testing.expect(t, ok && se == .None && packet.kind == .Datagram)
	timer, ok2, se2 := sim.step(&link, 0, nil)
	testing.expect(
		t,
		ok2 && se2 == .None && timer.kind == .Timer && timer.sequence > packet.sequence,
	)
}

@(test)
codec_retransmission_driver :: proc(t: ^testing.T) {
	packets: [4]sim.Packet_Slot
	timers: [1]sim.Timer_Slot
	storage: [4 * 64]u8
	link: sim.Link
	testing.expect_value(t, sim.init(&link, packets[:], storage[:], 64, timers[:]), .None)
	defer sim.destroy(&link)
	// Real v1 header datagrams, with deliberately unauthenticated fake payload:
	// this driver checks link/codec integration, not a QUIC connection handshake.
	wire: [64]u8
	cid := []u8{1, 2, 3}
	n, _, error := quic.long_header_encode_v1(
		wire[:],
		{kind = .Initial, destination_id = cid, packet_number_length = 1, ciphertext_length = 16},
	)
	testing.expect_value(t, error, .None)
	for &b in wire[n:n + 16] {b = 42}
	client, server := sim.Address {
			peer = 1,
			path = 100,
		}, sim.Address {
			peer = 2,
			path = 200,
		}
	testing.expect_value(t, sim.send(&link, client, server, wire[:n + 16], {drop = true}), .None)
	retry, te := sim.schedule(&link, client.peer, 10, tag = 77)
	testing.expect_value(t, te, .None)
	out: [64]u8
	event, ok, se := sim.step(&link, 10, out[:])
	testing.expect(
		t,
		se == .None && ok && event.kind == .Timer && event.tag == 77 && event.timer == retry,
	)
	testing.expect(t, !sim.cancel(&link, retry))
	// A retransmission is duplicated; the later-enqueued copy arrives first.
	testing.expect_value(
		t,
		sim.send(
			&link,
			client,
			server,
			wire[:n + 16],
			{delay = 5, duplicate = true, duplicate_delay = 2},
		),
		.None,
	)
	deadline, de := sim.schedule(&link, 1, 30)
	testing.expect_value(t, de, .None)
	for tick in ([?]sim.Tick{12, 15}) {
		event, ok, se = sim.step(&link, tick, out[:])
		testing.expect(t, se == .None && ok && event.kind == .Datagram && event.at == tick)
		packet, consumed, pe := quic.packet_decode_v1(out[:event.size])
		testing.expect(
			t,
			pe == .None &&
			consumed == event.size &&
			packet.kind == .Initial &&
			bytes.equal(packet.invariant.destination_id, cid),
		)
		testing.expect(t, event.source == client && event.destination == server)
	}
	testing.expect(t, sim.cancel(&link, deadline))
	_, ok, se = sim.step(&link, 100, out[:])
	s := sim.stats(&link)
	testing.expect(
		t,
		!ok &&
		se == .None &&
		sim.now(&link) == 100 &&
		s.packets == 0 &&
		s.bytes == 0 &&
		s.timers == 0,
	)
	testing.expect(t, s.peak_packets == 2 && s.peak_timers == 1)
}

@(test)
stale_and_foreign_timer_handles :: proc(t: ^testing.T) {
	p: [1]sim.Packet_Slot; b: [8]u8; timers: [1]sim.Timer_Slot; link: sim.Link
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:]), .None)
	defer sim.destroy(&link)
	old, e := sim.schedule(&link, 9, 1); testing.expect_value(t, e, .None)
	testing.expect(t, sim.cancel(&link, old))
	newer, e2 := sim.schedule(&link, 9, 2); testing.expect_value(t, e2, .None)
	testing.expect(
		t,
		newer.slot == old.slot && newer.generation != old.generation && !sim.cancel(&link, old),
	)
	other_p: [1]sim.Packet_Slot; other_b: [8]u8; other_t: [1]sim.Timer_Slot; other: sim.Link
	testing.expect_value(t, sim.init(&other, other_p[:], other_b[:], 8, other_t[:]), .None)
	defer sim.destroy(&other)
	other_handle, fe := sim.schedule(&other, 9, 2); testing.expect_value(t, fe, .None)
	testing.expect(t, !sim.cancel(&link, other_handle))
	sim.clear(&link)
	newest, e3 := sim.schedule(&link, 9, 3, tag = 11); testing.expect_value(t, e3, .None)
	testing.expect(t, !sim.cancel(&link, newer) && newest.generation != newer.generation)
	event, ok, se := sim.step(&link, 3, nil)
	testing.expect(
		t,
		ok &&
		se == .None &&
		event.timer == newest &&
		event.tag == 11 &&
		event.destination.peer == 9,
	)
	testing.expect(t, !sim.cancel(&link, newest))
}

@(test)
atomic_capacity_and_delivery_retry :: proc(t: ^testing.T) {
	p: [2]sim.Packet_Slot; b: [16]u8; timers: [1]sim.Timer_Slot; link: sim.Link
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:]), .None)
	defer sim.destroy(&link)
	data := []u8{1, 2, 3, 4}
	testing.expect_value(t, sim.send(&link, {peer = 1}, {peer = 2}, data, {delay = 5}), .None)
	before := sim.stats(&link)
	testing.expect_value(
		t,
		sim.send(&link, {peer = 1}, {peer = 2}, data, {duplicate = true}),
		.Capacity,
	)
	testing.expect_value(t, sim.stats(&link), before)
	event, ok, e := sim.step(&link, 10, data[:1])
	testing.expect(
		t,
		!ok && e == .Destination_Undersized && event.size == 4 && sim.now(&link) == 0,
	)
	testing.expect_value(t, sim.stats(&link), before)
	_, ok, e = sim.step(&link, 10, b[:])
	testing.expect(t, !ok && e == .Overlap && sim.now(&link) == 0)
	out: [8]u8; event, ok, e = sim.step(&link, 10, out[:])
	testing.expect(t, ok && e == .None && event.at == 5 && bytes.equal(out[:4], data))
	testing.expect_value(t, sim.send(&link, {}, {}, b[:1]), .Overlap)
	testing.expect_value(
		t,
		sim.send(&link, {}, {}, []u8{0, 1, 2, 3, 4, 5, 6, 7, 8}),
		.Packet_Too_Large,
	)
	_, e = sim.schedule(&link, 1, 6); testing.expect_value(t, e, .None)
	_, e = sim.schedule(&link, 1, 6); testing.expect_value(t, e, .Capacity)
}

Trace :: struct {
	at:       sim.Tick,
	sequence: u64,
	kind:     sim.Event_Kind,
	path:     u32,
	byte:     u8,
	tag:      u64,
}
replay :: proc(t: ^testing.T, dst: []Trace) {
	p: [4]sim.Packet_Slot; b: [32]u8; timers: [2]sim.Timer_Slot; link: sim.Link
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:]), .None)
	defer sim.destroy(&link)
	_, e := sim.schedule(&link, 2, 5, tag = 99); testing.expect_value(t, e, .None)
	for path, i in ([?]u32{100, 101, 102}) {
		byte := [1]u8{u8(i + 1)}
		testing.expect_value(
			t,
			sim.send(
				&link,
				{peer = 1, path = path},
				{peer = 2},
				byte[:],
				{delay = sim.Tick(8 - i * 2)},
			),
			.None,
		)
		byte[0] = 255 // Send copied source storage; no caller borrow is retained.
	}
	zero: []u8
	testing.expect_value(t, sim.send(&link, {}, {}, zero, {delay = 5}), .None)
	buffer: [8]u8
	for &entry in dst {
		event, ok, se := sim.step(&link, 20, buffer[:]); testing.expect(t, ok && se == .None)
		entry = {
			at       = event.at,
			sequence = event.sequence,
			kind     = event.kind,
			path     = event.source.path,
			tag      = event.tag,
		}
		if event.size > 0 {
			entry.byte = buffer[0]
		}
	}
	_, ok, se := sim.step(&link, 20, nil); testing.expect(t, !ok && se == .None)
}

@(test)
replay_and_address_change :: proc(t: ^testing.T) {
	a, b: [5]Trace
	replay(t, a[:]); replay(t, b[:])
	for entry, i in a {testing.expect_value(t, entry, b[i])}
	testing.expect(t, a[0].at == 4 && a[0].path == 102 && a[0].byte == 3)
	testing.expect(t, a[1].at == 5 && a[1].kind == .Timer && a[1].tag == 99)
	testing.expect(t, a[2].at == 5 && a[2].kind == .Datagram && a[1].sequence < a[2].sequence)
	testing.expect(t, a[3].path == 101 && a[4].path == 100)
}

@(test)
invalid_configuration_and_time :: proc(t: ^testing.T) {
	p: [1]sim.Packet_Slot; b: [8]u8; timers: [1]sim.Timer_Slot; link: sim.Link
	testing.expect_value(t, sim.init(nil, p[:], b[:], 8, timers[:]), .Invalid_State)
	testing.expect_value(t, sim.init(&link, p[:], b[:], 0, timers[:]), .Invalid_Config)
	testing.expect_value(t, sim.init(&link, p[:], b[:7], 8, timers[:]), .Invalid_Config)
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:], -1), .Invalid_Config)
	testing.expect_value(
		t,
		sim.init(&link, p[:], mem.slice_to_bytes(p[:]), size_of(sim.Packet_Slot), timers[:]),
		.Overlap,
	)
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:], 10), .None)
	defer sim.destroy(&link)
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:]), .Invalid_State)
	_, e := sim.schedule(&link, 1, 9); testing.expect_value(t, e, .Invalid_Time)
	testing.expect_value(t, sim.send(&link, {}, {}, nil, {delay = -1}), .Invalid_Time)
	testing.expect_value(t, sim.send(&link, {}, {}, nil, {delay = max(sim.Tick)}), .Invalid_Time)
	_, ok, se := sim.step(&link, 9, nil)
	testing.expect(t, !ok && se == .Invalid_Time && sim.now(&link) == 10)
	sim.destroy(&link)
	testing.expect_value(t, sim.send(&link, {}, {}, nil), .Invalid_State)
	_, e = sim.schedule(&link, 1, 10); testing.expect_value(t, e, .Invalid_State)
}

@(test)
fixed_storage_under_long_run :: proc(t: ^testing.T) {
	context.allocator = mem.nil_allocator(); context.temp_allocator = mem.nil_allocator()
	p: [2]sim.Packet_Slot; b: [32]u8; timers: [1]sim.Timer_Slot; link: sim.Link
	assert(sim.init(&link, p[:], b[:], 16, timers[:]) == .None)
	defer sim.destroy(&link)
	for i in 0 ..< 10000 {
		byte := [1]u8{u8(i % 256)}
		assert(
			sim.send(&link, {peer = 1, path = u32(i)}, {peer = 2}, byte[:], {duplicate = true}) ==
			.None,
		)
		timer, error := sim.schedule(&link, 1, sim.now(&link) + 1); assert(error == .None)
		assert(sim.cancel(&link, timer))
		for _ in 0 ..< 2 {
			out: [16]u8; event, ok, error := sim.step(&link, sim.now(&link) + 1, out[:])
			assert(ok && error == .None && event.source.path == u32(i) && out[0] == byte[0])
		}
	}
	s := sim.stats(&link)
	assert(
		s.packets == 0 &&
		s.bytes == 0 &&
		s.timers == 0 &&
		s.peak_packets == 2 &&
		s.peak_bytes == 2 &&
		s.peak_timers == 1,
	)
	_ = t
}

@(test)
exhaustion_never_reuses_identifiers :: proc(t: ^testing.T) {
	p: [2]sim.Packet_Slot; b: [16]u8; timers: [1]sim.Timer_Slot; link: sim.Link
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:]), .None)
	defer sim.destroy(&link)
	// Set the caller-owned storage near its integer boundaries rather than
	// relying on an impractically long run to reach wraparound.
	timers[0].generation = max(u64) - 1
	last, e := sim.schedule(&link, 1, 0)
	testing.expect(t, e == .None && last.generation == max(u64))
	testing.expect(t, sim.cancel(&link, last))
	_, e = sim.schedule(&link, 1, 0); testing.expect_value(t, e, .Capacity)
	link.sequence = max(u64) - 1
	testing.expect_value(t, sim.send(&link, {}, {}, nil, {duplicate = true}), .Exhausted)
	testing.expect_value(t, sim.stats(&link).packets, 0)
	testing.expect_value(t, sim.send(&link, {}, {}, nil), .None)
	event, ok, se := sim.step(&link, max(sim.Tick), nil)
	testing.expect(t, ok && se == .None && event.sequence == max(u64))
	_, ok, se = sim.step(&link, max(sim.Tick), nil)
	testing.expect(t, !ok && se == .None)
	testing.expect_value(t, sim.send(&link, {}, {}, nil, {delay = 1}), .Invalid_Time)
	testing.expect_value(t, sim.send(&link, {}, {}, nil), .Exhausted)
}

@(test)
allocation_failure_injection :: proc(t: ^testing.T) {
	p: [2]sim.Packet_Slot
	b: [16]u8
	timers: [1]sim.Timer_Slot
	link: sim.Link
	testing.expect_value(t, sim.init(&link, p[:], b[:], 8, timers[:]), .None)
	defer sim.destroy(&link)
	testing.expect_value(t, sim.inject_allocation_failure(nil, 1), .Invalid_State)
	testing.expect_value(t, sim.inject_allocation_failure(&link, -1), .Invalid_State)
	testing.expect_value(t, sim.inject_allocation_failure(&link, 1), .None)
	testing.expect_value(t, sim.send(&link, {}, {}, nil, {drop = true}), .None)
	testing.expect_value(t, link.fail_allocations, 1)
	testing.expect_value(t, sim.send(&link, {}, {}, nil, {delay = -1}), .Invalid_Time)
	testing.expect_value(t, link.fail_allocations, 1)
	testing.expect_value(t, sim.send(&link, {}, {}, []u8{1, 2}), .Allocation)
	testing.expect(t, link.fail_allocations == 0 && sim.stats(&link).packets == 0 && sim.stats(&link).bytes == 0)
	testing.expect_value(t, sim.send(&link, {}, {}, []u8{1, 2}), .None)
	out: [8]u8
	event, ok, se := sim.step(&link, 0, out[:])
	testing.expect(t, ok && se == .None && event.size == 2 && out[0] == 1 && out[1] == 2)

	testing.expect_value(t, sim.inject_allocation_failure(&link, 1), .None)
	testing.expect_value(t, sim.send(&link, {}, {}, []u8{3}, {duplicate = true, duplicate_delay = 1}), .Allocation)
	testing.expect(t, sim.stats(&link).packets == 0 && link.fail_allocations == 0)
	_, e := sim.schedule(&link, 1, 0)
	testing.expect_value(t, e, .None)
	testing.expect_value(t, sim.inject_allocation_failure(&link, 1), .None)
	_, e = sim.schedule(&link, 1, 1)
	testing.expect(t, e == .Allocation && sim.stats(&link).timers == 1 && link.fail_allocations == 0)
	sim.clear(&link)
	testing.expect(t, link.fail_allocations == 0 && sim.stats(&link).timers == 0 && sim.now(&link) == 0)
	testing.expect_value(t, sim.inject_allocation_failure(&link, 4), .None)
	sim.clear(&link)
	testing.expect_value(t, link.fail_allocations, 4)
	sim.destroy(&link)
	testing.expect_value(t, link.fail_allocations, 0)
	testing.expect_value(t, sim.inject_allocation_failure(&link, 1), .Invalid_State)
}
