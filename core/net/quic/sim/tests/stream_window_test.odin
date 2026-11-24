package tests

import "core:mem"
import "core:net/quic/conn"
import "core:net/quic/sim"
import "core:testing"
import "core:time"

BULK_WINDOW :: 64 * 1024
BULK_BYTES :: 200_000

@(private)
bulk_windows :: proc() -> conn.Stream_Windows {
	return {send = BULK_WINDOW, recv = BULK_WINDOW, allocator = context.allocator}
}

@(private)
bulk_byte :: proc(seed, i: int) -> u8 {
	return u8((i * 131 + i >> 9 + seed) % 251)
}

@(private)
bulk_random :: proc(state: ^u64) -> u64 {
	state^ ~= state^ << 13; state^ ~= state^ >> 7; state^ ~= state^ << 17
	return state^
}

// One direction of a bulk transfer on stream 0.
@(private)
Bulk_Side :: struct {
	c:               ^conn.Connection,
	seed:            int,
	written, got:    int,
	fin:             bool,
	largest_write:   int,
}

@(private)
bulk_step :: proc(t: ^testing.T, side, other: ^Bulk_Side) {
	chunk: [4096]u8
	for side.written < BULK_BYTES {
		n := min(conn.stream_send_room(side.c, 0), BULK_BYTES - side.written, len(chunk))
		if n == 0 {
			break
		}
		for &v, i in chunk[:n] {v = bulk_byte(side.seed, side.written + i)}
		wn, e := conn.write(side.c, 0, chunk[:n], side.written + n == BULK_BYTES)
		if e == .Flow_Control {
			break
		}
		if !testing.expect(t, e == .None && wn == n) {
			return
		}
		side.written += n; side.largest_write = max(side.largest_write, n)
	}
	for !side.fin {
		n, fin, e := conn.read(side.c, 0, chunk[:])
		if !testing.expect_value(t, e, conn.Error.None) {
			return
		}
		for v, i in chunk[:n] {
			if v != bulk_byte(other.seed, side.got + i) {
				testing.expectf(t, false, "byte %d differs", side.got + i)
				return
			}
		}
		side.got += n; side.fin = fin
		if n == 0 {
			break
		}
	}
}

@(test)
conn_wide_windows_carry_bulk_both_ways_through_loss_and_reordering :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	limits := wide_limits()
	limits.max_stream_data = BULK_WINDOW; limits.recv_max_stream_data = BULK_WINDOW
	p := open_pair(t, limits, false, bulk_windows()); defer close_pair(p); settle(t, p)
	send, recv := conn.stream_windows(p.client)
	testing.expect(t, send == BULK_WINDOW && recv == BULK_WINDOW)

	client := Bulk_Side{c = p.client, seed = 1}; server := Bulk_Side{c = p.server, seed = 2}
	random := u64(0x9e3779b97f4a7c15); packet: [conn.MAX_DATAGRAM]u8
	dropped, delayed, duplicated := 0, 0, 0
	rounds := 0
	for ; rounds < 200_000 && !(client.fin && server.fin); rounds += 1 {
		bulk_step(t, &client, &server); bulk_step(t, &server, &client)
		sent := 0
		for c in ([2]^conn.Connection{p.client, p.server}) {
			for _ in 0 ..< 12 {
				n, e := conn.pump(c, i64(p.link.now), packet[:])
				if !testing.expect(t, e == .None || e == .Congestion, c.reason) {
					return
				}
				if n == 0 {
					break
				}
				sent += 1
				plan: sim.Plan; roll := bulk_random(&random) % 100
				switch {
				case roll < 5:
					plan.drop = true; dropped += 1
				case roll < 20:
					plan.delay = sim.Tick(1 + bulk_random(&random) % 30); delayed += 1
				case roll < 23:
					plan.duplicate = true; plan.duplicate_delay = sim.Tick(bulk_random(&random) % 10)
					duplicated += 1
				}
				src, dst := endpoint(c, p)
				// A full link is one more loss.
				_ = sim.send(&p.link, src, dst, packet[:n], plan)
			}
		}
		until := i64(p.link.now) + 1
		if sent == 0 && p.link.stats.packets == 0 {
			// Nothing moves until a timer does.
			for c in ([2]^conn.Connection{p.client, p.server}) {
				if timer := conn.timer(c, i64(p.link.now)); timer.armed && timer.at > until {
					until = timer.at
				}
			}
		}
		if e := deliver(p, until); e != .None {
			testing.expectf(t, false, "round %d: %v, client %q, server %q", rounds, e, p.client.reason, p.server.reason)
			return
		}
		for c in ([2]^conn.Connection{p.client, p.server}) {
			timer := conn.timer(c, i64(p.link.now))
			if !timer.armed || timer.at > i64(p.link.now) {
				continue
			}
			n, e := conn.on_timeout(c, i64(p.link.now), packet[:])
			if !testing.expect(t, e == .None || e == .Congestion, c.reason) {
				return
			}
			if n > 0 {
				src, dst := endpoint(c, p)
				_ = sim.send(&p.link, src, dst, packet[:n], {})
			}
		}
	}
	testing.expect(t, client.fin && server.fin, "transfer did not finish")
	testing.expect_value(t, client.got, BULK_BYTES); testing.expect_value(t, server.got, BULK_BYTES)
	testing.expect(t, dropped > 20 && delayed > 60 && duplicated > 10)
	// One write took far more than the old 256-byte window.
	testing.expect(t, client.largest_write > conn.STREAM_BYTES && server.largest_write > conn.STREAM_BYTES)
	// Let the last acknowledgments land; every block then returns to the pool.
	for _ in 0 ..< 64 {
		for c in ([2]^conn.Connection{p.client, p.server}) {
			if n, e := conn.pump(c, i64(p.link.now), packet[:]); e == .None && n > 0 {
				src, dst := endpoint(c, p); _ = sim.send(&p.link, src, dst, packet[:n], {})
			}
		}
		testing.expect_value(t, deliver(p, i64(p.link.now) + 30), conn.Error.None)
	}
	for c in ([2]^conn.Connection{p.client, p.server}) {
		testing.expect_value(t, c.streams.held[.Send], 0)
		testing.expect_value(t, c.streams.held[.Recv], 0)
		testing.expect_value(t, conn.stats(c).retained, 0)
	}
}

@(private)
adopt_from :: proc(p: ^Pair, windows: conn.Stream_Windows, recv_max_stream_data: u64) -> conn.Adopt_Config {
	limits := wide_limits(); limits.recv_max_stream_data = recv_max_stream_data
	return {
		role = .Client,
		local_cid = p.client.local_cid[:p.client.local_cid_len],
		peer_cid = p.client.peer_cid[:p.client.peer_cid_len],
		limits = limits,
		next_send_pn = p.client.model.spaces[2].next_send,
		windows = windows,
	}
}

@(test)
conn_adoption_sizes_windows_from_config_and_default_allocates_nothing :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false); defer close_pair(p); settle(t, p)
	candidate := new(conn.Connection); defer free(candidate)
	wide := conn.Stream_Windows{send = BULK_WINDOW, recv = BULK_WINDOW}

	// A window above the embedded one needs an allocator, and the advertised
	// stream credit must fit the receive window. Neither failure moves the keys.
	testing.expect_value(t, conn.adopt_established(candidate, &p.client.hs, adopt_from(p, wide, BULK_WINDOW)), conn.Error.Invalid)
	wide.allocator = context.allocator
	testing.expect_value(t, conn.adopt_established(candidate, &p.client.hs, adopt_from(p, wide, BULK_WINDOW + 1)), conn.Error.Invalid)
	testing.expect_value(t, conn.adopt_established(candidate, &p.client.hs, adopt_from(p, {send_pool = 4096}, 256)), conn.Error.Invalid)
	testing.expect(t, p.client.hs.have_one_rtt && !candidate.initialized)

	// A shared pool smaller than every stream's full window: one stream can
	// fill its window, the next is refused until bytes are acknowledged.
	wide.send_pool = BULK_WINDOW
	testing.expect_value(t, conn.adopt_established(candidate, &p.client.hs, adopt_from(p, wide, BULK_WINDOW)), conn.Error.None)
	testing.expect(t, !p.client.hs.have_one_rtt && candidate.streams.heap)
	send, recv := conn.stream_windows(candidate)
	testing.expect(t, send == BULK_WINDOW && recv == BULK_WINDOW)
	previous := context.allocator; context.allocator = mem.panic_allocator()
	data := make([]u8, BULK_WINDOW + 1, previous); defer delete(data, previous)
	for &v, i in data {v = bulk_byte(3, i)}
	testing.expect_value(t, conn.stream_send_room(candidate, 0), BULK_WINDOW)
	n, e := conn.write(candidate, 0, data, false)
	testing.expect(t, n == 0 && e == .Capacity)
	n, e = conn.write(candidate, 0, data[:BULK_WINDOW], false)
	testing.expect(t, n == BULK_WINDOW && e == .None)
	testing.expect_value(t, conn.stream_send_room(candidate, 0), 0)
	testing.expect_value(t, conn.stream_send_room(candidate, 4), conn.POOL_BLOCK)
	n, e = conn.write(candidate, 4, data[:conn.POOL_BLOCK + 1], false)
	testing.expect(t, n == 0 && e == .Capacity)
	n, e = conn.write(candidate, 4, data[:conn.POOL_BLOCK], false)
	testing.expect(t, n == conn.POOL_BLOCK && e == .None)
	// The first packet carries a datagram's worth, not 256 bytes.
	packet: [conn.MAX_DATAGRAM]u8
	pn, pe := conn.pump(candidate, i64(p.link.now), packet[:])
	testing.expect(t, pe == .None && pn > 1000 && pn <= 1200)
	context.allocator = previous
	conn.destroy(candidate)

	// The default takes nothing from any allocator and keeps the old bound.
	q := open_pair(t, wide_limits(), false); defer close_pair(q); settle(t, q)
	context.allocator = mem.panic_allocator()
	testing.expect_value(t, conn.adopt_established(candidate, &q.client.hs, adopt_from(q, {}, 256)), conn.Error.None)
	send, recv = conn.stream_windows(candidate)
	testing.expect(t, send == conn.STREAM_BYTES && recv == conn.STREAM_BYTES && !candidate.streams.heap)
	n, e = conn.write(candidate, 0, data[:conn.STREAM_BYTES + 1], false)
	testing.expect(t, n == 0 && e == .Capacity)
	n, e = conn.write(candidate, 0, data[:conn.STREAM_BYTES], false)
	testing.expect(t, n == conn.STREAM_BYTES && e == .None)
	conn.destroy(candidate)
	context.allocator = previous
}
