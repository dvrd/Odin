package tests

import "core:net/quic/conn"
import "core:net/quic/harness"
import "core:net/quic/sim"
import "core:testing"

@(private)
many_stream_limits :: proc() -> harness.Limits {
	limits := wide_limits(); limits.max_streams = 1000; limits.recv_max_streams = 1000
	return limits
}

@(private)
has_record :: proc(c: ^conn.Connection, id: u64) -> bool {
	for b in c.bufs {
		if b.used && b.id == id {
			return true
		}
	}
	return false
}

// A real protected packet from the client that the client's model never sent.
@(private)
inject_from_client :: proc(t: ^testing.T, p: ^Pair, content: []u8) -> conn.Error {
	packet := raw_application_packet(t, p, content); defer delete(packet)
	p.client.model.spaces[2].next_send += 1
	return conn.ingest(p.server, i64(p.link.now), p.server.model.path, packet)
}

@(test)
conn_closed_streams_release_their_records_for_new_streams :: proc(t: ^testing.T) {
	p := open_pair(t, many_stream_limits(), false); defer close_pair(p); settle(t, p)
	free := conn.remaining_stream_records(p.client)
	testing.expect_value(t, free, conn.STREAMS)
	got: [16]u8
	// Four times the record table, as request/response pairs and one-way streams.
	for i in 0 ..< 4 * conn.STREAMS {
		id := u64(i) * 4
		testing.expect_value(t, conn.stream_admission(p.client, id), conn.Error.None)
		n, e := conn.write(p.client, id, []u8{'q', u8(i)}, true); testing.expect(t, n == 2 && e == .None)
		n, e = conn.write(p.client, id + 2, []u8{'u', u8(i)}, true); testing.expect(t, n == 2 && e == .None)
		settle(t, p)
		rn, fin, re := conn.read(p.server, id, got[:])
		testing.expect(t, rn == 2 && fin && re == .None && got[1] == u8(i))
		rn, fin, re = conn.read(p.server, id + 2, got[:])
		testing.expect(t, rn == 2 && fin && re == .None && got[0] == 'u')
		n, e = conn.write(p.server, id, []u8{'r', u8(i), '!'}, true); testing.expect(t, n == 3 && e == .None)
		settle(t, p)
		rn, fin, re = conn.read(p.client, id, got[:])
		testing.expect(t, rn == 3 && fin && re == .None && got[1] == u8(i))
		settle(t, p)
		if !testing.expect_value(t, conn.remaining_stream_records(p.client), free) ||
		   !testing.expect_value(t, conn.remaining_stream_records(p.server), free) {
			return
		}
	}
	for c in ([2]^conn.Connection{p.client, p.server}) {
		testing.expect_value(t, conn.stats(c).live_streams, 0)
		testing.expect_value(t, conn.stats(c).retained, 0)
		_, readable := conn.next_readable(c, nil); testing.expect(t, !readable)
	}

	// The table still bounds streams that are open at once.
	next := u64(4 * conn.STREAMS) * 4
	for i in 0 ..< conn.STREAMS {
		_, e := conn.write(p.client, next + u64(i) * 4, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.None)
	}
	testing.expect_value(t, conn.remaining_stream_records(p.client), 0)
	full := next + u64(conn.STREAMS) * 4
	testing.expect_value(t, conn.stream_admission(p.client, full), conn.Error.Capacity)
	_, e := conn.write(p.client, full, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.Capacity)
	// Capacity did not open the stream: it is still the next one.
	testing.expect_value(t, conn.reset_stream_with_error(p.client, next, 7), conn.Error.None)
	settle(t, p)
	testing.expect(t, conn.receive_reset(p.server, next))
	testing.expect_value(t, conn.stop_sending_with_error(p.server, next, 7), conn.Error.None)
	testing.expect_value(t, conn.reset_stream_with_error(p.server, next, 7), conn.Error.None)
	settle(t, p)
	_, _, re := conn.read(p.client, next, got[:]); testing.expect_value(t, re, conn.Error.Protocol)
	settle(t, p)
	testing.expect(t, !has_record(p.client, next) && !has_record(p.server, next))
	_, e = conn.write(p.client, full, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.None)
}

@(test)
conn_stale_frames_for_a_released_stream_are_ignored :: proc(t: ^testing.T) {
	p := open_pair(t, many_stream_limits(), false); defer close_pair(p); settle(t, p)
	got: [16]u8
	n, e := conn.write(p.client, 0, []u8{'a', 'b'}, true); testing.expect(t, n == 2 && e == .None)
	settle(t, p)
	rn, fin, re := conn.read(p.server, 0, got[:]); testing.expect(t, rn == 2 && fin && re == .None)
	n, e = conn.write(p.server, 0, []u8{'c'}, true); testing.expect(t, n == 1 && e == .None)
	settle(t, p)
	rn, fin, re = conn.read(p.client, 0, got[:]); testing.expect(t, rn == 1 && fin && re == .None)
	settle(t, p)
	testing.expect(t, !has_record(p.server, 0) && !has_record(p.client, 0))
	free := conn.remaining_stream_records(p.server)
	limit := p.server.model.recv_max_data; received := p.server.model.recv_data

	// A retransmitted STREAM frame, then RESET_STREAM, MAX_STREAM_DATA and
	// STOP_SENDING, all for the stream that is gone. Even data that would have
	// contradicted the stream is not looked at.
	frame: [64]u8
	at, ok := conn.encode_stream(frame[:], 0, 0, 0, []u8{'a', 'b'}, true); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.None)
	at, ok = conn.encode_stream(frame[:], 0, 0, 0, []u8{'z', 'z', 'z', 'z'}, false); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.None)
	at, ok = conn.encode_reset(frame[:], 0, 0, 2, 9); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.None)
	at, ok = conn.encode_reset(frame[:], 0, 0, 5000, 9); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.None)
	frame[0] = 0x11; frame[1] = 0; at, ok = conn.put_varint(frame[:], 2, 9999); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.None)
	frame[0] = 0x05; frame[1] = 0; frame[2] = 9
	testing.expect_value(t, inject_from_client(t, p, frame[:3]), conn.Error.None)

	testing.expect(t, conn.established(p.server) && !has_record(p.server, 0))
	testing.expect_value(t, conn.remaining_stream_records(p.server), free)
	testing.expect_value(t, conn.stats(p.server).live_streams, 0)
	testing.expect(t, p.server.model.recv_max_data == limit && p.server.model.recv_data == received)
	_, readable := conn.next_readable(p.server, nil); testing.expect(t, !readable)
	testing.expect(t, !conn.receive_reset(p.server, 0))

	// Calls about the closed stream have defined answers and reopen nothing.
	rn, fin, re = conn.read(p.server, 0, got[:]); testing.expect(t, rn == 0 && !fin && re == .None)
	_, e = conn.write(p.server, 0, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.Protocol)
	_, e = conn.write(p.client, 0, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.Protocol)
	testing.expect_value(t, conn.stream_admission(p.client, 0), conn.Error.Protocol)
	for c in ([2]^conn.Connection{p.client, p.server}) {
		testing.expect_value(t, conn.reset_stream_with_error(c, 0, 1), conn.Error.None)
		testing.expect_value(t, conn.stop_sending_with_error(c, 0, 1), conn.Error.None)
		testing.expect(t, !has_record(c, 0))
	}
	// The connection carries on with the next stream.
	n, e = conn.write(p.client, 4, []u8{'n'}, true); testing.expect(t, n == 1 && e == .None)
	settle(t, p)
	rn, fin, re = conn.read(p.server, 4, got[:]); testing.expect(t, rn == 1 && fin && re == .None)
}

@(test)
conn_local_streams_open_in_order_and_peer_streams_open_the_lower_ones :: proc(t: ^testing.T) {
	p := open_pair(t, many_stream_limits(), false); defer close_pair(p); settle(t, p)
	free := conn.remaining_stream_records(p.client)
	// Skipping an ID is refused by name and opens nothing.
	testing.expect_value(t, conn.stream_admission(p.client, 4), conn.Error.Stream_Order)
	_, e := conn.write(p.client, 4, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.Stream_Order)
	testing.expect_value(t, conn.reset_stream_with_error(p.client, 6, 1), conn.Error.Stream_Order)
	testing.expect_value(t, conn.remaining_stream_records(p.client), free)
	// Each kind of stream counts on its own.
	for id in ([]u64{0, 2, 4, 6}) {
		_, e = conn.write(p.client, id, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.None)
	}
	_, e = conn.write(p.server, 3, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.None)
	_, e = conn.write(p.server, 11, []u8{'x'}, false); testing.expect_value(t, e, conn.Error.Stream_Order)

	// The peer's packets can arrive in any order: stream 16 opens 8 and 12 too,
	// so the late frame for 12 is new data, not a stale frame for a closed stream.
	settle(t, p)
	before := conn.remaining_stream_records(p.server)
	frame: [64]u8
	at, ok := conn.encode_stream(frame[:], 0, 16, 0, []u8{'s'}, true); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.None)
	testing.expect_value(t, conn.remaining_stream_records(p.server), before - 3)
	testing.expect(t, has_record(p.server, 8) && has_record(p.server, 12) && has_record(p.server, 16))
	at, ok = conn.encode_stream(frame[:], 0, 12, 0, []u8{'t'}, true); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.None)
	got: [4]u8; rn, fin, re := conn.read(p.server, 12, got[:])
	testing.expect(t, rn == 1 && fin && re == .None && got[0] == 't')
}

@(test)
conn_released_reset_stream_returns_its_unread_connection_credit :: proc(t: ^testing.T) {
	p := open_pair(t, many_stream_limits(), false); defer close_pair(p); settle(t, p)
	data: [200]u8
	n, e := conn.write(p.client, 0, data[:], false); testing.expect(t, n == 200 && e == .None)
	settle(t, p)
	limit := p.server.model.recv_max_data
	// The client abandons the stream; the server never reads the 200 bytes.
	testing.expect_value(t, conn.reset_stream_with_error(p.client, 0, 3), conn.Error.None)
	testing.expect_value(t, conn.stop_sending_with_error(p.client, 0, 3), conn.Error.None)
	settle(t, p)
	testing.expect(t, conn.receive_reset(p.server, 0))
	testing.expect_value(t, conn.stop_sending_with_error(p.server, 0, 3), conn.Error.None)
	testing.expect_value(t, conn.reset_stream_with_error(p.server, 0, 3), conn.Error.None)
	// The MAX_DATA that returns the credit is lost once and sent again.
	lost := false
	for _ in 0 ..< 200 {
		if !has_record(p.server, 0) && p.server.max_data_dirty && !lost {
			sent, se := post(p, p.server, {drop = true}); testing.expect(t, sent > 0 && se == .None)
			lost = true
			continue
		}
		cn, _ := post(p, p.client, {}); sn, _ := post(p, p.server, {})
		testing.expect_value(t, deliver(p, i64(p.link.now)), conn.Error.None)
		if cn == 0 && sn == 0 {
			if p.client.model.max_data == limit + 200 {
				break
			}
			for c in ([2]^conn.Connection{p.client, p.server}) {
				if timer := conn.timer(c, i64(p.link.now)); timer.armed {
					p.link.now = max(p.link.now, sim_tick(timer.at))
					packet: [conn.MAX_DATAGRAM]u8
					if tn, te := conn.on_timeout(c, i64(p.link.now), packet[:]); te == .None && tn > 0 {
						src, dst := endpoint(c, p); _ = sim_send(p, src, dst, packet[:tn])
					}
				}
			}
		}
	}
	testing.expect(t, lost && !has_record(p.server, 0) && !has_record(p.client, 0))
	testing.expect_value(t, p.server.model.recv_max_data, limit + 200)
	testing.expect_value(t, p.client.model.max_data, limit + 200)
}

@(private)
sim_tick :: proc(at: i64) -> sim.Tick {return sim.Tick(at)}
@(private)
sim_send :: proc(p: ^Pair, src, dst: sim.Address, packet: []u8) -> sim.Error {
	return sim.send(&p.link, src, dst, packet, {})
}

@(test)
conn_stream_waiting_for_credit_stays_open_and_keeps_later_streams_in_order :: proc(t: ^testing.T) {
	limits := many_stream_limits(); limits.max_stream_data = 1
	p := open_pair(t, limits, false); defer close_pair(p); settle(t, p)
	_, e := conn.write(p.client, 2, []u8{'a', 'b'}, false); testing.expect_value(t, e, conn.Error.Flow_Control)
	// The blocked stream counts as opened, so the next one is not out of order.
	n: int
	n, e = conn.write(p.client, 6, []u8{'c'}, false); testing.expect(t, n == 1 && e == .None)
	n, e = conn.write(p.client, 2, []u8{'a'}, false); testing.expect(t, n == 1 && e == .None)
	// A stream the peer's stream limit refuses is not opened.
	limits.max_streams = 1
	q := open_pair(t, limits, false); defer close_pair(q); settle(t, q)
	n, e = conn.write(q.client, 0, []u8{'a'}, false); testing.expect(t, n == 1 && e == .None)
	free := conn.remaining_stream_records(q.client)
	_, e = conn.write(q.client, 4, []u8{'a'}, false); testing.expect_value(t, e, conn.Error.Flow_Control)
	testing.expect_value(t, conn.remaining_stream_records(q.client), free)
	testing.expect_value(t, conn.stream_admission(q.client, 4), conn.Error.Flow_Control)
}
