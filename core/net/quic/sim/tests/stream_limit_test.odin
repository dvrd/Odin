package tests

import "core:net/quic/conn"
import "core:net/quic/harness"
import "core:net/quic/sim"
import "core:testing"

@(private)
four_stream_limits :: proc() -> harness.Limits {
	limits := wide_limits(); limits.max_streams = 4; limits.recv_max_streams = 4
	return limits
}

// One round of traffic. When nothing moves, the earliest timer fires.
@(private)
pair_round :: proc(t: ^testing.T, p: ^Pair) {
	cn, ce := post(p, p.client, {}); sn, se := post(p, p.server, {})
	testing.expect(t, (ce == .None || ce == .Congestion) && (se == .None || se == .Congestion))
	testing.expect_value(t, deliver(p, i64(p.link.now)), conn.Error.None)
	if cn != 0 || sn != 0 {
		return
	}
	packet: [conn.MAX_DATAGRAM]u8
	for c in ([2]^conn.Connection{p.client, p.server}) {
		timer := conn.timer(c, i64(p.link.now)); if !timer.armed {
			continue
		}
		p.link.now = max(p.link.now, sim.Tick(timer.at))
		if n, e := conn.on_timeout(c, i64(p.link.now), packet[:]); e == .None && n > 0 {
			src, dst := endpoint(c, p); _ = sim.send(&p.link, src, dst, packet[:n], {})
		}
	}
}

// A request and response on a client bidirectional stream, read to the end.
@(private)
exchange :: proc(t: ^testing.T, p: ^Pair, id: u64) -> bool {
	got: [8]u8
	n, e := conn.write(p.client, id, []u8{'q'}, true)
	if !testing.expect(t, n == 1 && e == .None) {
		return false
	}
	settle(t, p)
	rn, fin, re := conn.read(p.server, id, got[:]); testing.expect(t, rn == 1 && fin && re == .None)
	n, e = conn.write(p.server, id, []u8{'r'}, true); testing.expect(t, n == 1 && e == .None)
	settle(t, p)
	rn, fin, re = conn.read(p.client, id, got[:]); testing.expect(t, rn == 1 && fin && re == .None)
	return true
}

@(test)
conn_stream_limit_is_for_life_unless_the_caller_asks_to_raise_it :: proc(t: ^testing.T) {
	p := open_pair(t, four_stream_limits(), false); defer close_pair(p); settle(t, p)
	for i in 0 ..< 4 {
		if !exchange(t, p, u64(i) * 4) {
			return
		}
	}
	settle(t, p)
	// Every record is free again, yet no MAX_STREAMS is sent and none is due.
	testing.expect_value(t, conn.remaining_stream_records(p.server), conn.STREAMS)
	testing.expect(t, p.server.recv_streams == [2]u64{4, 4} && p.server.max_streams_dirty == {})
	testing.expect_value(t, conn.stream_admission(p.client, 16), conn.Error.Flow_Control)
	_, e := conn.write(p.client, 16, []u8{'q'}, true); testing.expect_value(t, e, conn.Error.Flow_Control)
	// A peer that opens a fifth stream anyway exceeds the limit.
	frame: [16]u8; at, ok := conn.encode_stream(frame[:], 0, 16, 0, []u8{'q'}, true); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.Flow_Control)
}

@(test)
conn_max_streams_is_emitted_lost_and_retransmitted :: proc(t: ^testing.T) {
	p := open_pair(t, four_stream_limits(), false, {}, true); defer close_pair(p); settle(t, p)
	// Use up the four streams; finish only the first.
	for id in ([]u64{0, 4, 8, 12}) {
		_, e := conn.write(p.client, id, nil, false); testing.expect_value(t, e, conn.Error.None)
	}
	testing.expect_value(t, conn.stream_admission(p.client, 16), conn.Error.Flow_Control)
	got: [8]u8
	n, e := conn.write(p.client, 0, []u8{'q'}, true); testing.expect(t, n == 1 && e == .None)
	settle(t, p)
	rn, fin, re := conn.read(p.server, 0, got[:]); testing.expect(t, rn == 1 && fin && re == .None)
	n, e = conn.write(p.server, 0, []u8{'r'}, true); testing.expect(t, n == 1 && e == .None)
	// The client's acknowledgment of the response releases the server's record
	// and makes MAX_STREAMS due. Lose the packet that carries it.
	lost := false
	for _ in 0 ..< 200 {
		if p.server.max_streams_dirty[0] && !lost {
			testing.expect_value(t, p.server.recv_streams[0], 5)
			sent, se := post(p, p.server, {drop = true}); testing.expect(t, sent > 0 && se == .None)
			testing.expect(t, !p.server.max_streams_dirty[0])
			lost = true
			// The client has not heard of it.
			testing.expect_value(t, conn.stream_admission(p.client, 16), conn.Error.Flow_Control)
			continue
		}
		if lost && conn.stream_admission(p.client, 16) == .None {
			break
		}
		_, _, _ = conn.read(p.client, 0, got[:])
		pair_round(t, p)
	}
	testing.expect(t, lost, "MAX_STREAMS never became due")
	testing.expect_value(t, conn.stream_admission(p.client, 16), conn.Error.None)
	// Only the bidirectional limit moved, and only by the one closed stream.
	testing.expect(t, p.server.recv_streams == [2]u64{5, 4})
	testing.expect_value(t, conn.stream_admission(p.client, 20), conn.Error.Stream_Order)
	if !exchange(t, p, 16) {
		return
	}
}

@(test)
conn_raised_stream_limits_carry_many_streams_of_both_kinds :: proc(t: ^testing.T) {
	p := open_pair(t, four_stream_limits(), false, {}, true); defer close_pair(p); settle(t, p)
	got: [8]u8
	for i in 0 ..< 3 * conn.STREAMS {
		id := u64(i) * 4
		for round := 0; round < 400 && conn.stream_admission(p.client, id) != .None; round += 1 {
			pair_round(t, p)
		}
		if !exchange(t, p, id) {
			return
		}
		// One-way streams from each side have their own limit.
		n, e := conn.write(p.client, id + 2, []u8{'u'}, true); testing.expect(t, n == 1 && e == .None, "client uni")
		n, e = conn.write(p.server, id + 3, []u8{'v'}, true); testing.expect(t, n == 1 && e == .None, "server uni")
		settle(t, p)
		rn, fin, re := conn.read(p.server, id + 2, got[:]); testing.expect(t, rn == 1 && fin && re == .None)
		rn, fin, re = conn.read(p.client, id + 3, got[:]); testing.expect(t, rn == 1 && fin && re == .None)
		settle(t, p)
		if !testing.expect(t, p.server.recv_streams == [2]u64{u64(i) + 5, u64(i) + 5}) ||
		   !testing.expect(t, p.client.recv_streams == [2]u64{4, u64(i) + 5}) {
			return
		}
	}
	// The peer never had more than four of a kind open, and may not now.
	frame: [16]u8; next := u64(3 * conn.STREAMS)
	at, ok := conn.encode_stream(frame[:], 0, (next + 4) * 4, 0, []u8{'q'}, true); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.Flow_Control)
	at, ok = conn.encode_stream(frame[:], 0, (next + 3) * 4, 0, []u8{'q'}, true); assert(ok)
	testing.expect_value(t, inject_from_client(t, p, frame[:at]), conn.Error.None)
	testing.expect_value(t, conn.remaining_stream_records(p.server), conn.STREAMS - 4)
}
