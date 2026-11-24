package tests
import "core:net"
import "core:net/quic/conn"
import "core:testing"

@(test)
conn_authenticated_ecn_ce_feedback_reduces_congestion_once :: proc(t: ^testing.T) {
	p := migration_pair(t)
	defer close_pair(p)
	now := i64(p.link.now)
	conn.ecn_enable(p.client, true, now)
	conn.ecn_enable(p.server, true, now)
	payload := []u8{1, 2, 3}
	_, we := conn.write(p.client, 0, payload, true)
	assert(we == .None)
	buf: [conn.MAX_DATAGRAM]u8
	n, _, e := conn.pump_to(p.client, now, buf[:])
	testing.expect_value(t, e, .None)
	testing.expect_value(t, conn.output_ecn(p.client), .ECT_0)
	testing.expect_value(
		t,
		conn.ingest_from_ecn(p.server, now + 1, {net.IP4_Loopback, 4000}, buf[:n], .CE, true),
		.None,
	)
	testing.expect_value(t, p.server.ecn.received[2].ce, 1)
	before := p.client.model.congestion_window
	count, _, se := conn.pump_to(p.server, now + 2, buf[:])
	testing.expect_value(t, se, .None)
	testing.expect(t, count > 0)
	testing.expect_value(
		t,
		conn.ingest_from_ecn(p.client, now + 3, {net.IP4_Loopback, 4001}, buf[:count], .ECT_0, true),
		.None,
	)
	testing.expect_value(t, p.client.ecn.sender.state, .Capable)
	after := p.client.model.congestion_window
	testing.expect(t, after < before)
	testing.expect_value(
		t,
		conn.ingest_from_ecn(p.client, now + 4, {net.IP4_Loopback, 4001}, buf[:count], .ECT_0, true),
		.None,
	)
	testing.expect_value(t, p.client.model.congestion_window, after)
	got: [8]u8
	received, fin, re := conn.read(p.server, 0, got[:])
	testing.expect_value(t, re, .None)
	testing.expect(t, received == 3 && fin)
}

@(test)
conn_invalid_ecn_feedback_disables_marks_preserves_streams :: proc(t: ^testing.T) {
	p := migration_pair(t)
	defer close_pair(p)
	now := i64(p.link.now)
	conn.ecn_enable(p.client, true, now)
	conn.ecn_enable(p.server, true, now)
	_, we := conn.write(p.client, 0, []u8{1}, true)
	assert(we == .None)
	buf: [conn.MAX_DATAGRAM]u8
	n, _, e := conn.pump_to(p.client, now, buf[:])
	assert(e == .None && n > 0)
	testing.expect_value(
		t,
		conn.ingest_from_ecn(p.server, now + 1, {net.IP4_Loopback, 4000}, buf[:n], .Not_ECT, true),
		.None,
	)
	n, _, e = conn.pump_to(p.server, now + 2, buf[:])
	assert(e == .None && n > 0)
	testing.expect_value(
		t,
		conn.ingest_from_ecn(p.client, now + 3, {net.IP4_Loopback, 4001}, buf[:n], .Not_ECT, true),
		.None,
	)
	testing.expect_value(t, p.client.ecn.sender.state, .Failed)
	_, we = conn.write(p.client, 4, []u8{2}, true)
	assert(we == .None)
	n, _, e = conn.pump_to(p.client, now + 4, buf[:])
	assert(e == .None && n > 0)
	testing.expect_value(t, conn.output_ecn(p.client), .Not_ECT)
	testing.expect_value(
		t,
		conn.ingest_from_ecn(p.server, now + 5, {net.IP4_Loopback, 4000}, buf[:n], .Not_ECT, true),
		.None,
	)
	got: [8]u8
	received, fin, re := conn.read(p.server, 4, got[:])
	testing.expect_value(t, re, .None)
	testing.expect(t, received == 1 && fin && got[0] == 2)
}
