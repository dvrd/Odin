package tests
import "core:net"
import "core:net/quic/conn"
import "core:testing"

@(test)
conn_stateless_reset_unknown_prefix_releases_retained_owners_once :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	_, we := conn.write(p.client, 0, []u8{1, 2, 3}, false); assert(we == .None)
	token := [16]u8 {
		0  = 77,
		15 = 123,
	}; p.client.migration.peer[0].token = token; p.client.migration.peer[0].has_token = true
	packet: [21]u8; packet[0] = 0x40; copy(packet[5:], token[:])
	testing.expect(t, conn.observe_unrouted_reset(p.client, packet[:]))
	testing.expect(t, conn.was_stateless_reset(p.client))
	testing.expect_value(t, p.client.phase, .Closed)
	testing.expect_value(t, conn.stats(p.client).retained, 0)
	testing.expect_value(t, conn.stats(p.client).live_packets, 0)
	testing.expect(t, !conn.observe_unrouted_reset(p.client, packet[:]))
}
@(test)
conn_authentication_precedes_reset_suffix_matching :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	packet := raw_application_packet(t, p, []u8{1, 0, 0, 0}); defer delete(packet)
	copy(p.server.migration.peer[0].token[:], packet[len(packet) - 16:])
	p.server.migration.peer[0].has_token = true
	testing.expect(t, !conn.observe_unrouted_reset(p.server, packet))
	testing.expect(t, conn.established(p.server))
	testing.expect_value(
		t,
		conn.ingest_from(p.server, i64(p.link.now), {net.IP4_Loopback, 4000}, packet),
		.None,
	)
	packet[len(packet) - 1] ~= 1
	copy(p.server.migration.peer[0].token[:], packet[len(packet) - 16:])
	testing.expect(t, conn.observe_unrouted_reset(p.server, packet))
	testing.expect(t, conn.was_stateless_reset(p.server))
}
@(test)
conn_stop_and_reset_application_codes_survive_loss :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	_, we := conn.write(p.client, 0, []u8{1}, false); assert(we == .None)
	migration_exchange(t, p, 4000, 20)
	testing.expect_value(t, conn.stop_sending_with_error(p.server, 0, 0x10c), .None)
	packet: [conn.MAX_DATAGRAM]u8
	n, _, e := conn.pump_to(p.server, i64(p.link.now), packet[:]); assert(e == .None && n > 0)
	// Lose the first STOP and retransmit it through ordinary recovery.
	timer := conn.timer(p.server, i64(p.link.now)); assert(timer.armed)
	n, e = conn.on_timeout(p.server, timer.at, packet[:]); assert(e == .None && n > 0)
	testing.expect_value(
		t,
		conn.ingest_from(p.client, timer.at, {net.IP4_Loopback, 4001}, packet[:n]),
		.None,
	)
	code, found := conn.receive_stop_error(p.client, 0); testing.expect(t, found)
	testing.expect_value(t, code, 0x10c)
	n, _, e = conn.pump_to(p.client, timer.at + 1, packet[:]); assert(e == .None && n > 0)
	// Lose the first RESET response too.
	timer = conn.timer(p.client, timer.at + 1); assert(timer.armed)
	n, e = conn.on_timeout(p.client, timer.at, packet[:]); assert(e == .None && n > 0)
	testing.expect_value(
		t,
		conn.ingest_from(p.server, timer.at, {net.IP4_Loopback, 4000}, packet[:n]),
		.None,
	)
	code, found = conn.receive_reset_error(p.server, 0); testing.expect(t, found)
	testing.expect_value(t, code, 0x10c)
}
