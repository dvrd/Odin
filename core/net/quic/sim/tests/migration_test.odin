package tests
import "core:net"
import "core:net/quic/conn"
import "core:net/quic/harness"
import "core:testing"

@(private)
migration_pair :: proc(t: ^testing.T) -> ^Pair {
	p := open_pair(t, wide_limits(), false); settle(t, p)
	testing.expect_value(t, conn.migration_enable(p.client, {net.IP4_Loopback, 4001}, 4), .None)
	testing.expect_value(t, conn.migration_enable(p.server, {net.IP4_Loopback, 4000}, 4), .None)
	migration_exchange(t, p, 4000, 20)
	return p
}
@(private)
migration_exchange :: proc(
	t: ^testing.T,
	p: ^Pair,
	client_port: int,
	rounds: int,
	client_address: net.IP4_Address = net.IP4_Loopback,
) {
	buf: [conn.MAX_DATAGRAM]u8
	for step in 0 ..< rounds {
		now := i64(p.link.now) + i64(step)
		connections := [2]^conn.Connection{p.client, p.server}
		for c in connections {
			n, _, e := conn.pump_to(c, now, buf[:])
			testing.expect(t, e == .None || e == .Congestion || e == .Anti_Amplification)
			if n <= 0 {
				continue
			}
			target := p.server; from := net.Endpoint{client_address, client_port}
			if c == p.server {
				target = p.client; from = {net.IP4_Loopback, 4001}
			}
			testing.expect_value(t, conn.ingest_from(target, now, from, buf[:n]), .None)
		}
	}
}
@(test)
conn_cid_rotation_and_retirement_preserve_streams :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	original := p.client.peer_cid
	testing.expect_value(t, conn.rotate_peer_id(p.client), .None)
	testing.expect(t, original != p.client.peer_cid)
	payload := []u8{1, 2, 3}; _, e := conn.write(p.client, 0, payload, true)
	testing.expect_value(t, e, .None)
	migration_exchange(t, p, 4000, 40)
	got: [8]u8; n, fin, re := conn.read(p.server, 0, got[:]); testing.expect_value(t, re, .None)
	testing.expect_value(t, n, 3); testing.expect(t, fin)
	count := 0; for entry in p.server.migration.local {
		if entry.used {
			count += 1
		}
	}
	testing.expect_value(t, count, 4)
}
@(test)
conn_nat_rebinding_requires_endpoint_bound_response :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	// An authenticated packet from a new port must not immediately change output.
	testing.expect_value(
		t,
		conn.migrate(p.client, i64(p.link.now), {net.IP4_Loopback, 4001}),
		.None,
	)
	buf: [conn.MAX_DATAGRAM]u8; n, _, e := conn.pump_to(p.client, i64(p.link.now), buf[:])
	testing.expect_value(t, e, .None)
	testing.expect_value(
		t,
		conn.ingest_from(p.server, i64(p.link.now), {net.IP4_Loopback, 5000}, buf[:n]),
		.None,
	)
	testing.expect_value(t, p.server.migration.active, 0)
	migration_exchange(t, p, 5000, 40)
	active := p.server.migration.active; testing.expect(t, active != 0)
	testing.expect_value(t, p.server.migration.paths[active].endpoint.port, 5000)
	testing.expect(t, p.server.migration.paths[active].validated)
}
@(test)
conn_migration_unauthenticated_candidate_cannot_consume_slots_or_recovery :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	before := p.server.model
	forged: [48]u8; forged[0] = 0x40; copy(forged[1:], p.server.local_cid[:p.server.local_cid_len])
	for port in 6000 ..< 6040 {_ = conn.ingest_from(p.server, 100, {net.IP4_Loopback, port}, forged[:])}
	testing.expect_value(t, p.server.model.path, before.path)
	testing.expect_value(t, p.server.model.path_received, before.path_received)
	testing.expect_value(t, p.server.model.congestion_window, before.congestion_window)
	used := 0; for path in p.server.migration.paths {
		if path.used {
			used += 1
		}
	}
	testing.expect_value(t, used, 1)
}

@(test)
conn_migration_probe_loss_and_repeated_rebinding_recover :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	now := i64(p.link.now)
	testing.expect_value(t, conn.migrate(p.client, now, {net.IP4_Loopback, 4001}), .None)
	packet: [conn.MAX_DATAGRAM]u8
	dropped, _, e := conn.pump_to(p.client, now, packet[:]); testing.expect_value(t, e, .None)
	testing.expect(t, dropped >= 1200)
	// The challenge is retransmitted independently of application stream output.
	p.link.now += 1000
	n, _, pe := conn.pump_to(p.client, i64(p.link.now), packet[:])
	testing.expect_value(t, pe, .None); testing.expect(t, n >= 1200)
	testing.expect_value(
		t,
		conn.ingest_from(p.server, i64(p.link.now), {net.IP4_Loopback, 5000}, packet[:n]),
		.None,
	)
	// Lose the first PATH_RESPONSE too; the peer's own challenge still validates
	// its path and the retained original challenge can be retried later.
	n, _, pe = conn.pump_to(p.server, i64(p.link.now), packet[:])
	testing.expect_value(t, pe, .None); testing.expect(t, n > 0)
	migration_exchange(t, p, 5000, 60)
	testing.expect_value(t, conn.active_endpoint(p.server).port, 5000)
	for port in 5001 ..< 5010 {
		p.link.now += 1000
		testing.expect_value(
			t,
			conn.migrate(p.client, i64(p.link.now), {net.IP4_Loopback, 4001}),
			.None,
		)
		migration_exchange(t, p, port, 60)
		testing.expect_value(t, conn.active_endpoint(p.server).port, port)
	}
	testing.expect(t, conn.established(p.client) && conn.established(p.server))
}

@(test)
conn_network_migration_starts_new_recovery_epoch_old_ack_cannot_tune :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	old_epoch := p.server.model.path_epoch
	_, we := conn.write(p.server, 1, []u8{8}, true); assert(we == .None)
	packet: [conn.MAX_DATAGRAM]u8
	pn := p.server.model.spaces[2].next_send
	n, _, pe := conn.pump_to(p.server, i64(p.link.now), packet[:]); assert(pe == .None && n > 0)
	// Retain the old network's packet in flight while validating another address.
	testing.expect_value(
		t,
		conn.migrate(p.client, i64(p.link.now), {net.IP4_Loopback, 4001}),
		.None,
	)
	migration_exchange(t, p, 5000, 40, net.IP4_Address{127, 0, 0, 2})
	testing.expect_value(t, p.server.model.path_epoch, old_epoch + 1)
	before := p.server.model
	_, ae := harness.acknowledge(
		&p.server.model,
		i64(p.link.now) + 100,
		.Application,
		pn,
		pn,
		0,
		false,
		0,
		nil,
	)
	testing.expect_value(t, ae, .None)
	testing.expect_value(t, p.server.model.congestion_window, before.congestion_window)
	testing.expect_value(t, p.server.model.smoothed_rtt, before.smoothed_rtt)
}

@(test)
conn_candidate_probe_respects_its_own_amplification_budget :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	assert(conn.queue_ping(p.client) == .None)
	packet: [conn.MAX_DATAGRAM]u8; n, _, e := conn.pump_to(p.client, i64(p.link.now), packet[:])
	assert(e == .None && n > 0 && n < 1200)
	testing.expect_value(
		t,
		conn.ingest_from(p.server, i64(p.link.now), {net.IP4_Loopback, 5000}, packet[:n]),
		.None,
	)
	probe, endpoint, pe := conn.pump_to(p.server, i64(p.link.now), packet[:])
	testing.expect_value(t, pe, .None)
	testing.expect_value(t, endpoint.port, 5000)
	testing.expect(t, probe > 0 && probe <= 3 * n, "candidate exceeded 3x authenticated input")
	testing.expect_value(t, conn.active_endpoint(p.server).port, 4000)
}
