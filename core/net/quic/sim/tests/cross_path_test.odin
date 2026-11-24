package tests

import "core:net"
import "core:net/quic"
import "core:net/quic/conn"
import "core:testing"

@(private)
migration_response_packet :: proc(p: ^Pair, dst: []u8, token: [8]u8, pn: u64, bad_tag: bool = false) -> int {
	plain: [9]u8
	plain[0] = 0x1b
	for byte, i in token {plain[i + 1] = byte}
	return migration_peer_packet(p, dst, plain[:], pn, bad_tag)
}

@(test)
conn_encrypted_cross_path_response_validates_origin_and_preserves_cid_binding :: proc(t: ^testing.T) {
	p := migration_pair(t)
	defer close_pair(p)
	old_cid := p.client.peer_cid
	old_n := p.client.peer_cid_len
	endpoint := net.Endpoint{net.IP4_Loopback, 5001}
	now := i64(p.link.now)
	testing.expect_value(t, conn.migrate(p.client, now, endpoint), .None)
	candidate := -1
	for path, i in p.client.migration.paths {
		if path.used && path.endpoint == endpoint {
			candidate = i
		}
	}
	testing.expect(t, candidate >= 0)
	if candidate < 0 {
		return
	}
	path := p.client.migration.paths[candidate]
	testing.expect(t, path.owns_peer_id && path.has_peer_id)
	selected := -1
	for entry, i in p.client.migration.peer {
		if entry.used && entry.sequence == path.peer_sequence {
			selected = i
		}
	}
	testing.expect(t, selected >= 0)
	if selected < 0 {
		return
	}
	packet: [conn.MAX_DATAGRAM]u8
	n, to, e := conn.pump_to(p.client, now, packet[:])
	testing.expect_value(t, e, .None)
	testing.expect(t, n >= 1200)
	testing.expect_value(t, to, endpoint)
	view, _, ve := quic.packet_decode_v1(packet[:n], p.server.local_cid_len)
	testing.expect_value(t, ve, .None)
	reserved := p.client.migration.peer[selected]
	testing.expect_value(t, string(view.invariant.destination_id), string(reserved.id[:reserved.n]))
	testing.expect(t, string(view.invariant.destination_id) != string(old_cid[:old_n]))
	testing.expect_value(t, p.client.peer_cid, old_cid)
	token := p.client.migration.paths[candidate].challenge
	wrong := token
	wrong[0] ~= 1
	base := p.server.model.spaces[2].next_send + 8
	n = migration_response_packet(p, packet[:], wrong, base)
	testing.expect_value(t, conn.ingest_from(p.client, now + 1, {net.IP4_Loopback, 4001}, packet[:n]), .None)
	testing.expect(t, !p.client.migration.paths[candidate].validated)
	n = migration_response_packet(p, packet[:], token, base + 1, true)
	bad := conn.ingest_from(p.client, now + 2, {net.IP4_Loopback, 4001}, packet[:n])
	testing.expect(t, bad == .None || bad == .Discarded)
	testing.expect(t, !p.client.migration.paths[candidate].validated)
	n = migration_response_packet(p, packet[:], token, base + 2)
	testing.expect_value(t, conn.ingest_from(p.client, now + 3, {net.IP4_Loopback, 4001}, packet[:n]), .None)
	testing.expect(
		t,
		p.client.migration.paths[candidate].validated && !p.client.migration.paths[candidate].challenge_pending,
	)
	testing.expect_value(t, p.client.migration.active, candidate)
	testing.expect_value(t, p.client.migration.peer_sequence, reserved.sequence)
	testing.expect_value(t, p.client.peer_cid, reserved.id)
	// The exact packet replay from another endpoint cannot allocate/validate it.
	testing.expect_value(t, conn.ingest_from(p.client, now + 4, {net.IP4_Loopback, 6001}, packet[:n]), .None)
	for other in p.client.migration.paths {
		if other.endpoint.port == 6001 {
			testing.expect(t, !other.used && !other.validated)
		}
	}
	// Nor can the consumed token validate a different path with a fresh PN.
	n = migration_response_packet(p, packet[:], token, base + 3)
	testing.expect_value(t, conn.ingest_from(p.client, now + 5, {net.IP4_Loopback, 6001}, packet[:n]), .None)
	for other in p.client.migration.paths {
		if other.endpoint.port == 6001 {
			testing.expect(t, !other.validated)
		}
	}
	testing.expect_value(t, p.client.migration.active, candidate)
}

@(private)
migration_peer_packet :: proc(p: ^Pair, dst, plain: []u8, pn: u64, bad_tag: bool = false) -> int {
	hn, _, he := quic.short_header_encode_v1(
		dst,
		{
			destination_id = p.client.local_cid[:p.client.local_cid_len],
			packet_number = u32(pn),
			packet_number_length = 4,
		},
	); assert(he == .None)
	n, e := quic.handshake_payload_seal(&p.server.hs, dst[hn:], dst[:hn], plain, .One_RTT, pn)
	assert(e == .None)
	if bad_tag {
		dst[hn + n - 1] ~= 1
	}
	assert(
		quic.handshake_header_protection_apply(&p.server.hs, dst[:hn + n], .One_RTT, p.client.local_cid_len) == .None,
	); return hn + n
}

@(test)
conn_withdrawn_current_cid_waits_for_fresh_credit_without_cross_path_reuse :: proc(t: ^testing.T) {
	p := migration_pair(t)
	defer close_pair(p)
	now := i64(p.link.now)
	for port in 5001 ..< 5004 {testing.expect_value(t, conn.migrate(p.client, now, {net.IP4_Loopback, port}), .None)}
	// Every other issued peer CID is already reserved for a distinct destination.
	highest := p.client.migration.peer[3]
	testing.expect(t, highest.used && highest.bound)
	frame: [28]u8
	frame[0] = 0x18
	frame[1] = u8(highest.sequence)
	frame[2] = 1
	frame[3] = u8(highest.n)
	copy(frame[4:], highest.id[:highest.n])
	copy(frame[4 + highest.n:], highest.token[:])
	packet: [conn.MAX_DATAGRAM]u8
	base := p.server.model.spaces[2].next_send + 8
	n := migration_peer_packet(p, packet[:], frame[:4 + highest.n + 16], base)
	testing.expect_value(t, conn.ingest_from(p.client, now, {net.IP4_Loopback, 4001}, packet[:n]), .None)
	testing.expect(t, p.client.migration.peer_blocked)
	payload := []u8{1, 2, 3}
	wn, we := conn.write(p.client, 0, payload, true)
	testing.expect_value(t, we, .None)
	testing.expect_value(t, wn, 3)
	before := p.client.model.spaces[2].next_send
	pe: conn.Error
	n, pe = conn.pump(p.client, now + 1, packet[:])
	testing.expect_value(t, pe, .Not_Ready)
	testing.expect_value(t, n, 0)
	testing.expect_value(t, p.client.model.spaces[2].next_send, before)
	for b in p.client.bufs {
		if b.used && b.id == 0 {
			testing.expect(t, b.n == 3 && b.sent == 0 && !b.fin_sent)
		}
	}
	// Fresh peer credit unblocks the original destination, with a CID never
	// used on any of the pending candidate paths.
	frame[1] = 4
	frame[2] = 1
	frame[3] = 8
	for i in 4 ..< 28 {frame[i] = 44}
	n = migration_peer_packet(p, packet[:], frame[:], base + 1)
	testing.expect_value(t, conn.ingest_from(p.client, now + 2, {net.IP4_Loopback, 4001}, packet[:n]), .None)
	testing.expect(t, !p.client.migration.peer_blocked)
	testing.expect_value(t, p.client.peer_cid[0], u8(44))
	for _ in 0 ..< 8 {
		n, pe = conn.pump(p.client, now + 3, packet[:])
		testing.expect_value(t, pe, .None)
		if n == 0 {
			break
		}
		view, _, ve := quic.packet_decode_v1(packet[:n], 8)
		testing.expect_value(t, ve, .None)
		testing.expect_value(t, view.invariant.destination_id[0], u8(44))
	}
	for b in p.client.bufs {
		if b.used && b.id == 0 {
			testing.expect(t, b.sent == 3 && b.fin_sent)
		}
	}
}

@(test)
conn_authenticated_retirement_of_never_advertised_cid_is_rejected :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false)
	defer close_pair(p)
	settle(t, p)
	testing.expect_value(t, conn.migration_enable(p.client, {net.IP4_Loopback, 4001}, 4), .None)
	testing.expect(t, p.client.migration.local[1].used && !p.client.migration.local[1].sent_once)
	packet: [conn.MAX_DATAGRAM]u8
	n := migration_peer_packet(p, packet[:], []u8{0x19, 1}, p.server.model.spaces[2].next_send + 8)
	testing.expect_value(
		t,
		conn.ingest_from(p.client, i64(p.link.now), {net.IP4_Loopback, 4001}, packet[:n]),
		.Protocol,
	)
	testing.expect_value(t, p.client.phase, .Failed)
	testing.expect(t, p.client.migration.local[1].used)
}

@(test)
conn_local_migration_waits_for_client_handshake_confirmation :: proc(t: ^testing.T) {
	p := migration_pair(t)
	defer close_pair(p)
	p.client.seen_done = false
	before := p.client.migration
	testing.expect_value(t, conn.migrate(p.client, i64(p.link.now), {net.IP4_Loopback, 5001}), .Not_Ready)
	testing.expect_value(t, p.client.migration, before)
}
