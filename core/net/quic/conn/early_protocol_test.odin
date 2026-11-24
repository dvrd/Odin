package conn

import "core:crypto/aes"
import "core:crypto/tls"
import "core:net"
import "core:net/quic"
import "core:testing"

@(private)
early_protocol_fixture :: proc() -> ^Connection {
	c := new(Connection)
	h := quic.Handshake {
		role          = .Server,
		have_zero_rtt = true,
	}
	secret: [32]u8
	secret[0] = 42
	keys, e := tls.quic_packet_keys_derive(secret, .Application)
	assert(e == nil)
	assert(
		quic.packet_keys_set_aes(&h.zero_rtt_read, keys.key[:], keys.iv[:], keys.hp[:], keys.secret[:], false) ==
		.None,
	)
	h.zero_rtt_read.zero_rtt = true
	h.zero_rtt_write = h.zero_rtt_read
	tls.quic_direction_keys_clear(&keys)
	assert(
		adopt_early(
			c,
			&h,
			{
				role = .Server,
				local_cid = []u8{1, 2, 3, 4, 5, 6, 7, 8},
				peer_cid = []u8{8, 7, 6, 5, 4, 3, 2, 1},
				max_datagram = 1200,
				limits = {
					max_data = 8192,
					max_stream_data = 8192,
					max_streams = 16,
					recv_max_data = 8192,
					recv_max_stream_data = 256,
					recv_max_streams = 16,
				},
			},
		) ==
		.None,
	)
	quic.handshake_fail(&h)
	return c
}

@(private)
early_protocol_packet :: proc(
	c: ^Connection,
	dst, plain: []u8,
	pn: u64,
	reserved: bool = false,
	bad_tag: bool = false,
	destination: []u8 = nil,
) -> int {
	target := destination
	if target == nil {
		target = c.local_cid[:c.local_cid_len]
	}
	hn, _, he := quic.long_header_encode_v1(
		dst,
		{
			kind = .Zero_RTT,
			destination_id = target,
			source_id = c.peer_cid[:c.peer_cid_len],
			packet_number = u32(pn),
			packet_number_length = 4,
			ciphertext_length = u64(len(plain) + 16),
			length_width = 2,
		},
	); assert(he == .None)
	if reserved {
		dst[0] |= 4
	}
	keys := &c.hs.zero_rtt_read
	nonce, ne := quic.packet_nonce(keys, pn)
	assert(ne == .None)
	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, keys.key[:16])
	defer aes.reset_gcm(&ctx)
	aes.seal_gcm(&ctx, dst[hn:hn + len(plain)], dst[hn + len(plain):hn + len(plain) + 16], nonce[:], dst[:hn], plain)
	n := hn + len(plain) + 16
	if bad_tag {
		dst[n - 1] ~= 1
	}
	assert(quic.header_protection_apply(dst[:n], keys, .Zero_RTT) == .None)
	return n
}

@(test)
early_authenticated_frame_admission_and_reserved_bits :: proc(t: ^testing.T) {
	forbidden := [][]u8 {
		[]u8{2, 0, 0, 0, 0},
		[]u8{6, 0, 0},
		[]u8{7, 1, 9},
		[]u8{0x1e},
		[]u8{0x1b, 1, 2, 3, 4, 5, 6, 7, 8},
		nil,
	}
	for plain in forbidden {
		c := early_protocol_fixture()
		packet: [MAX_DATAGRAM]u8
		n := early_protocol_packet(c, packet[:], plain, 0)
		testing.expect_value(t, ingest(c, 1, 0, packet[:n]), .Protocol)
		testing.expect_value(t, c.phase, .Failed)
		destroy(c)
		free(c)
	}
	c := early_protocol_fixture()
	defer {destroy(c); free(c)}
	packet: [MAX_DATAGRAM]u8
	n := early_protocol_packet(c, packet[:], []u8{1}, 0, true, true)
	testing.expect_value(t, ingest(c, 1, 0, packet[:n]), .Discarded)
	testing.expect(t, early(c) && c.phase != .Failed)
	n = early_protocol_packet(c, packet[:], []u8{1}, 0, true, false)
	testing.expect_value(t, ingest(c, 2, 0, packet[:n]), .Protocol)
	testing.expect_value(t, c.phase, .Failed)
}

@(test)
early_padding_is_nonempty_and_not_ack_eliciting :: proc(t: ^testing.T) {
	c := early_protocol_fixture()
	defer {destroy(c); free(c)}
	packet: [MAX_DATAGRAM]u8
	n := early_protocol_packet(c, packet[:], []u8{0}, 0)
	testing.expect_value(t, ingest(c, 1, 0, packet[:n]), .None)
	testing.expect(t, !c.model.ack_pending[2])
}

@(test)
early_owned_cid_retirement_and_challenge_defer_until_confirmation :: proc(t: ^testing.T) {
	c := early_protocol_fixture()
	defer {destroy(c); free(c)}
	// NEW_CONNECTION_ID sequence1, RETIRE_CONNECTION_ID initial sequence0, challenge.
	frames := [?]u8 {
		0x18,
		1,
		0,
		8,
		9,
		9,
		9,
		9,
		9,
		9,
		9,
		9,
		1,
		2,
		3,
		4,
		5,
		6,
		7,
		8,
		9,
		10,
		11,
		12,
		13,
		14,
		15,
		16,
		0x19,
		0,
		0x1a,
		21,
		22,
		23,
		24,
		25,
		26,
		27,
		28,
	}
	original := [8]u8{9, 9, 9, 9, 9, 9, 9, 9}
	copy(c.early_state.original[:], original[:])
	c.early_state.original_n = 8
	peer := net.Endpoint{net.IP4_Loopback, 4000}
	packet: [MAX_DATAGRAM]u8
	n := early_protocol_packet(c, packet[:], frames[:], 0, false, false, original[:])
	testing.expect_value(t, ingest_early_ecn(c, 1, peer, packet[:n], .Not_ECT, false), .None)
	testing.expect_value(t, c.early_state.control_n, 3)
	testing.expect(t, !c.migration.enabled)
	second := [?]u8{0x1a, 31, 32, 33, 34, 35, 36, 37, 38}
	n = early_protocol_packet(c, packet[:], second[:], 1)
	testing.expect_value(t, ingest_early_ecn(c, 1, peer, packet[:n], .Not_ECT, false), .None)
	packet = {}
	frames = {}
	owner := quic.Handshake {
		role                = .Server,
		have_one_rtt        = true,
		handshake_complete  = true,
		peer_authenticated  = true,
		handshake_discarded = true,
	}
	owner.one_rtt_write = c.hs.zero_rtt_read
	owner.one_rtt_write.zero_rtt = false
	owner.one_rtt_write.one_rtt = true
	local := c.local_cid
	remote := c.peer_cid
	testing.expect_value(
		t,
		confirm_early(c, &owner, {role = .Server, local_cid = local[:8], peer_cid = remote[:8]}, true, 2),
		.None,
	)
	testing.expect_value(t, c.early_state.control_n, 4)
	testing.expect_value(t, migration_enable(c, peer, 4), .None)
	testing.expect_value(t, c.early_state.control_n, 1)
	found := false
	retired := true
	for entry in c.migration.peer {
		if entry.used && entry.sequence == 1 {
			found = true
			testing.expect_value(t, entry.n, 8)
			testing.expect_value(t, entry.id[0], u8(9))
			testing.expect_value(t, entry.token[15], u8(16))
		}
	}
	for entry in c.migration.local {
		if entry.used && entry.sequence == 0 {
			retired = false
		}
	}
	testing.expect(t, found && retired)
	path := c.migration.paths[0]
	testing.expect(t, path.response_pending && path.validated && path.endpoint == peer)
	testing.expect_value(t, path.response, [8]u8{21, 22, 23, 24, 25, 26, 27, 28})
	testing.expect_value(t, c.migration.active, 0)
	// A second challenge remains owned until the first response has been sent.
	early_protocol_expect_response(t, c, peer, [8]u8{21, 22, 23, 24, 25, 26, 27, 28}, 3)
	early_tick(c, 4)
	testing.expect_value(t, c.early_state.control_n, 0)
	testing.expect_value(t, c.migration.paths[0].response, [8]u8{31, 32, 33, 34, 35, 36, 37, 38})
	testing.expect_value(t, c.migration.paths[0].endpoint, peer)
	early_protocol_expect_response(t, c, peer, [8]u8{31, 32, 33, 34, 35, 36, 37, 38}, 5)
}

@(test)
early_control_retention_is_bounded_before_effects :: proc(t: ^testing.T) {
	c := early_protocol_fixture()
	defer {destroy(c); free(c)}
	packet: [MAX_DATAGRAM]u8
	for i in 0 ..< EARLY_CONTROL_CAP + 1 {
		frame := [9]u8 {
			0 = 0x1a,
		}
		frame[1] = u8(i)
		n := early_protocol_packet(c, packet[:], frame[:], u64(i))
		e := ingest_early_ecn(c, i64(i + 1), {net.IP4_Loopback, 4000}, packet[:n], .Not_ECT, false)
		if i < EARLY_CONTROL_CAP {
			testing.expect_value(t, e, .None)
		} else {
			testing.expect_value(t, e, .Protocol)
		}
	}
	testing.expect_value(t, c.early_state.control_n, EARLY_CONTROL_CAP)
	testing.expect(t, !c.migration.enabled)
}

@(test)
early_deferred_controls_keep_destination_and_endpoint_constraints :: proc(t: ^testing.T) {
	for challenge in ([]bool{false, true}) {
		c := early_protocol_fixture()
		frame := []u8{0x19, 0}
		if challenge {
			frame = []u8{0x1a, 1, 2, 3, 4, 5, 6, 7, 8}
		}
		packet: [MAX_DATAGRAM]u8
		n := early_protocol_packet(c, packet[:], frame, 0)
		testing.expect_value(t, ingest_early_ecn(c, 1, {net.IP4_Loopback, 4000}, packet[:n], .Not_ECT, false), .None)
		owner := quic.Handshake {
			role                = .Server,
			have_one_rtt        = true,
			handshake_complete  = true,
			peer_authenticated  = true,
			handshake_discarded = true,
		}
		local := c.local_cid
		remote := c.peer_cid
		testing.expect_value(
			t,
			confirm_early(c, &owner, {role = .Server, local_cid = local[:8], peer_cid = remote[:8]}, true, 2),
			.None,
		)
		endpoint := net.Endpoint{net.IP4_Loopback, 4000}
		if challenge {
			endpoint.port = 5000
		}
		e := migration_enable(c, endpoint, 4)
		// Retiring the containing packet's destination remains invalid. A replayed
		// challenge cannot cause a response on a newly admitted different endpoint.
		testing.expect_value(t, e, .Protocol)
		testing.expect(t, !c.migration.paths[0].response_pending)
		testing.expect_value(t, c.migration.paths[0].endpoint, endpoint)
		testing.expect_value(t, c.migration.active, 0)
		destroy(c)
		free(c)
	}
}

@(test)
early_zero_length_cids_cannot_gain_or_retire_connection_ids :: proc(t: ^testing.T) {
	for new_id in ([]bool{false, true}) {
		c := early_protocol_fixture()
		frame := []u8{0x19, 0}
		if new_id {
			c.peer_cid_len = 0
			c.model.peer_cid_len = 0
			frame = []u8{0x18, 1, 0, 1, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		} else {
			c.local_cid_len = 0
			c.model.local_cid_len = 0
		}
		packet: [MAX_DATAGRAM]u8
		n := early_protocol_packet(c, packet[:], frame, 0)
		testing.expect_value(t, ingest(c, 1, 0, packet[:n]), .Protocol)
		testing.expect_value(t, c.early_state.control_n, 0)
		destroy(c)
		free(c)
	}
}

@(private)
early_protocol_expect_response :: proc(t: ^testing.T, c: ^Connection, peer: net.Endpoint, want: [8]u8, now: i64) {
	packet: [MAX_DATAGRAM]u8
	n: int
	to: net.Endpoint
	e: Error
	if c.migration.enabled {
		n, to, e = pump_to(c, now, packet[:])
	} else {
		n, e = pump(c, now, packet[:])
		to = c.early_state.endpoint
	}
	testing.expect_value(t, e, .None)
	testing.expect(t, n > 0)
	testing.expect_value(t, to, peer)
	if n <= 0 {
		return
	}
	testing.expect_value(
		t,
		quic.header_protection_remove(packet[:n], &c.hs.one_rtt_write, .One_RTT, c.peer_cid_len),
		.None,
	)
	view, _, ve := quic.packet_decode_v1(packet[:n], c.peer_cid_len)
	testing.expect_value(t, ve, .None)
	fields, fe := quic.unprotected_fields_decode(view, packet[:n])
	testing.expect_value(t, fe, .None)
	hn := 1 + c.peer_cid_len + fields.packet_number_length
	plain: [MAX_DATAGRAM]u8
	pn, pe := quic.payload_open(plain[:], packet[:hn], packet[hn:n], &c.hs.one_rtt_write, u64(fields.packet_number))
	testing.expect_value(t, pe, .None)
	parsed, ok := parse_frames(plain[:pn])
	testing.expect(t, ok)
	testing.expect_value(t, parsed.path_n, 1)
	testing.expect(t, parsed.paths[0].response)
	testing.expect_value(t, parsed.paths[0].token, want)
	testing.expect(t, !c.migration.paths[0].response_pending)
	testing.expect(t, c.migration.enabled || !c.path_response_pending)
}

@(test)
early_zero_cid_challenges_respond_after_confirmation_without_migration :: proc(t: ^testing.T) {
	c := early_protocol_fixture()
	defer {destroy(c); free(c)}
	c.local_cid_len = 0
	c.peer_cid_len = 0
	c.model.local_cid_len = 0
	c.model.peer_cid_len = 0
	frames := []u8{0x1a, 1, 2, 3, 4, 5, 6, 7, 8, 0x1a, 11, 12, 13, 14, 15, 16, 17, 18}
	peer := net.Endpoint{net.IP4_Loopback, 4000}
	packet: [MAX_DATAGRAM]u8
	n := early_protocol_packet(c, packet[:], frames, 0)
	testing.expect_value(t, ingest_early_ecn(c, 1, peer, packet[:n], .Not_ECT, false), .None)
	testing.expect(t, !c.path_response_pending)
	testing.expect_value(t, c.early_state.control_n, 2)
	owner := quic.Handshake {
		role                = .Server,
		have_one_rtt        = true,
		handshake_complete  = true,
		peer_authenticated  = true,
		handshake_discarded = true,
	}
	owner.one_rtt_write = c.hs.zero_rtt_read
	owner.one_rtt_write.zero_rtt = false
	owner.one_rtt_write.one_rtt = true
	testing.expect_value(t, confirm_early(c, &owner, {role = .Server}, true, 2, peer), .None)
	early_protocol_expect_response(t, c, peer, [8]u8{1, 2, 3, 4, 5, 6, 7, 8}, 3)
	early_protocol_expect_response(t, c, peer, [8]u8{11, 12, 13, 14, 15, 16, 17, 18}, 4)
	testing.expect_value(t, c.early_state.control_n, 0)
	testing.expect(t, !c.migration.enabled)
}

@(private)
early_protocol_application_packet :: proc(c: ^Connection, dst, plain: []u8, pn: u64) -> int {
	hn, _, he := quic.short_header_encode_v1(
		dst,
		{destination_id = c.local_cid[:c.local_cid_len], packet_number = u32(pn), packet_number_length = 4},
	); assert(he == .None)
	n, e := quic.payload_seal(dst[hn:], dst[:hn], plain, &c.hs.one_rtt_read, pn)
	assert(e == .None)
	assert(quic.header_protection_apply(dst[:hn + n], &c.hs.one_rtt_read, .One_RTT, c.local_cid_len) == .None)
	return hn + n
}

@(test)
zero_cid_manager_supports_normal_application_and_nonzero_cid_retirement :: proc(t: ^testing.T) {
	for local_zero in ([]bool{false, true}) {
		c := early_protocol_fixture()
		if local_zero {
			c.local_cid_len = 0
			c.model.local_cid_len = 0
		} else {
			c.peer_cid_len = 0
			c.model.peer_cid_len = 0
		}
		owner := quic.Handshake {
			role                = .Server,
			have_one_rtt        = true,
			handshake_complete  = true,
			peer_authenticated  = true,
			handshake_discarded = true,
		}
		owner.one_rtt_write = c.hs.zero_rtt_read
		owner.one_rtt_write.zero_rtt = false
		owner.one_rtt_write.one_rtt = true
		owner.one_rtt_read = owner.one_rtt_write
		local := c.local_cid
		remote := c.peer_cid
		peer := net.Endpoint{net.IP4_Loopback, 4000}
		testing.expect_value(
			t,
			confirm_early(
				c,
				&owner,
				{role = .Server, local_cid = local[:c.local_cid_len], peer_cid = remote[:c.peer_cid_len]},
				true,
				2,
				peer,
			),
			.None,
		)
		testing.expect_value(t, migration_enable(c, peer, 4), .None)
		packet: [MAX_DATAGRAM]u8
		pn := u64(0)
		if local_zero {
			testing.expect_value(t, c.migration.local_next, u64(1))
			testing.expect(t, !c.migration.local[0].pending)
			n := early_protocol_application_packet(c, packet[:], []u8{1}, pn)
			testing.expect_value(t, ingest_from(c, 3, {net.IP4_Loopback, 5000}, packet[:n]), .Discarded)
			testing.expect_value(t, c.migration.active, 0)
		} else {
			// The peer can retire an ID only after an actual NEW_CONNECTION_ID emit.
			for _ in 0 ..< 3 {
				sent, se, ready := migration_control(c, 2, packet[:])
				assert(se == .None && ready && sent > 0)
			}
			n := early_protocol_application_packet(c, packet[:], []u8{0x19, 1}, pn)
			testing.expect_value(t, ingest_from(c, 3, peer, packet[:n]), .None)
			pn += 1
			found := false
			for entry in c.migration.local {
				if entry.used && entry.sequence == 1 {
					found = true
				}
			}
			testing.expect(t, !found)
			testing.expect_value(t, c.migration.local_next, u64(5))
			testing.expect_value(t, migrate(c, 4, {net.IP4_Loopback, 5000}), .Invalid)
		}
		n := early_protocol_application_packet(c, packet[:], []u8{0x0b, 0, 1, 42}, pn)
		testing.expect_value(t, ingest_from(c, 5, peer, packet[:n]), .None)
		pn += 1
		output: [4]u8
		rn, fin, re := read(c, 0, output[:])
		testing.expect_value(t, re, .None)
		testing.expect(t, rn == 1 && fin && output[0] == 42)
		invalid := []u8{0x19, 0}
		if !local_zero {
			invalid = []u8{0x18, 1, 0, 1, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		}
		n = early_protocol_application_packet(c, packet[:], invalid, pn)
		testing.expect_value(t, ingest_from(c, 6, peer, packet[:n]), .Protocol)
		destroy(c)
		free(c)
	}
}
