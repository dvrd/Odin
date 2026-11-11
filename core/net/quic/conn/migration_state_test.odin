package conn
import "core:net"
import "core:testing"

@(private)
cid_fixture :: proc(c: ^Connection) {
	c.initialized = true; c.phase = .Established; c.local_cid_len = 8; c.peer_cid_len = 8
	copy(c.local_cid[:], []u8{1, 2, 3, 4, 5, 6, 7, 8})
	copy(c.peer_cid[:], []u8{8, 7, 6, 5, 4, 3, 2, 1})
	assert(migration_enable(c, {net.IP4_Loopback, 1234}, 4) == .None)
}
@(test)
cid_retire_prior_rotates_and_rejects_conflicting_reuse :: proc(t: ^testing.T) {
	c: Connection; cid_fixture(&c)
	p := Parsed {
		new_id_n = 1,
	}; p.new_ids[0] = CID_Frame {
		sequence = 1,
		retire_prior_to = 1,
		id = []u8{9, 9, 9, 9, 9, 9, 9, 9},
		token = {0 = 1},
	}
	testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .None)
	testing.expect_value(t, c.migration.peer_sequence, 1)
	testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .None)
	p.new_ids[0].token[0] = 2
	testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .Protocol)
}
@(test)
cid_retirement_rejects_unissued_and_packet_destination :: proc(t: ^testing.T) {
	c: Connection; cid_fixture(&c)
	p := Parsed {
		retire_id_n = 1,
	}; p.retire_ids[0] = c.migration.local_next
	testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .Protocol)
	p.retire_ids[0] = 0
	testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .Protocol)
	current := c.migration.local[1].id
	testing.expect_value(t, apply_ids(&c, p, current[:8]), .None)
	testing.expect(t, !accepts_destination_id(&c, c.local_cid[:8]))
	count := 0; for entry in c.migration.local {
		if entry.used {
			count += 1
		}
	}
	testing.expect_value(t, count, 4)
}
@(test)
cid_limit_and_stale_new_ids_are_bounded :: proc(t: ^testing.T) {
	c: Connection; cid_fixture(&c)
	p := Parsed {
		new_id_n = 1,
	}
	for seq in 1 ..< 4 {
		id := [8]u8 {
			0 = u8(seq),
		}
		p.new_ids[0] = CID_Frame {
			sequence = u64(seq),
			id = id[:],
			token = {0 = u8(seq)},
		}
		testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .None)
	}
	p.new_ids[0] = CID_Frame {
		sequence = 4,
		id = []u8{99},
		token = {0 = 99},
	}
	testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .Protocol)
	p.new_ids[0].retire_prior_to = 4
	testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .None)
	p.new_ids[0] = CID_Frame {
		sequence = 2,
		id = []u8{2},
		token = {0 = 2},
	}
	testing.expect_value(t, apply_ids(&c, p, c.local_cid[:8]), .None)
	testing.expect_value(t, c.migration.peer_sequence, 4)
}
@(test)
path_challenge_response_requires_same_path_and_exact_nonce :: proc(t: ^testing.T) {
	c: Connection; cid_fixture(&c)
	m := &c.migration
	m.paths[1] = Path {
		used = true,
		endpoint = {net.IP4_Loopback, 2345},
		activate = true,
		challenge_pending = true,
		challenge = {0 = 4, 1 = 5},
	}
	p := Parsed {
		path_n = 1,
	}; p.paths[0] = Path_Frame {
		response = true,
		token = {0 = 4, 1 = 5},
	}
	testing.expect_value(t, migration_receive(&c, 10, 1, .One_RTT, 1, p, c.local_cid[:8]), .None)
	testing.expect_value(t, m.active, 0)
	p.paths[0].token[1] = 6
	testing.expect_value(t, migration_receive(&c, 10, 2, .One_RTT, 2, p, c.local_cid[:8]), .None)
	testing.expect_value(t, m.active, 0)
	p.paths[0].token[1] = 5
	testing.expect_value(t, migration_receive(&c, 10, 2, .One_RTT, 3, p, c.local_cid[:8]), .None)
	testing.expect_value(t, m.active, 1)
}
@(test)
path_frames_parse_all_nonces_and_reject_invalid_ids :: proc(t: ^testing.T) {
	frame := [18]u8{0x1a, 1, 2, 3, 4, 5, 6, 7, 8, 0x1b, 8, 7, 6, 5, 4, 3, 2, 1}
	p, ok := parse_frames(frame[:]); testing.expect(t, ok); testing.expect_value(t, p.path_n, 2)
	testing.expect(t, !p.paths[0].response && p.paths[1].response)
	_, ok = parse_frames([]u8{0x18, 0, 1, 1, 9}); testing.expect(t, !ok)
	_, ok = parse_frames([]u8{0x18, 0, 0, 0}); testing.expect(t, !ok)
}

@(test)
path_candidate_budget_expiry_and_active_path_survive_exhaustion :: proc(t: ^testing.T) {
	c: Connection; cid_fixture(&c)
	for i in 1 ..< PATH_SLOTS {
		c.migration.paths[i] = Path {
			used              = true,
			endpoint          = {net.IP4_Loopback, 2000 + i},
			challenge_pending = true,
			expires_at        = 10,
		}
	}
	testing.expect_value(t, candidate_slot(&c), -1)
	buf: [MAX_DATAGRAM]u8; _, _, _ = pump_to(&c, 11, buf[:])
	testing.expect(t, candidate_slot(&c) > 0)
	testing.expect_value(t, active_endpoint(&c).port, 1234)
}
