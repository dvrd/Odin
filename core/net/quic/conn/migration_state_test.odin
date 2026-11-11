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
cid_retirement_rejects_allocated_but_never_sent_sequence :: proc(t:^testing.T) {
 c:Connection;cid_fixture(&c)
 p:=Parsed{retire_id_n=1};p.retire_ids[0]=1
 testing.expect(t,c.migration.local[1].used&&!c.migration.local[1].sent_once)
 testing.expect_value(t,apply_ids(&c,p,c.local_cid[:8]),.Protocol)
 testing.expect(t,c.migration.local[1].used)
}

@(test)
preferred_address_decline_retires_without_selection_and_remembers_duplicates :: proc(t:^testing.T) {
 c:Connection;cid_fixture(&c);before:=c.peer_cid
 id:=[8]u8{9,9,9,9,9,9,9,9};token:=[16]u8{0=19}
 testing.expect_value(t,decline_preferred_address(&c,id[:],token[:]),.None)
 testing.expect_value(t,c.peer_cid,before);testing.expect_value(t,c.migration.peer_sequence,u64(0))
 testing.expect(t,c.migration.declined_preferred.used&&peer_was_retired(&c,1));testing.expect_value(t,peer_id_index(&c,1),-1)
 for &retired in c.migration.retire {if retired.used&&retired.sequence==1 {retired.in_flight=true;retired.pn=5}}
 ack:=Parsed{ack=true,ack_n=1};ack.ack_ranges[0]={5,5};migration_ack(&c,ack)
 p:=Parsed{new_id_n=1};p.new_ids[0]={sequence=1,id=id[:],token=token}
 testing.expect_value(t,apply_ids(&c,p,c.local_cid[:8]),.None);testing.expect_value(t,peer_id_index(&c,1),-1)
 queued:=false;for retired in c.migration.retire {if retired.used&&retired.sequence==1 {queued=true}};testing.expect(t,queued)
 p.new_ids[0].token[0]~=1;testing.expect_value(t,apply_ids(&c,p,c.local_cid[:8]),.Protocol)
 testing.expect_value(t,c.peer_cid,before)
 testing.expect_value(t,decline_preferred_address(&c,id[:],token[:]),.None)
 id[0]~=1;testing.expect_value(t,decline_preferred_address(&c,id[:],token[:]),.Protocol)
}

@(test)
retired_peer_history_merges_holes_and_never_forgets_a_retired_id :: proc(t:^testing.T) {
 r:Retired_Peer_Ids
 for value in ([]u64{2,4,1,0}) {testing.expect_value(t,retired_peer_record(&r,value),.None)}
 testing.expect_value(t,r.base,u64(3));testing.expect_value(t,r.n,1);testing.expect_value(t,r.values[0],u64(4))
 testing.expect_value(t,retired_peer_record(&r,3),.None);testing.expect_value(t,r.base,u64(5));testing.expect_value(t,r.n,0)
 for i in 0..<CID_CONTROL_SLOTS {testing.expect_value(t,retired_peer_record(&r,u64(100+i*2)),.None)}
 before:=r;testing.expect_value(t,retired_peer_record(&r,1000),.Capacity);testing.expect_value(t,r,before)
 retired_peer_advance(&r,1000);testing.expect_value(t,r.base,u64(1000));testing.expect_value(t,r.n,0)
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
path_response_validates_sent_challenge_origin_on_any_arrival_path :: proc(t:^testing.T) {
 c:Connection;cid_fixture(&c);m:=&c.migration
 m.paths[1]={used=true,endpoint={net.IP4_Loopback,2345},activate=true,challenge_pending=true,challenge={0=4,1=5},attempts=1,expires_at=100}
 m.paths[2]={used=true,endpoint={net.IP4_Loopback,3456},challenge_pending=true,challenge={0=6},expires_at=100}
 m.paths[3]={used=true,endpoint={net.IP4_Loopback,4567},activate=true,challenge_pending=true,challenge={0=7},attempts=1,expires_at=5}
 p:=Parsed{path_n=1};p.paths[0]={response=true,token={0=4,1=6}}
 testing.expect_value(t,migration_receive(&c,10,3,.One_RTT,1,p,c.local_cid[:8]),.None)
 testing.expect_value(t,m.active,0);testing.expect(t,!m.paths[1].validated&&!m.paths[2].validated)
 p.paths[0].token={0=6};_=migration_receive(&c,10,3,.One_RTT,2,p,c.local_cid[:8]);testing.expect(t,!m.paths[2].validated)
 p.paths[0].token={0=7};_=migration_receive(&c,10,3,.One_RTT,3,p,c.local_cid[:8]);testing.expect(t,!m.paths[3].validated)
 p.paths[0].token={0=4,1=5}
 testing.expect_value(t,migration_receive(&c,10,3,.One_RTT,4,p,c.local_cid[:8]),.None)
 testing.expect_value(t,m.active,1);testing.expect(t,m.paths[1].validated&&!m.paths[1].challenge_pending)
 testing.expect(t,!m.paths[2].validated);testing.expect_value(t,m.paths[1].endpoint.port,2345)
 // A replay of the consumed token cannot validate its new arrival path.
 _=migration_receive(&c,11,3,.One_RTT,5,p,c.local_cid[:8]);testing.expect(t,!m.paths[2].validated)
 // A small initial probe validates only its origin address; a fresh expanded
 // challenge is still necessary before promotion/MTU admission.
 m.paths[3].expires_at=100;m.paths[3].small_challenge=true;p.paths[0].token={0=7}
 _=migration_receive(&c,12,3,.One_RTT,6,p,c.local_cid[:8])
 testing.expect(t,m.paths[3].validated&&m.paths[3].challenge_pending&&!m.paths[3].small_challenge)
 testing.expect_value(t,m.paths[3].attempts,0);testing.expect_value(t,m.active,1)
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
