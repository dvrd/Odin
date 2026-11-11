package conn

import "core:bytes"
import "core:crypto"
import "core:net"
import "core:net/quic"
import ecn "core:net/quic/ecn"
import "core:net/quic/harness"

CID_SLOTS :: 4
PATH_SLOTS :: 4
CID_CONTROL_SLOTS :: 16
CID_Entry :: struct {
	used, pending, in_flight, has_token: bool,
	sequence, pn:                        u64,
	id:                                  [CID_CAP]u8,
	n:                                   int,
	token:                               [16]u8,
}
CID_Retirement :: struct {
	used, in_flight: bool,
	sequence, pn:    u64,
}
Path :: struct {
	used, validated, challenge_pending, activate: bool,
	endpoint:                                     net.Endpoint,
	challenge:                                    [8]u8,
	challenge_at, expires_at:                     i64,
	attempts:                                     int,
	small_challenge:                              bool,
	received, sent:                               int,
	response_pending:                             bool,
	response:                                     [8]u8,
	latest_nonprobing:                            u64,
}
Migration :: struct {
	enabled, peer_disables:             bool,
	paths:                              [PATH_SLOTS]Path,
	active, receiving, output:          int,
	local, peer:                        [CID_SLOTS]CID_Entry,
	retire:                             [CID_CONTROL_SLOTS]CID_Retirement,
	local_next, peer_prior, peer_limit: u64,
	peer_sequence:                      u64,
	latest_nonprobing:                  u64,
	have_nonprobing:                    bool,
}

// Enable only after peer transport parameters have been authenticated. Arrays
// and reset tokens remain connection-owned. A zero-length CID cannot migrate.
migration_enable :: proc(
	c: ^Connection,
	peer: net.Endpoint,
	peer_cid_limit: u64 = 2,
	peer_disables_migration: bool = false,
	initial_reset_token: []u8 = nil,
	peer_reset_token: []u8 = nil,
) -> Error {
	if e := usable(c); e != .None {
		return e
	}
	if c.migration.enabled ||
	   peer.address == nil ||
	   peer_cid_limit < 2 ||
	   c.local_cid_len == 0 ||
	   c.peer_cid_len == 0 ||
	   (len(initial_reset_token) != 0 && len(initial_reset_token) != 16) ||
	   (len(peer_reset_token) != 0 && len(peer_reset_token) != 16) {
		return .Invalid
	}
	m := &c.migration; m.enabled = true; m.peer_disables = peer_disables_migration
	m.peer_limit = min(peer_cid_limit, u64(CID_SLOTS)); m.local_next = 1
	m.local[0] = CID_Entry {
		used = true,
		n    = c.local_cid_len,
		id   = c.local_cid,
	}; m.peer[0] = CID_Entry {
		used = true,
		n    = c.peer_cid_len,
		id   = c.peer_cid,
	}
	if len(initial_reset_token) == 16 {
		copy(m.local[0].token[:], initial_reset_token); m.local[0].has_token = true
	}
	if len(peer_reset_token) == 16 {
		copy(m.peer[0].token[:], peer_reset_token); m.peer[0].has_token = true
	}
	m.paths[0] = Path {
		used      = true,
		validated = true,
		endpoint  = peer,
	}
	c.model.has_path = true; c.model.path = 1; c.model.address_validated = true
	return replenish_ids(c)
}

accepts_destination_id :: proc(c: ^Connection, id: []u8) -> bool {
	if c == nil {
		return false
	}
	if !c.migration.enabled {
		return cid_equal(c.local_cid[:c.local_cid_len], id)
	}
	for &entry in c.migration.local {
		if entry.used && cid_equal(entry.id[:entry.n], id) {
			return true
		}
	}
	return false
}

// Token ownership query is also used by the independent stateless-reset layer.
peer_reset_tokens :: proc(c: ^Connection, dst: [][16]u8) -> int {
	if c == nil {
		return 0
	}; n := 0
	for &entry in c.migration.peer {
		if entry.used && entry.has_token {
			if n == len(dst) {
				break
			}; dst[n] = entry.token; n += 1
		}
	}
	return n
}

@(private)
replenish_ids :: proc(c: ^Connection) -> Error {
	m := &c.migration; count := 0
	for &entry in m.local {
		if entry.used {
			count += 1
		}
	}
	for &entry in m.local {
		if count >= int(m.peer_limit) {
			break
		}; if entry.used {
			continue
		}
		if m.local_next >= u64(1) << 62 {
			return .Capacity
		}
		entry = CID_Entry {
			used      = true,
			pending   = true,
			sequence  = m.local_next,
			n         = c.local_cid_len,
			has_token = true,
		}; m.local_next += 1
		crypto.rand_bytes(entry.id[:entry.n]); crypto.rand_bytes(entry.token[:]); count += 1
	}
	return .None
}

@(private)
queue_retirement :: proc(c: ^Connection, sequence: u64) -> Error {
	for &entry in c.migration.retire {
		if entry.used && entry.sequence == sequence {
			return .None
		}
	}
	for &entry in c.migration.retire {
		if !entry.used {
			entry = CID_Retirement {
				used     = true,
				sequence = sequence,
			}; return .None
		}
	}
	return .Capacity
}

@(private)
select_peer_id :: proc(c: ^Connection, sequence: u64) -> bool {
	for &entry in c.migration.peer {
		if entry.used && entry.sequence == sequence {
			c.peer_cid = entry.id; c.peer_cid_len = entry.n; c.model.peer_cid = entry.id
			c.model.peer_cid_len = entry.n; c.migration.peer_sequence = sequence; return true
		}
	}
	return false
}

// Rotate the destination CID without losing packet number or retained streams.
rotate_peer_id :: proc(c: ^Connection) -> Error {
	if e := usable(c); e != .None {
		return e
	}; m := &c.migration
	if !m.enabled {
		return .Invalid
	}
	for &entry in m.peer {
		if entry.used && entry.sequence != m.peer_sequence {
			old := m.peer_sequence
			if e := queue_retirement(c, old); e != .None {
				return e
			}
			if !select_peer_id(c, entry.sequence) {
				return .Invalid
			}
			for &prior in m.peer {
				if prior.used && prior.sequence == old {
					prior = {}; break
				}
			}
			return .None
		}
	}
	return .Not_Ready
}

@(private)
apply_ids :: proc(c: ^Connection, p: Parsed, destination_id: []u8) -> Error {
	m := &c.migration
	if !m.enabled {
		return .None
	}
	for i in 0 ..< p.new_id_n {
		f := p.new_ids[i]
		if f.retire_prior_to > f.sequence {
			return .Protocol
		}
		// Conflicting reuse of either a sequence, a CID, or a token is a protocol error.
		found := false
		for &entry in m.peer {
			if !entry.used {
				continue
			}
			same := entry.sequence == f.sequence
			if same {
				if !cid_equal(entry.id[:entry.n], f.id) ||
				   !bytes.equal(entry.token[:], f.token[:]) {
					return .Protocol
				}; found = true
			}
			if !same &&
			   (cid_equal(entry.id[:entry.n], f.id) ||
					   entry.has_token && bytes.equal(entry.token[:], f.token[:])) {
				return .Protocol
			}
		}
		m.peer_prior = max(m.peer_prior, f.retire_prior_to)
		for &entry in m.peer {
			if entry.used && entry.sequence < m.peer_prior {
				if e := queue_retirement(c, entry.sequence); e != .None {
					return e
				}; entry = {}
			}
		}
		if f.sequence < m.peer_prior {
			if e := queue_retirement(c, f.sequence); e != .None {
				return e
			}; continue
		}
		if !found {
			index := -1; for entry, j in m.peer {
				if !entry.used {
					index = j; break
				}
			}
			if index < 0 {
				c.reason = "connection id limit"; return .Protocol
			}
			entry := &m.peer[index]; entry^ = CID_Entry {
				used      = true,
				sequence  = f.sequence,
				n         = len(f.id),
				token     = f.token,
				has_token = true,
			}; copy(entry.id[:], f.id)
		}
		have_current := false
		for &entry in m.peer {
			if entry.used && entry.sequence == m.peer_sequence {
				have_current = true
			}
		}
		if !have_current {
			for &entry in m.peer {
				if entry.used {
					_ = select_peer_id(c, entry.sequence); break
				}
			}
		}
	}
	for i in 0 ..< p.retire_id_n {
		seq := p.retire_ids[i]
		if seq >= m.local_next {
			return .Protocol
		}
		for &entry in m.local {
			if entry.used && entry.sequence == seq {
				if cid_equal(entry.id[:entry.n], destination_id) {
					return .Protocol
				}
				entry = {}; break
			}
		}
	}
	return replenish_ids(c)
}

@(private)
packet_active :: proc(c: ^Connection, pn: u64) -> bool {
	for packet in c.model.packets[2] {
		if packet.active && packet.number == pn {
			return true
		}
	}
	return false
}
@(private)
acked_number :: proc(p: Parsed, pn: u64) -> bool {
	for i in 0 ..< p.ack_n {
		if pn >= p.ack_ranges[i][0] && pn <= p.ack_ranges[i][1] {
			return true
		}
	}
	return false
}
@(private)
migration_ack :: proc(c: ^Connection, p: Parsed) {
	if !c.migration.enabled {
		return
	}
	for &entry in c.migration.local {
		if entry.used && entry.in_flight && acked_number(p, entry.pn) {
			entry.in_flight = false; entry.pending = false
		}
	}
	for &entry in c.migration.retire {
		if entry.used && entry.in_flight && acked_number(p, entry.pn) {
			entry = {}
		}
	}
}
@(private)
migration_control :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error, bool) {
	if !c.migration.enabled {
		return 0, .None, false
	}
	frame: [96]u8
	for &entry in c.migration.local {
		if !entry.used || !entry.pending || entry.in_flight && packet_active(c, entry.pn) {
			continue
		}
		at := 1; frame[0] = 0x18; ok: bool
		at, ok = put_varint(frame[:], at, entry.sequence); if !ok {
			return 0, .Capacity, true
		}
		at, ok = put_varint(frame[:], at, 0); if !ok {
			return 0, .Capacity, true
		}
		frame[at] = u8(entry.n); at += 1; copy(frame[at:], entry.id[:entry.n]); at += entry.n
		copy(frame[at:], entry.token[:]); at += 16
		pn := c.model.spaces[2].next_send
		n, e := seal_and_emit(
			c,
			now,
			dst,
			harness.Emit{space = .Application, ping = true},
			frame[:at],
			0,
		)
		if e == .None && n > 0 {
			entry.in_flight = true; entry.pn = pn
		}; return n, e, true
	}
	for &entry in c.migration.retire {
		if !entry.used || entry.in_flight && packet_active(c, entry.pn) {
			continue
		}
		frame[0] = 0x19; at, ok := put_varint(frame[:], 1, entry.sequence); if !ok {
			return 0, .Capacity, true
		}
		pn := c.model.spaces[2].next_send
		n, e := seal_and_emit(
			c,
			now,
			dst,
			harness.Emit{space = .Application, ping = true},
			frame[:at],
			0,
		)
		if e == .None && n > 0 {
			entry.in_flight = true; entry.pn = pn
		}; return n, e, true
	}
	return 0, .None, false
}

@(private)
path_index :: proc(c: ^Connection, peer: net.Endpoint) -> int {
	for path, i in c.migration.paths {
		if path.used && path.endpoint == peer {
			return i
		}
	}
	return -1
}

@(private)
candidate_slot :: proc(c: ^Connection) -> int {
	m := &c.migration
	for path, i in m.paths {
		if !path.used {
			return i
		}
	}
	oldest := -1
	for path, i in m.paths {
		if i == m.active || !path.validated || path.challenge_pending || path.response_pending {
			continue
		}
		if oldest < 0 || path.latest_nonprobing < m.paths[oldest].latest_nonprobing {
			oldest = i
		}
	}
	return oldest
}

// Called by the real UDP owner. A free candidate slot is reserved provisionally;
// authentication must succeed before any bytes or validation state are changed.
ingest_from :: proc(c: ^Connection, now: i64, from: net.Endpoint, datagram: []u8) -> Error {
	if c == nil || !c.migration.enabled || from.address == nil {
		return .Invalid
	}
	index := path_index(c, from); fresh := index < 0
	if fresh {
		index = candidate_slot(c)
		if index < 0 {
			return .Discarded
		}
	}
	old := c.migration.paths[index]
	if fresh {
		c.migration.paths[index] = Path {
			endpoint = from,
		}
	}
	c.migration.receiving = index
	e := ingest(c, now, u32(index + 1), datagram)
	if fresh && !c.migration.paths[index].used {
		c.migration.paths[index] = old
	}
	return e
}

migrate :: proc(c: ^Connection, now: i64, peer: net.Endpoint) -> Error {
	if e := usable(c); e != .None {
		return e
	}; m := &c.migration
	if !m.enabled || m.peer_disables || now < 0 || peer.address == nil {
		return .Invalid
	}
	index := path_index(c, peer)
	if index < 0 {
		index = candidate_slot(c)
	}
	if index < 0 {
		return .Capacity
	}
	path := &m.paths[index]
	// A local socket rebind can retain the remote endpoint. Validation still runs
	// on that socket, while the peer sees a new source and validates its new path.
	if !path.used || path.endpoint != peer {
		path^ = Path {
			used     = true,
			endpoint = peer,
		}
	}
	crypto.rand_bytes(path.challenge[:]); path.challenge_pending = true; path.challenge_at = now
	path.attempts = 0; path.expires_at = now + max(i64(1000), c.model.smoothed_rtt * 9)
	path.activate = true
	return .None
}

@(private)
migration_receive :: proc(
	c: ^Connection,
	now: i64,
	path_id: u32,
	level: quic.Encryption_Level,
	pn: u64,
	p: Parsed,
	destination_id: []u8,
) -> Error {
	m := &c.migration; if !m.enabled {
		return .None
	}
	if level != .One_RTT {
		if int(path_id) != m.active + 1 {
			return .Discarded
		}; return .None
	}
	index := int(path_id) - 1; if index < 0 || index >= len(m.paths) {
		return .Discarded
	}
	path := &m.paths[index]
	if e := apply_ids(c, p, destination_id); e != .None {
		fail(c, "connection id lifecycle"); return e
	}
	nonprobing :=
		p.stream ||
		p.ack ||
		p.ping ||
		p.crypto ||
		p.close ||
		p.handshake_done ||
		p.reset ||
		p.stop ||
		p.max_data ||
		p.max_stream_data ||
		p.max_streams_bidi ||
		p.max_streams_uni ||
		p.retire_id_n > 0
	if !path.used {
		path.used = true; crypto.rand_bytes(path.challenge[:]); path.challenge_pending = true
		path.challenge_at = now; path.attempts = 0
		path.expires_at = now + max(i64(1000), c.model.smoothed_rtt * 9)
	}
	if nonprobing && (!m.have_nonprobing || pn > m.latest_nonprobing) {
		m.latest_nonprobing = pn; m.have_nonprobing = true; path.latest_nonprobing = pn
		if index != m.active {
			path.activate = true; if path.validated {
				promote_path(c, index, now)
			}
		}
	}
	for i in 0 ..< p.path_n {
		f := p.paths[i]
		if !f.response {
			path.response_pending = true; path.response = f.token; continue
		}
		if path.challenge_pending &&
		   crypto.compare_constant_time(f.token[:], path.challenge[:]) == 1 {
			path.validated = true; path.challenge_pending = false
			if path.small_challenge {
				crypto.rand_bytes(path.challenge[:]); path.challenge_pending = true
				path.challenge_at = now; path.attempts = 0; path.small_challenge = false
				path.expires_at = now + max(i64(1000), c.model.smoothed_rtt * 9)
			} else if path.activate {
				promote_path(c, index, now)
			}
		}
	}
	return .None
}

@(private)
promote_path :: proc(c: ^Connection, index: int, now: i64) {
	m := &c.migration
	if index == m.active {
		return
	}
	old := m.paths[m.active].endpoint; next := m.paths[index].endpoint
	m.paths[m.active].received = c.model.path_received; m.paths[m.active].sent = c.model.path_sent
	m.active = index; c.model.path = u32(index + 1); c.model.address_validated = true
	c.model.bytes_in_flight = 0; for packet in c.model.packets[2] {
		if packet.active && packet.in_flight && packet.path == c.model.path {
			c.model.bytes_in_flight += packet.sent_bytes
		}
	}
	c.model.path_received = m.paths[index].received; c.model.path_sent = m.paths[index].sent
	// A port-only NAT rebind can retain congestion/RTT estimates. A different
	// network starts fresh; old in-flight packets remain retained for recovery.
	if old.address != next.address {
		harness.migrate_path(&c.model, now)
	}
	ecn.reset_path(&c.ecn.sender); c.ecn.started = now
	// Rotation prevents linking subsequent packets through the old peer CID.
	_ = rotate_peer_id(c)
}

pump_to :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, net.Endpoint, Error) {
	if c == nil || !c.migration.enabled {
		return 0, {}, .Invalid
	}
	m := &c.migration
	if c.phase == .Draining {
		return 0, m.paths[m.active].endpoint, .None
	}
	if e := usable(c); e != .None {
		return 0, m.paths[m.active].endpoint, e
	}
	for &path, i in m.paths {
		if !path.used {
			continue
		}
		if i != m.active &&
		   path.challenge_pending &&
		   path.expires_at > 0 &&
		   now >= path.expires_at {
			path = {}; continue
		}
		response := path.response_pending
		challenge := path.challenge_pending && now >= path.challenge_at
		if challenge && path.attempts >= 3 {
			path.challenge_pending = false
			if i != m.active {
				path = {}
			}; continue
		}
		if !response && !challenge {
			continue
		}
		// Validation datagrams are padded to the minimum QUIC path size. Until the
		// server validates a candidate, its independent budget is at most 3x input.
		budget := 1200
		if c.role == .Server && !path.validated {
			budget = min(1200, max(0, path.received * 3 - path.sent)); if budget < 64 {
				continue
			}
		}
		old_path := c.model.path; old_validated := c.model.address_validated
		old_recv := c.model.path_received; old_sent := c.model.path_sent
		old_flight := c.model.bytes_in_flight
		c.model.bytes_in_flight = 0; for packet in c.model.packets[2] {
			if packet.active &&
			   packet.in_flight &&
			   packet.path == u32(i + 1) &&
			   packet.path_epoch == c.model.path_epoch {
				c.model.bytes_in_flight += packet.sent_bytes
			}
		}
		c.model.path = u32(i + 1); c.model.address_validated = path.validated
		c.model.path_received = path.received; c.model.path_sent = path.sent
		frame: [1200]u8; frame[0] = 0x1a
		token := path.challenge
		if response {
			frame[0] = 0x1b; token = path.response
		}; copy(frame[1:9], token[:])
		size := c.max_datagram; c.max_datagram = budget; full := c.full_size; c.full_size = true
		sent_before := c.model.path_sent
		n, e := seal_and_emit(
			c,
			now,
			dst,
			harness.Emit{space = .Application, ping = true},
			frame[:9],
			0,
		)
		c.max_datagram = size; c.full_size = full; path.sent = c.model.path_sent
		c.model.path = old_path; c.model.address_validated = old_validated
		c.model.path_received = old_recv; c.model.path_sent = old_sent
		if i != m.active {
			c.model.bytes_in_flight = old_flight
		} else {
			c.model.path_sent = old_sent + max(0, path.sent - sent_before)
		}
		if e == .None && n > 0 {
			if response {
				path.response_pending = false
			} else {
				path.small_challenge = n < 1200; path.attempts += 1
				path.challenge_at = now + max(i64(100), c.model.smoothed_rtt * 3)
			}
		}
		return n, path.endpoint, e
	}
	n, e := pump(c, now, dst); m.output = m.active
	return n, m.paths[m.active].endpoint, e
}

// Current validated remote endpoint; timer-generated output uses this path.
active_endpoint :: proc(c: ^Connection) -> net.Endpoint {
	if c == nil || !c.migration.enabled {
		return {}
	}; return c.migration.paths[c.migration.active].endpoint
}
