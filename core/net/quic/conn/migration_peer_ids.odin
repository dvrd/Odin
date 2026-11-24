package conn

import "core:net"

Retired_Peer_Ids :: struct {
	base:   u64,
	values: [CID_CONTROL_SLOTS]u64,
	n:      int,
}

Declined_Preferred_Id :: struct {
	used:  bool,
	id:    [CID_CAP]u8,
	n:     int,
	token: [16]u8,
}

@(private)
peer_was_retired :: proc(c: ^Connection, sequence: u64) -> bool {
	if sequence < c.migration.retired_peer.base {
		return true
	}
	for i in 0 ..< c.migration.retired_peer.n {
		if c.migration.retired_peer.values[i] == sequence {
			return true
		}
	}
	return false
}

@(private)
retired_peer_advance :: proc(r: ^Retired_Peer_Ids, base: u64) {
	r.base = max(r.base, base)
	at := 0
	for at < r.n {
		value := r.values[at]
		if value > r.base {
			at += 1
			continue
		}
		if value == r.base {
			r.base += 1
		}
		r.n -= 1
		r.values[at] = r.values[r.n]
		r.values[r.n] = 0
		at = 0
	}
}

@(private)
retired_peer_record :: proc(r: ^Retired_Peer_Ids, sequence: u64) -> Error {
	if sequence < r.base {
		return .None
	}
	for i in 0 ..< r.n {
		if r.values[i] == sequence {
			return .None
		}
	}
	if sequence == r.base {
		retired_peer_advance(r, r.base + 1)
		return .None
	}
	if r.n == len(r.values) {
		return .Capacity
	}
	r.values[r.n] = sequence
	r.n += 1
	return .None
}

@(private)
peer_id_index :: proc(c: ^Connection, sequence: u64) -> int {
	for entry, i in c.migration.peer {
		if entry.used && entry.sequence == sequence {
			return i
		}
	}
	return -1
}

@(private)
unused_peer_id :: proc(c: ^Connection) -> int {
	for entry, i in c.migration.peer {
		if entry.used && !entry.bound {
			return i
		}
	}
	return -1
}

@(private)
bind_peer_id :: proc(c: ^Connection, index: int, endpoint: net.Endpoint) {
	entry := &c.migration.peer[index]
	entry.bound = true
	entry.destination = endpoint
}

@(private)
retire_peer_id :: proc(c: ^Connection, sequence: u64) -> Error {
	next := c.migration.retired_peer
	if e := retired_peer_record(&next, sequence); e != .None {
		return e
	}
	if e := queue_retirement(c, sequence); e != .None {
		return e
	}
	c.migration.retired_peer = next
	index := peer_id_index(c, sequence)
	if index >= 0 {
		c.migration.peer[index] = {}
	}
	for &path in c.migration.paths {
		if path.has_peer_id && path.peer_sequence == sequence {
			path.has_peer_id = false
			path.owns_peer_id = false
		}
	}
	return .None
}

@(private)
withdraw_peer_binding :: proc(c: ^Connection, sequence: u64) {
	if c.migration.peer_sequence == sequence {
		c.migration.peer_blocked = true
	}
	for &path in c.migration.paths {
		if path.has_peer_id && path.peer_sequence == sequence {
			path.has_peer_id = false
		}
	}
}

@(private)
ensure_current_peer_id :: proc(c: ^Connection) {
	m := &c.migration
	if peer_id_index(c, m.peer_sequence) >= 0 {
		return
	}
	index := unused_peer_id(c)
	if index < 0 {
		m.peer_blocked = true
		return
	}
	bind_peer_id(c, index, m.paths[m.active].endpoint)
	_ = select_peer_id(c, m.peer[index].sequence)
	active := &m.paths[m.active]
	active.has_peer_id = true
	active.peer_sequence = m.peer_sequence
}

// Decline only the optional address migration. The authenticated sequence1 CID
// is still an issued CID and must be retired, including after duplicate offers.
decline_preferred_address :: proc(c: ^Connection, id, token: []u8) -> Error {
	if e := usable(c); e != .None {
		return e
	}
	if !c.migration.enabled ||
	   c.role != .Client ||
	   len(id) < 1 ||
	   len(id) > CID_CAP ||
	   len(token) != 16 ||
	   c.peer_cid_len == 0 {
		return .Invalid
	}
	m := &c.migration
	declined := &m.declined_preferred
	if declined.used {
		if string(id) != string(declined.id[:declined.n]) || string(token) != string(declined.token[:]) {
			return .Protocol
		}
		return queue_retirement(c, 1)
	}
	if m.peer_sequence == 1 {
		return .Protocol
	}
	for path in m.paths {
		if path.used && path.has_peer_id && path.peer_sequence == 1 {
			return .Protocol
		}
	}
	p := Parsed {
		new_id_n = 1,
	}
	p.new_ids[0] = {
		sequence = 1,
		id       = id,
	}
	copy(p.new_ids[0].token[:], token)
	if e := apply_ids(c, p, c.local_cid[:c.local_cid_len]); e != .None {
		return e
	}
	if e := retire_peer_id(c, 1); e != .None {
		return e
	}
	declined.used = true
	declined.n = copy(declined.id[:], id)
	copy(declined.token[:], token)
	return .None
}
