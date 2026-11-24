package conn

import "core:net/quic"
import "core:net/quic/harness"

// Adopt only after the wire TLS driver has authenticated its peer and completed
// Finished. Success transfers key ownership; failure leaves owner unchanged.
Adopt_Config :: struct {
	role:                                                             quic.Role,
	local_cid, peer_cid:                                              []u8,
	limits:                                                           harness.Limits,
	max_datagram:                                                     int,
	next_send_pn, next_handshake_send_pn, largest_recv_pn, recv_bits: u64,
	have_largest_recv:                                                bool,
	directional_limits:                                               bool,
	peer_max_data, peer_bidi_local, peer_bidi_remote, peer_uni:       u64,
	peer_bidi_streams, peer_uni_streams:                              u64,
}
adopt_established :: proc(c: ^Connection, owner: ^quic.Handshake, cfg: Adopt_Config) -> Error {
	if c == nil ||
	   owner == nil ||
	   c.initialized ||
	   owner.failed ||
	   !owner.have_one_rtt ||
	   !owner.handshake_complete ||
	   !owner.peer_authenticated ||
	   owner.role != cfg.role {
		return .Invalid
	}
	if len(cfg.local_cid) > CID_CAP ||
	   len(cfg.peer_cid) > CID_CAP ||
	   cfg.next_send_pn >= u64(1) << 62 {
		return .Invalid
	}
	if cfg.limits.recv_max_stream_data > STREAM_BYTES {
		return .Invalid
	}
	size := cfg.max_datagram; if size == 0 {
		size = harness.K_MIN_INITIAL_DATAGRAM
	}
	c^ = {}; c.role = cfg.role; c.max_datagram = size
	copy(c.local_cid[:], cfg.local_cid); copy(c.peer_cid[:], cfg.peer_cid)
	c.local_cid_len = len(cfg.local_cid); c.peer_cid_len = len(cfg.peer_cid)
	role := harness.Role.Client; if cfg.role == .Server {
		role = .Server
	}
	if e := harness.init(
		&c.model,
		role,
		cfg.local_cid,
		cfg.peer_cid,
		c.initial_pkts[:],
		c.handshake_pkts[:],
		c.app_pkts[:],
		c.model_streams[:],
		size,
	); e != .None {
		return map_harness(e)
	}
	if e := harness.configure(&c.model, cfg.limits); e != .None {
		harness.destroy(&c.model); return map_harness(e)
	}
	_ = harness.discard_space(&c.model, .Initial); _ = harness.confirm_handshake(&c.model)
	c.model.address_validated = true; c.model.has_path = true
	c.directional_limits = cfg.directional_limits
	c.peer_bidi_local = cfg.peer_bidi_local; c.peer_bidi_remote = cfg.peer_bidi_remote
	c.peer_uni = cfg.peer_uni
	c.peer_bidi_streams = cfg.peer_bidi_streams; c.peer_uni_streams = cfg.peer_uni_streams
	if cfg.directional_limits {
		c.model.max_data = cfg.peer_max_data
	}
	sp := &c.model.spaces[2]; sp.next_send = cfg.next_send_pn
	if cfg.have_largest_recv {
		sp.has_recv = true; sp.has_largest_recv = true; sp.largest_recv = cfg.largest_recv_pn
		sp.recv_base = cfg.largest_recv_pn - min(cfg.largest_recv_pn, u64(63))
		for i in 0 ..< 64 {
			if cfg.recv_bits & (u64(1) << uint(i)) != 0 && u64(i) <= cfg.largest_recv_pn {
				sp.recv_bits |= u64(1) << uint(cfg.largest_recv_pn - u64(i) - sp.recv_base)
			}
		}
		c.model.ack_pending[2] = true
	}
	c.hs = owner^; owner^ = {}
	if cfg.role == .Client && !c.hs.handshake_discarded {
		c.model.handshake_armed = true; c.model.spaces[1].discarded = false
		c.model.spaces[1].next_send = cfg.next_handshake_send_pn
	}
	c.initialized = true; c.phase = .Established; c.server_keys = true; c.accepted = true
	c.authed = true; c.finished_marked = true; c.got_finished = true
	c.seen_done = cfg.role == .Server || c.hs.handshake_discarded
	if c.seen_done {
		c.fin_off = c.hs.client_finished_len
	}; c.done_sent = cfg.role == .Client; c.noted_send = true
	c.noted_recv = true
	return .None
}

next_readable :: proc(c: ^Connection, after: Maybe(u64)) -> (u64, bool) {
	best := max(u64); found := false
	for b in c.bufs {
		if b.used && (b.recv_n > 0 || b.recv_fin || b.recv_reset) {
			if a, ok := after.?; ok && b.id <= a {
				continue
			}; if b.id < best {
				best = b.id; found = true
			}
		}
	}
	return best, found
}

Tx_Packet :: struct {
	active:                   bool,
	pn, id, offset:           u64,
	n:                        int,
	fin, reset, credit, done,stop: bool,
	credit_value:             u64,
}

@(private)
send_direction :: proc(c: ^Connection, id: u64) -> bool {
	if id >= u64(1) << 62 {
		return false
	}
	local := id % 2 == u64(c.role)
	return local || id & 2 == 0 && find_buf(c, id) != nil
}
@(private)
send_limits :: proc(c: ^Connection, id: u64) -> (u64, u64) {
	if !c.directional_limits {
		return c.model.max_stream_data_send, c.model.max_streams_send
	}
	if id & 2 != 0 {
		return c.peer_uni, c.peer_uni_streams
	}
	if id % 2 == u64(c.role) {
		return c.peer_bidi_remote, c.peer_bidi_streams
	}
	return c.peer_bidi_local, c.peer_bidi_streams
}
@(private)
compact_send :: proc(c: ^Connection, b: ^Buf) {
	n := 0; for n < b.n && b.send_acked[n] {n += 1}; if n == 0 {
		return
	}
	idx := int((uintptr(b) - uintptr(&c.bufs[0])) / size_of(Buf))
	copy(c.send_mem[idx][:], c.send_mem[idx][n:b.n])
	for i in 0 ..< b.n -
		n {b.send_acked[i] = b.send_acked[i + n]; b.send_retry[i] = b.send_retry[i + n]}
	for i in b.n - n ..< STREAM_BYTES {b.send_acked[i] = false; b.send_retry[i] = false}
	b.n -= n; b.sent = max(0, b.sent - n); b.send_base += u64(n)
}
@(private)
receive_stream :: proc(c: ^Connection, p: Parsed) -> Error {
	b, e := take_recv(c, p.stream_id); if e != .None {
		return e
	}
	end := p.stream_off + u64(len(p.stream_data)); if end < p.stream_off {
		return .Protocol
	}
	if b.recv_reset {
		if end > b.recv_final || p.fin && end != b.recv_final {
			return .Protocol
		}
		return .None
	}
	if b.recv_fin && (end > b.recv_final || p.fin && end != b.recv_final) {
		return .Protocol
	}
	if end > b.recv_base + STREAM_BYTES {
		return .Discarded
	}
	unique := 0; idx := int((uintptr(b) - uintptr(&c.bufs[0])) / size_of(Buf))
	present := b.recv_present
	for v, i in p.stream_data {
		off := p.stream_off + u64(i); if off < b.recv_base {
			continue
		}; at := int(off - b.recv_base)
		if present[at] {
			if c.recv_mem[idx][at] != v {
				return .Protocol
			}
		} else {
			present[at] = true; unique += 1
		}
	}
	contiguous := 0; for contiguous < STREAM_BYTES && present[contiguous] {contiguous += 1}
	if e := harness.stream_receive_admit(
		&c.model,
		p.stream_id,
		p.stream_off,
		len(p.stream_data),
		unique,
		b.recv_base + u64(contiguous),
		p.fin,
	); e != .None {
		c.reason = "stream receive accounting"; return map_harness(e)
	}
	for v, i in p.stream_data {
		off := p.stream_off + u64(i); if off >= b.recv_base {
			c.recv_mem[idx][int(off - b.recv_base)] = v
		}
	}
	b.recv_present = present; b.recv_n = contiguous
	if b.recv_credit == 0 {
		b.recv_credit = c.model.max_stream_data_recv
	}
	if p.fin {
		b.recv_fin = true; b.recv_final = end
	}
	return .None
}
@(private)
mark_retry :: proc(c: ^Connection, t: Tx_Packet) {
	if t.done {
		c.done_sent = false; return
	}
	if b := find_buf(c, t.id); b != nil {
		if t.stop {b.stop_retry=true;return}
        if t.credit {
			b.credit_dirty = true; return
		}
		for i in 0 ..< t.n {
			off := t.offset + u64(i); if off >= b.send_base && off < b.send_base + u64(b.n) {
				at := int(off - b.send_base); if !b.send_acked[at] {
					b.send_retry[at] = true
				}
			}
		}
		if t.fin && !b.fin_acked {
			b.fin_retry = true
		}; if t.reset && !b.reset_acked {
			b.reset_retry = true
		}
	}
}
@(private)
sync_tx :: proc(c: ^Connection) {
	for &t in c.tx {
		if t.active {
			found := false; for p in c.app_pkts {
				if p.active && p.number == t.pn {
					found = true; break
				}
			}; if !found {
				mark_retry(c, t); t.active = false
			}
		}
	}
}
@(private)
retry_oldest :: proc(c: ^Connection) {
	best := max(u64); slot := -1; for t, i in c.tx {
		if t.active && t.pn < best {
			best = t.pn; slot = i
		}
	}; if slot >= 0 {
		mark_retry(c, c.tx[slot])
	}
}
@(private)
acknowledge_tx :: proc(c: ^Connection, p: Parsed) {
	if !p.ack {
		return
	}
	for &t in c.tx {
		if !t.active {
			continue
		}; acked := false; for ri in 0 ..< p.ack_n {
			r := p.ack_ranges[ri]; if t.pn >= r[0] && t.pn <= r[1] {
				acked = true; break
			}
		}; if acked {
			if b:=find_buf(c,t.id);b!=nil&&t.stop {b.stop_acked=true;b.stop_retry=false}
            if b := find_buf(c, t.id); b != nil && !t.credit && !t.stop {
				n := 0; for i in 0 ..< t.n {
					off := t.offset + u64(i)
					if off >= b.send_base && off < b.send_base + u64(b.n) {
						at := int(off - b.send_base); if !b.send_acked[at] {
							b.send_acked[at] = true; b.send_retry[at] = false; n += 1
						}
					}
				}
				if t.fin {
					b.fin_acked = true; b.fin_retry = false
				}; if t.reset {
					b.reset_retry = false;b.reset_acked=true;b.fin_acked=true;b.fin_retry=false
                    idx:=int((uintptr(b)-uintptr(&c.bufs[0]))/size_of(Buf));for &value in c.send_mem[idx] {value=0}
                    b.send_base=b.reset_final;b.n=0;b.sent=0;b.send_acked={};b.send_retry={}
				}
				_ = harness.stream_send_ack(&c.model, b.id, n, t.fin, t.reset); compact_send(c, b)
			}
			t.active = false
		}
	}
}
@(private)
record_tx :: proc(c: ^Connection, t: Tx_Packet) -> bool {
	for &slot in c.tx {
		if !slot.active {
			slot = t; slot.active = true; return true
		}
	}; return false
}
@(private)
send_owned_stream :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error, bool) {
	if !journal_room(c) {
		return 0, .None, false
	}
	for &b, idx in c.bufs {
		if !b.used {
			continue
		}
		if b.credit_dirty {
			// A probe after a PTO is not held back by the congestion window.
			req := harness.Emit {
				space = .Application,
				ping  = true,
				probe = c.force_probe,
			}; attach_ack(c, &req, .Application)
			frame: [MAX_DATAGRAM]u8; at, ok := encode_ack_if(c,frame[:], 0, req)
			if ok {
				at, ok = encode_credit(frame[:], at, b.id, b.recv_credit, c.model.recv_max_data)
			}
			if !ok {
				return 0, .Capacity, true
			}
			pn := c.model.spaces[2].next_send
			amount, e := seal_and_emit(c, now, dst, req, frame[:at], 0); if e != .None {
				return amount, e, true
			}
			if !record_tx(c, {pn = pn, id = b.id, credit = true, credit_value = b.recv_credit}) {
				fail(c, "retention journal full"); return 0, .Failed, true
			}
			b.credit_dirty = false; c.force_probe = false
			return amount, .None, true
		}
		off, n := 0, 0; fin, reset := false, false
		if b.reset {
			if b.reset_acked || b.reset_sent && !b.reset_retry {
				continue
			}; reset = true
		} else {
			retry := -1; for i in 0 ..< b.n {
				if b.send_retry[i] && !b.send_acked[i] {
					retry = i; break
				}
			}
			if retry >= 0 {
				off = retry
				for off + n < b.n && b.send_retry[off + n] && !b.send_acked[off + n] {n += 1}
			} else {
				off = b.sent; n = b.n - b.sent
			}
			fin =
				b.fin && !b.fin_acked && (off + n == b.n) && (!b.fin_sent || b.fin_retry || n > 0)
			if n == 0 && !fin {
				continue
			}
		}
		req := harness.Emit {
			space     = .Application,
			ping      = true,
			more_data = true,
			probe     = c.force_probe,
		}; attach_ack(c, &req, .Application)
		frame: [MAX_DATAGRAM]u8; at, ok := encode_ack_if(c,frame[:], 0, req)
		if !ok {
			return 0, .Capacity, true
		}
		if reset {
			at, ok = encode_reset(frame[:], at, b.id, b.reset_final,b.reset_error)
		} else {
			at, ok = encode_stream(
				frame[:],
				at,
				b.id,
				b.send_base + u64(off),
				c.send_mem[idx][off:off + n],
				fin,
			)
		}
		if !ok {
			return 0, .Capacity, true
		}
		pn := c.model.spaces[2].next_send
		amount, e := seal_and_emit(c, now, dst, req, frame[:at], 0); if e != .None {
			return amount, e, true
		}
		if !record_tx(
			c,
			{pn = pn, id = b.id, offset = b.send_base + u64(off), n = n, fin = fin, reset = reset},
		) {
			fail(c, "retention journal full"); return 0, .Failed, true
		}
		for i in off ..< off + n {b.send_retry[i] = false}; b.sent = max(b.sent, off + n)
		if fin {
			b.fin_sent = true; b.fin_retry = false
		}; if reset {
			b.reset_sent = true; b.reset_retry = false
		}
		c.force_probe = false
		return amount, .None, true
	}
	return 0, .None, false
}

@(private)
send_path_response :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error) {
	req := harness.Emit {
		space = .Application,
		ping  = true,
	}; attach_ack(c, &req, .Application)
	frame: [64]u8; at, ok := encode_ack_if(c,frame[:], 0, req); if !ok || len(frame) - at < 9 {
		return 0, .Capacity
	}
	frame[at] = 0x1b; at += 1; copy(frame[at:at + 8], c.path_response_token[:]); at += 8
	n, e := seal_and_emit(c, now, dst, req, frame[:at], 0); if e == .None {
		c.path_response_pending = false
	}; return n, e
}

@(private)
journal_room :: proc(c: ^Connection) -> bool {
	sync_tx(c)
	for t in c.tx {
		if !t.active {
			return true
		}
	}
	return false
}
