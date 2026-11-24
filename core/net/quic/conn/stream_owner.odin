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
	// Zero keeps the embedded STREAM_BYTES windows and allocates nothing.
	// limits.recv_max_stream_data must fit in the receive window.
	windows:                                                          Stream_Windows,
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
	recv_window := cfg.windows.recv if cfg.windows.recv != 0 else STREAM_BYTES
	if recv_window < 0 || cfg.limits.recv_max_stream_data > u64(recv_window) {
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
	if e := pool_setup(c, cfg.windows, cfg.limits.recv_max_data); e != .None {
		harness.destroy(&c.model); return e
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
	n := win_run(c, b, .Send, .Acked, b.send_base, b.n, true); if n == 0 {
		return
	}
	// An idle stream holds no block.
	if n == b.n {
		win_clear(c, b, .Send)
	} else {
		win_advance(c, b, .Send, b.send_base + u64(n))
	}
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
	window := u64(c.streams.window[.Recv])
	if end > b.recv_base + window {
		return .Discarded
	}
	// Bytes below recv_base were delivered. The rest must agree with what is held.
	lo := max(p.stream_off, b.recv_base); data: []u8
	if lo < end {
		data = p.stream_data[int(lo - p.stream_off):]
	}
	unique := 0
	for done := 0; done < len(data); {
		block, at, count := win_segment(c, b, .Recv, lo + u64(done), len(data) - done)
		if block == nil {
			unique += count
		} else {
			present := win_bitmap(c, block, PRESENT)
			for i in 0 ..< count {
				bit := at + i
				if present[bit >> 3] & (1 << uint(bit & 7)) == 0 {
					unique += 1
				} else if block[bit] != data[done + i] {
					return .Protocol
				}
			}
		}
		done += count
	}
	frontier := b.recv_base + u64(b.recv_n); contiguous := frontier
	if lo <= frontier && end > frontier {
		contiguous = end + u64(win_run(c, b, .Recv, PRESENT, end, int(b.recv_base + window - end), true))
	}
	if !win_reserve(c, b, .Recv, lo, end) {
		c.reason = "stream receive pool"; return .Capacity
	}
	if e := harness.stream_receive_admit(
		&c.model,
		p.stream_id,
		p.stream_off,
		len(p.stream_data),
		unique,
		contiguous,
		p.fin,
	); e != .None {
		if b.recv_held == 0 {
			win_clear(c, b, .Recv)
		}
		c.reason = "stream receive accounting"; return map_harness(e)
	}
	win_write(c, b, .Recv, lo, data); win_set(c, b, .Recv, PRESENT, lo, len(data), true)
	b.recv_held += unique; b.recv_n = int(contiguous - b.recv_base)
	if b.recv_credit == 0 {
		b.recv_credit = c.model.max_stream_data_recv
	}
	if p.fin {
		b.recv_fin = true; b.recv_final = end
	}
	return .None
}
// The part of [offset, offset+n) the stream still retains.
@(private)
retained_range :: proc(b: ^Buf, offset: u64, n: int) -> (u64, int) {
	lo := max(offset, b.send_base); hi := min(offset + u64(n), b.send_base + u64(b.n))
	if hi <= lo {
		return lo, 0
	}
	return lo, int(hi - lo)
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
		win_retry(c, b, retained_range(b, t.offset, t.n))
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
				n := win_ack(c, b, retained_range(b, t.offset, t.n))
				if t.fin {
					b.fin_acked = true; b.fin_retry = false
				}; if t.reset {
					b.reset_retry = false;b.reset_acked=true;b.fin_acked=true;b.fin_retry=false
                    win_clear(c,b,.Send)
                    b.send_base=b.reset_final;b.n=0;b.sent=0;b.retry_pending=false
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
	for &b in c.bufs {
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
			// A byte is never both acknowledged and marked for retry.
			retry := b.n
			if b.retry_pending {
				retry = win_run(c, &b, .Send, .Retry, b.send_base, b.n, false)
				b.retry_pending = retry < b.n
			}
			if retry < b.n {
				off = retry
				n = win_run(c, &b, .Send, .Retry, b.send_base + u64(off), b.n - off, true)
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
			// One frame per packet: a window larger than a datagram goes out in
			// pieces, and FIN rides only with the last one.
			if room := stream_frame_room(c, len(dst), at, b.id, b.send_base + u64(off)); n > room {
				if room <= 0 {
					return 0, .Capacity, true
				}
				n = room; fin = false
			}
			payload: [MAX_DATAGRAM]u8; win_read(c, &b, .Send, b.send_base + u64(off), payload[:n])
			at, ok = encode_stream(frame[:], at, b.id, b.send_base + u64(off), payload[:n], fin)
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
		win_set(c, &b, .Send, .Retry, b.send_base + u64(off), n, false); b.sent = max(b.sent, off + n)
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

// STREAM payload bytes that fit one packet after the frames already encoded.
@(private)
stream_frame_room :: proc(c: ^Connection, dst, used: int, id, offset: u64) -> int {
	header := 1 + c.peer_cid_len + 4
	if early(c) {
		header = 7 + c.local_cid_len + c.peer_cid_len + 2 + 4
	}
	id_n, _ := quic.varint_size(id); offset_n, _ := quic.varint_size(offset)
	// Type, stream ID, offset and a two-byte length, then the AEAD tag.
	room := min(c.max_datagram, dst, MAX_DATAGRAM) - header - used - (1 + id_n + offset_n + 2) - 16
	return min(room, 16383)
}
