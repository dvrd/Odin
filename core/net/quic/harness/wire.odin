package harness

import "core:bytes"
import "core:mem"
import "core:net/quic"

// Harness datagram body. This is not a QUIC frame encoding and it is not
// authenticated. The UDP payload begins with a real unprotected v1 header so
// packet number spaces are visible to the codec; the bytes after the packet
// number are this private layout.
HARNESS_MAGIC :: u32(0x4841524e)
HARNESS_VERSION :: u8(1)

FLAG_ACK :: u8(1)
FLAG_PING :: u8(2)
FLAG_STREAM :: u8(4)
FLAG_RESET :: u8(8)
FLAG_MAX_DATA :: u8(16)
FLAG_STOP :: u8(32)
FLAG_CLOSE :: u8(64)
FLAG_CONFIRM :: u8(128)

@(private)
put_u16 :: proc(dst: []u8, v: u16) {
	dst[0] = u8(v >> 8)
	dst[1] = u8(v)
}
@(private)
put_u32 :: proc(dst: []u8, v: u32) {
	for i in 0 ..< 4 {
		dst[i] = u8((v >> uint((3 - i) * 8)) & 255)
	}
}
@(private)
put_u64 :: proc(dst: []u8, v: u64) {
	for i in 0 ..< 8 {
		dst[i] = u8((v >> uint((7 - i) * 8)) & 255)
	}
}
@(private)
get_u16 :: proc(src: []u8) -> (u16, bool) {
	if len(src) < 2 {
		return 0, false
	}
	return u16(src[0]) << 8 | u16(src[1]), true
}
@(private)
get_u32 :: proc(src: []u8) -> (u32, bool) {
	if len(src) < 4 {
		return 0, false
	}
	v: u32
	for b in src[:4] {
		v = v << 8 | u32(b)
	}
	return v, true
}
@(private)
get_u64 :: proc(src: []u8) -> (u64, bool) {
	if len(src) < 8 {
		return 0, false
	}
	v: u64
	for b in src[:8] {
		v = v << 8 | u64(b)
	}
	return v, true
}

@(private)
ack_eliciting_emit :: proc(req: Emit) -> bool {
	return req.ping || req.stream || req.reset || req.stop_sending || req.max_data || req.handshake_confirmed
}

@(private)
free_packet :: proc(m: ^Model, space: int) -> int {
	for p, i in m.packets[space] {
		if !p.active {
			return i
		}
	}
	return -1
}

@(private)
storage_alias :: proc(m: ^Model, data: []u8) -> bool {
	if len(data) == 0 {
		return false
	}
	owner := (cast([^]u8)m)[:size_of(Model)]
	if bytes.alias(data, owner) {
		return true
	}
	for i in 0 ..< 3 {
		if bytes.alias(data, mem.slice_to_bytes(m.packets[i])) {
			return true
		}
	}
	return bytes.alias(data, mem.slice_to_bytes(m.streams))
}

@(private)
long_header_size :: proc(m: ^Model, space: Space, pn_len, body: int) -> (int, Error) {
	token: int
	if space == .Initial {
		token = 1
	}
	length := u64(pn_len + body)
	lw, err := quic.varint_size(length)
	if err != .None {
		return 0, .Invalid_Input
	}
	return 7 + m.peer_cid_len + m.local_cid_len + token + lw + pn_len, .None
}

emit :: proc(m: ^Model, now: i64, dst: []u8, req: Emit) -> (int, Error) {
	if m == nil || !m.initialized {
		return 0, .Invalid_State
	}
	if m.closed {
		return 0, .Closed
	}
	if now < 0 || int(req.space) > 2 {
		return 0, .Invalid_Input
	}
	sp := &m.spaces[int(req.space)]
	if sp.discarded {
		return 0, .Discarded
	}
	if req.connection_close && (req.stream || req.ping || req.reset || req.attach_ack || req.max_data || req.handshake_confirmed || req.stop_sending) {
		return 0, .Invalid_Input
	}
	if req.attach_ack && req.ack_largest < req.ack_smallest || req.ack_delay < 0 {
		return 0, .Invalid_Input
	}
	if req.space == .Handshake && !m.handshake_armed {
		return 0, .Invalid_Input
	}
	if req.zero_rtt && (m.role != .Client || req.space != .Application || m.handshake_confirmed) {
		return 0, .Invalid_Input
	}
	if req.space == .Application && !m.handshake_confirmed && !req.zero_rtt && !req.connection_close {
		return 0, .Invalid_Input
	}
	eliciting := ack_eliciting_emit(req)
	in_flight := eliciting || req.padding
	body: [K_MAX_DATAGRAM]u8
	flags: u8
	at := 6
	put_u32(body[:], HARNESS_MAGIC)
	body[4] = HARNESS_VERSION
	if req.attach_ack {
		flags |= FLAG_ACK
		if at + 33 > len(body) {
			return 0, .Invalid_Input
		}
		put_u64(body[at:], req.ack_largest)
		put_u64(body[at + 8:], req.ack_smallest)
		put_u64(body[at + 16:], u64(req.ack_delay))
		body[at + 24] = 1 if req.ack_ecn else 0
		put_u64(body[at + 25:], req.ack_ecn_ce)
		at += 33
	}
	if req.ping {
		flags |= FLAG_PING
	}
	stream_slot := -1
	stream_fresh := false
	if req.stream || req.reset {
		if req.stream && req.reset {
			return 0, .Invalid_Input
		}
		slot, fresh, err := plan_send_stream(m, req.stream_id, req.stream_len, req.fin, req.reset, req.reset_final)
		if err == .Flow_Control {
			m.flow_limited = true
		}
		// A full stream table is still an admission. Injection wins over Capacity.
		if err == .Capacity && m.allocation_failures > 0 {
			m.allocation_failures -= 1
			return 0, .Allocation
		}
		if err != .None {
			return 0, err
		}
		stream_slot, stream_fresh = slot, fresh
		if req.reset {
			flags |= FLAG_RESET
			if at + 16 > K_MAX_DATAGRAM {
				return 0, .Invalid_Input
			}
			put_u64(body[at:], req.stream_id)
			put_u64(body[at + 8:], req.reset_final)
			at += 16
		} else {
			if req.stream_len > 65535 || at + 19 + req.stream_len > K_MAX_DATAGRAM {
				return 0, .Invalid_Input
			}
			flags |= FLAG_STREAM
			put_u64(body[at:], req.stream_id)
			put_u64(body[at + 8:], 0)
			if stream_slot >= 0 {
				put_u64(body[at + 8:], m.streams[stream_slot].next_offset)
			}
			put_u16(body[at + 16:], u16(req.stream_len))
			body[at + 18] = 1 if req.fin else 0
			at += 19 + req.stream_len
		}
	}
	if req.stop_sending {
		flags |= FLAG_STOP
		if at + 8 > K_MAX_DATAGRAM {
			return 0, .Invalid_Input
		}
		put_u64(body[at:], req.stream_id)
		at += 8
	}
	if req.max_data {
		flags |= FLAG_MAX_DATA
		if at + 8 > K_MAX_DATAGRAM {
			return 0, .Invalid_Input
		}
		put_u64(body[at:], req.max_data_value)
		at += 8
	}
	if req.connection_close {
		flags |= FLAG_CLOSE
	}
	if req.handshake_confirmed {
		flags |= FLAG_CONFIRM
	}
	body[5] = flags
	structured := at
	pn_len, trunc, pn_err := pn_wire_length(sp.next_send, sp.has_largest_acked, sp.largest_acked)
	if pn_err != .None {
		return 0, pn_err
	}
	min_size := 0
	if req.space == .Initial && (m.role == .Client || eliciting) {
		min_size = K_MIN_INITIAL_DATAGRAM
	}
	body_len := structured
	header := 0
	target := req.bytes
	if req.space == .Application && (m.handshake_confirmed||req.connection_close) {
		header = 1 + m.peer_cid_len + pn_len
		if header > max(int) - body_len {
			return 0, .Invalid_Input
		}
		natural := header + body_len
		if target == 0 {
			target = natural
			if target < min_size {
				target = min_size
			}
		}
		if target < natural || target < min_size || target > m.max_datagram_size {
			return 0, .Datagram_Too_Small
		}
	} else {
		for _ in 0 ..< 4 {
			sized, err := long_header_size(m, req.space, pn_len, body_len)
			if err != .None {
				return 0, err
			}
			header = sized
			natural := header + body_len
			want := target
			if want == 0 {
				want = natural
				if want < min_size {
					want = min_size
				}
			}
			if want < min_size || want > m.max_datagram_size || want < header + structured {
				return 0, .Datagram_Too_Small
			}
			target = want
			if natural == want {
				break
			}
			body_len = want - header
		}
		if header + body_len != target {
			return 0, .Datagram_Too_Small
		}
	}
	if len(dst) < target {
		return 0, .Destination_Undersized
	}
	if storage_alias(m, dst[:target]) {
		return 0, .Overlap
	}
	if in_flight && !req.probe && m.bytes_in_flight > max(int) - target {
		return 0, .Congestion_Limited
	}
	if in_flight && !req.probe && m.bytes_in_flight + target > m.congestion_window {
		return 0, .Congestion_Limited
	}
	if m.role == .Server && !m.address_validated && target > amplification_budget(m) {
		return 0, .Anti_Amplification
	}
	needs_slot := in_flight || stream_fresh
	if needs_slot && m.allocation_failures > 0 {
		m.allocation_failures -= 1
		return 0, .Allocation
	}
	packet_index := -1
	if in_flight {
		packet_index = free_packet(m, int(req.space))
		if packet_index < 0 {
			return 0, .Capacity
		}
	}
	wire: [K_MAX_DATAGRAM]u8
	dcid := m.peer_cid[:m.peer_cid_len]
	scid := m.local_cid[:m.local_cid_len]
	if req.space == .Application && (m.handshake_confirmed||req.connection_close) {
		n, _, err := quic.short_header_encode_v1(wire[:], {
			destination_id = dcid,
			packet_number = u32(trunc),
			packet_number_length = pn_len,
		})
		if err != .None || n != header {
			return 0, .Protocol
		}
		copy(wire[n:], body[:structured])
		for i in n + structured ..< target {
			wire[i] = 0
		}
	} else {
		kind := quic.Packet_Kind.Initial
		if req.space == .Handshake {
			kind = .Handshake
		} else if req.zero_rtt {
			kind = .Zero_RTT
		}
		pad := body_len - structured
		n, _, err := quic.long_header_encode_v1(wire[:], {
			kind = kind,
			destination_id = dcid,
			source_id = scid,
			packet_number = u32(trunc),
			packet_number_length = pn_len,
			ciphertext_length = u64(body_len),
		})
		if err != .None || n != header {
			return 0, .Protocol
		}
		copy(wire[n:], body[:structured])
		for i in n + structured ..< n + structured + pad {
			wire[i] = 0
		}
	}
	if req.stream || req.reset {
		stream_slot = commit_send_stream(m, req.stream_id, req.stream_len if !req.reset else 0, req.fin, req.reset, req.reset_final)
		m.flow_limited = false
	}
	if in_flight {
		p := &m.packets[int(req.space)][packet_index]
		p^ = {}
		p.active = true
        p.path_epoch=m.path_epoch;p.path=m.path
		p.number = sp.next_send
		p.sent_at = now
		p.sent_bytes = target
		p.ack_eliciting = eliciting
		p.in_flight = true
		p.zero_rtt = req.zero_rtt
		p.stream_slot = -1
		p.retires_reset = req.reset
		if req.reset || req.stream {
			p.stream_slot = stream_slot
		}
		if req.stream && !req.reset {
			p.stream_bytes = req.stream_len
		}
		m.live_packets += 1
		m.bytes_in_flight += target
		if eliciting {
			sp.ack_eliciting_flight += 1
			sp.last_ack_eliciting_at = now
		}
		note_peaks(m)
		if !req.more_data && m.bytes_in_flight < m.congestion_window {
			m.app_limited = true
		} else if m.bytes_in_flight >= m.congestion_window {
			m.app_limited = false
		}
	}
	sp.next_send += 1
	if m.role == .Server {
		m.path_sent += target
	}
	if req.attach_ack {
		m.ack_pending[int(req.space)] = false
	}
	copy(dst[:target], wire[:target])
	if req.connection_close {
		release_all(m)
	}
	if m.role == .Client && req.space == .Handshake {
		_ = discard_space(m, .Initial)
	}
	return target, .None
}

pending_ack :: proc(m: ^Model, space: Space) -> (smallest, largest: u64, ok: bool) {
	if m == nil || !m.initialized || int(space) > 2 {
		return 0, 0, false
	}
	sp := m.spaces[int(space)]
	if !sp.has_recv || !m.ack_pending[int(space)] {
		return 0, 0, false
	}
	top := -1
	for i := K_RECV_WINDOW - 1; i >= 0; i -= 1 {
		if sp.recv_bits & (u64(1) << uint(i)) != 0 {
			top = i
			break
		}
	}
	if top < 0 {
		return 0, 0, false
	}
	bot := top
	for bot > 0 && sp.recv_bits & (u64(1) << uint(bot - 1)) != 0 {
		bot -= 1
	}
	return sp.recv_base + u64(bot), sp.recv_base + u64(top), true
}

@(private)
mark_received :: proc(sp: ^Space_State, pn: u64) -> bool {
	if !sp.has_recv {
		sp.has_recv = true
		sp.recv_base = pn
		sp.recv_bits = 1
		sp.largest_recv = pn
		sp.has_largest_recv = true
		return false
	}
	if pn < sp.recv_base {
		shift := sp.recv_base - pn
		if shift >= u64(K_RECV_WINDOW) {
			return true
		}
		sp.recv_bits <<= uint(shift)
		sp.recv_base -= shift
	}
	if pn >= sp.recv_base + K_RECV_WINDOW {
		shift := pn - (sp.recv_base + u64(K_RECV_WINDOW) - 1)
		if shift >= u64(K_RECV_WINDOW) {
			sp.recv_bits = 0
		} else {
			sp.recv_bits >>= uint(shift)
		}
		sp.recv_base += shift
	}
	bit := uint(pn - sp.recv_base)
	mask := u64(1) << bit
	if sp.recv_bits & mask != 0 {
		return true
	}
	sp.recv_bits |= mask
	if !sp.has_largest_recv || pn > sp.largest_recv {
		sp.largest_recv = pn
		sp.has_largest_recv = true
	}
	return false
}

@(private)
cid_equal :: proc(model_cid: []u8, got: []u8) -> bool {
	return len(model_cid) == len(got) && bytes.equal(model_cid, got)
}

receive :: proc(m: ^Model, now: i64, path: u32, datagram: []u8) -> Error {
	if m == nil || !m.initialized {
		return .Invalid_State
	}
	if now < 0 {
		return .Invalid_Input
	}
	if storage_alias(m, datagram) {
		return .Overlap
	}
	packet, consumed, err := quic.packet_decode_v1(datagram, m.local_cid_len)
	if err != .None || consumed != len(datagram) {
		return .Protocol
	}
	if !cid_equal(m.local_cid[:m.local_cid_len], packet.invariant.destination_id) {
		return .Discarded
	}
	if packet.invariant.long_header && !cid_equal(m.peer_cid[:m.peer_cid_len], packet.invariant.source_id) {
		return .Discarded
	}
	space: Space
	zero_rtt := false
	switch packet.kind {
	case .Initial:
		space = .Initial
	case .Handshake:
		space = .Handshake
	case .Zero_RTT:
		space = .Application
		zero_rtt = true
	case .One_RTT:
		space = .Application
	case .Retry, .Version_Negotiation:
		return .Discarded
	}
	if !m.has_path {
		// What was sent before the first datagram arrived went out on this path.
		// Left on path zero, those packets would never leave bytes_in_flight.
		for &packets in m.packets {
			for &p in packets {
				if p.active && p.path_epoch == m.path_epoch {
					p.path = path
				}
			}
		}
	}
	if !m.has_path || path != m.path {
		m.has_path = true
		m.path = path
		m.address_validated = false
		m.path_received = 0
		m.path_sent = 0
	}
	if len(datagram) > max(int) - m.path_received {
		return .Protocol
	}
	m.path_received += len(datagram)
	if m.closed {
		return .Closed
	}
	if m.role == .Server && space == .Initial && len(datagram) < K_MIN_INITIAL_DATAGRAM {
		return .Datagram_Too_Small
	}
	if m.spaces[int(space)].discarded || (zero_rtt && m.handshake_confirmed) {
		return .Discarded
	}
	fields, ferr := quic.unprotected_fields_decode(packet, datagram[:consumed])
	if ferr != .None {
		return .Protocol
	}
	full, ok := pn_decode(m.spaces[int(space)].has_largest_recv, m.spaces[int(space)].largest_recv, u64(fields.packet_number), fields.packet_number_length * 8)
	if !ok {
		return .Protocol
	}
	if mark_received(&m.spaces[int(space)], full) {
		return .None
	}
	body := datagram[packet.packet_number_offset + fields.packet_number_length:consumed]
	magic, mok := get_u32(body)
	if !mok || magic != HARNESS_MAGIC || len(body) < 6 || body[4] != HARNESS_VERSION {
		return .Protocol
	}
	flags := body[5]
	at := 6
	ack_largest, ack_smallest: u64
	ack_delay: i64
	has_ack := flags & FLAG_ACK != 0
	has_ecn := false
	ecn: u64
	if has_ack {
		a, aok := get_u64(body[at:])
		b, bok := get_u64(body[at + 8:])
		d, dok := get_u64(body[at + 16:])
		if !aok || !bok || !dok || len(body) < at + 33 || d > u64(max(i64)) {
			return .Protocol
		}
		has_ecn = body[at + 24] != 0
		e, eok := get_u64(body[at + 25:])
		if !eok {
			return .Protocol
		}
		ack_largest, ack_smallest, ack_delay, ecn = a, b, i64(d), e
		at += 33
	}
	stream_id, stream_off, reset_final, max_data_v, stop_id: u64
	stream_len: int
	fin := false
	if flags & FLAG_STREAM != 0 {
		id, idok := get_u64(body[at:])
		off, ook := get_u64(body[at + 8:])
		ln, lok := get_u16(body[at + 16:])
		if !idok || !ook || !lok || len(body) < at + 19 + int(ln) {
			return .Protocol
		}
		stream_id, stream_off, stream_len = id, off, int(ln)
		fin = body[at + 18] != 0
		at += 19 + int(ln)
	}
	if flags & FLAG_RESET != 0 {
		id, idok := get_u64(body[at:])
		final, fok := get_u64(body[at + 8:])
		if !idok || !fok {
			return .Protocol
		}
		stream_id, reset_final = id, final
		at += 16
	}
	if flags & FLAG_MAX_DATA != 0 {
		v, vok := get_u64(body[at:])
		if !vok {
			return .Protocol
		}
		max_data_v = v
		at += 8
	}
	if flags & FLAG_STOP != 0 {
		id, idok := get_u64(body[at:])
		if !idok {
			return .Protocol
		}
		stop_id = id
		at += 8
	}
	if at > len(body) {
		return .Protocol
	}
	for b in body[at:] {
		if b != 0 {
			return .Protocol
		}
	}
	if flags & (FLAG_PING | FLAG_STREAM | FLAG_RESET | FLAG_MAX_DATA | FLAG_STOP | FLAG_CONFIRM) != 0 {
		m.ack_pending[int(space)] = true
	}
	if flags & FLAG_MAX_DATA != 0 && max_data_v > m.max_data {
		limits := Limits {
			max_data = max_data_v,
			max_stream_data = m.max_stream_data_send,
			max_streams = m.max_streams_send,
			recv_max_data = m.recv_max_data,
			recv_max_stream_data = m.max_stream_data_recv,
			recv_max_streams = m.max_streams_recv,
		}
		if err := configure(m, limits); err != .None {
			return err
		}
	}
	if flags & FLAG_RESET != 0 {
		if err := commit_recv_reset(m, stream_id, reset_final); err != .None {
			return err
		}
	}
	if flags & FLAG_STOP != 0 {
		if err := abandon_send(m, stop_id); err != .None {
			return err
		}
	}
	if flags & FLAG_STREAM != 0 {
		if err := commit_recv_data(m, stream_id, stream_off, stream_len, fin); err != .None {
			return err
		}
	}
	if has_ack {
		if _, err := acknowledge(m, now, space, ack_smallest, ack_largest, ack_delay, has_ecn, ecn, nil); err != .None {
			return err
		}
	}
	if flags & FLAG_CONFIRM != 0 {
		if err := confirm_handshake(m); err != .None {
			return err
		}
	}
	if flags & FLAG_CLOSE != 0 {
		release_all(m)
	}
	if space == .Handshake {
		m.handshake_armed = true
		if m.role == .Server {
			m.address_validated = true
		}
		if err := discard_space(m, .Initial); err != .None {
			return err
		}
	}
	return .None
}
