package harness

configure :: proc(m: ^Model, limits: Limits) -> Error {
	if m == nil || !m.initialized || m.closed {
		return .Invalid_State
	}
	if limits.max_data < m.max_data ||
	   limits.max_stream_data < m.max_stream_data_send ||
	   limits.max_streams < m.max_streams_send ||
	   limits.recv_max_data < m.recv_max_data ||
	   limits.recv_max_stream_data < m.max_stream_data_recv ||
	   limits.recv_max_streams < m.max_streams_recv {
		return .Protocol
	}
	m.max_data = limits.max_data
	m.max_stream_data_send = limits.max_stream_data
	m.max_streams_send = limits.max_streams
	m.recv_max_data = limits.recv_max_data
	m.max_stream_data_recv = limits.recv_max_stream_data
	m.max_streams_recv = limits.recv_max_streams
	for &s in m.streams {
		if !s.active {
			continue
		}
		if m.max_stream_data_send > s.max_send {
			s.max_send = m.max_stream_data_send
		}
		if m.max_stream_data_recv > s.recv_max {
			s.recv_max = m.max_stream_data_recv
		}
	}
	return .None
}

@(private)
note_peaks :: proc(m: ^Model) {
	if m.live_packets > m.peak_packets {
		m.peak_packets = m.live_packets
	}
	if m.live_streams > m.peak_streams {
		m.peak_streams = m.live_streams
	}
	if m.retained > m.peak_retained {
		m.peak_retained = m.retained
	}
}

@(private)
add_retained :: proc(m: ^Model, s: ^Stream, n: int) {
	s.retained += n
	m.retained += n
	note_peaks(m)
}

@(private)
sub_retained :: proc(m: ^Model, s: ^Stream, n: int) {
	drop := n
	if drop > s.retained {
		drop = s.retained
	}
	s.retained -= drop
	m.retained -= drop
	if m.retained < 0 {
		m.retained = 0
	}
}

@(private)
add_send_retained :: proc(m: ^Model, s: ^Stream, n: int) {
	s.send_retained += n; add_retained(m, s, n)
}
@(private)
sub_send_retained :: proc(m: ^Model, s: ^Stream, n: int) {
	drop := min(n, s.send_retained); s.send_retained -= drop; sub_retained(m, s, drop)
}
@(private)
add_recv_retained :: proc(m: ^Model, s: ^Stream, n: int) {
	s.recv_retained += n; add_retained(m, s, n)
}
@(private)
sub_recv_retained :: proc(m: ^Model, s: ^Stream, n: int) {
	drop := min(n, s.recv_retained); s.recv_retained -= drop; sub_retained(m, s, drop)
}

@(private)
find_stream :: proc(m: ^Model, id: u64) -> int {
	for s, i in m.streams {
		if s.active && s.id == id {
			return i
		}
	}
	return -1
}

@(private)
free_stream_slots :: proc(m: ^Model) -> int {
	n := 0
	for s in m.streams {
		if !s.active {
			n += 1
		}
	}
	return n
}

@(private)
alloc_stream :: proc(m: ^Model) -> int {
	for &s, i in m.streams {
		if !s.active {
			s = {}
			s.active = true
			m.live_streams += 1
			note_peaks(m)
			return i
		}
	}
	return -1
}

@(private)
stream_in_flight :: proc(m: ^Model, index: int) -> bool {
	for space in 0 ..< 3 {
		for p in m.packets[space] {
			if p.active && p.stream_slot == index {
				return true
			}
		}
	}
	return false
}

@(private)
maybe_free_stream :: proc(m: ^Model, index: int) {
	s := &m.streams[index]
	if !s.active || s.externally_owned || stream_in_flight(m, index) {
		return
	}
	send_done := s.send == .Empty || s.send == .Data_Recvd || s.send == .Reset_Recvd
	recv_done := s.recv == .Empty || s.recv == .Data_Recvd || s.recv == .Reset_Recvd
	if send_done && recv_done && s.retained == 0 {
		s^ = {}
		m.live_streams -= 1
	}
}

@(private)
release_all :: proc(m: ^Model) {
	for space in 0 ..< 3 {
		for &p in m.packets[space] {
			p = {}
			p.stream_slot = -1
		}
		m.spaces[space].ack_eliciting_flight = 0
		m.spaces[space].has_loss_at = false
	}
	for &s in m.streams {
		s = {}
	}
	m.live_packets = 0
	m.live_streams = 0
	m.retained = 0
	m.bytes_in_flight = 0
	m.closed = true
}

@(private)
our_bidi :: proc(role: Role, id: u64) -> bool {
	return id % 4 == (0 if role == .Client else 1)
}

@(private)
peer_bidi :: proc(role: Role, id: u64) -> bool {
	return id % 4 == (1 if role == .Client else 0)
}

// Dry-run. Does not allocate. Gaps are rejected; lower ids are not implied open.
@(private)
plan_send_stream :: proc(
	m: ^Model,
	id: u64,
	n: int,
	fin, reset: bool,
	reset_final: u64,
) -> (
	slot: int,
	fresh: bool,
	err: Error,
) {
	if reset && (n != 0 || fin) {
		return -1, false, .Invalid_Input
	}
	slot = find_stream(m, id)
	fresh = slot < 0
	if fresh {
		if !our_bidi(m.role, id) || id != m.next_send_stream {
			return -1, false, .Protocol
		}
		if m.max_streams_send == 0 || id / 4 >= m.max_streams_send {
			return -1, false, .Flow_Control
		}
		if free_stream_slots(m) < 1 {
			return -1, false, .Capacity
		}
	}
	high := u64(0)
	if slot >= 0 {
		s := m.streams[slot]
		if s.send == .Reset_Recvd ||
		   s.send == .Data_Recvd ||
		   (s.send == .Data_Sent && !reset) ||
		   (s.send == .Reset_Sent && !reset) {
			return -1, false, .Protocol
		}
		high = s.next_offset
	}
	if reset {
		if reset_final < high {
			return -1, false, .Protocol
		}
		extra := reset_final - high
		if m.data_sent > max(u64) - extra || m.data_sent + extra > m.max_data {
			return -1, false, .Flow_Control
		}
		return slot, fresh, .None
	}
	if n < 0 || (n == 0 && !fin) {
		return -1, false, .Invalid_Input
	}
	add := u64(n)
	if high > max(u64) - add {
		return -1, false, .Protocol
	}
	end := high + add
	limit := m.max_stream_data_send
	if slot >= 0 && m.streams[slot].max_send > limit {
		limit = m.streams[slot].max_send
	}
	if end > limit || m.data_sent > max(u64) - add || m.data_sent + add > m.max_data {
		return -1, false, .Flow_Control
	}
	return slot, fresh, .None
}

@(private)
commit_send_stream :: proc(m: ^Model, id: u64, n: int, fin, reset: bool, reset_final: u64) -> int {
	slot := find_stream(m, id)
	if slot < 0 {
		slot = alloc_stream(m)
		s := &m.streams[slot]
		s.id = id
		s.max_send = m.max_stream_data_send
		s.recv_max = m.max_stream_data_recv
		s.send = .Send
		m.next_send_stream = id + 4
	}
	s := &m.streams[slot]
	if reset {
		extra := reset_final - s.next_offset
		m.data_sent += extra
		s.next_offset = reset_final
		sub_send_retained(m, s, s.send_retained)
		s.send = .Reset_Sent
		s.fin_sent = false
		return slot
	}
	if n > 0 {
		add_send_retained(m, s, n)
		m.data_sent += u64(n)
		s.next_offset += u64(n)
		if s.send == .Empty {
			s.send = .Send
		}
	}
	if fin {
		s.fin_sent = true
		s.send = .Data_Sent
	}
	return slot
}

@(private)
retire_stream_ack :: proc(m: ^Model, p: Packet) {
	if p.stream_slot < 0 || p.stream_slot >= len(m.streams) {
		return
	}
	s := &m.streams[p.stream_slot]
	if !s.active {
		return
	}
	if p.retires_reset {
		if s.send == .Reset_Sent {
			s.send = .Reset_Recvd
			sub_send_retained(m, s, s.send_retained)
			maybe_free_stream(m, p.stream_slot)
		}
		return
	}
	if p.stream_bytes > 0 {
		sub_send_retained(m, s, p.stream_bytes)
		s.acked += u64(p.stream_bytes)
		if s.acked > s.next_offset {
			s.acked = s.next_offset
		}
	}
	if s.fin_sent && s.retained == 0 && s.send == .Data_Sent {
		s.send = .Data_Recvd
		maybe_free_stream(m, p.stream_slot)
	}
}

// Local STOP_SENDING reaction: drop payload retention immediately. The RESET
// frame is a later emit and is what the peer acknowledges.
abandon_send :: proc(m: ^Model, id: u64) -> Error {
	if m == nil || !m.initialized || m.closed {
		return .Invalid_State
	}
	slot := find_stream(m, id)
	if slot < 0 {
		return .Invalid_Input
	}
	s := &m.streams[slot]
	if s.send == .Reset_Sent || s.send == .Reset_Recvd || s.send == .Data_Recvd {
		return .None
	}
	sub_send_retained(m, s, s.send_retained)
	s.send = .Reset_Sent
	return .None
}

consume_recv :: proc(m: ^Model, id: u64, n: int) -> Error {
	if m == nil || !m.initialized || n < 0 {
		return .Invalid_State
	}
	slot := find_stream(m, id)
	if slot < 0 {
		return .Invalid_Input
	}
	s := &m.streams[slot]
	if n > s.recv_retained {
		return .Invalid_Input
	}
	sub_recv_retained(m, s, n)
	s.consumed += u64(n)
	if s.recv_fin && s.recv_got == s.recv_final && s.recv_retained == 0 && s.recv == .Size_Known {
		s.recv = .Data_Recvd
		maybe_free_stream(m, slot)
	}
	if s.recv == .Reset_Recvd && s.retained == 0 {
		maybe_free_stream(m, slot)
	}
	return .None
}

@(private)
accept_recv_stream :: proc(m: ^Model, id: u64) -> (int, Error) {
	slot := find_stream(m, id)
	if slot >= 0 {
		return slot, .None
	}
	if !peer_bidi(m.role, id) || id != m.next_recv_stream {
		return -1, .Protocol
	}
	if m.max_streams_recv == 0 || id / 4 >= m.max_streams_recv {
		return -1, .Flow_Control
	}
	if free_stream_slots(m) < 1 {
		return -1, .Capacity
	}
	return -1, .None
}

@(private)
open_recv_stream :: proc(m: ^Model, id: u64) -> int {
	slot := find_stream(m, id)
	if slot >= 0 {
		return slot
	}
	slot = alloc_stream(m)
	s := &m.streams[slot]
	s.id = id
	s.max_send = m.max_stream_data_send
	s.recv_max = m.max_stream_data_recv
	s.recv = .Recv
	m.next_recv_stream = id + 4
	return slot
}

@(private)
commit_recv_data :: proc(m: ^Model, id: u64, offset: u64, n: int, fin: bool) -> Error {
	if n < 0 || u64(n) > max(u64) - offset {
		return .Invalid_Input
	}
	end := offset + u64(n)
	slot := find_stream(m, id)
	if slot < 0 {
		_, err := accept_recv_stream(m, id)
		// Capacity is an admission. Injection wins over a full stream table.
		// Flow-control and stream-id rejection above are not admissions.
		if err == .Capacity && m.allocation_failures > 0 {
			m.allocation_failures -= 1
			return .Allocation
		}
		if err != .None {
			return err
		}
		if offset != 0 {
			return .Protocol
		}
		if u64(n) > m.max_stream_data_recv ||
		   m.recv_data > max(u64) - u64(n) ||
		   m.recv_data + u64(n) > m.recv_max_data {
			return .Flow_Control
		}
		if m.allocation_failures > 0 {
			m.allocation_failures -= 1
			return .Allocation
		}
		slot = open_recv_stream(m, id)
	}
	s := &m.streams[slot]
	if s.recv == .Reset_Recvd || s.recv == .Data_Recvd {
		return .Protocol
	}
	if s.recv_fin && end > s.recv_final {
		return .Protocol
	}
	if s.recv_fin && fin && end != s.recv_final {
		return .Protocol
	}
	if end < s.recv_got || (end == s.recv_got && n > 0) {
		return .None
	}
	if end > s.recv_got {
		if offset != s.recv_got {
			return .Protocol
		}
		if end > s.recv_max ||
		   m.recv_data > max(u64) - u64(n) ||
		   m.recv_data + u64(n) > m.recv_max_data {
			return .Flow_Control
		}
		add_recv_retained(m, s, n)
		s.recv_got = end
		m.recv_data += u64(n)
		if s.recv == .Empty {
			s.recv = .Recv
		}
	}
	if fin {
		s.recv_fin = true
		s.recv_final = s.recv_got
		s.recv = .Size_Known
		if s.retained == 0 {
			s.recv = .Data_Recvd
			maybe_free_stream(m, slot)
		}
	}
	return .None
}

@(private)
commit_recv_reset :: proc(m: ^Model, id, final_size: u64) -> Error {
	slot, err := accept_recv_stream(m, id)
	if err == .Capacity && m.allocation_failures > 0 {
		m.allocation_failures -= 1
		return .Allocation
	}
	if err != .None {
		return err
	}
	if slot >= 0 {
		s := m.streams[slot]
		if s.recv == .Reset_Recvd {
			if final_size != s.recv_final {
				return .Protocol
			}
			return .None
		}
		if final_size < s.recv_got || (s.recv_fin && final_size != s.recv_final) {
			return .Protocol
		}
		extra := final_size - s.recv_got
		if m.recv_data > max(u64) - extra || m.recv_data + extra > m.recv_max_data {
			return .Flow_Control
		}
	} else if final_size > m.recv_max_data - m.recv_data || final_size > m.max_stream_data_recv {
		return .Flow_Control
	}
	if slot < 0 && m.allocation_failures > 0 {
		m.allocation_failures -= 1
		return .Allocation
	}
	slot = open_recv_stream(m, id)
	s := &m.streams[slot]
	extra := final_size - s.recv_got
	m.recv_data += extra
	s.recv_final = final_size
	s.recv_got = final_size
	sub_recv_retained(m, s, s.recv_retained)
	s.recv = .Reset_Recvd
	maybe_free_stream(m, slot)
	return .None
}
