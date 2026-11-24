package harness

// The authenticated connection owns actual byte/range storage. These accounting
// calls admit unique bytes independently of packet transmissions, so a retry
// never consumes flow credit or retention twice. All calls are serialized with
// the owning connection; allocation injection is checked before mutation.
stream_send_admit :: proc(
	m: ^Model,
	id: u64,
	n: int,
	fin: bool,
	limit, count_limit: u64,
) -> Error {
	if m == nil || !m.initialized || m.closed || n < 0 || id >= u64(1) << 62 {
		return .Invalid_Input
	}
	slot := find_stream(m, id)
	local := id % 2 == u64(m.role)
	if !local && (id & 2 != 0 || slot < 0) {
		return .Protocol
	}
	if local && id / 4 >= count_limit {
		return .Flow_Control
	}
	high: u64
	if slot >= 0 {
		s := &m.streams[slot]; high = s.next_offset
		if s.send == .Data_Sent ||
		   s.send == .Data_Recvd ||
		   s.send == .Reset_Sent ||
		   s.send == .Reset_Recvd {
			return .Protocol
		}
	}
	if u64(n) > max(u64) - high ||
	   high + u64(n) > limit ||
	   u64(n) > max(u64) - m.data_sent ||
	   m.data_sent + u64(n) > m.max_data {
		return .Flow_Control
	}
	if slot < 0 {
		if m.allocation_failures > 0 {
			m.allocation_failures -= 1; return .Allocation
		}
		if free_stream_slots(m) == 0 {
			return .Capacity
		}
		slot = alloc_stream(m); m.streams[slot].id = id
		m.streams[slot].recv_max = m.max_stream_data_recv
	}
	s := &m.streams[slot]; s.externally_owned = true; s.max_send = limit
	s.send = .Send; s.next_offset = high + u64(n); m.data_sent += u64(n)
	add_send_retained(m, s, n)
	if fin {
		s.fin_sent = true; s.send = .Data_Sent
	}
	if local && id & 2 == 0 && id >= m.next_send_stream {
		m.next_send_stream = id + 4
	}
	return .None
}

stream_send_ack :: proc(m: ^Model, id: u64, n: int, fin, reset: bool) -> Error {
	if m == nil || !m.initialized || n < 0 {
		return .Invalid_Input
	}
	slot := find_stream(m, id); if slot < 0 {
		return .None
	}
	s := &m.streams[slot]
	if n > s.send_retained {
		return .Invalid_Input
	}
	sub_send_retained(m, s, n); s.acked += u64(n)
	if fin {
		s.fin_acked = true
	}
	if reset {
		s.send = .Reset_Recvd; sub_send_retained(m, s, s.send_retained)
	}
	if s.fin_sent && s.fin_acked && s.send_retained == 0 && s.send == .Data_Sent {
		s.send = .Data_Recvd
	}
	maybe_free_stream(m, slot)
	return .None
}

stream_send_reset :: proc(m: ^Model, id, final_size: u64) -> Error {
	if m == nil || !m.initialized {
		return .Invalid_Input
	}
	slot := find_stream(m, id); if slot < 0 {
		return .Invalid_Input
	}
	s := &m.streams[slot]
	if final_size != s.next_offset {
		return .Protocol
	}
	sub_send_retained(m, s, s.send_retained); s.send = .Reset_Sent
	return .None
}

// unique is the count of newly retained bytes in the connection's bounded
// receive bitmap. contiguous is its absolute contiguous frontier, not the
// highest offset. Flow credit counts highest offsets, including gaps.
stream_receive_admit :: proc(
	m: ^Model,
	id, offset: u64,
	n, unique: int,
	contiguous: u64,
	fin: bool,
) -> Error {
	if m == nil ||
	   !m.initialized ||
	   m.closed ||
	   n < 0 ||
	   unique < 0 ||
	   unique > n ||
	   id >= u64(1) << 62 ||
	   u64(n) > max(u64) - offset {
		return .Invalid_Input
	}
	end := offset + u64(n); slot := find_stream(m, id)
	local := id % 2 == u64(m.role)
	if local && (id & 2 != 0 || slot < 0) {
		return .Protocol
	}
	if !local && id / 4 >= m.max_streams_recv {
		return .Flow_Control
	}
	high, old_contiguous: u64; limit := m.max_stream_data_recv
	if slot >= 0 {
		s := &m.streams[slot]; high = s.recv_highest; old_contiguous = s.recv_got
		limit = s.recv_max
		if s.recv == .Reset_Recvd {
			return .None
		}
		if s.recv_fin && (end > s.recv_final || fin && end != s.recv_final) {
			return .Protocol
		}
	}
	if fin && end < high {
		return .Protocol
	}
	if end > limit || contiguous < old_contiguous || contiguous > max(high, end) {
		return .Flow_Control
	}
	extra := max(high, end) - high
	if extra > max(u64) - m.recv_data || m.recv_data + extra > m.recv_max_data {
		return .Flow_Control
	}
	if slot < 0 {
		if m.allocation_failures > 0 {
			m.allocation_failures -= 1; return .Allocation
		}
		if free_stream_slots(m) == 0 {
			return .Capacity
		}
		slot = alloc_stream(m); m.streams[slot].id = id; m.streams[slot].recv_max = limit
	}
	s := &m.streams[slot]; s.externally_owned = true; s.recv_highest = max(high, end)
	s.recv_got = contiguous
	m.recv_data += extra; add_recv_retained(m, s, unique)
	if s.recv == .Empty {
		s.recv = .Recv
	}
	if fin {
		s.recv_fin = true; s.recv_final = end; s.recv = .Size_Known
	}
	// FIN is complete only when every preceding byte has arrived and been read.
	if s.recv_fin && s.recv_got == s.recv_final && s.recv_retained == 0 {
		s.recv = .Data_Recvd
	}
	return .None
}

stream_receive_reset :: proc(m: ^Model, id, final_size: u64) -> Error {
	if m == nil || !m.initialized {
		return .Invalid_Input
	}
	slot := find_stream(m, id)
	if slot < 0 {
		if e := stream_receive_admit(m, id, final_size, 0, 0, 0, false); e != .None {
			return e
		}
		slot = find_stream(m, id)
	}
	s := &m.streams[slot]
	if final_size < s.recv_highest ||
	   s.recv_fin && final_size != s.recv_final ||
	   final_size > s.recv_max {
		return .Protocol
	}
	extra := final_size - s.recv_highest
	if extra > m.recv_max_data - m.recv_data {
		return .Flow_Control
	}
	m.recv_data += extra; s.recv_highest = final_size; s.recv_final = final_size; s.recv_fin = true
	sub_recv_retained(m, s, s.recv_retained); s.recv = .Reset_Recvd
	maybe_free_stream(m, slot)
	return .None
}

stream_receive_release :: proc(m: ^Model, id: u64, n: int) -> Error {
	if m == nil || !m.initialized || n < 0 {
		return .Invalid_Input
	}
	slot := find_stream(m, id); if slot < 0 {
		return .Invalid_Input
	}
	if u64(n) > (u64(1) << 62) - 1 - m.recv_max_data ||
	   u64(n) > (u64(1) << 62) - 1 - m.streams[slot].recv_max {
		return .Invalid_Input
	}
	stream_limit := m.streams[slot].recv_max + u64(n)
	if e := consume_recv(m, id, n); e != .None {
		return e
	}
	m.recv_max_data += u64(n)
	if resumed_slot := find_stream(m, id); resumed_slot >= 0 {
		m.streams[resumed_slot].recv_max = stream_limit
	}
	return .None
}

stream_send_limit :: proc(m: ^Model, id, limit: u64) -> Error {
	slot := find_stream(m, id); if slot < 0 {
		return .Protocol
	}
	if limit > m.streams[slot].max_send {
		m.streams[slot].max_send = limit
	}
	return .None
}

// Frees the slot of an externally owned stream that its owner has closed in
// both directions. Received bytes the application never consumed, including
// the unseen remainder of a reset stream, are returned as connection credit;
// credit is how far the connection receive limit rose.
stream_release :: proc(m: ^Model, id: u64) -> (credit: u64, err: Error) {
	if m == nil || !m.initialized {
		return 0, .Invalid_Input
	}
	slot := find_stream(m, id); if slot < 0 {
		return 0, .None
	}
	s := &m.streams[slot]
	if s.recv_highest > s.consumed {
		credit = min(s.recv_highest - s.consumed, (u64(1) << 62) - 1 - m.recv_max_data)
	}
	m.recv_max_data += credit
	sub_send_retained(m, s, s.send_retained); sub_recv_retained(m, s, s.recv_retained)
	s^ = {}; m.live_streams -= 1
	return credit, .None
}
