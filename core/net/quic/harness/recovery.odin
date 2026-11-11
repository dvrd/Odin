package harness

@(private)
peer_completed :: proc(m: ^Model) -> bool {
	if m.role == .Server {
		return true
	}
	return m.peer_validated_us || m.handshake_confirmed
}

@(private)
any_ack_eliciting :: proc(m: ^Model) -> bool {
	for s in m.spaces {
		if s.ack_eliciting_flight > 0 {
			return true
		}
	}
	return false
}

@(private)
server_at_amp_limit :: proc(m: ^Model) -> bool {
	if m.role != .Server || m.address_validated {
		return false
	}
	return amplification_budget(m) <= 0
}

amplification_budget :: proc(m: ^Model) -> int {
	if m == nil || !m.initialized {
		return 0
	}
	if m.role != .Server || m.address_validated {
		return max(int)
	}
	if m.path_received > max(int) / K_ANTI_AMPLIFICATION {
		return max(int) - m.path_sent
	}
	room := K_ANTI_AMPLIFICATION * m.path_received - m.path_sent
	if room < 0 {
		return 0
	}
	return room
}

@(private)
saturating_add :: proc(a, b: i64) -> i64 {
	if b < 0 {
		return a
	}
	if a > max(i64) - b {
		return max(i64)
	}
	return a + b
}

@(private)
pto_duration :: proc(m: ^Model, space: Space) -> i64 {
	varied := m.rttvar
	if varied > max(i64) / 4 {
		varied = max(i64) / 4
	}
	varied *= 4
	if varied < m.granularity {
		varied = m.granularity
	}
	base := saturating_add(m.smoothed_rtt, varied)
	shift := m.pto_count
	if shift < 0 {
		shift = 0
	}
	if shift > 30 {
		shift = 30
	}
	duration := base
	for _ in 0 ..< shift {
		if duration > max(i64) / 2 {
			duration = max(i64)
			break
		}
		duration *= 2
	}
	if space == .Application {
		extra := m.max_ack_delay
		for _ in 0 ..< shift {
			if extra > max(i64) / 2 {
				extra = max(i64)
				break
			}
			extra *= 2
		}
		duration = saturating_add(duration, extra)
	}
	if duration < m.granularity {
		duration = m.granularity
	}
	return duration
}

loss_detection_timer :: proc(m: ^Model, now: i64) -> Timer {
	if m == nil || !m.initialized || m.closed {
		return {}
	}
	earliest: i64
	have := false
	space := Space.Initial
	for i in 0 ..< 3 {
		sp := m.spaces[i]
		if sp.has_loss_at && (!have || sp.loss_at < earliest) {
			have = true
			earliest = sp.loss_at
			space = Space(i)
		}
	}
	if have {
		return {armed = true, at = earliest, space = space, kind = .Loss}
	}
	if server_at_amp_limit(m) {
		return {}
	}
	if !any_ack_eliciting(m) && peer_completed(m) {
		return {}
	}
	if !any_ack_eliciting(m) {
		kind := Timer_Kind.Anti_Deadlock_Initial
		sp := Space.Initial
		if m.handshake_armed {
			kind = .Anti_Deadlock_Handshake
			sp = .Handshake
		}
		return {armed = true, at = saturating_add(now, pto_duration(m, sp)), space = sp, kind = kind}
	}
	best: i64
	best_space: Space
	found := false
	for i in 0 ..< 3 {
		sp := m.spaces[i]
		s := Space(i)
		if sp.ack_eliciting_flight <= 0 || sp.discarded {
			continue
		}
		if s == .Application && !m.handshake_confirmed {
			if !found {
				return {}
			}
			return {armed = true, at = best, space = best_space, kind = .Probe}
		}
		at := saturating_add(sp.last_ack_eliciting_at, pto_duration(m, s))
		if !found || at < best {
			found = true
			best = at
			best_space = s
		}
	}
	if !found {
		return {}
	}
	return {armed = true, at = best, space = best_space, kind = .Probe}
}

@(private)
loss_delay :: proc(m: ^Model) -> i64 {
	hi := m.latest_rtt
	if m.smoothed_rtt > hi {
		hi = m.smoothed_rtt
	}
	delay := hi
	if hi > max(i64) / K_TIME_NUM {
		delay = max(i64)
	} else {
		delay = (hi * K_TIME_NUM) / K_TIME_DEN
	}
	if delay < m.granularity {
		delay = m.granularity
	}
	return delay
}

@(private)
retire_packet :: proc(m: ^Model, space, index: int) -> Packet {
	p := &m.packets[space][index]
	copy := p^
	if p.in_flight {
		m.bytes_in_flight -= p.sent_bytes
		if m.bytes_in_flight < 0 {
			m.bytes_in_flight = 0
		}
	}
	sp := &m.spaces[space]
	if p.ack_eliciting && sp.ack_eliciting_flight > 0 {
		sp.ack_eliciting_flight -= 1
	}
	if m.live_packets > 0 {
		m.live_packets -= 1
	}
	p^ = {}
	p.stream_slot = -1
	return copy
}

@(private)
update_rtt :: proc(m: ^Model, now, ack_delay: i64, sent_at: i64) {
	if sent_at > now {
		return
	}
	m.latest_rtt = now - sent_at
	if !m.has_first_rtt {
		m.min_rtt = m.latest_rtt
		m.smoothed_rtt = m.latest_rtt
		m.rttvar = m.latest_rtt / 2
		m.first_rtt_sample = now
		m.has_first_rtt = true
		return
	}
	if m.latest_rtt < m.min_rtt {
		m.min_rtt = m.latest_rtt
	}
	delay := ack_delay
	if delay < 0 {
		delay = 0
	}
	if m.handshake_confirmed && delay > m.max_ack_delay {
		delay = m.max_ack_delay
	}
	adjusted := m.latest_rtt
	if m.latest_rtt >= saturating_add(m.min_rtt, delay) {
		adjusted = m.latest_rtt - delay
	}
	// rttvar uses the previous smoothed_rtt, matching Appendix A.7's order.
	diff := m.smoothed_rtt - adjusted
	if diff < 0 {
		diff = -diff
	}
	m.rttvar = (3 * m.rttvar + diff) / 4
	m.smoothed_rtt = (7 * m.smoothed_rtt + adjusted) / 8
}

@(private)
detect_lost :: proc(m: ^Model, now: i64, space: int, lost_out: []u64) -> (n: int, err: Error) {
	if lost_out != nil && len(lost_out) < len(m.packets[space]) {
		return 0, .Destination_Undersized
	}
	sp := &m.spaces[space]
	sp.has_loss_at = false
	if !sp.has_largest_acked {
		return 0, .None
	}
	delay := loss_delay(m)
	lost_before := now - delay
	lost: [K_MAX_PACKETS_PER_SPACE]int
	count := 0
	for p, i in m.packets[space] {
		if !p.active || p.number > sp.largest_acked {
			continue
		}
		by_pn := p.number <= max(u64) - u64(K_PACKET_THRESHOLD) && sp.largest_acked >= p.number + u64(K_PACKET_THRESHOLD)
		by_time := p.sent_at <= lost_before
		if by_pn || by_time {
			lost[count] = i
			count += 1
			continue
		}
		at := saturating_add(p.sent_at, delay)
		if !sp.has_loss_at || at < sp.loss_at {
			sp.loss_at = at
			sp.has_loss_at = true
		}
	}
	copies: [K_MAX_PACKETS_PER_SPACE]Packet
	for i in 0 ..< count {
		copies[i] = retire_packet(m, space, lost[i])
		if lost_out != nil {
			lost_out[i] = copies[i].number
		}
	}
	on_packets_lost_cc(m, now, copies[:count])
	return count, .None
}

acknowledge :: proc(
	m: ^Model,
	now: i64,
	space: Space,
	smallest, largest: u64,
	ack_delay: i64,
	has_ecn: bool,
	ecn_ce: u64,
	lost_out: []u64,
) -> (lost_n: int, err: Error) {
	if m == nil || !m.initialized {
		return 0, .Invalid_State
	}
	if m.closed {
		return 0, .Closed
	}
	if now < 0 || ack_delay < 0 || largest < smallest || int(space) > 2 {
		return 0, .Invalid_Input
	}
	si := int(space)
	if m.spaces[si].discarded {
		return 0, .Discarded
	}
	if lost_out != nil && len(lost_out) < len(m.packets[si]) {
		return 0, .Destination_Undersized
	}
	sp := &m.spaces[si]
	if !sp.has_largest_acked || largest > sp.largest_acked {
		sp.largest_acked = largest
		sp.has_largest_acked = true
	}
	if space == .Handshake && m.role == .Client {
		m.peer_validated_us = true
	}
	acked: [K_MAX_PACKETS_PER_SPACE]Packet
	acked_n := 0
	for p, i in m.packets[si] {
		if p.active && p.number >= smallest && p.number <= largest {
			acked[acked_n] = p
			acked_n += 1
			retire_packet(m, si, i)
		}
	}
	if acked_n == 0 {
		lost_n, err = detect_lost(m, now, si, lost_out)
		if err == .None && peer_completed(m) {
			m.pto_count = 0
		}
		return lost_n, err
	}
	largest_i := 0
	eliciting := false
	for i in 0 ..< acked_n {
		if acked[i].number >= acked[largest_i].number {
			largest_i = i
		}
		if acked[i].ack_eliciting {
			eliciting = true
		}
	}
	if eliciting && acked[largest_i].number == largest {
		update_rtt(m, now, ack_delay, acked[largest_i].sent_at)
	}
	if has_ecn && (!m.has_ecn[si] || ecn_ce > m.ecn_ce[si]) {
		m.has_ecn[si] = true
		m.ecn_ce[si] = ecn_ce
		if acked[largest_i].number == largest {
			on_congestion_event(m, now, acked[largest_i].sent_at)
		}
	}
	lost_n, err = detect_lost(m, now, si, lost_out)
	if err != .None {
		return lost_n, err
	}
	for i in 0 ..< acked_n {
		on_packet_acked_cc(m, acked[i].sent_at, acked[i].sent_bytes)
		retire_stream_ack(m, acked[i])
	}
	if peer_completed(m) {
		m.pto_count = 0
	}
	return lost_n, .None
}

on_timeout :: proc(m: ^Model, now: i64, lost_out: []u64) -> (lost_n: int, kind: Timer_Kind, err: Error) {
	timer := loss_detection_timer(m, now)
	if !timer.armed {
		return 0, .None, .Invalid_State
	}
	if now < timer.at {
		return 0, .None, .Invalid_Input
	}
	if timer.kind == .Loss {
		lost_n, err = detect_lost(m, now, int(timer.space), lost_out)
		return lost_n, .Loss, err
	}
	m.pto_count += 1
	return 0, timer.kind, .None
}

discard_space :: proc(m: ^Model, space: Space) -> Error {
	if m == nil || !m.initialized {
		return .Invalid_State
	}
	if space == .Application {
		return .Invalid_Input
	}
	si := int(space)
	sp := &m.spaces[si]
	if sp.discarded {
		return .None
	}
	for i in 0 ..< len(m.packets[si]) {
		if m.packets[si][i].active {
			copy := retire_packet(m, si, i)
			if copy.stream_slot >= 0 {
				// Key discard abandons this space's payload count.
				if copy.stream_slot < len(m.streams) && m.streams[copy.stream_slot].active {
					sub_retained(m, &m.streams[copy.stream_slot], copy.stream_bytes)
				}
			}
		}
	}
	sp.discarded = true
	sp.has_loss_at = false
	sp.ack_eliciting_flight = 0
	m.pto_count = 0
	return .None
}

arm_handshake :: proc(m: ^Model) -> Error {
	if m == nil || !m.initialized || m.closed {
		return .Invalid_State
	}
	m.handshake_armed = true
	return .None
}

confirm_handshake :: proc(m: ^Model) -> Error {
	if m == nil || !m.initialized || m.closed {
		return .Invalid_State
	}
	m.handshake_confirmed = true
	m.peer_validated_us = true
	return discard_space(m, .Handshake)
}

reject_zero_rtt :: proc(m: ^Model) -> Error {
	if m == nil || !m.initialized {
		return .Invalid_State
	}
	si := int(Space.Application)
	for i in 0 ..< len(m.packets[si]) {
		if m.packets[si][i].active && m.packets[si][i].zero_rtt {
			retire_packet(m, si, i)
		}
	}
	return .None
}
