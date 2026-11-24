package harness

@(private)
in_recovery_at :: proc(m: ^Model, sent_at: i64) -> bool {
	return m.in_recovery && sent_at <= m.recovery_start
}

// RFC 9002 Appendix B.6. Half the congestion window, not bytes in flight.
// in_recovery stays set so a later loss of an older packet does not reduce again.
@(private)
on_congestion_event :: proc(m: ^Model, now, sent_at: i64) {
	if in_recovery_at(m, sent_at) {
		return
	}
	m.in_recovery = true
	m.recovery_start = now
	half := m.congestion_window / 2
	m.ssthresh = i64(half)
	floor := minimum_window(m.max_datagram_size)
	if half < floor {
		m.congestion_window = floor
	} else {
		m.congestion_window = half
	}
}

@(private)
on_packet_acked_cc :: proc(m: ^Model, sent_at: i64, sent_bytes: int) {
	if m.app_limited || m.flow_limited || sent_bytes <= 0 {
		return
	}
	if in_recovery_at(m, sent_at) {
		return
	}
	if m.ssthresh < 0 || i64(m.congestion_window) < m.ssthresh {
		if m.congestion_window <= max(int) - sent_bytes {
			m.congestion_window += sent_bytes
		}
		return
	}
	if m.congestion_window <= 0 {
		return
	}
	grow := m.max_datagram_size * sent_bytes / m.congestion_window
	if grow < 0 {
		return
	}
	if m.congestion_window <= max(int) - grow {
		m.congestion_window += grow
	}
}

@(private)
persistent_duration :: proc(m: ^Model) -> i64 {
	varied := m.rttvar
	if varied > max(i64) / 4 {
		varied = max(i64) / 4
	}
	varied *= 4
	if varied < m.granularity {
		varied = m.granularity
	}
	base := m.smoothed_rtt + varied + m.max_ack_delay
	return base * K_PERSISTENT_CONGESTION_THRESHOLD
}

@(private)
note_persistent :: proc(m: ^Model, lost: []Packet) {
	if !m.has_first_rtt || len(lost) == 0 {
		return
	}
	oldest, newest: i64
	count := 0
	for p in lost {
		if p.path_epoch != m.path_epoch || p.path != m.path || !p.ack_eliciting || p.sent_at <= m.first_rtt_sample {
			continue
		}
		if count == 0 || p.sent_at < oldest {
			oldest = p.sent_at
		}
		if count == 0 || p.sent_at > newest {
			newest = p.sent_at
		}
		count += 1
	}
	if count < 2 {
		return
	}
	if newest - oldest > persistent_duration(m) {
		m.congestion_window = minimum_window(m.max_datagram_size)
		m.in_recovery = false
	}
}

@(private)
on_packets_lost_cc :: proc(m: ^Model, now: i64, lost: []Packet) {
	last := i64(-1)
	for p in lost {
		if p.path_epoch == m.path_epoch && p.path == m.path && p.in_flight && p.sent_at > last {
			last = p.sent_at
		}
	}
	if last >= 0 {
		on_congestion_event(m, now, last)
	}
	note_persistent(m, lost)
}
