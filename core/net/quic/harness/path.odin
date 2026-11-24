package harness

// A validated change of network starts a new congestion epoch. Retained packets
// and packet numbers survive, but old-path ACK/loss cannot tune the new path.
migrate_path :: proc(m: ^Model, now: i64) {
	if m == nil || !m.initialized {
		return
	}
	m.path_epoch += 1
	m.bytes_in_flight = 0
	m.congestion_window = initial_window(m.max_datagram_size)
	m.ssthresh = -1
	m.latest_rtt = 0
	m.smoothed_rtt = K_INITIAL_RTT_MS
	m.rttvar = K_INITIAL_RTT_MS / 2
	m.min_rtt = 0
	m.has_first_rtt = false
	m.first_rtt_sample = now
	m.in_recovery = false
	m.recovery_start = 0
	m.pto_count = 0
}

// Apply only validated ECN feedback attributed to this congestion epoch.
ecn_congestion :: proc(m: ^Model, now, sent_at: i64) {
	if m != nil && m.initialized {
		on_congestion_event(m, now, sent_at)
	}
}
