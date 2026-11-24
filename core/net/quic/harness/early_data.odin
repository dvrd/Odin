package harness

// Rejection abandons only pre-confirmation Application packets, preserving the
// shared packet-number sequence and caller-owned stream offset accounting.
reject_early_packets :: proc(model: ^Model) -> Error {
	if model == nil || !model.initialized {
		return .Invalid_State
	}
	for i in 0 ..< len(model.packets[int(Space.Application)]) {
		if model.packets[int(Space.Application)][i].active {
			retire_packet(model, int(Space.Application), i)
		}
	}
	model.spaces[int(Space.Application)].has_loss_at = false
	model.spaces[int(Space.Application)].ack_eliciting_flight = 0
	model.pto_count = 0
	return .None
}

// Use the same variance/ACK-delay/backoff policy as recovery, with saturating
// arithmetic, when retaining server early keys for reordered packets.
early_key_discard_at :: proc(model: ^Model, now: i64) -> i64 {
	duration := pto_duration(model, .Application)
	return saturating_add(now, saturating_add(duration, saturating_add(duration, duration)))
}
