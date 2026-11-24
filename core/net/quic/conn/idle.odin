package conn
import "core:net/quic/idle"
import "core:net/quic/harness"

Timing_Stats :: struct {
	negotiated_timeout_ms:                           u64,
	effective_timeout_ms, remaining_ms, base_pto_ms: i64,
	expired:                                         bool,
}

// Transfer the wire driver's clock without restarting activity at TLS adoption.
configure_timing :: proc(c: ^Connection, state: idle.State, peer_max_ack_delay_ms: u64 = 25) -> Error {
	if c == nil || !c.initialized || peer_max_ack_delay_ms >= 1 << 14 {
		return .Invalid
	}
	c.idle = state
	c.model.max_ack_delay = i64(peer_max_ack_delay_ms)
	return .None
}

timing_stats :: proc(c: ^Connection, now: i64) -> Timing_Stats {
	if c == nil {
		return {}
	}
	pto := harness.base_pto(&c.model)
	if c.idle_expired {
		pto = c.idle_expiry_pto
	}
	result := Timing_Stats {
		negotiated_timeout_ms = idle.negotiated(&c.idle),
		effective_timeout_ms  = idle.period(&c.idle, pto),
		base_pto_ms           = pto,
		expired               = c.idle_expired,
	}
	if at, armed := idle.deadline(&c.idle, pto); armed {
		result.remaining_ms = max(0, at - now)
	}
	return result
}

// Call only after successful datagram transmission; output preparation is not I/O.
output_sent :: proc(c: ^Connection, now: i64, ack_eliciting: bool) {
	if c != nil && !idle_tick(c, now) && !c.idle_expired {
		idle.sent(&c.idle, now, ack_eliciting)
	}
}

output_ack_eliciting :: proc(c: ^Connection) -> bool {return c != nil && c.output_eliciting}

idle_tick :: proc(c: ^Connection, now: i64) -> bool {
	if c == nil || !c.initialized {
		return false
	}
	if c.idle_expired {
		return true
	}
	if c.phase == .Closed || c.phase == .Draining || c.phase == .Failed || c.want_close {
		return false
	}
	pto := harness.base_pto(&c.model)
	if !idle.expired(&c.idle, pto, now) {
		return false
	}
	clock := c.idle
	destroy(c)
	c.idle = clock
	c.idle_expired = true
	c.idle_expiry_pto = pto
	c.initialized = true
	c.phase = .Closed
	c.reason = "idle timeout"
	return true
}

@(private)
application_pto_confirmed :: proc(c: ^Connection) -> bool {
	return c != nil && !early(c) && (c.role == .Server || c.seen_done)
}
