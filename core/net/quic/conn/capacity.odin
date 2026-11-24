package conn

// Records free for streams that are open at the same time. A stream gives its
// record back once it is closed in both directions and acknowledged.
remaining_stream_records :: proc(c: ^Connection) -> int {
	if c == nil || !c.initialized {
		return 0
	}
	buffers, model := 0, 0
	for b in c.bufs {
		if !b.used {
			buffers += 1
		}
	}
	for s in c.model.streams {
		if !s.active {
			model += 1
		}
	}
	return min(buffers, model)
}

// Admission is read-only. A closed ID reports Protocol; an ID that would skip
// the next stream of its kind reports Stream_Order.
stream_admission :: proc(c: ^Connection, id: u64) -> Error {
	if e := usable(c); e != .None {
		return e
	}
	if id >= u64(1) << 62 {
		return .Invalid
	}
	if !our_stream(c, id) {
		if find_buf(c, id) != nil {
			return .None
		}
		return .Invalid
	}
	if id >> 2 < c.opened[id & 3] {
		if find_buf(c, id) != nil {
			return .None
		}
		return .Protocol
	}
	if id >> 2 > c.opened[id & 3] {
		return .Stream_Order
	}
	_, limit := send_limits(c, id)
	if id / 4 >= limit {
		return .Flow_Control
	}
	if find_buf(c, id) == nil && remaining_stream_records(c) <= 0 {
		return .Capacity
	}
	return .None
}

close_with_application_error :: proc(c: ^Connection, code: u64) -> Error {
	if e := usable(c); e != .None {
		return e
	}
	if code >= u64(1) << 62 || !c.hs.have_one_rtt || !c.hs.one_rtt_write.initialized {
		return .Invalid
	}
	c.close_application = true
	c.close_error = code
	c.want_close = true
	return .None
}

// Read-only terminal deadline query for event loops that poll at/after expiry.
drain_complete :: proc(c: ^Connection, now: i64) -> bool {
	return c != nil &&
		c.initialized &&
		(c.phase == .Closed || c.phase == .Failed || c.phase == .Draining && now >= c.draining_until)
}
