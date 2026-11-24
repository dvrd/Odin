package conn
import "core:net/quic/harness"

stop_sending_with_error :: proc(c: ^Connection, id, code: u64) -> Error {
	if e := usable(c); e != .None {
		return e
	}; if code >= u64(1) << 62 {
		return .Invalid
	}
	b, e := take_recv(c, id); if e != .None {
		return e
	}
	if b.want_stop {
		if b.stop_error == code {
			return .None
		}; return .Protocol
	}
	b.want_stop = true; b.stop_error = code; return .None
}
receive_reset_error :: proc(c: ^Connection, id: u64) -> (u64, bool) {
	if c != nil {
		if b := find_buf(c, id); b != nil && b.recv_reset {
			return b.recv_reset_error, true
		}
	}; return 0, false
}
receive_stop_error :: proc(c: ^Connection, id: u64) -> (u64, bool) {
	if c != nil {
		if b := find_buf(c, id); b != nil && b.stop {
			return b.received_stop_error, true
		}
	}; return 0, false
}
@(private)
send_stop_progress :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error, bool) {
	if !journal_room(c) {
		return 0, .None, false
	}
	for &b in c.bufs {
		if !b.used || !b.want_stop || b.stop_acked || b.stop_sent && !b.stop_retry {
			continue
		}
		frame: [64]u8; frame[0] = 0x05; at, ok := put_varint(frame[:], 1, b.id); if ok {
			at, ok = put_varint(frame[:], at, b.stop_error)
		}
		if !ok {
			return 0, .Capacity, true
		}
		pn := c.model.spaces[2].next_send
		n, e := seal_and_emit(
			c,
			now,
			dst,
			harness.Emit{space = .Application, ping = true, probe = c.force_probe},
			frame[:at],
			0,
		)
		if e != .None {
			return n, e, true
		}
		c.force_probe = false
		if !record_tx(c, {pn = pn, id = b.id, stop = true}) {
			fail(c, "stop retention"); return 0, .Failed, true
		}
		b.stop_sent = true; b.stop_retry = false; return n, .None, true
	}
	return 0, .None, false
}
