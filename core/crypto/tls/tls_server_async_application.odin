package tls

import "core:crypto"
import "core:time"

@(private)
server_async_post_handshake :: proc(s: ^Server_Async_Conn, body: []u8) -> bool {
	for b, i in body {
		if s._post_used >= 5 {
			server_async_fail(s, {kind = .Protocol_Failed}, {kind = .Post_Handshake})
			return false
		}
		s._post[s._post_used] = b
		s._post_used += 1
		if s._post[0] != 24 || s._post_used >= 4 && (s._post[1] != 0 || s._post[2] != 0 || s._post[3] != 1) {
			server_async_fail(s, {kind = .Protocol_Failed}, {kind = .Post_Handshake})
			return false
		}
		if s._post_used == 5 {
			if b > 1 || i != len(body) - 1 {
				server_async_fail(s, {kind = .Protocol_Failed}, {kind = .Post_Handshake})
				return false
			}
			server_async_rotate(s, .Read)
			if s._stats.received_key_updates < max(int) {
				s._stats.received_key_updates += 1
			}
			if b == 1 {
				s._key_update_pending = true
			}
			s._post, s._post_used = {}, 0
		}
	}
	return true
}

@(private)
server_async_application_drive :: proc(s: ^Server_Async_Conn) {
	if s._read_op != nil {
		if len(s._read_buffer) == 0 {
			server_async_emit(s, .Read, {})
		} else if s._plain_at < s._plain_size {
			n := copy(s._read_buffer, s._rx_plain[s._plain_at:s._plain_size])
			s._plain_at += n
			s._read_op.result.count = n
			if s._plain_at == s._plain_size {
				server_async_plain_consumed(s)
			}
			s._non_application_records = 0
			server_async_emit(s, .Read, {})
		} else if s._peer_closed {
			server_async_emit(s, .Read, {kind = .Peer_Closed})
		} else {
			header, ready := server_async_receive_record(s, s._read_deadline)
			if ready {
				if header.content_type != .Application_Data {
					server_async_fail(
						s,
						{kind = .Protocol_Failed},
						{kind = .Record, protection = .Unexpected_Outer_Content_Type},
					); return
				}
				kind, body, ok := server_async_open(s)
				if !ok {
					return
				}
				if s._post_used > 0 && kind != .Handshake {
					server_async_fail(s, {kind = .Protocol_Failed}, {kind = .Post_Handshake})
					return
				}
				keep := false
				#partial switch kind {
				case .Application_Data:
					if len(body) > 0 {
						s._plain_at, s._plain_size = 0, len(body)
						keep = true
					}
				case .Handshake:
					if !server_async_post_handshake(s, body) {
						return
					}
				case .Alert:
					if body[1] == 0 {
						s._peer_closed = true
						record_protection_clear(&server_async_keys(s).read)
						crypto.zero_explicit(
							&server_async_keys(s).application.client_secret,
							size_of(server_async_keys(s).application.client_secret),
						)
					} else if body[1] != 90 {
						server_async_fail(
							s,
							{kind = .Protocol_Failed},
							{kind = .Peer_Alert, alert_level = body[0], alert_description = body[1]},
						); return
					}
				case:
					server_async_fail(
						s,
						{kind = .Protocol_Failed},
						{kind = .Record, record = .Unexpected_Content_Type},
					); return
				}
				server_async_record_consumed(s, keep)
				if !keep && !s._peer_closed {
					s._non_application_records += 1
					if s._non_application_records > MAX_NON_APPLICATION_RECORDS {
						server_async_fail(s, {kind = .Protocol_Failed}, {kind = .Limit})
						return
					}
				}
				server_async_queue(s)
			}
		}
	}
	if s._closing || s._failure.kind != .None || s._tx.pending || s._tx_done {
		return
	}
	keys := server_async_keys(s)
	if s._key_update_pending || s._write_op != nil && keys.write.seq >= record_protection_limit(&keys.write) - 1 {
		request := u8(1) if s._key_update_request else u8(0)
		s._key_update_pending, s._key_update_request = false, false
		deadline := time.time_add(time.now(), s._config.close_timeout)
		if s._write_op != nil && s._write_deadline != (time.Time{}) && time.diff(s._write_deadline, deadline) > 0 {
			deadline = s._write_deadline
		}
		_ = server_async_send_record(s, .Handshake, []u8{24, 0, 0, 1, request}, .Key_Update, deadline)
		return
	}
	if s._write_op == nil {
		return
	}
	if s._write_cancel {
		server_async_emit(s, .Write, {kind = .Cancelled})
		return
	}
	written := s._write_op.result.count
	if written == len(s._write_buffer) {
		server_async_emit(s, .Write, {})
		return
	}
	if s._write_deadline != (time.Time{}) && time.diff(time.now(), s._write_deadline) <= 0 {
		server_async_emit(s, .Write, {kind = .Timeout})
		return
	}
	count := min(MAX_PLAINTEXT_SIZE, len(s._write_buffer) - written)
	s._tx_plain_count = count
	_ = server_async_send_record(
		s,
		.Application_Data,
		s._write_buffer[written:written + count],
		.Data,
		s._write_deadline,
	)
}
