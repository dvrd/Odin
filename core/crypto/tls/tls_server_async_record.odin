package tls

import "core:crypto"
import "core:net"
import "core:time"

@(private)
server_async_receive_done :: proc(op: ^net.Async_Operation) {
	s := cast(^Server_Async_Conn)op.user_data
	remaining := 5 - s._rx_header_used if s._rx_into_header else s._rx_expected - s._rx_used
	n := op.result.count
	if n < 0 || n > remaining {
		s._rx_error = net.Connection_Error.Invalid_Count
	} else {
		if s._rx_into_header {
			s._rx_header_used += n
		} else {
			s._rx_used += n
		}
		s._rx_error = op.result.err
		if n == 0 && s._rx_error == nil {
			s._rx_error = net.Connection_Error.No_Progress
		}
	}
	server_async_queue(s)
}

@(private)
server_async_receive_error :: proc(s: ^Server_Async_Conn) -> bool {
	e := s._rx_error
	if e == nil {
		return false
	}
	if s._phase == .Established && (e == net.TCP_Recv_Error.Timeout || e == net.Connection_Error.Cancelled) {
		s._rx_error = nil
		if s._read_cancel {
			e = net.Connection_Error.Cancelled
		}
		server_async_emit(s, .Read, e)
	} else {
		kind := Server_Async_Failure_Kind.Transport
		if e == net.Connection_Error.Peer_Closed {
			kind = .Unexpected_EOF
			e = net.Connection_Error.Protocol_Failed
		}
		server_async_fail(s, e, {kind = kind, transport = s._rx_error})
	}
	return true
}

@(private)
server_async_receive_record :: proc(s: ^Server_Async_Conn, deadline: time.Time) -> (Record_Header, bool) {
	if s._rx.pending {
		return {}, false
	}
	if s._rx_header_used == 5 && s._rx_expected == 0 {
		h, e := record_header_decode(s._rx_header)
		if e != .None {
			server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Record, record = e})
			return {}, false
		}
		if h.legacy_version != LEGACY_TLS_1_2 &&
		   !(s._phase == .Handshaking &&
				   !s._ccs_allowed &&
				   h.content_type == .Handshake &&
				   h.legacy_version == LEGACY_TLS_1_0) {
			server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Record, protection = .Invalid_Legacy_Version})
			return {}, false
		}
		if h.content_type == .Application_Data {
			if !s._read_keys {
				server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Record, protection = .Invalid_State})
				return {}, false
			}
			if int(h.length) > MAX_CIPHERTEXT_SIZE || int(h.length) < GCM_TAG_SIZE + 1 {
				server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Record, protection = .Record_Oversized})
				return {}, false
			}
		} else {
			if error := record_header_validate_plaintext(h); error != .None {
				server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Record, record = error})
				return {}, false
			}
		}
		if !server_async_grant(s, &s._rx_wire, RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE) {
			return {}, false
		}
		copy(s._rx_wire, s._rx_header[:])
		s._rx_used = 5
		s._rx_expected = 5 + int(h.length)
	}
	if s._rx_expected != 0 && s._rx_used == s._rx_expected {
		h, _ := record_header_decode(s._rx_header)
		// Complete authenticated records win transient cancellation/deadline
		// races. Other trailing transport errors stay visible at the next read.
		if s._rx_error == net.TCP_Recv_Error.Timeout || s._rx_error == net.Connection_Error.Cancelled {
			s._rx_error = nil
		}
		return h, true
	}
	if server_async_receive_error(s) {
		return {}, false
	}
	if s._phase == .Established && s._read_cancel {
		server_async_emit(s, .Read, net.Connection_Error.Cancelled)
		return {}, false
	}
	if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {
		if s._phase == .Established {
			server_async_emit(s, .Read, net.TCP_Recv_Error.Timeout)
		} else {
			server_async_fail(s, net.TCP_Recv_Error.Timeout, {kind = .Handshake})
		}
		return {}, false
	}
	s._rx_into_header = s._rx_header_used < 5
	dst := s._rx_header[s._rx_header_used:]
	if !s._rx_into_header {
		dst = s._rx_wire[s._rx_used:s._rx_expected]
	}
	e := net.async_read(s._transport, &s._rx, dst, deadline)
	if e != nil {
		s._rx_error = e
		server_async_queue(s)
	}
	return {}, false
}

@(private)
server_async_record_consumed :: proc(s: ^Server_Async_Conn, keep_plain := false) {
	if s._stats.read_records < max(int) {
		s._stats.read_records += 1
	}
	if len(s._rx_wire) > 0 {
		crypto.zero_explicit(raw_data(s._rx_wire), len(s._rx_wire))
	}
	crypto.zero_explicit(&s._rx_header, size_of(s._rx_header))
	s._rx_header_used, s._rx_used, s._rx_expected = 0, 0, 0
	if !keep_plain {
		server_async_plain_consumed(s)
	}
}

@(private)
server_async_plain_consumed :: proc(s: ^Server_Async_Conn) {
	if len(s._rx_plain) > 0 {
		crypto.zero_explicit(raw_data(s._rx_plain), len(s._rx_plain))
	}
	s._plain_at, s._plain_size = 0, 0
}

@(private)
server_async_open :: proc(s: ^Server_Async_Conn) -> (TLS_Content_Type, []u8, bool) {
	if !server_async_grant(s, &s._rx_plain, MAX_CIPHERTEXT_SIZE) {
		return {}, nil, false
	}
	kind, body, e := engine_record_open(&server_async_keys(s).read, s._rx_plain, s._rx_wire[:s._rx_expected])
	if e != .None {
		server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Record, protection = e})
		return {}, nil, false
	}
	return kind, body, true
}

@(private)
server_async_send_record :: proc(
	s: ^Server_Async_Conn,
	content: TLS_Content_Type,
	body: []u8,
	kind: Server_Async_Send,
	deadline: time.Time,
) -> bool {
	if !server_async_grant(s, &s._tx_wire, RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE) {
		return false
	}
	n := 0
	if s._write_keys {
		size, e := engine_record_seal(&server_async_keys(s).write, s._tx_wire, content, body)
		if e != .None {
			server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Record, protection = e})
			return false
		}
		n = size
	} else {
		if len(body) > MAX_PLAINTEXT_SIZE {
			server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Limit})
			return false
		}
		header := record_header_encode(
			{content_type = content, legacy_version = LEGACY_TLS_1_2, length = u16(len(body))},
		)
		copy(s._tx_wire, header[:])
		copy(s._tx_wire[5:], body)
		n = 5 + len(body)
	}
	s._tx_kind, s._tx_size = kind, n
	e := net.async_write(s._transport, &s._tx, s._tx_wire[:n], deadline)
	if e != nil {
		s._tx.result = {
			err = e,
		}
		s._tx_done = true
		server_async_queue(s)
	}
	return true
}

@(private)
server_async_send_done :: proc(op: ^net.Async_Operation) {
	s := cast(^Server_Async_Conn)op.user_data
	s._tx_done = true
	server_async_queue(s)
}

@(private)
server_async_send_process :: proc(s: ^Server_Async_Conn) {
	kind := s._tx_kind
	s._tx_kind = .None
	n, e := s._tx.result.count, s._tx.result.err
	if n < 0 || n > s._tx_size {
		e = net.Connection_Error.Invalid_Count
	}
	if n == s._tx_size && (e == net.Connection_Error.Cancelled || e == net.TCP_Send_Error.Timeout) {
		e = {}
	}
	if n != s._tx_size || e != nil {
		if e == nil {
			e = net.TCP_Send_Error.Unknown
		}
		if kind == .Notify {
			s._close_error = e
		}
		server_async_fail(s, e, {kind = .Transport, transport = e, wire_transferred = n})
		return
	}
	if s._stats.written_records < max(int) {
		s._stats.written_records += 1
	}
	if len(s._tx_wire) > 0 {
		crypto.zero_explicit(raw_data(s._tx_wire), len(s._tx_wire))
	}
	switch kind {
	case .Handshake:
		e := engine_server_handshake_accept(&s._engine, s._engine_event)
		s._engine_event = 0
		if e != .None {
			server_async_fail(s, net.Connection_Error.Protocol_Failed, {kind = .Handshake, engine = e})
		}
	case .Data:
		if s._write_op != nil {
			s._write_op.result.count += s._tx_plain_count
			if s._write_op.result.count == len(s._write_buffer) {
				server_async_emit(s, .Write, {})
			}
		}
	case .Key_Update:
		server_async_rotate(s, .Write)
		if s._stats.sent_key_updates < max(int) {
			s._stats.sent_key_updates += 1
		}
	case .Notify:
		s._notify_sent = true
	case .Fatal_Alert:
		s._fatal_alert_sent = true
	case .None:
	}
	s._tx_size, s._tx_plain_count = 0, 0
}

// Installs a handshake traffic secret of suite for one direction.
@(private)
server_async_install :: proc(
	s: ^Server_Async_Conn,
	direction: Server_Handshake_Direction,
	suite: Cipher_Suite,
	secret: []u8,
) {
	keys := server_async_keys(s)
	if direction == .Read {
		record_protection_init(&keys.read, suite, secret)
		s._read_keys = true
	} else {
		record_protection_init(&keys.write, suite, secret)
		s._write_keys = true
	}
}

// Keeps an application traffic secret for KeyUpdate. The client's secret
// protects what this server reads.
@(private)
server_async_application_secret :: proc(
	s: ^Server_Async_Conn,
	direction: Server_Handshake_Direction,
	suite: Cipher_Suite,
	secret: []u8,
) {
	keys := server_async_keys(s)
	schedule_load_secret(&keys.application, suite, secret, direction == .Read)
	keys.application.is_client = false
}

// Derives the keys of the current application secret of one direction
// (upstream's update_connection_aead) and moves them into its protection.
@(private)
server_async_application_install :: proc(s: ^Server_Async_Conn, direction: Server_Handshake_Direction) {
	keys := server_async_keys(s)
	if direction == .Read {
		update_connection_aead(&keys.application, true, false)
		record_protection_init(&keys.read, &keys.application.client_aead)
		s._read_keys = true
	} else {
		update_connection_aead(&keys.application, false, false)
		record_protection_init(&keys.write, &keys.application.server_aead)
		s._write_keys = true
	}
}

// KeyUpdate: the next generation of one direction (upstream's
// update_connection_secret), installed at sequence zero.
@(private)
server_async_rotate :: proc(s: ^Server_Async_Conn, direction: Server_Handshake_Direction) {
	keys := server_async_keys(s)
	update_connection_secret(&keys.application, direction == .Write)
	if direction == .Read {
		record_protection_init(&keys.read, &keys.application.client_aead)
	} else {
		record_protection_init(&keys.write, &keys.application.server_aead)
	}
}
