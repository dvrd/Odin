package tls

import "core:crypto"
import "core:crypto/aead"
import transport "core:net"
import "core:time"

// Bounds memory and processing for peers that never produce application data.
MAX_NEW_SESSION_TICKET_BODY_SIZE :: 4 + 4 + 1 + 255 + 2 + 65535 + 2 + 65534
@(private)
MAX_NON_APPLICATION_RECORDS :: 1024
// Upstream's client gives up a recv after this many records without data.
@(private)
UPSTREAM_MAX_USELESS_RECORDS :: 16
@(private)
NEW_SESSION_TICKET_TYPE :: cast(u8)4

@(private)
IO_Error_Kind :: enum {
	None,
	EOF,
	Closed,
	Invalid_State,
	Handshake_Failed,
	Transport_Read_Failed,
	Transport_Write_Failed,
	Transport_Close_Failed,
	Unexpected_EOF,
	Invalid_Record,
	Encryption_Failed,
	Decryption_Failed,
	Unexpected_Content_Type,
	Peer_Alert,
	Interleaved_Record,
	Record_Boundary_Violation,
	Invalid_Post_Handshake,
	Post_Handshake_Oversized,
	No_Progress,
}

@(private)
IO_Error :: struct {
	kind:                           IO_Error_Kind,
	handshake:                      Handshake_Error,
	transport:                      transport.Connection_Error,
	protection:                     Record_Protection_Error,
	record:                         Record_Error,
	transferred:                    int,
	alert_level, alert_description: u8,
}

// Internal connection-owned state. Its fixed post-handshake buffer covers the
// protocol's largest NewSessionTicket, without attacker-controlled allocation.
// Reading and writing this connection concurrently is not supported yet.
Application_State :: struct {
	initialized:                                  bool,
	send, receive:                                Record_Protection,
	// Application traffic secrets of both directions (upstream's schedule
	// state); a KeyUpdate advances one of them and re-keys its protection.
	secrets:                                      Connection_Secrets,
	inbound:                                      [MAX_INNER_PLAINTEXT_SIZE]u8,
	inbound_at, inbound_size:                     int,
	post_handshake:                               [4 + MAX_NEW_SESSION_TICKET_BODY_SIZE]u8,
	post_used, post_expected:                     int,
	peer_closed:                                  bool,
	key_update_pending:                           bool,
	failure:                                      IO_Error,
	resumption_secret:                            [MAX_TRANSCRIPT_HASH_SIZE]u8,
	resumption_secret_size:                       int,
	have_resumption:                              bool,
}

application_init :: proc {
	application_init_schedule,
	application_init_secrets,
}

// Takes over the client's application traffic secrets and AEAD state from
// the schedule. A nonempty resumption_master allows tickets to be remembered.
@(private)
application_init_schedule :: proc(
	state: ^Application_State,
	secrets: ^Connection_Secrets,
	resumption_master: []u8 = nil,
) {
	if state == nil || secrets == nil {
		return
	}

	application_clear(state)
	state.secrets = secrets^
	// The key log moves with the secrets: later KeyUpdates are logged too,
	// and application_clear closes the file, as upstream's close does.
	secrets.unsafe_secret_logger = nil
	record_protection_init(&state.send, &state.secrets.client_aead)
	record_protection_init(&state.receive, &state.secrets.server_aead)
	aead.reset(&secrets.client_aead.ctx)
	aead.reset(&secrets.server_aead.ctx)

	if len(resumption_master) > 0 {
		state.resumption_secret_size = copy(state.resumption_secret[:], resumption_master)
		state.have_resumption = true
	}
	state.initialized = true
}

// TLS_AES_128_GCM_SHA256 application secrets by value, for peers that drive
// the pure codecs. The protections use the keys and IVs exactly as given; a
// later KeyUpdate derives from the traffic secrets.
@(private)
application_init_secrets :: proc(
	state: ^Application_State,
	secrets: Application_Secrets,
	resumption_master: [32]u8 = {},
	remember: bool = false,
) {
	if state == nil {
		return
	}

	local := secrets
	defer crypto.zero_explicit(&local, size_of(local))

	application_clear(state)
	schedule_load_secret(&state.secrets, .TLS_AES_128_GCM_SHA256, local.client_traffic_secret[:], true)
	copy(state.secrets.server_secret[:], local.server_traffic_secret[:])
	record_protection_init(&state.send, local.client_key, local.client_iv)
	record_protection_init(&state.receive, local.server_key, local.server_iv)

	if remember {
		master := resumption_master
		state.resumption_secret_size = copy(state.resumption_secret[:], master[:])
		state.have_resumption = true
	}
	state.initialized = true
}

@(private)
application_clear :: proc(state: ^Application_State) {
	if state != nil {
		clear_connection_secrets(&state.secrets)
		crypto.zero_explicit(state, size_of(Application_State))
	}
}

// Reads stream bytes only after handshake authentication succeeds. A short
// destination retains the rest of the decrypted record for later calls. EOF
// means authenticated close_notify; a raw transport close is Unexpected_EOF.
@(private)
engine_read :: proc(conn: ^Conn, dst: []u8) -> (received: int, error: IO_Error) {
	if err := application_ensure(conn); err.kind != .None {
		return 0, err
	}

	if conn.tls12.negotiated do return tls12_application_read(conn, dst)

	received, error = application_read_records(conn, dst)
	if error.kind != .None && error.kind != .EOF {
		return 0, application_fail(conn, error)
	}
	return received, error
}

// The receive direction of an established TLS 1.3 connection: it touches
// only the receive protection, the inbound buffer and the server's traffic
// secret, so one thread may run it while another runs
// application_write_records. A failure is returned, not recorded: the caller
// owns the connection's terminal state. A KeyUpdate request is answered here
// unless conn.defer_key_updates leaves key_update_pending for the caller.
@(private)
application_read_records :: proc(conn: ^Conn, dst: []u8) -> (received: int, error: IO_Error) {
	if len(dst) == 0 {
		return 0, {}
	}

	state := &conn.application
	if state.inbound_at < state.inbound_size {
		count := copy(dst, state.inbound[state.inbound_at:state.inbound_size])
		state.inbound_at += count
		return count, {}
	}

	if state.peer_closed {
		return 0, {kind = .EOF}
	}

	limit := MAX_NON_APPLICATION_RECORDS
	if conn.upstream_client {
		limit = UPSTREAM_MAX_USELESS_RECORDS
	}

	for useless := 0; useless < limit; useless += 1 {
		content_type, content, record_err := application_record_read(conn)
		if record_err.kind != .None {
			return 0, record_err
		}

		if state.post_used > 0 && content_type != .Handshake {
			return 0, {kind = .Interleaved_Record}
		}

		#partial switch content_type {
		case .Application_Data:
			if len(content) == 0 {
				continue
			}

			state.inbound_at = copy(dst, content)
			state.inbound_size = len(content)
			return state.inbound_at, {}
		case .Alert:
			if alert_error := application_alert_apply(state, content); alert_error.kind != .None {
				return 0, alert_error
			}
		case .Handshake:
			if err := application_post_handshake(conn, content); err.kind != .None {
				return 0, err
			}

			// Upstream counts empty records and user_canceled, not KeyUpdates.
			if conn.upstream_client {
				useless -= 1
			}
		case:
			return 0, {kind = .Unexpected_Content_Type}
		}
	}
	return 0, {kind = .No_Progress}
}

@(private)
application_alert_read :: proc(conn: ^Conn, content: []u8) -> IO_Error {
	err := application_alert_apply(&conn.application, content)
	if err.kind == .Peer_Alert {
		return application_fail(conn, err)
	}
	return err
}

// close_notify ends the receive direction (EOF) and user_canceled is
// ignored; any other alert is the peer's fatal error, returned unrecorded.
@(private)
application_alert_apply :: proc(state: ^Application_State, content: []u8) -> IO_Error {
	switch content[1] {
	case 0:
		state.peer_closed = true
		record_protection_clear(&state.receive)
		crypto.zero_explicit(&state.secrets.server_secret, size_of(state.secrets.server_secret))
		return {kind = .EOF}
	case 90:
		return {}
	}
	return {kind = .Peer_Alert, alert_level = content[0], alert_description = content[1]}
}

// Splits application bytes into records of at most 16KiB. A partial transport
// write is terminal: its record cannot be retried under a reused nonce. The
// returned count includes only complete records successfully sent.
@(private)
engine_write :: proc(conn: ^Conn, src: []u8) -> (written: int, error: IO_Error) {
	if err := application_ensure(conn); err.kind != .None {
		return 0, err
	}
	if conn.tls12.negotiated do return tls12_application_write(conn, src)

	written, error = application_write_records(conn, src)
	if error.kind != .None {
		return written, application_fail(conn, error)
	}
	return written, {}
}

// The send direction of an established TLS 1.3 connection: it touches only
// the send protection and the client's traffic secret. A failure is
// returned, not recorded.
@(private)
application_write_records :: proc(conn: ^Conn, src: []u8) -> (written: int, error: IO_Error) {
	for written < len(src) {
		// Reserve the final allowed old-key record for KeyUpdate itself.
		if application_send_key_exhausted(&conn.application) {
			if err := application_send_key_update(conn); err.kind != .None {
				return written, err
			}
		}

		count := min(MAX_PLAINTEXT_SIZE, len(src) - written)
		if err := application_record_write(conn, .Application_Data, src[written:][:count]); err.kind != .None {
			return written, err
		}

		written += count
	}
	return written, {}
}

// Sends close_notify under the current application keys, then always closes
// the transport once and destroys key material. It does not wait for a reply.
@(private)
engine_close :: proc(conn: ^Conn) -> IO_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Closed do return {}

	if conn.phase == .Uninitialized {
		return {kind = .Invalid_State}
	}

	err: IO_Error
	if conn.phase == .Established && conn.application.initialized && !conn.send_ended {
		alert := [?]u8{1, 0}
		if conn.tls12.negotiated {
			err = tls12_application_close_notify(conn)
		} else {
			err = application_record_write(conn, .Alert, alert[:])
		}
	}

	conn.phase = .Closed
	alpn_clear(conn)
	application_clear(&conn.application)
	handshake_keys_clear(conn)
	transport_err := conn.transport.close(conn.transport.data)
	if err.kind == .None && transport_err.kind != .None {
		err = {
			kind      = .Transport_Close_Failed,
			transport = transport_err,
		}
	}

	return err
}

@(private)
application_ensure :: proc(conn: ^Conn) -> IO_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Closed do return {kind = .Closed}

	if conn.phase == .Uninitialized {
		return {kind = .Invalid_State}
	}

	if conn.application.failure.kind != .None {
		return conn.application.failure
	}

	if conn.phase != .Established {
		if err := engine_handshake(conn); err.kind != .None {
			return application_fail(conn, {kind = .Handshake_Failed, handshake = err})
		}
	}

	if !conn.application.initialized {
		return {kind = .Invalid_State}
	}

	return {}
}

@(private)
application_record_write :: proc(
	conn: ^Conn,
	content_type: TLS_Content_Type,
	content: []u8,
) -> IO_Error {
	wire: [RECORD_HEADER_SIZE + MAX_INNER_PLAINTEXT_SIZE + GCM_TAG_SIZE]u8
	size, protection_err := engine_record_seal(&conn.application.send, wire[:], content_type, content)
	if protection_err != .None {
		return {kind = .Encryption_Failed, protection = protection_err}
	}

	written, transport_err := transport.write_all(conn.transport, wire[:size])
	if transport_err.kind != .None {
		return {kind = .Transport_Write_Failed, transport = transport_err, transferred = written}
	}

	return {}
}

@(private)
application_record_read :: proc(conn: ^Conn) -> (TLS_Content_Type, []u8, IO_Error) {
	wire: [RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE]u8
	wire_size, wire_error := application_record_wire_read(conn, wire[:])
	if wire_error.kind != .None do return {}, nil, wire_error
	content_type, content, protection_err := engine_record_open(
		&conn.application.receive,
		conn.application.inbound[:],
		wire[:wire_size],
	)
	if protection_err != .None {
		return {}, nil, {kind = .Decryption_Failed, protection = protection_err}
	}

	return content_type, content, {}
}

@(private)
application_record_wire_read :: proc(conn: ^Conn, wire: []u8) -> (int, IO_Error) {
	header_count, header_err := transport.read_exact(conn.transport, wire[:RECORD_HEADER_SIZE])
	if header_err.kind != .None {
		kind: IO_Error_Kind = .Transport_Read_Failed
		if header_err.kind == .Peer_Closed {
			kind = .Unexpected_EOF
		}

		return 0, {kind = kind, transport = header_err, transferred = header_count}
	}

	header_bytes: [RECORD_HEADER_SIZE]u8
	copy(header_bytes[:], wire[:RECORD_HEADER_SIZE])
	header, header_decode_err := record_header_decode(header_bytes)
	if header_decode_err != .None {
		return 0, {kind = .Invalid_Record, record = header_decode_err}
	}

	if header.content_type != .Application_Data {
		return 0, {kind = .Unexpected_Content_Type}
	}

	if cast(int)header.length > MAX_CIPHERTEXT_SIZE {
		return 0, {kind = .Invalid_Record, record = .Record_Oversized}
	}

	body_count, body_err := transport.read_exact(
		conn.transport,
		wire[RECORD_HEADER_SIZE:][:cast(int)header.length],
	)
	if body_err.kind != .None {
		kind: IO_Error_Kind = .Transport_Read_Failed
		if body_err.kind == .Peer_Closed {
			kind = .Unexpected_EOF
		}

		return 0, {kind = kind, transport = body_err, transferred = body_count}
	}

	return RECORD_HEADER_SIZE + cast(int)header.length, {}
}

@(private)
application_post_handshake :: proc(conn: ^Conn, content: []u8) -> IO_Error {
	state := &conn.application

	// Upstream's client takes one whole KeyUpdate per handshake record.
	if conn.upstream_client && len(content) < 4 {
		return {kind = .Record_Boundary_Violation}
	}

	at := 0
	for at < len(content) {
		if state.post_used < 4 {
			count := min(4 - state.post_used, len(content) - at)
			copy(state.post_handshake[state.post_used:], content[at:][:count])
			state.post_used += count
			at += count
			if state.post_used < 4 do return {}

			if header_error := application_post_header_validate(state); header_error.kind != .None do return header_error

			// Upstream's client offers no resumption and takes a ticket for
			// a protocol error.
			if conn.upstream_client && state.post_handshake[0] != u8(Handshake_Type.Key_Update) {
				return {kind = .Invalid_Post_Handshake}
			}
		}

		count := min(state.post_expected - state.post_used, len(content) - at)
		copy(state.post_handshake[state.post_used:], content[at:][:count])
		state.post_used += count
		at += count
		if state.post_used < state.post_expected {
			if conn.upstream_client {
				return {kind = .Record_Boundary_Violation}
			}
			return {}
		}

		message := state.post_handshake[:state.post_expected]
		if message_error := application_post_message(conn, message, at == len(content)); message_error.kind != .None do return message_error

		crypto.zero_explicit(raw_data(message), len(message))
		state.post_used, state.post_expected = 0, 0
	}
	return {}
}

@(private)
application_post_message :: proc(conn: ^Conn, message: []u8, record_ended: bool) -> IO_Error {
	state := &conn.application
	if message[0] == cast(u8)Handshake_Type.Key_Update {
		if !record_ended {
			return {kind = .Record_Boundary_Violation}
		}

		if message[4] > u8(Key_Update_Request.Update_Requested) {
			return {kind = .Invalid_Post_Handshake}
		}

		update_connection_secret(&state.secrets, false)
		record_protection_init(&state.receive, &state.secrets.server_aead)
		if message[4] == u8(Key_Update_Request.Update_Requested) {
			// The async driver serializes this response with application writes.
			if conn.defer_key_updates {
				state.key_update_pending = true
				return {}
			}
			// Respond under the current send key, then install its successor.
			if err := application_send_key_update(conn); err.kind != .None {
				return err
			}
		}
	} else if !application_ticket_valid(message[4:]) {
		return {kind = .Invalid_Post_Handshake}
	} else if conn.config.remember_tickets && state.have_resumption {
		// Storage failure keeps the previous session. Default 0-RTT stays off.
		resumption_remember_ticket(conn, message)
	}

	return {}
}

@(private)
application_post_header_validate :: proc(state: ^Application_State) -> IO_Error {
	size := handshake_body_size(state.post_handshake[:4])
	message_type := state.post_handshake[0]
	if message_type != NEW_SESSION_TICKET_TYPE &&
	   message_type != cast(u8)Handshake_Type.Key_Update {
		return {kind = .Invalid_Post_Handshake}
	}

	if size > MAX_NEW_SESSION_TICKET_BODY_SIZE {
		return {kind = .Post_Handshake_Oversized}
	}

	if message_type == cast(u8)Handshake_Type.Key_Update && size != 1 {
		return {kind = .Invalid_Post_Handshake}
	}

	if message_type == NEW_SESSION_TICKET_TYPE && size < 13 {
		return {kind = .Invalid_Post_Handshake}
	}

	state.post_expected = size + 4
	return {}
}

@(private)
application_send_key_update :: proc(conn: ^Conn, update_requested := Key_Update_Request.Update_Not_Requested) -> IO_Error {
	response := [?]u8{cast(u8)Handshake_Type.Key_Update, 0, 0, 1, u8(update_requested)}
	if err := application_record_write(conn, .Handshake, response[:]); err.kind != .None {
		return err
	}

	application_rotate_send_key(conn)
	return {}
}

// Advances the client's send secret one generation (upstream's
// update_connection_secret) and installs its keys at sequence zero.
@(private)
application_rotate_send_key :: proc(conn: ^Conn) {
	state := &conn.application
	update_connection_secret(&state.secrets, true)
	record_protection_init(&state.send, &state.secrets.client_aead)
}

// True when the next record must be a KeyUpdate: the final record allowed
// under the current send key is reserved for it.
@(private)
application_send_key_exhausted :: proc(state: ^Application_State) -> bool {
	return state.send.seq >= record_protection_limit(&state.send) - 1
}

// Validate every nested vector. Tickets are stored only by session_remember.
// early_data is checked for shape here and never becomes a key.
@(private)
application_ticket_valid :: proc(body: []u8) -> bool {
	if len(body) < 13 do return false

	lifetime :=
		cast(u32)body[0] << 24 | cast(u32)body[1] << 16 | cast(u32)body[2] << 8 | cast(u32)body[3]
	if lifetime > 7 * 24 * 60 * 60 do return false

	at := 9 + cast(int)body[8]
	if len(body) - at < 2 do return false

	ticket_size := cast(int)body[at] << 8 | cast(int)body[at + 1]
	at += 2
	if ticket_size == 0 || ticket_size > len(body) - at {
		return false
	}

	at += ticket_size
	if len(body) - at < 2 do return false

	extensions_size := cast(int)body[at] << 8 | cast(int)body[at + 1]
	at += 2
	if extensions_size > 65534 do return false

	if extensions_size != len(body) - at do return false

	seen: [1024]u64
	for at < len(body) {
		if len(body) - at < 4 do return false

		extension := cast(int)body[at] << 8 | cast(int)body[at + 1]
		size := cast(int)body[at + 2] << 8 | cast(int)body[at + 3]
		at += 4
		if size > len(body) - at do return false

		index, bit := extension / 64, cast(u64)1 << cast(uint)(extension % 64)
		if seen[index] & bit != 0 do return false

		seen[index] |= bit
		if extension == 42 && size != 4 {
			return false
		} // early_data

		at += size
	}
	return true
}

@(private)
application_fail :: proc(conn: ^Conn, err: IO_Error) -> IO_Error {
	conn.phase = .Failed
	alpn_clear(conn)
	application_clear(&conn.application)
	conn.application.failure = err
	handshake_keys_clear(conn)
	return err
}


// Asynchronous application operations

@(private)
async_application_drive :: proc(conn: ^Async_Conn) {
	p := &conn.protocol
	state := &p.application
	if conn.read_op != nil {
		if len(conn.read_buffer) == 0 {
			async_emit(conn, .Read, {})
		} else if state.inbound_at < state.inbound_size {
			n := copy(conn.read_buffer, state.inbound[state.inbound_at:state.inbound_size])
			state.inbound_at += n
			conn.read_op.result.count = n
			async_emit(conn, .Read, {})
		} else if state.peer_closed {
			async_emit(conn, .Read, {kind = .Peer_Closed})
		} else if conn.read_cancel &&
		   !conn.rx.pending &&
		   (conn.rx_expected == 0 || conn.rx_used < conn.rx_expected) {
			// A transport timeout may win its cancellation race. Both errors
			// belong to this read; preserve only the partial record for retry.
			if conn.rx_error.kind == .Cancelled || conn.rx_error.kind == .Timeout do conn.rx_error = {}
			async_emit(conn, .Read, {kind = .Cancelled})
		} else {
			header, ready := async_receive_record(conn, conn.read_deadline)
			if ready {
				if header.content_type != .Application_Data {
					async_terminal(
						conn,
						{kind = .Protocol_Failed},
						{kind = .Unexpected_Content_Type},
					); return
				}
				content_type, content, err := engine_record_open(
					&state.receive,
					conn.rx_plain[:],
					conn.rx_wire[:conn.rx_expected],
				)
				if err != .None {
					async_terminal(
						conn,
						{kind = .Protocol_Failed},
						{kind = .Decryption_Failed, protection = err},
					)
					return
				}
				if state.post_used > 0 && content_type != .Handshake {
					async_terminal(conn, {kind = .Protocol_Failed}, {kind = .Interleaved_Record})
					return
				}
				#partial switch content_type {
				case .Application_Data:
					state.inbound_size = copy(state.inbound[:], content)
					state.inbound_at = 0
				case .Alert:
					alert_error := application_alert_read(p, content)
					if alert_error.kind != .None && alert_error.kind != .EOF {
						async_terminal(conn, {kind = .Protocol_Failed}, alert_error)
						return
					}
				case .Handshake:
					if post_error := application_post_handshake(p, content);
					   post_error.kind != .None {
						async_terminal(conn, {kind = .Protocol_Failed}, post_error)
						return
					}
				case:
					async_terminal(
						conn,
						{kind = .Protocol_Failed},
						{kind = .Unexpected_Content_Type},
					); return
				}
				async_record_consumed(conn)
				async_queue(conn)
			}
		}
	}
	if conn.closing || conn.failure.kind != .None || conn.tx.pending || conn.tx_done do return
	if state.key_update_pending ||
	   conn.write_op != nil && application_send_key_exhausted(state) {
		size, err := engine_record_seal(&state.send, conn.tx_wire[:], .Handshake, []u8{24, 0, 0, 1, 0})
		if err != .None {
			async_terminal(
				conn,
				{kind = .Protocol_Failed},
				{kind = .Encryption_Failed, protection = err},
			)
			return
		}
		state.key_update_pending = false
		deadline := time.time_add(time.now(), time.Second)
		if conn.write_op != nil && conn.write_deadline != (time.Time{}) do deadline = conn.write_deadline
		async_send_start(conn, .Key_Update, size, deadline)
		return
	}
	if conn.write_op == nil do return
	if conn.write_cancel {
		async_emit(conn, .Write, {kind = .Cancelled})
		return
	}
	if conn.write_deadline != (time.Time{}) && time.diff(time.now(), conn.write_deadline) <= 0 {
		async_emit(conn, .Write, {kind = .Timeout}); return
	}
	written := conn.write_op.result.count
	if written == len(conn.write_buffer) {
		async_emit(conn, .Write, {})
		return
	}
	count := min(MAX_PLAINTEXT_SIZE, len(conn.write_buffer) - written)
	size, err := engine_record_seal(
		&state.send,
		conn.tx_wire[:],
		.Application_Data,
		conn.write_buffer[written:][:count],
	)
	if err != .None {
		async_terminal(
			conn,
			{kind = .Protocol_Failed},
			{kind = .Encryption_Failed, protection = err},
		)
		return
	}
	conn.tx_plain_count = count
	async_send_start(conn, .Data, size, conn.write_deadline)
}
