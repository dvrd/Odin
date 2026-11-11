package tls

import "core:bytes"
import "core:crypto"
import "core:crypto/aes"
import transport "core:net"
import "core:net"
import "core:time"

// Record headers and plaintext validation

RECORD_HEADER_SIZE :: 5

MAX_PLAINTEXT_SIZE :: 1 << 14
MAX_CIPHERTEXT_SIZE :: MAX_PLAINTEXT_SIZE + 256

TLS_Legacy_Record_Version :: distinct u16

LEGACY_TLS_1_0 :: cast(TLS_Legacy_Record_Version)0x0301
LEGACY_TLS_1_2 :: cast(TLS_Legacy_Record_Version)0x0303

TLS_Content_Type :: enum u8 {
	Change_Cipher_Spec = 20,
	Alert              = 21,
	Handshake          = 22,
	Application_Data   = 23,
}


Record_Header :: struct {
	content_type:   TLS_Content_Type,
	legacy_version: TLS_Legacy_Record_Version,
	length:         u16,
}

Record_Error :: enum {
	None,
	Unknown_Content_Type,
	Unexpected_Content_Type,
	Record_Oversized,
	Empty_Handshake,
	Invalid_Alert_Length,
	Invalid_Change_Cipher_Spec_Length,
}

record_header_encode :: proc(header: Record_Header) -> [5]u8 {
	version := cast(u16)header.legacy_version
	return {
		cast(u8)header.content_type,
		cast(u8)(version >> 8) & 0xff,
		cast(u8)version & 0xff,
		cast(u8)(header.length >> 8) & 0xff,
		cast(u8)header.length & 0xff,
	}
}

record_header_decode :: proc(data: [5]u8) -> (header: Record_Header, error: Record_Error) {
	content_type := cast(TLS_Content_Type)data[0]

	#partial switch content_type {
	case .Change_Cipher_Spec, .Alert, .Handshake, .Application_Data:
		version := cast(u16)data[1] << 8 | cast(u16)data[2]
		header = {
			content_type   = cast(TLS_Content_Type)data[0],
			legacy_version = cast(TLS_Legacy_Record_Version)version,
			length         = cast(u16)data[3] << 8 | cast(u16)data[4],
		}
	case:
		return {}, .Unknown_Content_Type
	}

	return header, .None
}

is_plaintext :: proc(content_type: TLS_Content_Type) -> bool {
	#partial switch content_type {
	case .Change_Cipher_Spec, .Alert, .Handshake:
		return true
	}
	return false
}

record_header_validate_plaintext :: proc(header: Record_Header) -> Record_Error {
	if !is_plaintext(header.content_type) {
		return .Unexpected_Content_Type
	}

	if cast(int)header.length > MAX_PLAINTEXT_SIZE {
		return .Record_Oversized
	}

	#partial switch header.content_type {
	case .Handshake:
		if header.length == 0 {
			return .Empty_Handshake
		}

	case .Alert:
		if header.length != 2 {
			return .Invalid_Alert_Length
		}

	case .Change_Cipher_Spec:
		if header.length != 1 {
			return .Invalid_Change_Cipher_Spec_Length
		}
	}

	return .None
}

// Plaintext record I/O

Record_Read_Error_Kind :: enum {
	None,
	Destination_Undersized,
	Header_Read_Failed,
	Invalid_Header,
	Body_Read_Failed,
}

Record_Read_Error :: struct {
	kind:      Record_Read_Error_Kind,
	record:    Record_Error,
	transport: transport.Connection_Error,
	received:  int, // Bytes received during the failed header/body read.
}

// Reads one unprotected TLS record.
//
// dst must hold MAX_PLAINTEXT_SIZE bytes.
// The returned body borrows dst.
//
// Destination_Undersized consumes no bytes and can be retried.
// Every other error requires abandoning this connection;
// this reader does not retain state for resuming failed reads.
record_read_plaintext :: proc {
	record_read_plaintext_tcp,
	record_read_plaintext_conn,
}

// Compatibility entry point; the socket remains owned by the caller.
record_read_plaintext_tcp :: proc(
	socket: net.TCP_Socket,
	dst: []u8,
) -> (
	Record_Header,
	[]u8,
	Record_Read_Error,
) {
	tcp := transport.TCP_Connection {
		socket = socket,
	}
	return record_read_plaintext_conn(transport.tcp_connection(&tcp), dst)
}

record_read_plaintext_conn :: proc(
	conn: transport.Connection,
	dst: []u8,
) -> (
	header: Record_Header,
	body: []u8,
	error: Record_Read_Error,
) {
	if len(dst) < MAX_PLAINTEXT_SIZE {
		return {}, nil, {kind = .Destination_Undersized}
	}

	wire_header: [RECORD_HEADER_SIZE]u8

	header_received, header_err := transport.read_exact(conn, wire_header[:])

	if header_err.kind != .None {
		return {}, nil, {
			kind = .Header_Read_Failed,
			transport = header_err,
			received = header_received,
		}
	}

	decoded, decode_err := record_header_decode(wire_header)
	if decode_err != .None {
		return {}, nil, {kind = .Invalid_Header, record = decode_err}
	}

	header = decoded

	validation_err := record_header_validate_plaintext(header)
	if validation_err != .None {
		return header, nil, {kind = .Invalid_Header, record = validation_err}
	}

	body_buffer := dst[:cast(int)header.length]

	body_received, body_err := transport.read_exact(conn, body_buffer)

	if body_err.kind != .None {
		return header, nil, {
			kind = .Body_Read_Failed,
			transport = body_err,
			received = body_received,
		}
	}

	return header, body_buffer, {}
}

// Authenticated record encryption

GCM_TAG_SIZE :: aes.GCM_TAG_SIZE
MAX_INNER_PLAINTEXT_SIZE :: MAX_PLAINTEXT_SIZE + 1
// Conservative bound below the 2^24.5 full-record AES-GCM limit in RFC 8446
// section 5.5. Rekey before this many records are used in either direction.
MAX_RECORDS_PER_KEY :: cast(u64)(1 << 24)

Record_Protection_Error :: enum {
	None,
	Invalid_State,
	Key_Usage_Limit,
	Destination_Undersized,
	Overlapping_Buffers,
	Header_Incomplete,
	Unexpected_Outer_Content_Type,
	Invalid_Legacy_Version,
	Record_Length_Mismatch,
	Ciphertext_Too_Short,
	Record_Oversized,
	Inner_Plaintext_Oversized,
	Authentication_Failed,
	Missing_Content_Type,
	Unexpected_Inner_Content_Type,
	Empty_Handshake,
	Invalid_Alert_Length,
}

// One direction under one set of traffic keys. Do not copy initialized state
// or share it between reading and writing: each direction has its own nonce
// sequence. Reinitialization is only safe when installing fresh traffic keys.
Record_Protection :: struct {
	ctx:         aes.Context_GCM,
	iv:          [12]u8,
	sequence:    u64,
	initialized: bool,
	failure:     Record_Protection_Error,
}

record_protection_init :: proc(state: ^Record_Protection, key: [16]u8, iv: [12]u8) {
	if state == nil do return

	record_protection_clear(state)
	key_copy := key
	defer crypto.zero_explicit(&key_copy, size_of(key_copy))
	aes.init_gcm(&state.ctx, key_copy[:])
	state.iv = iv
	state.initialized = true
}

record_protection_clear :: proc(state: ^Record_Protection) {
	if state != nil {
		crypto.zero_explicit(state, size_of(Record_Protection))
	}
}

// Produces a complete TLSCiphertext record without optional zero padding.
// dst and body must not overlap. Invalid local arguments consume no nonce and
// can be corrected and retried. The caller must send the returned record once.
record_seal :: proc(
	state: ^Record_Protection,
	dst: []u8,
	content_type: TLS_Content_Type,
	body: []u8,
) -> (
	written: int,
	error: Record_Protection_Error,
) {
	if err := protection_state_validate(state); err != .None {
		return 0, err
	}

	if err := protection_content_validate(content_type, len(body)); err != .None {
		return 0, err
	}

	inner_size := len(body) + 1
	encrypted_size := inner_size + GCM_TAG_SIZE
	wire_size := RECORD_HEADER_SIZE + encrypted_size
	if len(dst) < wire_size {
		return 0, .Destination_Undersized
	}

	if bytes.alias(dst[:wire_size], body) {
		return 0, .Overlapping_Buffers
	}

	header := record_header_encode(
		{
			content_type = .Application_Data,
			legacy_version = LEGACY_TLS_1_2,
			length = cast(u16)encrypted_size,
		},
	)
	copy(dst[:RECORD_HEADER_SIZE], header[:])
	inner := dst[RECORD_HEADER_SIZE:][:inner_size]
	copy(inner, body)
	inner[len(body)] = cast(u8)content_type
	nonce := protection_nonce(state)
	aes.seal_gcm(
		&state.ctx,
		inner,
		dst[RECORD_HEADER_SIZE + inner_size:wire_size],
		nonce[:],
		dst[:RECORD_HEADER_SIZE],
		inner,
	)
	state.sequence += 1
	return wire_size, .None
}

// Authenticates and opens one complete TLSCiphertext record. dst needs room
// for the inner plaintext (ciphertext length minus the 16-byte GCM tag), which
// includes content type and padding. Returned content borrows dst. dst and
// wire must not overlap. Destination/alias errors are retryable without nonce
// consumption; malformed records and authentication failures poison the state.
record_open :: proc(
	state: ^Record_Protection,
	dst: []u8,
	wire: []u8,
) -> (
	content_type: TLS_Content_Type,
	body: []u8,
	error: Record_Protection_Error,
) {
	if err := protection_state_validate(state); err != .None {
		return {}, nil, err
	}

	inner_size, size_error := record_open_inner_size(state, wire)
	if size_error != .None do return {}, nil, size_error

	if len(dst) < inner_size {
		return {}, nil, .Destination_Undersized
	}

	if bytes.alias(dst[:inner_size], wire) {
		return {}, nil, .Overlapping_Buffers
	}

	inner := dst[:inner_size]
	nonce := protection_nonce(state)
	valid := aes.open_gcm(
		&state.ctx,
		inner,
		nonce[:],
		wire[:RECORD_HEADER_SIZE],
		wire[RECORD_HEADER_SIZE:][:inner_size],
		wire[RECORD_HEADER_SIZE + inner_size:],
	)
	if !valid {
		// core:crypto/aes also clears this slice on failure. Keep the TLS
		// boundary explicit so no unauthenticated plaintext can escape.
		crypto.zero_explicit(raw_data(inner), len(inner))
		return {}, nil, protection_fail(state, .Authentication_Failed)
	}

	at := inner_size - 1
	for at >= 0 && inner[at] == 0 do at -= 1
	if at < 0 {
		crypto.zero_explicit(raw_data(inner), len(inner))
		return {}, nil, protection_fail(state, .Missing_Content_Type)
	}

	content_type = cast(TLS_Content_Type)inner[at]
	if err := protection_content_validate(content_type, at); err != .None {
		crypto.zero_explicit(raw_data(inner), len(inner))
		return {}, nil, protection_fail(state, err)
	}

	state.sequence += 1
	return content_type, inner[:at], .None
}

record_open_inner_size :: proc(
	state: ^Record_Protection,
	wire: []u8,
) -> (
	int,
	Record_Protection_Error,
) {
	if len(wire) < RECORD_HEADER_SIZE {
		return 0, protection_fail(state, .Header_Incomplete)
	}

	if wire[0] != cast(u8)TLS_Content_Type.Application_Data {
		return 0, protection_fail(state, .Unexpected_Outer_Content_Type)
	}

	if wire[1] != 3 || wire[2] != 3 {
		return 0, protection_fail(state, .Invalid_Legacy_Version)
	}

	encrypted_size := cast(int)wire[3] << 8 | cast(int)wire[4]
	if encrypted_size > MAX_CIPHERTEXT_SIZE {
		return 0, protection_fail(state, .Record_Oversized)
	}

	if len(wire) != RECORD_HEADER_SIZE + encrypted_size {
		return 0, protection_fail(state, .Record_Length_Mismatch)
	}

	if encrypted_size < GCM_TAG_SIZE + 1 {
		return 0, protection_fail(state, .Ciphertext_Too_Short)
	}

	inner_size := encrypted_size - GCM_TAG_SIZE
	// Padding counts toward this limit too (RFC 8446 section 5.4).
	if inner_size > MAX_INNER_PLAINTEXT_SIZE {
		return 0, protection_fail(state, .Inner_Plaintext_Oversized)
	}

	return inner_size, .None
}

protection_content_validate :: proc(
	content_type: TLS_Content_Type,
	size: int,
) -> Record_Protection_Error {
	if size > MAX_PLAINTEXT_SIZE {
		return .Inner_Plaintext_Oversized
	}

	#partial switch content_type {
	case .Application_Data:
	case .Handshake:
		if size == 0 do return .Empty_Handshake

	case .Alert:
		if size != 2 do return .Invalid_Alert_Length

	case:
		return .Unexpected_Inner_Content_Type
	}
	return .None
}

protection_state_validate :: proc(state: ^Record_Protection) -> Record_Protection_Error {
	if state == nil do return .Invalid_State

	if state.failure != .None do return state.failure

	if !state.initialized do return .Invalid_State

	if state.sequence >= MAX_RECORDS_PER_KEY {
		return protection_fail(state, .Key_Usage_Limit)
	}

	return .None
}

protection_nonce :: proc(state: ^Record_Protection) -> [12]u8 {
	nonce := state.iv
	for i in 0 ..< 8 do nonce[11 - i] ~= cast(u8)(state.sequence >> cast(uint)(i * 8))
	return nonce
}

protection_fail :: proc(
	state: ^Record_Protection,
	err: Record_Protection_Error,
) -> Record_Protection_Error {
	aes.reset_gcm(&state.ctx)
	crypto.zero_explicit(&state.iv, size_of(state.iv))
	state.initialized = false
	state.failure = err
	return err
}


// Asynchronous record operations

@(private)
async_receive_start :: proc(conn: ^Async_Conn, deadline: time.Time) {
	if conn.rx.pending do return
	if conn.rx_expected == 0 do conn.rx_expected = RECORD_HEADER_SIZE
	if conn.rx_error.kind != .None {
		async_queue(conn)
		return
	}
	error := net.async_read(
		conn.transport,
		&conn.rx,
		conn.rx_wire[conn.rx_used:conn.rx_expected],
		deadline,
	)
	if error.kind != .None {
		conn.rx_error = error; async_queue(conn)
	}
}

@(private)
async_receive_done :: proc(op: ^net.Async_Operation) {
	conn := cast(^Async_Conn)op.user_data
	n := op.result.count
	if n < 0 || n > conn.rx_expected - conn.rx_used {
		conn.rx_error = {
			kind = .Invalid_Count,
		}
	} else {
		conn.rx_used += n
		conn.rx_error = op.result.err
		if n == 0 && conn.rx_error.kind == .None do conn.rx_error = {
			kind = .No_Progress,
		}
	}
	async_queue(conn)
}

// Returns a complete record without reading ahead into the next one. Partial
// record bytes survive read cancellation/timeouts, permitting a later retry.
@(private)
async_receive_record :: proc(conn: ^Async_Conn, deadline: time.Time) -> (Record_Header, bool) {
	if conn.rx.pending do return {}, false
	if conn.rx_expected == 0 do conn.rx_expected = RECORD_HEADER_SIZE
	if conn.rx_used == RECORD_HEADER_SIZE && conn.rx_expected == RECORD_HEADER_SIZE {
		header_bytes: [RECORD_HEADER_SIZE]u8
		copy(header_bytes[:], conn.rx_wire[:RECORD_HEADER_SIZE])
		header, err := record_header_decode(header_bytes)
		if err != .None || int(header.length) > MAX_CIPHERTEXT_SIZE {
			if err == .None do err = .Record_Oversized
			async_terminal(conn, {kind = .Protocol_Failed}, {kind = .Invalid_Record, record = err})
			return {}, false
		}
		conn.rx_expected += int(header.length)
	}
	if conn.rx_used == conn.rx_expected {
		header_bytes: [RECORD_HEADER_SIZE]u8
		copy(header_bytes[:], conn.rx_wire[:RECORD_HEADER_SIZE])
		header, _ := record_header_decode(header_bytes)
		// Full-record bytes win transient timeout/cancellation errors.
		if conn.rx_error.kind == .Cancelled || conn.rx_error.kind == .Timeout do conn.rx_error = {}
		return header, true
	}
	if conn.rx_error.kind != .None {
		error := conn.rx_error
		if conn.protocol.phase == .Established &&
		   (error.kind == .Cancelled || error.kind == .Timeout) {
			conn.rx_error = {}
			async_emit(conn, .Read, error)
		} else {
			details := IO_Error {
				kind      = .Transport_Read_Failed,
				transport = error,
			}
			if error.kind == .Peer_Closed do details.kind = .Unexpected_EOF
			async_terminal(
				conn,
				error if \
					error.kind != .Peer_Closed else \
					net.Connection_Error{kind = .Protocol_Failed},
				details,
			)
		}
		return {}, false
	}
	async_receive_start(conn, deadline)
	return {}, false
}

@(private)
async_record_consumed :: proc(conn: ^Async_Conn) {
	conn.rx_used, conn.rx_expected = 0, 0
	crypto.zero_explicit(&conn.rx_plain, size_of(conn.rx_plain))
}

@(private)
async_send_start :: proc(
	conn: ^Async_Conn,
	kind: Async_Send_Kind,
	size: int,
	deadline: time.Time,
) {
	conn.tx_kind, conn.tx_size = kind, size
	error := net.async_write(conn.transport, &conn.tx, conn.tx_wire[:size], deadline)
	if error.kind != .None {
		conn.tx.result = {
			err = error,
		}
		conn.tx_done = true
		async_queue(conn)
	}
}

@(private)
async_send_done :: proc(op: ^net.Async_Operation) {
	conn := cast(^Async_Conn)op.user_data
	conn.tx_done = true
	async_queue(conn)
}

@(private)
async_send_process :: proc(conn: ^Async_Conn) {
	kind := conn.tx_kind
	conn.tx_kind = .None
	error := conn.tx.result.err
	if conn.tx.result.count == conn.tx_size && (error.kind == .Cancelled || error.kind == .Timeout) do error = {}
	if conn.tx.result.count != conn.tx_size || error.kind != .None {
		if error.kind == .None do error = {
			kind = .Write_Failed,
		}
		if kind == .Notify do conn.close_error = error
		async_terminal(
			conn,
			error,
			{
				kind = .Transport_Write_Failed,
				transport = error,
				transferred = conn.tx.result.count,
			},
		)
		return
	}
	switch kind {
	case .Client_Auth:
		// The next handshake drive emits the remaining auth records or Finished.
	case .Hello, .Retry:
		conn.protocol.phase = .Awaiting_Server_Hello
	case .Finished:
		handshake_application_activate(&conn.protocol, conn.secrets, false)
		crypto.zero_explicit(&conn.secrets, size_of(conn.secrets))
		async_handshake_complete(conn, {})
	case .Data:
		if conn.write_op != nil {
			conn.write_op.result.count += conn.tx_plain_count
			if conn.write_op.result.count == len(conn.write_buffer) do async_emit(conn, .Write, {})
		}
	case .Key_Update:
		application_rotate_send_key(&conn.protocol)
	case .Notify:
		conn.notify_sent = true
	case .None:
	}
}
