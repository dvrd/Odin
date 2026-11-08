package tls

import "core:crypto"
import "core:crypto/sha2"
import "core:crypto/x25519"
import "core:mem"
import transport "core:net"
import "core:net"
import "core:time"

// Authenticated handshake orchestration

MAX_SERVER_FLIGHT_SIZE :: 1 << 20

Handshake_Error_Kind :: enum {
	None,
	Invalid_State,
	Client_Hello_Failed,
	Server_Hello_Failed,
	Key_Derivation_Failed,
	Server_Flight_Read_Failed,
	Server_Flight_Oversized,
	Unexpected_Handshake_Message,
	Malformed_Message,
	Unsupported_Extension,
	Client_Authentication_Unsupported,
	Authentication_Failed,
	Finished_Failed,
	Finished_Write_Failed,
	Deadline_Failed,
	Allocation_Failed,
	Invalid_ALPN,
}

Handshake_Error :: struct {
	kind:           Handshake_Error_Kind,
	client_hello:   Client_Hello_Send_Error,
	server_hello:   Server_Hello_Read_Error,
	keys:           Handshake_Keys_Error,
	record:         Handshake_Record_Read_Error,
	authentication: Authentication_Error,
	finished:       Finished_Error,
	protection:     Record_Protection_Error,
	transport:      transport.Connection_Error,
	message_type:   u8,
	allocation:     mem.Allocator_Error,
}

// Authenticate the server, verify Finished, then send our Finished before
// allowing application bytes. Repeated successful calls perform no I/O.
// This blocking client currently supports certificate authentication without
// client certificates, PSKs or early data.
handshake :: proc(conn: ^Conn) -> Handshake_Error {
	return handshake_until_internal(conn, {})
}

// Authenticates within the earlier of the configured handshake budget and the
// caller's absolute deadline. Zero preserves handshake's existing behavior.
// Synchronous callbacks cannot be interrupted; expiry is checked on return.
handshake_until :: proc(conn: ^Conn, deadline: time.Time) -> Handshake_Error {
	effective := deadline
	// Preserve one effective absolute cutoff, including for callbacks which
	// return success after the earlier configured handshake budget elapsed.
	if deadline != (time.Time{}) && conn != nil {
		timeout := conn.config.handshake_timeout
		if timeout == 0 {timeout = 10 * time.Second}
		now := time.now()
		if time.diff(now, deadline) > timeout {effective = time.time_add(now, timeout)}
	}
	error := handshake_until_internal(conn, effective)
	if error.kind != .None {return error}
	return handshake_until_check(conn, effective)
}

@(private)
handshake_until_internal :: proc(conn: ^Conn, deadline: time.Time) -> Handshake_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Established do return {}

	if conn.phase == .Failed {
		if conn.handshake_error.kind != .None {
			return conn.handshake_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Handshake_Pending {
		return {kind = .Invalid_State}
	}

	deadlines_set, deadline_error := handshake_deadline_start_until(conn, deadline)
	if deadline_error.kind != .None do return deadline_error

	defer {
		if deadlines_set {
			transport.set_deadline(conn.transport, {})
		}
	}
	if error := handshake_until_check(conn, deadline); error.kind != .None {return error}
	if hello_error := handshake_hello_exchange(conn); hello_error.kind != .None {
		return hello_error
	}
	// A stable bounded allocation keeps borrowed DER valid while parsing and
	// verifying the entire certificate chain. It is released before returning.
	flight_storage, allocation_error := make([]u8, MAX_SERVER_FLIGHT_SIZE)
	if allocation_error != nil {
		return handshake_fail(conn, {kind = .Allocation_Failed, allocation = allocation_error})
	}
	defer delete(flight_storage)
	if error := handshake_until_check(conn, deadline); error.kind != .None {return error}
	flight, flight_error := handshake_server_flight_read(conn, flight_storage)
	if flight_error.kind != .None do return flight_error
	transcript_hash, verify_error := handshake_server_flight_verify(conn, flight)
	if verify_error.kind != .None do return verify_error
	secrets := application_secrets_derive(conn.handshake_secrets.handshake_secret, transcript_hash)
	defer crypto.zero_explicit(&secrets, size_of(secrets))
	if error := handshake_until_check(conn, deadline); error.kind != .None {return error}
	if finish_error := handshake_client_finished_send(conn, &transcript_hash); finish_error.kind != .None do return finish_error
	if error := handshake_until_check(conn, deadline); error.kind != .None {return error}
	activation_error := handshake_application_activate(conn, secrets, deadlines_set)
	if activation_error.kind == .None do deadlines_set = false
	return activation_error
}

handshake_deadline_start :: proc(conn: ^Conn) -> (bool, Handshake_Error) {
	return handshake_deadline_start_until(conn, {})
}

@(private)
handshake_deadline_start_until :: proc(conn: ^Conn, deadline: time.Time) -> (bool, Handshake_Error) {
	deadlines_set := false
	if conn.transport.set_read_deadline != nil && conn.transport.set_write_deadline != nil {
		timeout := conn.config.handshake_timeout
		if timeout == 0 do timeout = 10 * time.Second

		now := time.now()
		selected := deadline
		if deadline == (time.Time{}) {
			// Only the legacy path establishes a relative deadline here.
			selected = time.time_add(now, timeout)
		} else if time.diff(now, deadline) <= 0 {
			return false, handshake_fail(conn, {kind = .Deadline_Failed, transport = {kind = .Timeout}})
		}
		if err := transport.set_deadline(conn.transport, selected);
		   err.kind != .None {
			transport.set_deadline(conn.transport, {})
			return false, handshake_fail(conn, {kind = .Deadline_Failed, transport = err})
		}

		if deadline != (time.Time{}) && time.diff(time.now(), selected) <= 0 {
			transport.set_deadline(conn.transport, {})
			return false, handshake_fail(conn, {kind = .Deadline_Failed, transport = {kind = .Timeout}})
		}
		deadlines_set = true
	} else if conn.config.handshake_timeout > 0 || deadline != (time.Time{}) {
		return false, handshake_fail(
			conn,
			{kind = .Deadline_Failed, transport = {kind = .Deadline_Unsupported}},
		)
	}

	return deadlines_set, {}
}

handshake_hello_exchange :: proc(conn: ^Conn) -> Handshake_Error {
	if err := client_hello_send(conn); err.kind != .None {
		return handshake_fail(conn, {kind = .Client_Hello_Failed, client_hello = err})
	}

	if err := server_hello_read(conn); err.kind != .None {
		return handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
	}

	if conn.phase == .Hello_Retry_Received {
		if err := client_hello_retry_send(conn); err.kind != .None {
			return handshake_fail(conn, {kind = .Client_Hello_Failed, client_hello = err})
		}

		if err := server_hello_read(conn); err.kind != .None {
			return handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
		}
	}

	if err := client_handshake_keys_init(conn); err.kind != .None {
		return handshake_fail(conn, {kind = .Key_Derivation_Failed, keys = err})
	}

	return {}
}

handshake_server_flight_read :: proc(
	conn: ^Conn,
	flight_storage: []u8,
) -> (
	[]u8,
	Handshake_Error,
) {
	storage: [MAX_CIPHERTEXT_SIZE]u8
	size := 0
	for conn.phase == .Handshake_Keys_Ready {
		content, err := handshake_record_read(conn, storage[:])
		if err.kind != .None {
			return nil, handshake_fail(conn, {kind = .Server_Flight_Read_Failed, record = err})
		}

		if len(content) > len(flight_storage) - size {
			return nil, handshake_fail(conn, {kind = .Server_Flight_Oversized})
		}

		copy(flight_storage[size:], content)
		size += len(content)
	}
	if conn.phase != .Server_Finished_Received {
		return nil, handshake_fail(conn, {kind = .Invalid_State})
	}

	return flight_storage[:size], {}
}

handshake_server_flight_verify :: proc(conn: ^Conn, flight: []u8) -> ([32]u8, Handshake_Error) {
	transcript: Handshake_Transcript
	transcript_init(&transcript)
	transcript_update(&transcript, conn.retry_transcript[:conn.retry_transcript_size])
	transcript_update(&transcript, handshake_effective_client_hello(conn))
	transcript_update(&transcript, conn.server_hello[:conn.server_hello_size])
	at := 0
	encrypted_extensions, message_err := handshake_next_message(flight, &at, .Encrypted_Extensions)
	if message_err.kind != .None {
		return {}, handshake_fail(conn, message_err)
	}

	selected, extension_error := encrypted_extensions_decode(encrypted_extensions, conn.config.server_name, conn.config.alpn_protocols)
	if extension_error.kind != .None {return {},handshake_fail(conn,extension_error)}

	transcript_update(&transcript, encrypted_extensions)
	if cert_error := handshake_flight_certificates_verify(conn, flight, &at, &transcript); cert_error.kind != .None do return {}, cert_error
	hash, finished_error := handshake_flight_finished_verify(conn, flight, &at, &transcript)
	if finished_error.kind != .None {return {},finished_error}
	// The flight buffer is released by the async driver before Finished is sent.
	// Retain a bounded owned copy, still hidden until authentication completes.
	copy(conn.alpn_selected[:],selected)
	conn.alpn_selected_size=len(selected)
	return hash,{}
}

handshake_flight_certificates_verify :: proc(
	conn: ^Conn,
	flight: []u8,
	at: ^int,
	transcript: ^sha2.Context_256,
) -> Handshake_Error {
	certificate, certificate_message_err := handshake_next_message(flight, at, .Certificate)
	if certificate_message_err.kind != .None {
		return handshake_fail(conn, certificate_message_err)
	}

	certs, auth_err := server_certificates_parse(certificate)
	if auth_err.kind != .None {
		return handshake_fail(conn, {kind = .Authentication_Failed, authentication = auth_err})
	}

	defer server_certificates_destroy(&certs)
	if err := verify_server_certificates(
		&certs,
		conn.config.server_name,
		conn.config.root_cas,
		time.now(),
	); err.kind != .None {
		return handshake_fail(conn, {kind = .Authentication_Failed, authentication = err})
	}

	transcript_update(transcript, certificate)
	return handshake_flight_signature_verify(conn, &certs, flight, at, transcript)
}

handshake_flight_signature_verify :: proc(
	conn: ^Conn,
	certs: ^Server_Certificates,
	flight: []u8,
	at: ^int,
	transcript: ^sha2.Context_256,
) -> Handshake_Error {
	certificate_verify, verify_message_err := handshake_next_message(
		flight,
		at,
		.Certificate_Verify,
	)
	if verify_message_err.kind != .None {
		return handshake_fail(conn, verify_message_err)
	}

	transcript_hash: [32]u8
	transcript_hash = transcript_snapshot(transcript)
	if err := verify_server_certificate_signature(certs, certificate_verify, transcript_hash);
	   err.kind != .None {
		return handshake_fail(conn, {kind = .Authentication_Failed, authentication = err})
	}

	transcript_update(transcript, certificate_verify)
	return {}
}

handshake_flight_finished_verify :: proc(
	conn: ^Conn,
	flight: []u8,
	at: ^int,
	transcript: ^sha2.Context_256,
) -> (
	[32]u8,
	Handshake_Error,
) {
	transcript_hash: [32]u8
	finished_message, finished_message_err := handshake_next_message(flight, at, .Finished)
	if finished_message_err.kind != .None {
		return {}, handshake_fail(conn, finished_message_err)
	}

	if at^ != len(flight) {
		return {}, handshake_fail(conn, {kind = .Unexpected_Handshake_Message})
	}

	transcript_hash = transcript_snapshot(transcript)
	if err := finished_verify(
		finished_message,
		conn.handshake_secrets.server_traffic_secret,
		transcript_hash,
	); err != .None {
		return {}, handshake_fail(conn, {kind = .Finished_Failed, finished = err})
	}

	transcript_update(transcript, finished_message)
	transcript_hash = transcript_snapshot(transcript)
	return transcript_hash, {}
}

handshake_client_finished_encode :: proc(
	conn: ^Conn,
	transcript_hash: ^[32]u8,
	wire: []u8,
) -> (
	int,
	Handshake_Error,
) {
	client_finished: [36]u8
	_, finish_err := finished_encode(
		client_finished[:],
		conn.handshake_secrets.client_traffic_secret,
		transcript_hash^,
	)
	if finish_err != .None {
		return 0, handshake_fail(conn, {kind = .Finished_Failed, finished = finish_err})
	}

	written, protection_err := record_seal(
		&conn.handshake_send,
		wire,
		.Handshake,
		client_finished[:],
	)
	if protection_err != .None {
		return 0, handshake_fail(
			conn,
			{kind = .Finished_Write_Failed, protection = protection_err},
		)
	}

	return written, {}
}

handshake_client_finished_send :: proc(conn: ^Conn, transcript_hash: ^[32]u8) -> Handshake_Error {
	wire: [5 + 36 + 1 + 16]u8
	written, err := handshake_client_finished_encode(conn, transcript_hash, wire[:])
	if err.kind != .None do return err

	_, send_err := transport.write_all(conn.transport, wire[:written])
	if send_err.kind != .None {
		return handshake_fail(conn, {kind = .Finished_Write_Failed, transport = send_err})
	}

	return {}
}

handshake_application_activate :: proc(
	conn: ^Conn,
	secrets: Application_Secrets,
	deadlines_set: bool,
) -> Handshake_Error {
	if deadlines_set {
		if err := transport.set_deadline(conn.transport, {}); err.kind != .None {
			return handshake_fail(conn, {kind = .Deadline_Failed, transport = err})
		}
	}

	application_init(&conn.application, secrets)
	handshake_keys_clear(conn)
	conn.phase = .Established
	conn.handshake_complete = true
	return {}
}

handshake_sni_offered :: proc(server_name: string) -> bool {
	return net.parse_address(server_name) == nil
}

handshake_fail :: proc(conn: ^Conn, err: Handshake_Error) -> Handshake_Error {
	conn.phase = .Failed
	alpn_clear(conn)
	conn.handshake_error = err
	handshake_keys_clear(conn)
	application_clear(&conn.application)
	return err
}

handshake_next_message :: proc(
	flight: []u8,
	at: ^int,
	expected: Handshake_Type,
) -> (
	[]u8,
	Handshake_Error,
) {
	if at^ > len(flight) - 4 {
		return nil, {kind = .Malformed_Message}
	}

	kind := flight[at^]
	if kind == cast(u8)Handshake_Type.Certificate_Request {
		return nil, {kind = .Client_Authentication_Unsupported, message_type = kind}
	}

	if kind != cast(u8)expected {
		return nil, {kind = .Unexpected_Handshake_Message, message_type = kind}
	}

	size := 4 + handshake_body_size(flight[at^:])
	if size > len(flight) - at^ {
		return nil, {kind = .Malformed_Message}
	}

	message := flight[at^:][:size]
	at^ += size
	return message, {}
}

// Legacy no-ALPN validation keeps its exported signature and rejects unsolicited
// protocol selections. The shared decoder also handles configured offers.
encrypted_extensions_validate :: proc(message: []u8, server_name: string) -> Handshake_Error {
	_, error := encrypted_extensions_decode(message,server_name,nil)
	return error
}

@(private)
encrypted_extensions_decode :: proc(message: []u8, server_name: string, offers: []string) -> (selected: []u8, error: Handshake_Error) {
	if len(message) < 6 {
		return nil,{kind = .Malformed_Message}
	}

	extensions_size := cast(int)message[4] << 8 | cast(int)message[5]
	if extensions_size != len(message) - 6 {
		return nil,{kind = .Malformed_Message}
	}

	at := 6
	name_seen, groups_seen, alpn_seen: bool
	for at < len(message) {
		if len(message) - at < 4 {
			return nil,{kind = .Malformed_Message}
		}

		kind := cast(u16)message[at] << 8 | cast(u16)message[at + 1]
		size := cast(int)message[at + 2] << 8 | cast(int)message[at + 3]
		at += 4
		if size > len(message) - at {
			return nil,{kind = .Malformed_Message}
		}

		switch kind {
		case cast(u16)Extension_Type.Server_Name:
			if name_seen || size != 0 || !handshake_sni_offered(server_name) {
				return nil,{kind = .Malformed_Message}
			}

			name_seen = true
		case cast(u16)Extension_Type.Supported_Groups:
			if groups_seen || size < 4 || size % 2 != 0 {
				return nil,{kind = .Malformed_Message}
			}

			list_size := cast(int)message[at] << 8 | cast(int)message[at + 1]
			if list_size != size - 2 {
				return nil,{kind = .Malformed_Message}
			}

			groups_seen = true
		case cast(u16)Extension_Type.Application_Layer_Protocol_Negotiation:
			if alpn_seen {return nil,{kind=.Malformed_Message}}
			alpn_seen=true
			selected, error = alpn_selection_decode(message[at:at+size],offers)
			if error.kind != .None {return nil,error}
		case:
			return nil,{kind = .Unsupported_Extension}
		}
		at += size
	}
	return selected,{}
}

// Initial ClientHello exchange

Client_Hello_Send_Error_Kind :: enum {
	None,
	Invalid_State,
	Entropy_Unavailable,
	Encode_Failed,
	Invalid_Retry,
	Write_Failed,
}

Client_Hello_Send_Error :: struct {
	kind:      Client_Hello_Send_Error_Kind,
	encode:    Client_Hello_Error,
	retry:     Server_Hello_Error,
	transport: transport.Connection_Error,
	written:   int,
}

// First step of the handshake, not a completed TLS connection. A successful
// call leaves the connection awaiting ServerHello. Errors are terminal and
// cached: retrying must never send a second or partially repeated ClientHello.
client_hello_prepare :: proc(conn: ^Conn) -> Client_Hello_Send_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.client_hello_error.kind != .None {
			return conn.client_hello_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Handshake_Pending {
		return {kind = .Invalid_State}
	}

	when !crypto.HAS_RAND_BYTES {
		return client_hello_fail(conn, {kind = .Entropy_Unavailable})
	}
	hello := Client_Hello {
		server_name = conn.config.server_name,
		alpn_protocols = conn.config.alpn_protocols,
	}
	crypto.rand_bytes(hello.random[:])
	crypto.rand_bytes(conn.x25519_private_key[:])
	x25519.scalarmult_basepoint(hello.x25519_public_key[:], conn.x25519_private_key[:])
	size, encode_err := client_hello_encode(conn.client_hello[:], hello)
	if encode_err != .None {
		return client_hello_fail(conn, {kind = .Encode_Failed, encode = encode_err})
	}

	conn.client_hello_size = size

	return {}
}

client_hello_send :: proc(conn: ^Conn) -> Client_Hello_Send_Error {
	if err := client_hello_prepare(conn); err.kind != .None do return err
	size := conn.client_hello_size

	// Initial ClientHello may use legacy record version 0x0301. The inner
	// ClientHello still uses 0x0303 plus supported_versions = TLS 1.3.
	header := record_header_encode(
		{content_type = .Handshake, legacy_version = LEGACY_TLS_1_0, length = cast(u16)size},
	)
	wire: [RECORD_HEADER_SIZE + MAX_CLIENT_HELLO_SIZE]u8
	copy(wire[:RECORD_HEADER_SIZE], header[:])
	copy(wire[RECORD_HEADER_SIZE:], conn.client_hello[:size])
	written, write_err := transport.write_all(conn.transport, wire[:RECORD_HEADER_SIZE + size])
	if write_err.kind != .None {
		return client_hello_fail(
			conn,
			{kind = .Write_Failed, transport = write_err, written = written},
		)
	}

	conn.phase = .Awaiting_Server_Hello
	return {}
}

client_hello_fail :: proc(conn: ^Conn, err: Client_Hello_Send_Error) -> Client_Hello_Send_Error {
	conn.phase = .Failed
	alpn_clear(conn)
	conn.client_hello_error = err
	crypto.zero_explicit(&conn.x25519_private_key, size_of(conn.x25519_private_key))
	return err
}

// ServerHello exchange

// Resource limit for compatibility records that make no handshake progress.
MAX_IGNORED_CHANGE_CIPHER_SPECS :: 16

Server_Hello_Read_Error_Kind :: enum {
	None,
	Invalid_State,
	Record_Read_Failed,
	Peer_Alert,
	Invalid_Change_Cipher_Spec,
	Too_Many_Change_Cipher_Specs,
	Interleaved_Record,
	Message_Oversized,
	Record_Boundary_Violation,
	Invalid_Server_Hello,
	Invalid_Key_Share,
}

Server_Hello_Read_Error :: struct {
	kind:              Server_Hello_Read_Error_Kind,
	record:            Record_Read_Error,
	decode:            Server_Hello_Error,
	// Preserve the peer's wire alert, including descriptions unknown to us.
	alert_level:       u8,
	alert_description: u8,
}

// Reassembles exactly one ServerHello, retaining its handshake bytes for the
// transcript. It must end at a record boundary because encryption keys change
// immediately afterwards (RFC 8446 section 5.1). No encrypted bytes are read.
// Failure is terminal; close this connection. One bounded cookie-only retry
// can instead transition to Hello_Retry_Received without discarding the key.
server_hello_read :: proc(conn: ^Conn) -> Server_Hello_Read_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.server_hello_error.kind != .None {
			return conn.server_hello_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Awaiting_Server_Hello {
		return {kind = .Invalid_State}
	}

	message: [MAX_HELLO_RETRY_REQUEST_SIZE]u8
	received, read_error := server_hello_message_read(conn, message[:])
	if read_error.kind != .None do return server_hello_fail(conn, read_error)
	if hello_is_retry(message[:received]) {
		return server_hello_retry_accept(conn, message[:received])
	}
	return server_hello_accept(conn, message[:received])
}

server_hello_message_append :: proc(
	message, body: []u8,
	received: ^int,
) -> (
	bool,
	Server_Hello_Read_Error,
) {
	if len(body) > len(message) - received^ {
		return false, {kind = .Message_Oversized}
	}

	copy(message[received^:], body)
	received^ += len(body)
	if message[0] != cast(u8)Handshake_Type.Server_Hello {
		return false, {kind = .Invalid_Server_Hello, decode = .Unexpected_Handshake_Type}
	}

	if received^ < 4 do return false, {}

	expected := 4 + handshake_body_size(message[:received^])
	if expected > len(message) {
		return false, {kind = .Message_Oversized}
	}

	if received^ >= 38 &&
	   !hello_is_retry(message[:received^]) &&
	   expected > MAX_SERVER_HELLO_SIZE {
		return false, {kind = .Message_Oversized}
	}

	if received^ > expected {
		return false, {kind = .Record_Boundary_Violation}
	}

	if received^ < expected do return false, {}

	return true, {}
}

server_hello_ccs_validate :: proc(body: []u8, ignored_ccs: ^int) -> Server_Hello_Read_Error {
	if body[0] != 1 {
		return {kind = .Invalid_Change_Cipher_Spec}
	}

	ignored_ccs^ += 1
	if ignored_ccs^ > MAX_IGNORED_CHANGE_CIPHER_SPECS {
		return {kind = .Too_Many_Change_Cipher_Specs}
	}

	return {}
}

server_hello_message_read :: proc(conn: ^Conn, message: []u8) -> (int, Server_Hello_Read_Error) {
	storage: [MAX_PLAINTEXT_SIZE]u8
	received, ignored_ccs: int
	for {
		header, body, err := record_read_plaintext(conn.transport, storage[:])
		if err.kind != .None {
			return 0, {kind = .Record_Read_Failed, record = err}
		}

		if header.content_type != .Handshake && received > 0 {
			return 0, {kind = .Interleaved_Record}
		}

		#partial switch header.content_type {
		case .Alert:
			return 0, {kind = .Peer_Alert, alert_level = body[0], alert_description = body[1]}
		case .Change_Cipher_Spec:
			if ccs_error := server_hello_ccs_validate(body, &ignored_ccs); ccs_error.kind != .None do return 0, ccs_error
			continue
		case .Handshake:
			complete, append_error := server_hello_message_append(message, body, &received)
			if append_error.kind != .None do return 0, append_error
			if !complete do continue
		}
		break
	}
	return received, {}
}

server_hello_retry_accept :: proc(conn: ^Conn, message: []u8) -> Server_Hello_Read_Error {
	if conn.retry_transcript_size != 0 {
		return server_hello_fail(
			conn,
			{kind = .Invalid_Server_Hello, decode = .Repeated_Hello_Retry},
		)
	}

	cookie, cookie_error := hello_retry_request_decode(message)
	if cookie_error != .None {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = cookie_error})
	}

	if err := client_hello_retry_prepare(conn, message, cookie); err != .None {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = err})
	}

	conn.phase = .Hello_Retry_Received
	return {}
}

server_hello_accept :: proc(conn: ^Conn, message: []u8) -> Server_Hello_Read_Error {
	received := len(message)
	copy(conn.server_hello[:], message[:received])
	parameters, decode_err := server_hello_decode(conn.server_hello[:received])
	if decode_err != .None {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = decode_err})
	}

	x25519.scalarmult(
		conn.shared_secret[:],
		conn.x25519_private_key[:],
		parameters.x25519_public_key[:],
	)
	crypto.zero_explicit(&conn.x25519_private_key, size_of(conn.x25519_private_key))
	// RFC 8446 section 7.4.2: reject low-order X25519 inputs.
	if crypto.is_zero_constant_time(conn.shared_secret[:]) == 1 {
		return server_hello_fail(conn, {kind = .Invalid_Key_Share})
	}

	conn.server_hello_size = received
	conn.server_parameters = parameters
	conn.phase = .Server_Hello_Received
	return {}
}

server_hello_fail :: proc(conn: ^Conn, err: Server_Hello_Read_Error) -> Server_Hello_Read_Error {
	conn.phase = .Failed
	alpn_clear(conn)
	conn.server_hello_error = err
	crypto.zero_explicit(&conn.x25519_private_key, size_of(conn.x25519_private_key))
	crypto.zero_explicit(&conn.shared_secret, size_of(conn.shared_secret))
	return err
}

// Handshake key installation and cleanup

Handshake_Keys_Error_Kind :: enum {
	None,
	Invalid_State,
	Derivation_Failed,
}

Handshake_Keys_Error :: struct {
	kind:  Handshake_Keys_Error_Kind,
	cause: Key_Schedule_Error,
}

// Install independent send/receive keys, each starting at sequence zero.
// This transition happens once; calling it again must never reset nonces.
// These keys encrypt the remaining handshake, not authenticated application I/O.
client_handshake_keys_init :: proc(conn: ^Conn) -> Handshake_Keys_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.handshake_keys_error.kind != .None {
			return conn.handshake_keys_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Server_Hello_Received {
		return {kind = .Invalid_State}
	}

	if conn.client_hello_size < 0 ||
	   conn.client_hello_size > len(conn.client_hello) ||
	   conn.server_hello_size < 0 ||
	   conn.server_hello_size > len(conn.server_hello) ||
	   conn.retry_client_hello_size < 0 ||
	   conn.retry_client_hello_size > len(conn.retry_client_hello) ||
	   conn.retry_transcript_size < 0 ||
	   conn.retry_transcript_size > len(conn.retry_transcript) {
		return {kind = .Invalid_State}
	}

	secrets, err := handshake_secrets_derive(
		conn.shared_secret,
		handshake_effective_client_hello(conn),
		conn.server_hello[:conn.server_hello_size],
		conn.retry_transcript[:conn.retry_transcript_size],
	)
	defer crypto.zero_explicit(&secrets, size_of(secrets))
	if err != .None {
		conn.phase = .Failed
		alpn_clear(conn)
		conn.handshake_keys_error = {
			kind  = .Derivation_Failed,
			cause = err,
		}
		handshake_keys_clear(conn)
		return conn.handshake_keys_error
	}

	conn.handshake_secrets = secrets
	record_protection_init(&conn.handshake_send, secrets.client_key, secrets.client_iv)
	record_protection_init(&conn.handshake_receive, secrets.server_key, secrets.server_iv)
	crypto.zero_explicit(&conn.shared_secret, size_of(conn.shared_secret))
	conn.phase = .Handshake_Keys_Ready
	return {}
}

handshake_keys_clear :: proc(conn: ^Conn) {
	crypto.zero_explicit(&conn.x25519_private_key, size_of(conn.x25519_private_key))
	crypto.zero_explicit(&conn.shared_secret, size_of(conn.shared_secret))
	crypto.zero_explicit(&conn.handshake_secrets, size_of(conn.handshake_secrets))
	record_protection_clear(&conn.handshake_send)
	record_protection_clear(&conn.handshake_receive)
}

handshake_effective_client_hello :: proc(conn: ^Conn) -> []u8 {
	if conn.retry_client_hello_size > 0 {
		return conn.retry_client_hello[:conn.retry_client_hello_size]
	}

	return conn.client_hello[:conn.client_hello_size]
}

// HelloRetryRequest handling

// Resource policy: accept cookie-only retries up to 1024 cookie bytes. Our
// fixed X25519 share rules out any legitimate HRR key_share selection.
MAX_RETRY_COOKIE_SIZE :: 1024
MAX_HELLO_RETRY_REQUEST_SIZE :: 44 + 6 + 6 + MAX_RETRY_COOKIE_SIZE
MAX_RETRY_TRANSCRIPT_SIZE :: 36 + MAX_HELLO_RETRY_REQUEST_SIZE
MAX_RETRY_CLIENT_HELLO_SIZE :: MAX_CLIENT_HELLO_SIZE + 6 + MAX_RETRY_COOKIE_SIZE
RETRY_COOKIE_EXTENSION :: cast(u16)44

// RFC 8446 sections 4.1.4, 4.2.2, 4.2.8. Cookie bytes borrow wire. For our
// fixed offer, any key_share HRR is invalid: X25519 was already shared, and
// every other group was not offered. A retry must make a real change, so a
// cookie is required and may not be empty.
hello_retry_request_decode :: proc(wire: []u8) -> (cookie: []u8, err: Server_Hello_Error) {
	if len(wire) < 44 do return nil, .Truncated

	if wire[0] != cast(u8)Handshake_Type.Server_Hello {
		return nil, .Unexpected_Handshake_Type
	}

	if handshake_body_size(wire) + 4 != len(wire) {
		return nil, .Length_Mismatch
	}

	if retry_u16(wire, 4) != cast(u16)LEGACY_TLS_1_2 {
		return nil, .Invalid_Legacy_Version
	}

	if !hello_is_retry(wire) {
		return nil, .Invalid_Hello_Retry_Request
	}

	if wire[38] != 0 do return nil, .Session_ID_Mismatch

	if retry_u16(wire, 39) != cast(u16)Cipher_Suite.AES_128_GCM_SHA256 {
		return nil, .Unoffered_Cipher
	}

	if wire[41] != 0 do return nil, .Invalid_Compression

	if cast(int)retry_u16(wire, 42) != len(wire) - 44 {
		return nil, .Extension_Length_Mismatch
	}

	return hello_retry_extensions_decode(wire)
}

hello_retry_extensions_decode :: proc(wire: []u8) -> (cookie: []u8, err: Server_Hello_Error) {
	version_seen, cookie_seen: bool
	at := 44
	for at < len(wire) {
		if len(wire) - at < 4 do return nil, .Truncated

		kind, size := retry_u16(wire, at), cast(int)retry_u16(wire, at + 2)
		at += 4
		if size > len(wire) - at do return nil, .Truncated

		switch kind {
		case cast(u16)Extension_Type.Supported_Versions:
			if version_seen {
				return nil, .Duplicate_Extension
			}

			version_seen = true
			if size != 2 {
				return nil, .Extension_Length_Mismatch
			}

			if retry_u16(wire, at) != VERSION_TLS_1_3 {
				return nil, .Unsupported_Version
			}

		case RETRY_COOKIE_EXTENSION:
			if cookie_seen {
				return nil, .Duplicate_Extension
			}

			cookie_seen = true
			if size < 3 || cast(int)retry_u16(wire, at) != size - 2 {
				return nil, .Invalid_Retry_Cookie
			}

			if size - 2 > MAX_RETRY_COOKIE_SIZE {
				return nil, .Retry_Cookie_Oversized
			}

			cookie = wire[at + 2:at + size]
		case cast(u16)Extension_Type.Key_Share:
			return nil, .Invalid_Retry_Group
		case:
			return nil, .Unsupported_Extension
		}
		at += size
	}
	if !version_seen {
		return nil, .Missing_Supported_Versions
	}

	if !cookie_seen do return nil, .Missing_Retry_Cookie

	return cookie, .None
}

// Sending is separate from receiving so the full handshake can drive a clear
// Hello_Retry_Received -> Awaiting_Server_Hello transition. The original
// ClientHello and ephemeral key are retained; cookie retries reuse both.
client_hello_retry_send :: proc(conn: ^Conn) -> Client_Hello_Send_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.client_hello_error.kind != .None {
			return conn.client_hello_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Hello_Retry_Received {
		return {kind = .Invalid_State}
	}

	if conn.retry_client_hello_size < 47 ||
	   conn.retry_client_hello_size > MAX_RETRY_CLIENT_HELLO_SIZE ||
	   conn.retry_transcript_size < 36 {
		return client_hello_fail(
			conn,
			{kind = .Invalid_Retry, retry = .Invalid_Retry_Client_Hello},
		)
	}

	size := conn.retry_client_hello_size
	header := record_header_encode(
		{content_type = .Handshake, legacy_version = LEGACY_TLS_1_2, length = cast(u16)size},
	)
	wire: [RECORD_HEADER_SIZE + MAX_RETRY_CLIENT_HELLO_SIZE]u8
	copy(wire[:RECORD_HEADER_SIZE], header[:])
	copy(wire[RECORD_HEADER_SIZE:], conn.retry_client_hello[:size])
	written, err := transport.write_all(conn.transport, wire[:RECORD_HEADER_SIZE + size])
	if err.kind != .None {
		return client_hello_fail(conn, {kind = .Write_Failed, transport = err, written = written})
	}

	conn.phase = .Awaiting_Server_Hello
	return {}
}

hello_is_retry :: proc(wire: []u8) -> bool {
	if len(wire) < 38 do return false

	for value, i in HELLO_RETRY_REQUEST_RANDOM {
		if wire[6 + i] != value do return false
	}
	return true
}

// Prepare CH2 and the transcript prefix atomically after validating HRR.
// RFC 8446 section 4.4.1 replaces CH1 with message_hash(Hash(CH1)).
client_hello_retry_prepare :: proc(conn: ^Conn, retry: []u8, cookie: []u8) -> Server_Hello_Error {
	if conn == nil do return .Invalid_Retry_Client_Hello
	if conn.retry_transcript_size != 0 {
		return .Repeated_Hello_Retry
	}

	size := conn.client_hello_size
	if size < 47 || size > len(conn.client_hello) {
		return .Invalid_Retry_Client_Hello
	}
	first := conn.client_hello[:size]
	layout, valid := client_hello_layout_decode(first)
	if !valid || layout.session_size != 0 || layout.has_cookie ||
	   !client_hello_layout_has_cipher(first, layout, u16(Cipher_Suite.AES_128_GCM_SHA256)) {
		return .Invalid_Retry_Client_Hello
	}
	if len(cookie) == 0 || len(cookie) > MAX_RETRY_COOKIE_SIZE {
		return .Invalid_Retry_Cookie
	}
	if len(retry) > MAX_HELLO_RETRY_REQUEST_SIZE {
		return .Retry_Cookie_Oversized
	}

	new_size := size + 6 + len(cookie)
	extensions_size := layout.extensions_size + 6 + len(cookie)
	if new_size > len(conn.retry_client_hello) || extensions_size > 65535 ||
	   36 + len(retry) > len(conn.retry_transcript) ||
	   !client_hello_retry_inputs_disjoint(conn, retry, cookie, new_size) {
		return .Invalid_Retry_Client_Hello
	}
	copy(conn.retry_client_hello[:], first)
	retry_put_u24(conn.retry_client_hello[:], 1, new_size - 4)
	retry_put_u16(conn.retry_client_hello[:], layout.extensions_length_offset, u16(extensions_size))
	retry_put_u16(conn.retry_client_hello[:], size, RETRY_COOKIE_EXTENSION)
	retry_put_u16(conn.retry_client_hello[:], size + 2, u16(2 + len(cookie)))
	retry_put_u16(conn.retry_client_hello[:], size + 4, u16(len(cookie)))
	copy(conn.retry_client_hello[size + 6:], cookie)
	conn.retry_client_hello_size = new_size

	client_hello_retry_transcript_prepare(conn, first, retry)
	return .None
}

client_hello_retry_transcript_prepare :: proc(conn: ^Conn, first, retry: []u8) {
	t: Handshake_Transcript
	transcript_init(&t)
	transcript_update(&t, first)
	message := transcript_message_hash(transcript_snapshot(&t))
	copy(conn.retry_transcript[:36], message[:])
	copy(conn.retry_transcript[36:], retry)
	conn.retry_transcript_size = 36 + len(retry)
}

retry_u16 :: proc(data: []u8, at: int) -> u16 {
	return cast(u16)data[at] << 8 | cast(u16)data[at + 1]
}

retry_put_u16 :: proc(data: []u8, at: int, value: u16) {
	data[at], data[at + 1] = cast(u8)(value >> 8), cast(u8)value
}

retry_put_u24 :: proc(data: []u8, at, value: int) {
	data[at], data[at + 1], data[at + 2] =
		cast(u8)(value >> 16), cast(u8)(value >> 8), cast(u8)value
}

// Encrypted handshake records and message boundaries

Handshake_Record_Read_Error_Kind :: enum {
	None,
	Invalid_State,
	Destination_Undersized,
	Header_Read_Failed,
	Invalid_Header,
	Body_Read_Failed,
	Unexpected_Content_Type,
	Invalid_Change_Cipher_Spec,
	Too_Many_Change_Cipher_Specs,
	Interleaved_Record,
	Record_Boundary_Violation,
	Decryption_Failed,
	Peer_Alert,
}

Handshake_Record_Read_Error :: struct {
	kind:              Handshake_Record_Read_Error_Kind,
	transport:         transport.Connection_Error,
	record:            Record_Error,
	protection:        Record_Protection_Error,
	received:          int,
	alert_level:       u8,
	alert_description: u8,
}

// Reads and authenticates one encrypted handshake record. Returned bytes
// borrow dst and may contain multiple handshake messages or a message fragment.
// Their certificate and Finished authentication is handled by later stages.
// Undersized buffers consume nothing; all other operational failures are
// terminal and cached. The caller still owns closing the failed connection.
handshake_record_read :: proc(
	conn: ^Conn,
	dst: []u8,
) -> (
	body: []u8,
	err: Handshake_Record_Read_Error,
) {
	if conn == nil do return nil, {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.handshake_record_error.kind != .None {
			return nil, conn.handshake_record_error
		}

		return nil, {kind = .Invalid_State}
	}

	if conn.phase != .Handshake_Keys_Ready {
		return nil, {kind = .Invalid_State}
	}

	if len(dst) < MAX_CIPHERTEXT_SIZE {
		return nil, {kind = .Destination_Undersized}
	}

	wire: [RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE]u8
	ignored_ccs: int
	for {
		header, wire_error := handshake_record_wire_read(conn, wire[:])
		if wire_error.kind != .None do return handshake_record_fail(conn, wire_error)

		if header.content_type == .Change_Cipher_Spec {
			if wire[RECORD_HEADER_SIZE] != 1 {
				return handshake_record_fail(conn, {kind = .Invalid_Change_Cipher_Spec})
			}

			ignored_ccs += 1
			if ignored_ccs > MAX_IGNORED_CHANGE_CIPHER_SPECS {
				return handshake_record_fail(conn, {kind = .Too_Many_Change_Cipher_Specs})
			}

			continue
		}

		return handshake_record_decrypt(conn, dst, wire[:], header)
	}
}

handshake_record_header_validate :: proc(
	conn: ^Conn,
	header: Record_Header,
) -> Handshake_Record_Read_Error {
	if header.content_type == .Change_Cipher_Spec {
		if conn.server_handshake_header_used > 0 || conn.server_handshake_remaining > 0 {
			return {kind = .Interleaved_Record}
		}

		if header.length != 1 {
			return {kind = .Invalid_Change_Cipher_Spec}
		}
	} else if header.content_type != .Application_Data {
		return {kind = .Unexpected_Content_Type}
	}

	if cast(int)header.length > MAX_CIPHERTEXT_SIZE {
		return {kind = .Invalid_Header, record = .Record_Oversized}
	}

	return {}
}

handshake_record_wire_read :: proc(
	conn: ^Conn,
	wire: []u8,
) -> (
	Record_Header,
	Handshake_Record_Read_Error,
) {
	count, header_err := transport.read_exact(conn.transport, wire[:RECORD_HEADER_SIZE])
	if header_err.kind != .None {
		return {}, {kind = .Header_Read_Failed, transport = header_err, received = count}
	}

	header_bytes: [RECORD_HEADER_SIZE]u8
	copy(header_bytes[:], wire[:RECORD_HEADER_SIZE])
	header, decode_err := record_header_decode(header_bytes)
	if decode_err != .None {
		return {}, {kind = .Invalid_Header, record = decode_err}
	}

	if validation_error := handshake_record_header_validate(conn, header); validation_error.kind != .None do return {}, validation_error
	body_count, body_err := transport.read_exact(
		conn.transport,
		wire[RECORD_HEADER_SIZE:][:cast(int)header.length],
	)
	if body_err.kind != .None {
		return {}, {kind = .Body_Read_Failed, transport = body_err, received = body_count}
	}

	return header, {}
}

handshake_record_decrypt :: proc(
	conn: ^Conn,
	dst, wire: []u8,
	header: Record_Header,
) -> (
	[]u8,
	Handshake_Record_Read_Error,
) {
	content_type, content, protection_err := record_open(
		&conn.handshake_receive,
		dst,
		wire[:RECORD_HEADER_SIZE + cast(int)header.length],
	)
	if protection_err != .None {
		return handshake_record_fail(
			conn,
			{kind = .Decryption_Failed, protection = protection_err},
		)
	}

	if content_type == .Alert {
		alert := Handshake_Record_Read_Error {
			kind              = .Peer_Alert,
			alert_level       = content[0],
			alert_description = content[1],
		}
		crypto.zero_explicit(raw_data(content), len(content))
		return handshake_record_fail(conn, alert)
	}

	if content_type != .Handshake {
		crypto.zero_explicit(raw_data(content), len(content))
		return handshake_record_fail(conn, {kind = .Unexpected_Content_Type})
	}

	if !handshake_record_track(conn, content) {
		crypto.zero_explicit(raw_data(content), len(content))
		return handshake_record_fail(conn, {kind = .Record_Boundary_Violation})
	}

	return content, {}
}

// Track message boundaries without buffering certificate-sized messages. This
// keeps compatibility records out of fragmented messages, and ensures messages
// that precede a key change finish at the end of their record (RFC 8446 5.1).
handshake_record_track :: proc(conn: ^Conn, content: []u8) -> bool {
	at := 0
	for at < len(content) {
		if conn.server_handshake_remaining > 0 {
			count := min(conn.server_handshake_remaining, len(content) - at)
			conn.server_handshake_remaining -= count
			at += count
			if conn.server_handshake_remaining > 0 {
				return true
			}

			if conn.server_handshake_type == cast(u8)Handshake_Type.Finished ||
			   conn.server_handshake_type == cast(u8)Handshake_Type.Key_Update {
				if at != len(content) do return false
			}

			if conn.server_handshake_type == cast(u8)Handshake_Type.Finished {
				conn.phase = .Server_Finished_Received
			}

			continue
		}

		count := min(4 - conn.server_handshake_header_used, len(content) - at)
		copy(
			conn.server_handshake_header[conn.server_handshake_header_used:],
			content[at:][:count],
		)
		conn.server_handshake_header_used += count
		at += count
		if conn.server_handshake_header_used < 4 {
			return true
		}

		conn.server_handshake_type = conn.server_handshake_header[0]
		conn.server_handshake_remaining = handshake_body_size(conn.server_handshake_header[:])
		conn.server_handshake_header_used = 0
		if conn.server_handshake_remaining == 0 &&
		   (conn.server_handshake_type == cast(u8)Handshake_Type.Finished ||
				   conn.server_handshake_type == cast(u8)Handshake_Type.Key_Update) &&
		   at != len(content) {
			return false
		}

		if conn.server_handshake_remaining == 0 &&
		   conn.server_handshake_type == cast(u8)Handshake_Type.Finished {
			conn.phase = .Server_Finished_Received
		}
	}
	return true
}

handshake_record_fail :: proc(
	conn: ^Conn,
	err: Handshake_Record_Read_Error,
) -> (
	[]u8,
	Handshake_Record_Read_Error,
) {
	conn.phase = .Failed
	alpn_clear(conn)
	conn.handshake_record_error = err
	handshake_keys_clear(conn)
	return nil, err
}


// Asynchronous handshake operations

@(private)
async_handshake_fail :: proc(conn: ^Async_Conn, error: Handshake_Error) {
	conn.protocol.handshake_error = error
	async_terminal(conn, {kind = .Protocol_Failed}, {kind = .Handshake_Failed, handshake = error})
}

@(private)
async_hello_send :: proc(conn: ^Async_Conn, retry: bool) {
	message := conn.protocol.client_hello[:conn.protocol.client_hello_size]
	version := LEGACY_TLS_1_0
	kind := Async_Send_Kind.Hello
	if retry {
		message = conn.protocol.retry_client_hello[:conn.protocol.retry_client_hello_size]
		version, kind = LEGACY_TLS_1_2, .Retry
	}
	header := record_header_encode(
		{content_type = .Handshake, legacy_version = version, length = u16(len(message))},
	)
	copy(conn.tx_wire[:], header[:])
	copy(conn.tx_wire[RECORD_HEADER_SIZE:], message)
	async_send_start(conn, kind, RECORD_HEADER_SIZE + len(message), conn.handshake_deadline)
}

@(private)
async_handshake_drive :: proc(conn: ^Async_Conn) {
	if conn.tx.pending || conn.tx_done do return
	p := &conn.protocol
	if p.phase == .Handshake_Pending {
		if err := client_hello_prepare(p); err.kind != .None {
			async_handshake_fail(conn, {kind = .Client_Hello_Failed, client_hello = err}); return
		}
		async_hello_send(conn, false)
		return
	}
	if p.phase == .Hello_Retry_Received {
		async_hello_send(conn, true)
		return
	}
	if p.phase == .Server_Finished_Received {
		if conn.finishing do return
		hash, err := handshake_server_flight_verify(p, conn.flight[:conn.flight_used])
		if err.kind != .None {
			async_handshake_fail(conn, err)
			return
		}
		conn.secrets = application_secrets_derive(p.handshake_secrets.handshake_secret, hash)
		size, finish_err := handshake_client_finished_encode(p, &hash, conn.tx_wire[:])
		if finish_err.kind != .None {
			async_handshake_fail(conn, finish_err)
			return
		}
		crypto.zero_explicit(raw_data(conn.flight), len(conn.flight))
		delete(conn.flight, conn.allocator)
		conn.flight = nil
		conn.finishing = true
		async_send_start(conn, .Finished, size, conn.handshake_deadline)
		return
	}
	if p.phase != .Awaiting_Server_Hello && p.phase != .Handshake_Keys_Ready {
		async_handshake_fail(conn, {kind = .Invalid_State}); return
	}
	header, ready := async_receive_record(conn, conn.handshake_deadline)
	if !ready do return
	body := conn.rx_wire[RECORD_HEADER_SIZE:conn.rx_expected]
	if p.phase == .Awaiting_Server_Hello {
		if err := record_header_validate_plaintext(header); err != .None {
			async_handshake_fail(
				conn,
				{
					kind = .Server_Hello_Failed,
					server_hello = {
						kind = .Record_Read_Failed,
						record = {kind = .Invalid_Header, record = err},
					},
				},
			); return
		}
		if header.content_type != .Handshake && conn.hello_used > 0 {
			async_handshake_fail(
				conn,
				{kind = .Server_Hello_Failed, server_hello = {kind = .Interleaved_Record}},
			); return
		}
		#partial switch header.content_type {
		case .Change_Cipher_Spec:
			if err := server_hello_ccs_validate(body, &conn.ignored_ccs); err.kind != .None {
				async_handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
				return
			}
		case .Alert:
			async_handshake_fail(
				conn,
				{
					kind = .Server_Hello_Failed,
					server_hello = {
						kind = .Peer_Alert,
						alert_level = body[0],
						alert_description = body[1],
					},
				},
			); return
		case .Handshake:
			complete, append_error := server_hello_message_append(
				conn.hello[:],
				body,
				&conn.hello_used,
			)
			if append_error.kind != .None {
				async_handshake_fail(
					conn,
					{kind = .Server_Hello_Failed, server_hello = append_error},
				)
				return
			}
			if complete {
				message := conn.hello[:conn.hello_used]
				err :=
					server_hello_retry_accept(p, message) if \
						hello_is_retry(message) else \
						server_hello_accept(p, message)
				if err.kind != .None {
					async_handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
					return
				}
				conn.hello_used = 0
				if p.phase == .Server_Hello_Received {
					if key_error := client_handshake_keys_init(p); key_error.kind != .None {
						async_handshake_fail(
							conn,
							{kind = .Key_Derivation_Failed, keys = key_error},
						)
						return
					}
					allocation_error: mem.Allocator_Error
					conn.flight, allocation_error = make([]u8, 4096, conn.allocator)
					if allocation_error != nil {
						async_handshake_fail(
							conn,
							{kind = .Allocation_Failed, allocation = allocation_error},
						)
						return
					}
				}
			}
		}
	} else {
		if err := handshake_record_header_validate(p, header); err.kind != .None {
			async_handshake_fail(conn, {kind = .Server_Flight_Read_Failed, record = err})
			return
		}
		if header.content_type == .Change_Cipher_Spec {
			if err := server_hello_ccs_validate(body, &conn.ignored_ccs); err.kind != .None {
				async_handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
				return
			}
		} else {
			content, err := handshake_record_decrypt(
				p,
				conn.rx_plain[:],
				conn.rx_wire[:conn.rx_expected],
				header,
			)
			if err.kind != .None {
				async_handshake_fail(conn, {kind = .Server_Flight_Read_Failed, record = err})
				return
			}
			needed := conn.flight_used + len(content)
			if needed > MAX_SERVER_FLIGHT_SIZE {
				async_handshake_fail(conn, {kind = .Server_Flight_Oversized})
				return
			}
			if needed > len(conn.flight) {
				storage, allocation_error := make(
					[]u8,
					min(MAX_SERVER_FLIGHT_SIZE, max(needed, 2 * len(conn.flight))),
					conn.allocator,
				)
				if allocation_error != nil {
					async_handshake_fail(
						conn,
						{kind = .Allocation_Failed, allocation = allocation_error},
					)
					return
				}
				copy(storage, conn.flight[:conn.flight_used])
				crypto.zero_explicit(raw_data(conn.flight), len(conn.flight))
				delete(conn.flight, conn.allocator)
				conn.flight = storage
			}
			copy(conn.flight[conn.flight_used:], content)
			conn.flight_used += len(content)
		}
	}
	async_record_consumed(conn)
	async_queue(conn)
}

@(private)
handshake_until_check :: proc(conn: ^Conn, deadline: time.Time) -> Handshake_Error {
	if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {
		conn.handshake_complete = false
		return handshake_fail(conn, {kind = .Deadline_Failed, transport = {kind = .Timeout}})
	}
	return {}
}
