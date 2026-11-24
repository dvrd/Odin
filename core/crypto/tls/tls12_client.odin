package tls

import "core:crypto"
import "core:crypto/ecdh"
import transport "core:net"
import "core:time"

// One fresh ECDHE handshake for the two AES-128-GCM suites. No tickets,
// resumption, renegotiation, or second connection. Certificate and hostname
// checks are the existing TLS 1.3 verifier.
TLS12_Client :: struct {
	negotiated:        bool,
	cipher:            u16,
	client_random:     [32]u8,
	server_random:     [32]u8,
	server_hello:      [TLS12_MAX_SERVER_HELLO_SIZE]u8,
	server_hello_size: int,
	send, receive:     TLS12_Record_Protection,
	// Handshake bytes that shared the ServerHello record. Owned until the
	// flight is consumed or the handshake is abandoned.
	prefix:            []u8,
}

// Certificate chains in the compatibility probes fit well under this. A larger
// message is refused instead of growing the flight without a bound.
@(private)
TLS12_FLIGHT_STORAGE :: 256 * 1024

@(private)
tls12_client_clear :: proc(conn: ^Conn) {
	if conn == nil do return
	tls12_prefix_release(conn)
	crypto.zero_explicit(&conn.tls12, size_of(conn.tls12))
}

@(private)
tls12_prefix_release :: proc(conn: ^Conn) {
	if conn == nil || conn.tls12.prefix == nil do return
	delete(conn.tls12.prefix, conn.allocator)
	conn.tls12.prefix = nil
}

@(private)
tls12_server_hello_selected :: proc(message: []u8) -> bool {
	cipher, ok := tls12_server_hello_cipher(message)
	return ok && (cipher == TLS12_ECDHE_RSA_AES128_GCM_SHA256 || cipher == TLS12_ECDHE_ECDSA_AES128_GCM_SHA256)
}

@(private)
tls12_server_hello_cipher :: proc(message: []u8) -> (u16, bool) {
	if len(message) < 39 do return 0, false
	session := int(message[38])
	if session > 32 do return 0, false
	at := 39 + session
	if len(message) < at + 2 do return 0, false
	return hello_u16(message, at), true
}

@(private)
tls12_server_hello_accept :: proc(conn: ^Conn, message: []u8) -> Server_Hello_Read_Error {
	if len(message) > len(conn.tls12.server_hello) {
		return server_hello_fail(conn, {kind = .Message_Oversized})
	}
	copy(conn.tls12.server_hello[:], message)
	conn.tls12.server_hello_size = len(message)
	offer := TLS12_Client_Hello {
		server_name    = conn.config.server_name,
		random         = conn.tls12.client_random,
		alpn_protocols = conn.config.alpn_protocols,
	}
	hello, decode_error := tls12_server_hello_decode(conn.tls12.server_hello[:len(message)], offer, true)
	if decode_error != .None {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = tls12_hello_error_map(decode_error)})
	}
	if len(hello.alpn_selected) > len(conn.alpn_selected) {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = .Unsupported_Extension})
	}
	copy(conn.alpn_selected[:], hello.alpn_selected)
	conn.alpn_selected_size = len(hello.alpn_selected)
	conn.tls12.server_random = hello.random
	conn.tls12.cipher = hello.cipher_suite
	conn.tls12.negotiated = true
	conn.phase = .Server_Hello_Received
	return {}
}

@(private)
tls12_hello_error_map :: proc(err: TLS12_Hello_Error) -> Server_Hello_Error {
	switch err {
	case .None:
		return .None
	case .Truncated:
		return .Truncated
	case .Length_Mismatch:
		return .Length_Mismatch
	case .Unexpected_Message:
		return .Unexpected_Handshake_Type
	case .Unsupported_Version, .Downgrade_Detected:
		return .Unsupported_Version
	case .Invalid_Session_ID:
		return .Session_ID_Mismatch
	case .Unoffered_Cipher:
		return .Unoffered_Cipher
	case .Invalid_Compression:
		return .Invalid_Compression
	case .Duplicate_Extension:
		return .Duplicate_Extension
	case .Unsupported_Extension, .Invalid_Extension, .Missing_Extended_Master_Secret,
	     .Missing_Secure_Renegotiation, .Invalid_ALPN, .Invalid_Server_Name,
	     .Destination_Undersized:
		return .Unsupported_Extension
	}
	return .Unsupported_Extension
}

@(private)
tls12_client_establish :: proc(conn: ^Conn) -> Handshake_Error {
	if conn == nil || !conn.tls12.negotiated || conn.phase != .Server_Hello_Received {
		return handshake_fail(conn, {kind = .Invalid_State})
	}
	storage, allocation_error := make([]u8, TLS12_FLIGHT_STORAGE, conn.allocator)
	if allocation_error != nil {
		return handshake_fail(conn, {kind = .Allocation_Failed, allocation = allocation_error})
	}
	defer delete(storage, conn.allocator)
	framer, framer_error := tls12_framing_init(storage)
	if framer_error != .None {
		return handshake_fail(conn, {kind = .Invalid_State})
	}

	transcript: Handshake_Transcript
	transcript_init(&transcript)
	transcript_update(&transcript, handshake_effective_client_hello(conn))
	transcript_update(&transcript, conn.tls12.server_hello[:conn.tls12.server_hello_size])

	pending := conn.tls12.prefix
	scratch: [MAX_PLAINTEXT_SIZE]u8
	certificate, certificate_error := tls12_take_handshake(conn, &framer, &pending, scratch[:], u8(Handshake_Type.Certificate))
	if certificate_error.kind != .None do return certificate_error
	defer delete(certificate, conn.allocator)
	transcript_update(&transcript, certificate)

	exchange, exchange_error := tls12_take_handshake(conn, &framer, &pending, scratch[:], TLS12_SERVER_KEY_EXCHANGE_TYPE)
	if exchange_error.kind != .None do return exchange_error
	defer delete(exchange, conn.allocator)
	transcript_update(&transcript, exchange)

	done, done_error := tls12_take_handshake(conn, &framer, &pending, scratch[:], 14)
	if done_error.kind != .None do return done_error
	defer delete(done, conn.allocator)
	if len(done) != 4 || handshake_body_size(done) != 0 {
		return handshake_fail(conn, {kind = .Malformed_Message, message_type = 14})
	}
	transcript_update(&transcript, done)
	if len(pending) != 0 {
		return handshake_fail(conn, {kind = .Unexpected_Handshake_Message})
	}

	certs, parse_error := tls12_server_certificates_parse(certificate, conn.allocator)
	if parse_error.kind != .None {
		return handshake_fail(conn, {kind = .Authentication_Failed, authentication = parse_error})
	}
	defer server_certificates_destroy(&certs, conn.allocator)
	groups := [?]Named_Group{.X25519, .Secp256r1}
	schemes := [?]Signature_Scheme{.Rsa_Pss_Rsae_Sha256, .Ecdsa_Secp256r1_Sha256, .Rsa_Pkcs1_Sha256}
	view, authenticated := tls12_authenticate_server_key_exchange(
		&certs,
		exchange,
		conn.config,
		conn.tls12.client_random,
		conn.tls12.server_random,
		conn.tls12.cipher,
		groups[:],
		schemes[:],
		time.now(),
		conn.allocator,
	)
	if authenticated.kind != .None {
		return handshake_fail(conn, {kind = .Authentication_Failed, authentication = authenticated.authentication, message_type = TLS12_SERVER_KEY_EXCHANGE_TYPE})
	}

	curve: ecdh.Curve
	point_len: int
	if view.group == .X25519 {
		curve, point_len = .X25519, 32
	} else if view.group == .Secp256r1 {
		curve, point_len = .SECP256R1, 65
	} else {
		return handshake_fail(conn, {kind = .Authentication_Failed, message_type = TLS12_SERVER_KEY_EXCHANGE_TYPE})
	}
	private: ecdh.Private_Key
	defer ecdh.private_key_clear(&private)
	if !ecdh.private_key_generate(&private, curve) {
		return handshake_fail(conn, {kind = .Key_Derivation_Failed})
	}
	public_point: [65]u8
	ecdh.private_key_public_bytes(&private, public_point[:point_len])
	peer: ecdh.Public_Key
	defer ecdh.public_key_clear(&peer)
	if !ecdh.public_key_set_bytes(&peer, curve, view.public_key) {
		return handshake_fail(conn, {kind = .Authentication_Failed, message_type = TLS12_SERVER_KEY_EXCHANGE_TYPE})
	}
	premaster: [32]u8
	defer crypto.zero_explicit(&premaster, size_of(premaster))
	if !ecdh.ecdh(&private, &peer, premaster[:]) {
		return handshake_fail(conn, {kind = .Key_Derivation_Failed})
	}

	cke: [4 + 1 + 65]u8
	body_len := 1 + point_len
	cke[0] = 16
	cke[1], cke[2], cke[3] = 0, 0, u8(body_len)
	cke[4] = u8(point_len)
	copy(cke[5:], public_point[:point_len])
	cke_size := 5 + point_len
	transcript_update(&transcript, cke[:cke_size])
	client_hash := transcript_snapshot(&transcript)
	master, schedule_error := tls12_extended_master_secret(premaster[:], client_hash)
	defer crypto.zero_explicit(&master, size_of(master))
	if schedule_error != .None {
		return handshake_fail(conn, {kind = .Key_Derivation_Failed})
	}
	keys := tls12_key_block(master, conn.tls12.client_random, conn.tls12.server_random)
	defer tls12_key_block_clear(&keys)
	tls12_record_protection_init(&conn.tls12.send, keys.client_key, keys.client_iv)
	tls12_record_protection_init(&conn.tls12.receive, keys.server_key, keys.server_iv)

	if send_error := tls12_send_plaintext(conn, .Handshake, cke[:cke_size]); send_error.kind != .None {
		return send_error
	}
	ccs := [?]u8{1}
	if send_error := tls12_send_plaintext(conn, .Change_Cipher_Spec, ccs[:]); send_error.kind != .None {
		return send_error
	}
	finished: [TLS12_FINISHED_MESSAGE_SIZE]u8
	finished_size, finished_error := tls12_finished_encode(finished[:], master, client_hash, false)
	if finished_error != .None {
		return handshake_fail(conn, {kind = .Finished_Failed, finished = finished_error})
	}
	if send_error := tls12_send_encrypted(conn, .Handshake, finished[:finished_size]); send_error.kind != .None {
		return send_error
	}
	transcript_update(&transcript, finished[:finished_size])
	server_hash := transcript_snapshot(&transcript)

	if ccs_error := tls12_expect_server_ccs(conn, scratch[:]); ccs_error.kind != .None {
		return ccs_error
	}
	content, peer_finished, open_error := tls12_read_encrypted(conn)
	if open_error.kind != .None do return open_error
	if content == .Alert {
		return tls12_encrypted_alert(conn, peer_finished)
	}
	if content != .Handshake {
		return handshake_fail(conn, {kind = .Unexpected_Handshake_Message})
	}
	if verified := tls12_finished_verify(peer_finished, master, server_hash, true); verified != .None {
		return handshake_fail(conn, {kind = .Finished_Failed, finished = verified})
	}

	conn.server_parameters = {
		random       = conn.tls12.server_random,
		version      = TLS12_VERSION,
		cipher_suite = cast(Cipher_Suite)conn.tls12.cipher,
	}
	clear_ephemeral_keys(&conn.ephemeral)
	tls12_prefix_release(conn)
	conn.application.initialized = true
	conn.phase = .Established
	conn.handshake_complete = true
	return {}
}

@(private)
tls12_take_handshake :: proc(
	conn: ^Conn,
	framer: ^TLS12_Handshake_Framer,
	pending: ^[]u8,
	scratch: []u8,
	expected: u8,
) -> (
	[]u8,
	Handshake_Error,
) {
	message, read_error := tls12_next_handshake(conn, framer, pending, scratch)
	if read_error.kind != .None do return nil, read_error
	kind := message[0]
	if kind == u8(Handshake_Type.Certificate_Request) {
		return nil, handshake_fail(conn, {kind = .Client_Authentication_Unsupported, message_type = kind})
	}
	if kind != expected {
		return nil, handshake_fail(conn, {kind = .Unexpected_Handshake_Message, message_type = kind})
	}
	copied, allocation_error := make([]u8, len(message), conn.allocator)
	if allocation_error != nil {
		return nil, handshake_fail(conn, {kind = .Allocation_Failed, allocation = allocation_error})
	}
	copy(copied, message)
	if tls12_framing_next(framer) != .None {
		delete(copied, conn.allocator)
		return nil, handshake_fail(conn, {kind = .Invalid_State})
	}
	return copied, {}
}

@(private)
tls12_next_handshake :: proc(
	conn: ^Conn,
	framer: ^TLS12_Handshake_Framer,
	pending: ^[]u8,
	scratch: []u8,
) -> (
	[]u8,
	Handshake_Error,
) {
	for {
		if len(pending^) > 0 {
			consumed, message, frame_error := tls12_framing_push(framer, pending^)
			if frame_error == .Message_Oversized {
				return nil, handshake_fail(conn, {kind = .Server_Flight_Oversized})
			}
			if frame_error != .None {
				return nil, handshake_fail(conn, {kind = .Malformed_Message})
			}
			if consumed > len(pending^) {
				return nil, handshake_fail(conn, {kind = .Invalid_State})
			}
			pending^ = pending^[consumed:]
			if message != nil do return message, {}
			if consumed == 0 {
				return nil, handshake_fail(conn, {kind = .Malformed_Message})
			}
			continue
		}
		header, body, read_error := record_read_plaintext(conn.transport, scratch)
		if read_error.kind != .None {
			return nil, tls12_plaintext_fail(conn, read_error)
		}
		switch header.content_type {
		case .Alert:
			return nil, handshake_fail(conn, {
				kind = .Server_Flight_Read_Failed,
				record = {
					kind = .Peer_Alert,
					alert_level = body[0],
					alert_description = body[1],
				},
			})
		case .Handshake:
			pending^ = body
		case .Change_Cipher_Spec:
			return nil, handshake_fail(conn, {kind = .Unexpected_Handshake_Message, message_type = u8(header.content_type)})
		case .Application_Data:
			return nil, handshake_fail(conn, {kind = .Unexpected_Handshake_Message, message_type = u8(header.content_type)})
		}
	}
}

@(private)
tls12_plaintext_fail :: proc(conn: ^Conn, err: Record_Read_Error) -> Handshake_Error {
	kind := Handshake_Record_Read_Error_Kind.Body_Read_Failed
	if err.kind == .Header_Read_Failed do kind = .Header_Read_Failed
	if err.kind == .Invalid_Header do kind = .Invalid_Header
	if err.kind == .Destination_Undersized do kind = .Destination_Undersized
	return handshake_fail(conn, {
		kind = .Server_Flight_Read_Failed,
		transport = err.transport,
		record = {kind = kind, transport = err.transport, record = err.record, received = err.received},
	})
}

@(private)
tls12_send_plaintext :: proc(conn: ^Conn, content: TLS_Content_Type, body: []u8) -> Handshake_Error {
	if len(body) > 256 {
		return handshake_fail(conn, {kind = .Invalid_State})
	}
	header := record_header_encode({content_type = content, legacy_version = LEGACY_TLS_1_2, length = u16(len(body))})
	wire: [5 + 256]u8
	copy(wire[:], header[:])
	copy(wire[RECORD_HEADER_SIZE:], body)
	_, write_error := transport.write_all(conn.transport, wire[:RECORD_HEADER_SIZE + len(body)])
	if write_error.kind != .None {
		return handshake_fail(conn, {kind = .Finished_Write_Failed, transport = write_error})
	}
	return {}
}

@(private)
tls12_send_encrypted :: proc(conn: ^Conn, content: TLS_Content_Type, body: []u8) -> Handshake_Error {
	wire: [RECORD_HEADER_SIZE + 256]u8
	written, protection_error := tls12_record_seal(&conn.tls12.send, wire[:], content, body)
	if protection_error != .None {
		return handshake_fail(conn, {kind = .Finished_Write_Failed, protection = protection_error})
	}
	_, write_error := transport.write_all(conn.transport, wire[:written])
	if write_error.kind != .None {
		return handshake_fail(conn, {kind = .Finished_Write_Failed, transport = write_error})
	}
	return {}
}

@(private)
tls12_expect_server_ccs :: proc(conn: ^Conn, scratch: []u8) -> Handshake_Error {
	header, body, read_error := record_read_plaintext(conn.transport, scratch)
	if read_error.kind != .None do return tls12_plaintext_fail(conn, read_error)
	if header.content_type == .Alert {
		return handshake_fail(conn, {
			kind = .Server_Flight_Read_Failed,
			record = {kind = .Peer_Alert, alert_level = body[0], alert_description = body[1]},
		})
	}
	if header.content_type != .Change_Cipher_Spec || len(body) != 1 || body[0] != 1 {
		return handshake_fail(conn, {kind = .Unexpected_Handshake_Message, message_type = u8(header.content_type)})
	}
	return {}
}

@(private)
tls12_read_encrypted :: proc(conn: ^Conn) -> (TLS_Content_Type, []u8, Handshake_Error) {
	wire: [RECORD_HEADER_SIZE + TLS12_MAX_CIPHERTEXT_SIZE]u8
	header_count, header_error := transport.read_exact(conn.transport, wire[:RECORD_HEADER_SIZE])
	if header_error.kind != .None {
		return {}, nil, handshake_fail(conn, {
			kind = .Server_Flight_Read_Failed,
			transport = header_error,
			record = {kind = .Header_Read_Failed, transport = header_error, received = header_count},
		})
	}
	cipher_size := int(wire[3]) << 8 | int(wire[4])
	if cipher_size < TLS12_GCM_OVERHEAD || cipher_size > TLS12_MAX_CIPHERTEXT_SIZE {
		return {}, nil, handshake_fail(conn, {kind = .Server_Flight_Read_Failed, record = {kind = .Invalid_Header}})
	}
	body_count, body_error := transport.read_exact(conn.transport, wire[RECORD_HEADER_SIZE:][:cipher_size])
	if body_error.kind != .None {
		return {}, nil, handshake_fail(conn, {
			kind = .Server_Flight_Read_Failed,
			transport = body_error,
			record = {kind = .Body_Read_Failed, transport = body_error, received = body_count},
		})
	}
	plain: [MAX_PLAINTEXT_SIZE]u8
	content, body, protection_error := tls12_record_open(&conn.tls12.receive, plain[:], wire[:RECORD_HEADER_SIZE + cipher_size])
	if protection_error != .None {
		return {}, nil, handshake_fail(conn, {kind = .Server_Flight_Read_Failed, protection = protection_error, record = {kind = .Decryption_Failed, protection = protection_error}})
	}
	// The returned view must outlive this frame. Finished is at most 16 bytes
	// and is verified before return; copy it into the connection inbound buffer.
	if len(body) > len(conn.application.inbound) {
		return {}, nil, handshake_fail(conn, {kind = .Server_Flight_Oversized})
	}
	copy(conn.application.inbound[:], body)
	return content, conn.application.inbound[:len(body)], {}
}

@(private)
tls12_encrypted_alert :: proc(conn: ^Conn, body: []u8) -> Handshake_Error {
	if len(body) < 2 {
		return handshake_fail(conn, {kind = .Malformed_Message})
	}
	return handshake_fail(conn, {
		kind = .Server_Flight_Read_Failed,
		record = {kind = .Peer_Alert, alert_level = body[0], alert_description = body[1]},
	})
}

@(private)
tls12_application_read :: proc(conn: ^Conn, dst: []u8) -> (int, IO_Error) {
	if err := application_ensure(conn); err.kind != .None do return 0, err
	if len(dst) == 0 do return 0, {}
	state := &conn.application
	if state.inbound_at < state.inbound_size {
		count := copy(dst, state.inbound[state.inbound_at:state.inbound_size])
		state.inbound_at += count
		return count, {}
	}
	if state.peer_closed do return 0, {kind = .EOF}
	for _ in 0 ..< MAX_NON_APPLICATION_RECORDS {
		content, payload, read_error := tls12_application_record_read(conn)
		if read_error.kind != .None do return 0, application_fail(conn, read_error)
		switch content {
		case .Application_Data:
			if len(payload) == 0 do continue
			state.inbound_at = copy(dst, payload)
			state.inbound_size = len(payload)
			return state.inbound_at, {}
		case .Alert:
			if len(payload) != 2 {
				return 0, application_fail(conn, {kind = .Invalid_Record})
			}
			if payload[1] == 0 {
				state.peer_closed = true
				tls12_record_protection_clear(&conn.tls12.receive)
				return 0, {kind = .EOF}
			}
			return 0, application_fail(conn, {kind = .Peer_Alert, alert_level = payload[0], alert_description = payload[1]})
		case .Handshake:
			return 0, application_fail(conn, {kind = .Invalid_Post_Handshake})
		case .Change_Cipher_Spec:
			return 0, application_fail(conn, {kind = .Unexpected_Content_Type})
		}
	}
	return 0, application_fail(conn, {kind = .No_Progress})
}

@(private)
tls12_application_write :: proc(conn: ^Conn, src: []u8) -> (written: int, error: IO_Error) {
	if err := application_ensure(conn); err.kind != .None do return 0, err
	for written < len(src) {
		if conn.tls12.send.sequence >= TLS12_MAX_RECORDS_PER_KEY {
			return written, application_fail(conn, {kind = .Encryption_Failed, protection = .Key_Usage_Limit})
		}
		count := min(MAX_PLAINTEXT_SIZE, len(src) - written)
		if err := tls12_application_record_write(conn, .Application_Data, src[written:][:count]); err.kind != .None {
			return written, application_fail(conn, err)
		}
		written += count
	}
	return written, {}
}

@(private)
tls12_application_close_notify :: proc(conn: ^Conn) -> IO_Error {
	alert := [?]u8{1, 0}
	return tls12_application_record_write(conn, .Alert, alert[:])
}

@(private)
tls12_application_record_write :: proc(conn: ^Conn, content: TLS_Content_Type, payload: []u8) -> IO_Error {
	wire: [RECORD_HEADER_SIZE + TLS12_MAX_CIPHERTEXT_SIZE]u8
	size, protection_error := tls12_record_seal(&conn.tls12.send, wire[:], content, payload)
	if protection_error != .None {
		return {kind = .Encryption_Failed, protection = protection_error}
	}
	written, transport_error := transport.write_all(conn.transport, wire[:size])
	if transport_error.kind != .None {
		return {kind = .Transport_Write_Failed, transport = transport_error, transferred = written}
	}
	return {}
}

@(private)
tls12_application_record_read :: proc(conn: ^Conn) -> (TLS_Content_Type, []u8, IO_Error) {
	wire: [RECORD_HEADER_SIZE + TLS12_MAX_CIPHERTEXT_SIZE]u8
	header_count, header_error := transport.read_exact(conn.transport, wire[:RECORD_HEADER_SIZE])
	if header_error.kind != .None {
		kind: IO_Error_Kind = .Transport_Read_Failed
		if header_error.kind == .Peer_Closed do kind = .Unexpected_EOF
		return {}, nil, {kind = kind, transport = header_error, transferred = header_count}
	}
	if wire[1] != 3 || wire[2] != 3 {
		return {}, nil, {kind = .Invalid_Record, record = .Unexpected_Content_Type}
	}
	cipher_size := int(wire[3]) << 8 | int(wire[4])
	if cipher_size < TLS12_GCM_OVERHEAD || cipher_size > TLS12_MAX_CIPHERTEXT_SIZE {
		return {}, nil, {kind = .Invalid_Record, record = .Record_Oversized}
	}
	body_count, body_error := transport.read_exact(conn.transport, wire[RECORD_HEADER_SIZE:][:cipher_size])
	if body_error.kind != .None {
		kind: IO_Error_Kind = .Transport_Read_Failed
		if body_error.kind == .Peer_Closed do kind = .Unexpected_EOF
		return {}, nil, {kind = kind, transport = body_error, transferred = body_count}
	}
	content, payload, protection_error := tls12_record_open(&conn.tls12.receive, conn.application.inbound[:], wire[:RECORD_HEADER_SIZE + cipher_size])
	if protection_error != .None {
		return {}, nil, {kind = .Decryption_Failed, protection = protection_error}
	}
	return content, payload, {}
}
