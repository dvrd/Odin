package tls

import "base:runtime"
import "core:crypto/x509"
import "core:io"
import "core:net"
import "core:os"
import "core:sync"
import "core:time"

// Socket is upstream's blocking client API over the client engine (Conn):
// one handshake implementation serves both. The engine runs on the calling
// thread; no worker threads exist. send and recv keep upstream's promise
// that one thread may send while another receives: the engine's two record
// directions share no state, and each is serialized by its own lock.
//
// What the peer and the caller observe is upstream's client: its ClientHello
// (the Upstream offer), its compatibility ChangeCipherSpec, the alert it
// sends for each failure and the Error it returns. Conn.upstream_client makes
// the engine refuse what upstream refuses (a HelloRetryRequest, a
// ChangeCipherSpec before the ServerHello or a second one after it, any
// EncryptedExtensions extension but server_name and ALPN, a
// NewSessionTicket) and accept what it accepts (any host name of at most
// SNI_MAX_HOSTNAME_SIZE bytes, any number of ALPN protocols).

// client_handshake performs a TLS handshake given an established
// TCP connection (`net_socket`).  `trust_roots` is expected to be
// populated with certificate authority certificates.
//
// Debugging options (that destroy security):
// - unsafe_skip_verify: Omits checking the certificate chain.
// - unsafe_secret_logger: Writes the handshake key material for use
//   with Wireshark and similar tools.
//
// Once this function returns with a non-error result `close` MUST
// be called to free up resources.
@(require_results)
client_handshake :: proc(
	socket:               ^Socket,
	net_socket:           net.TCP_Socket,
	host_name:            string,
	trust_roots:          []^x509.Certificate,
	alpn_protocols:       []Alpn_Protocols = nil,
	unsafe_skip_verify:   bool = false,
	unsafe_secret_logger: ^os.File = nil,
	allocator:            runtime.Allocator = context.allocator,
) -> Error {
	if err := net.set_blocking(net_socket, true); err != nil {
		return General_Error.Nonblocking_Socket
	}

	err := socket_engine_handshake(
		socket,
		net_socket,
		host_name,
		trust_roots,
		alpn_protocols,
		unsafe_skip_verify,
		unsafe_secret_logger,
		allocator,
	)
	return socket_set_error(socket, err)
}

@(private, require_results)
socket_engine_handshake :: proc(
	socket:               ^Socket,
	net_socket:           net.TCP_Socket,
	host_name:            string,
	trust_roots:          []^x509.Certificate,
	alpn_protocols:       []Alpn_Protocols,
	unsafe_skip_verify:   bool,
	unsafe_secret_logger: ^os.File,
	allocator:            runtime.Allocator,
) -> Error {
	if len(host_name) > SNI_MAX_HOSTNAME_SIZE {
		return General_Error.Invalid_SNI_Hostname
	}

	state := &socket._state
	socket.fd = net_socket
	socket.alpn_protocol = .None
	state.allocator = allocator
	state.err = nil
	state.handshaked = false
	state.rx_closed = false
	state.conn = nil
	sync.atomic_store(&state.closing, false)
	sync.atomic_store(&state.key_update_owed, false)
	sync.atomic_store(&state.rx_dead, false)
	sync.atomic_store(&state.tx_dead, false)

	// The engine's handshake allocations follow the caller's allocator.
	context.allocator = allocator

	names := make([]string, len(alpn_protocols), allocator) or_return
	defer delete(names, allocator)
	for protocol, i in alpn_protocols {
		names[i] = ALPN_STRINGS[protocol]

		// Upstream cannot encode a protocol without a name (`.None`).
		if len(names[i]) == 0 {
			return io.Error.Short_Buffer
		}
	}

	// The configuration is taken as given: upstream validates no more than
	// the length of the host name.
	conn := new(Conn, allocator) or_return
	conn.transport = {data = socket, read = socket_transport_read, write = socket_transport_write, close = socket_transport_close}
	conn.config = {
		server_name          = host_name,
		root_cas             = trust_roots,
		alpn_protocols       = names,
		offer                = .Upstream,
		unsafe_skip_verify   = unsafe_skip_verify,
		unsafe_secret_logger = unsafe_secret_logger,
		no_system_roots      = true,
	}
	conn.phase = .Handshake_Pending
	conn.upstream_client = true
	// A KeyUpdate request read by recv is left for the sender to answer.
	conn.defer_key_updates = true

	if failure := engine_handshake(conn); failure.kind != .None {
		socket_engine_release(conn, allocator)
		return socket_handshake_error(failure)
	}

	socket.cipher_suite = conn.server_parameters.cipher_suite
	selected := string(conn.alpn_selected[:conn.alpn_selected_size])
	for candidate in alpn_protocols {
		if selected == ALPN_STRINGS[candidate] {
			socket.alpn_protocol = candidate
			break
		}
	}

	// Everything the configuration borrowed was for the handshake.
	conn.config = {offer = .Upstream}
	state.conn = conn
	state.handshaked = true
	return nil
}

// Sanitizes and frees the engine. The TCP socket is not the engine's.
@(private)
socket_engine_release :: proc(conn: ^Conn, allocator: runtime.Allocator) {
	if conn == nil {
		return
	}

	application_clear(&conn.application)
	handshake_keys_clear(conn)
	free(conn, allocator)
}

@(private, require_results)
socket_engine_send :: proc(socket: ^Socket, buf: []byte) -> (n: int, err: Error) {
	state := &socket._state
	sync.guard(&state.tx_lock)

	if state.conn == nil {
		return 0, io.Error.Closed
	}

	if sync.atomic_load(&state.tx_dead) {
		return 0, io.Error.Unknown
	}

	// Record by record, so that a KeyUpdate owed to the peer goes out in
	// the middle of a long send instead of after it.
	for n < len(buf) {
		socket_engine_owed_key_update(socket) or_return

		count := min(MAX_PLAINTEXT_SIZE, len(buf) - n)
		written, failure := application_write_records(state.conn, buf[n:][:count])
		n += written
		if failure.kind != .None {
			return n, socket_engine_failure(socket, socket_io_error(failure))
		}
	}
	return n, nil
}

@(private, require_results)
socket_engine_recv :: proc(socket: ^Socket, buf: []byte) -> (n: int, err: Error) {
	state := &socket._state
	sync.guard(&state.rx_lock)

	conn := state.conn
	if conn == nil {
		return 0, io.Error.Closed
	}

	if sync.atomic_load(&state.rx_dead) {
		return 0, io.Error.Unknown
	}

	received, failure := application_read_records(conn, buf)

	// The peer asked for new keys in our direction. That is the sender's
	// to answer: a send in progress does so before its next record, and
	// recv never waits for it (the peer may not read on until we do).
	if conn.application.key_update_pending {
		conn.application.key_update_pending = false
		sync.atomic_store(&state.key_update_owed, true)
		if sync.mutex_try_lock(&state.tx_lock) {
			update := socket_engine_owed_key_update(socket)
			sync.mutex_unlock(&state.tx_lock)
			if update != nil && failure.kind == .None {
				return received, update
			}
		}
	}

	#partial switch failure.kind {
	case .None:
		return received, nil
	case .EOF:
		// Not sticky: the socket can still send.
		return 0, Protocol_Error.Close_Notify
	case .No_Progress:
		// Upstream's receiver gives up without recording an error.
		sync.atomic_store(&state.rx_dead, true)
		return 0, io.Error.No_Progress
	case .Invalid_Post_Handshake, .Post_Handshake_Oversized:
		// A handshake message other than KeyUpdate ends upstream's socket
		// with an alert to the peer and no error of its own.
		if conn.application.post_handshake[0] != u8(Handshake_Type.Key_Update) {
			socket_engine_alert(socket, .Internal_Error)
			sync.atomic_store(&state.rx_dead, true)
			sync.atomic_store(&state.tx_dead, true)
			return 0, io.Error.Unknown
		}
	}

	// Upstream names every failed recv to the peer: its own alert echoed
	// back, internal_error for a lost connection.
	err = socket_recv_error(conn, failure)
	socket_engine_alert(socket, error_to_alert(err))
	return 0, socket_engine_failure(socket, err)
}

// Sends the KeyUpdate the peer asked for, if one is owed. The caller holds
// the send lock.
@(private, require_results)
socket_engine_owed_key_update :: proc(socket: ^Socket) -> Error {
	state := &socket._state
	if !sync.atomic_exchange(&state.key_update_owed, false) {
		return nil
	}

	if failure := application_send_key_update(state.conn); failure.kind != .None {
		return socket_engine_failure(socket, socket_io_error(failure))
	}
	return nil
}

// Tells the peer why recv gave up, as upstream's receiver does through its
// sender: best effort, and never behind a send in progress.
@(private)
socket_engine_alert :: proc(socket: ^Socket, alert: Alert_Description) {
	state := &socket._state
	if sync.atomic_load(&state.closing) || !sync.mutex_try_lock(&state.tx_lock) {
		return
	}

	content := [2]u8{u8(alert_to_level(alert)), u8(alert)}
	application_record_write(state.conn, .Alert, content[:])
	state.conn.send_ended = true
	sync.mutex_unlock(&state.tx_lock)
}

// Records err as the socket's error, unless close is what interrupted the
// call.
@(private, require_results)
socket_engine_failure :: proc(socket: ^Socket, err: Error) -> Error {
	if sync.atomic_load(&socket._state.closing) {
		return io.Error.Closed
	}
	return socket_set_error(socket, err)
}

// Closes the engine once no other thread is inside it: conn_close sends
// close_notify, sanitizes the keys and closes the TCP socket through the
// transport. A sender blocked in the TCP stack is waited for at most
// max_close_wait; after that the connection is shut down under it, which is
// what makes it return (and costs the close_notify).
@(private)
socket_engine_close :: proc(socket: ^Socket, max_close_wait: time.Duration) {
	state := &socket._state

	sending := socket_lock_within(&state.tx_lock, max_close_wait)
	sync.atomic_store(&state.closing, true)

	// Wakes a thread blocked in recv; the send direction stays open for
	// close_notify unless a blocked sender has to be woken as well.
	if sending {
		net.shutdown(socket.fd, .Receive)
	} else {
		net.shutdown(socket.fd, .Both)
		sync.lock(&state.tx_lock)
	}
	sync.lock(&state.rx_lock)

	if state.conn != nil {
		engine_close(state.conn)
		free(state.conn, state.allocator)
		state.conn = nil
	}

	sync.unlock(&state.rx_lock)
	sync.unlock(&state.tx_lock)
}

@(private, require_results)
socket_lock_within :: proc(lock: ^sync.Mutex, wait: time.Duration) -> bool {
	start := time.tick_now()
	for {
		if sync.mutex_try_lock(lock) {
			return true
		}

		if time.tick_since(start) >= wait {
			return false
		}
		time.sleep(time.Millisecond)
	}
}

// The engine's blocking transport over the socket's descriptor.

@(private)
socket_transport_read :: proc(data: rawptr, dst: []u8) -> (int, net.Connection_Error) {
	socket := cast(^Socket)data
	n, err := net.recv_tcp(socket.fd, dst)
	if err != nil {
		return n, {kind = .Read_Failed, read_cause = err}
	}

	if n == 0 && len(dst) > 0 {
		return 0, {kind = .Peer_Closed}
	}
	return n, {}
}

@(private)
socket_transport_write :: proc(data: rawptr, src: []u8) -> (int, net.Connection_Error) {
	socket := cast(^Socket)data
	n, err := net.send_tcp(socket.fd, src)
	if err != nil {
		return n, {kind = .Write_Failed, write_cause = err}
	}
	return n, {}
}

// Reached through conn_close only: a failed handshake releases the engine
// without closing, and the descriptor stays the caller's until close.
@(private)
socket_transport_close :: proc(data: rawptr) -> net.Connection_Error {
	socket := cast(^Socket)data
	net.close(socket.fd)
	return {}
}

// The engine's failures as upstream's client reports them: the Error it
// returns and the alert it sends to the peer. A TCP failure keeps its cause
// and sends nothing.

@(private, require_results)
socket_transport_error :: proc(failure: net.Connection_Error) -> Error {
	if failure.write_cause != nil {
		return failure.write_cause
	}

	if failure.read_cause != nil {
		return failure.read_cause
	}

	if failure.kind == .Peer_Closed {
		return net.TCP_Recv_Error.Connection_Closed
	}
	return io.Error.Unknown
}

@(private, require_results)
socket_peer_alert_error :: proc(level, description: u8) -> Error {
	return alert_to_error(Alert_Level(level), Alert_Description(description))
}

// Upstream's validation of EncryptedExtensions: a server_name
// acknowledgement (empty, once, and only when a name was sent) and one ALPN
// selection among the offers; anything else is an illegal parameter.
@(private, require_results)
socket_encrypted_extensions_check :: proc(message: []u8, host_name: string, offers: []string) -> Handshake_Error {
	body := message[4:]
	if len(body) < 2 || int(hello_u16(body, 0)) != len(body) - 2 {
		return {kind = .Malformed_Message}
	}

	sni_sent := len(host_name) > 0 && net.parse_address(host_name) == nil
	got_sni, got_alpn: bool
	at := 2
	for len(body) - at >= 4 {
		extension := Extension_Type(hello_u16(body, at))
		size := int(hello_u16(body, at + 2))
		at += 4
		if size > len(body) - at {
			return {kind = .Malformed_Message, plaintext_alert = true}
		}

		data := body[at:at + size]
		at += size

		#partial switch extension {
		case .Server_Name:
			if got_sni || !sni_sent || len(data) != 0 {
				return {kind = .Unsupported_Extension}
			}
			got_sni = true
		case .Application_Layer_Protocol_Negotiation:
			if len(data) < 3 || len(offers) == 0 {
				return {kind = .Malformed_Message}
			}

			if got_alpn {
				return {kind = .Invalid_ALPN}
			}

			if int(hello_u16(data, 0)) != len(data) - 2 || int(data[2]) != len(data) - 3 {
				return {kind = .Malformed_Message}
			}

			if !socket_alpn_offered(offers, string(data[3:])) {
				return {kind = .Invalid_ALPN}
			}
			got_alpn = true
		case:
			return {kind = .Unsupported_Extension}
		}
	}

	if at != len(body) {
		return {kind = .Malformed_Message}
	}
	return {}
}

// Upstream's validation of CertificateRequest: any context, no extension
// that TLS 1.3 forbids there, signature_algorithms exactly once and none of
// the extensions it knows twice. Extensions it does not know are ignored.
@(private, require_results)
socket_certificate_request_check :: proc(message: []u8) -> Handshake_Error {
	body := message[4:]
	if len(body) < 1 || len(body) < 3 + int(body[0]) {
		return {kind = .Malformed_Message}
	}

	at := 1 + int(body[0])
	if int(hello_u16(body, at)) != len(body) - at - 2 {
		return {kind = .Malformed_Message}
	}
	at += 2

	got_signature_algorithms, got_duplicate: bool
	seen: bit_set[0 ..< 7]
	extension_loop: for len(body) - at >= 4 {
		extension := Extension_Type(hello_u16(body, at))
		size := int(hello_u16(body, at + 2))
		at += 4
		if size > len(body) - at {
			return {kind = .Malformed_Message}
		}

		data := body[at:at + size]
		at += size
		if socket_certificate_request_forbids(extension) {
			return {kind = .Unsupported_Extension, upstream_alert = .Unsupported_Extension}
		}

		index := -1
		#partial switch extension {
		case .Signature_Algorithms:
			// A second one counts as none.
			if got_signature_algorithms {
				got_signature_algorithms = false
				break extension_loop
			}

			got_signature_algorithms = true
			if size % 2 != 0 || size < 4 || int(hello_u16(data, 0)) != size - 2 {
				return {kind = .Malformed_Message}
			}
		case .Status_Request:
			index = 0
		case .Compress_Certificate:
			index = 1
		case .Delegated_Credential:
			index = 2
		case .Certificate_Authorities:
			index = 3
		case .Oid_Filters:
			index = 4
		case .Signature_Algorithms_Cert:
			index = 5
		case .Transparency_Info:
			index = 6
		}

		if index >= 0 {
			if index in seen {
				got_duplicate = true
				break extension_loop
			}
			seen += {index}
		}
	}

	if !got_signature_algorithms {
		return {kind = .Malformed_Message, upstream_alert = .Missing_Extension}
	}

	if got_duplicate {
		return {kind = .Malformed_Message, upstream_alert = .Illegal_Parameter}
	}

	if at != len(body) {
		return {kind = .Malformed_Message}
	}

	// Upstream echoes a context; the engine's Certificate carries none.
	if body[0] != 0 {
		return {kind = .Malformed_Message}
	}
	return {}
}

@(private, require_results)
socket_certificate_request_forbids :: proc(extension: Extension_Type) -> bool {
	for known in Extension_Type {
		if known == extension {
			return CERTIFICATE_FORBIDDEN_EXTENSIONS[extension]
		}
	}
	return false
}

@(private, require_results)
socket_alpn_offered :: proc(offers: []string, protocol: string) -> bool {
	for offer in offers {
		if offer == protocol {
			return true
		}
	}
	return false
}

// The alert upstream's client sends for a failed handshake, if any. Its
// alerts name the error it returns, with these exceptions: nothing answers a
// lost connection or the peer's own alert once records are protected, and a
// CertificateVerify whose signature length disagrees with the message is
// reported as a decode error but alerted as a decrypt error.
@(private, require_results)
socket_handshake_alert :: proc(failure: Handshake_Error) -> (alert: Alert_Description, plaintext: bool, send: bool) {
	#partial switch failure.kind {
	case .None, .Invalid_State, .Client_Hello_Failed, .Finished_Write_Failed, .Deadline_Failed:
		return
	case .Server_Hello_Failed:
		if failure.server_hello.kind == .Record_Read_Failed && failure.server_hello.record.transport.kind != .None {
			return
		}
	case .Server_Flight_Read_Failed:
		#partial switch failure.record.kind {
		case .None, .Header_Read_Failed, .Body_Read_Failed, .Peer_Alert:
			return
		case .Unexpected_Content_Type:
			if failure.record.content_type == .Alert {
				return
			}
		}
	case .Authentication_Failed:
		if socket_signature_length_mismatch(failure) {
			return .Decrypt_Error, false, true
		}
	}
	return error_to_alert(socket_handshake_error(failure)), failure.plaintext_alert, true
}

@(private, require_results)
socket_signature_length_mismatch :: proc(failure: Handshake_Error) -> bool {
	return failure.authentication.kind == .Length_Mismatch && failure.message_type == u8(Handshake_Type.Certificate_Verify)
}

@(private, require_results)
socket_handshake_error :: proc(failure: Handshake_Error) -> Error {
	if failure.upstream_alert != .Close_Notify {
		return alert_to_error(.Fatal, failure.upstream_alert)
	}

	switch failure.kind {
	case .None:
		return nil
	case .Client_Hello_Failed:
		return socket_client_hello_error(failure.client_hello)
	case .Server_Hello_Failed:
		return socket_server_hello_error(failure.server_hello)
	case .Server_Flight_Read_Failed:
		return socket_flight_read_error(failure.record)
	case .Unexpected_Handshake_Message, .Client_Authentication_Unsupported:
		return Protocol_Error.Unexpected_Message
	case .Malformed_Message:
		return Protocol_Error.Decode_Error
	case .Key_Derivation_Failed, .Unsupported_Extension, .Invalid_ALPN, .Early_Data_Disabled:
		return Protocol_Error.Illegal_Parameter
	case .Authentication_Failed:
		return socket_authentication_error(failure.authentication)
	case .Finished_Failed:
		if failure.finished == .Unexpected_Handshake_Type {
			return Protocol_Error.Unexpected_Message
		}
		return Protocol_Error.Decrypt_Error
	case .Finished_Write_Failed, .Deadline_Failed:
		return socket_transport_error(failure.transport)
	case .Allocation_Failed:
		return failure.allocation
	case .Invalid_State, .Server_Flight_Oversized:
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
socket_client_hello_error :: proc(failure: Client_Hello_Send_Error) -> Error {
	switch failure.kind {
	case .Entropy_Unavailable:
		return General_Error.Failed_Key_Share_Generation
	case .Write_Failed:
		return socket_transport_error(failure.transport)
	case .Encode_Failed:
		// The only name upstream refuses is one too long to send; what
		// else does not fit its ClientHello is a short buffer.
		if failure.encode == .Invalid_Server_Name {
			return General_Error.Invalid_SNI_Hostname
		}
		return io.Error.Short_Buffer
	case .None, .Invalid_State, .Invalid_Retry:
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
socket_server_hello_error :: proc(failure: Server_Hello_Read_Error) -> Error {
	switch failure.kind {
	case .Record_Read_Failed:
		if failure.record.transport.kind != .None {
			return socket_transport_error(failure.record.transport)
		}

		#partial switch failure.record.record {
		case .Record_Oversized:
			return Protocol_Error.Record_Overflow
		case .Empty_Handshake:
			return Protocol_Error.Decode_Error
		}
		return Protocol_Error.Unexpected_Message
	case .Peer_Alert, .Invalid_Change_Cipher_Spec, .Too_Many_Change_Cipher_Specs, .Interleaved_Record:
		// Before the ServerHello upstream expects a handshake record and
		// nothing else: the peer's alert is an unexpected message too.
		return Protocol_Error.Unexpected_Message
	case .Message_Oversized, .Record_Boundary_Violation:
		return Protocol_Error.Decode_Error
	case .Invalid_Server_Hello:
		return socket_server_hello_decode_error(failure.decode)
	case .Invalid_Key_Share:
		return Protocol_Error.General_Error
	case .None, .Invalid_State:
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
socket_server_hello_decode_error :: proc(failure: Server_Hello_Error) -> Error {
	switch failure {
	case .None:
		return nil
	case .Truncated, .Length_Mismatch, .Extension_Length_Mismatch, .Invalid_Key_Share_Length:
		return Protocol_Error.Decode_Error
	case .Unexpected_Handshake_Type, .Hello_Retry_Unsupported, .Invalid_Hello_Retry_Request, .Missing_Retry_Cookie,
	     .Invalid_Retry_Cookie, .Retry_Cookie_Oversized, .Invalid_Retry_Group, .Repeated_Hello_Retry,
	     .Invalid_Retry_Client_Hello:
		return Protocol_Error.Unexpected_Message
	case .Invalid_Legacy_Version:
		return Protocol_Error.Protocol_Version
	case .Unsupported_Extension:
		return Protocol_Error.Unsupported_Extension
	case .Missing_Key_Share:
		return Protocol_Error.Missing_Extension
	case .Unoffered_Group, .Key_Share_Size_Mismatch:
		// Upstream finds these when the key agreement fails.
		return Protocol_Error.General_Error
	case .Session_ID_Mismatch, .Unoffered_Cipher, .Invalid_Compression, .Duplicate_Extension, .Missing_Supported_Versions,
	     .Unsupported_Version:
	}
	return Protocol_Error.Illegal_Parameter
}

@(private, require_results)
socket_flight_read_error :: proc(failure: Handshake_Record_Read_Error) -> Error {
	switch failure.kind {
	case .Header_Read_Failed, .Body_Read_Failed:
		return socket_transport_error(failure.transport)
	case .Peer_Alert:
		return socket_peer_alert_error(failure.alert_level, failure.alert_description)
	case .Decryption_Failed:
		return socket_protection_error(failure.protection, .Unexpected_Message)
	case .Invalid_Header:
		if failure.record == .Record_Oversized {
			return Protocol_Error.Record_Overflow
		}
		return Protocol_Error.Unexpected_Message
	case .Invalid_Change_Cipher_Spec:
		if failure.record == .Invalid_Change_Cipher_Spec_Length {
			return Protocol_Error.Decode_Error
		}
		return Protocol_Error.Illegal_Parameter
	case .Unexpected_Content_Type, .Too_Many_Change_Cipher_Specs, .Interleaved_Record, .Record_Boundary_Violation:
		return Protocol_Error.Unexpected_Message
	case .None, .Invalid_State, .Destination_Undersized:
	}
	return Protocol_Error.Internal_Error
}

// A protected record the engine refused. empty_handshake is upstream's
// answer to a handshake record without content, which depends on the stage.
@(private, require_results)
socket_protection_error :: proc(failure: Record_Protection_Error, empty_handshake: Protocol_Error) -> Error {
	#partial switch failure {
	case .Ciphertext_Too_Short:
		return Protocol_Error.Decode_Error
	case .Record_Oversized, .Inner_Plaintext_Oversized:
		return Protocol_Error.Record_Overflow
	case .Unexpected_Inner_Content_Type:
		return Protocol_Error.Unexpected_Message
	case .Empty_Handshake:
		return empty_handshake
	case .Invalid_State, .Key_Usage_Limit, .Destination_Undersized, .Overlapping_Buffers:
		return Protocol_Error.Internal_Error
	}
	return Protocol_Error.Bad_Record_Mac
}

@(private, require_results)
socket_authentication_error :: proc(failure: Authentication_Error) -> Error {
	switch failure.kind {
	case .Certificate_Chain_Invalid, .Invalid_Certificate_Usage:
		return socket_chain_error(failure.x509)
	case .Invalid_Trust_Roots:
		return Protocol_Error.Unknown_Ca
	case .Invalid_Certificate:
		return Protocol_Error.Bad_Certificate
	case .Empty_Certificate_List, .Invalid_Certificate_Context, .Unsupported_Certificate_Extension:
		return Protocol_Error.Illegal_Parameter
	case .Truncated, .Length_Mismatch, .Message_Oversized, .Too_Many_Certificates:
		return Protocol_Error.Decode_Error
	case .Unexpected_Handshake_Type:
		return Protocol_Error.Unexpected_Message
	case .Invalid_Server_Name:
		return General_Error.Invalid_SNI_Hostname
	case .Unsupported_Signature_Scheme, .Signature_Key_Mismatch, .Invalid_Public_Key, .Invalid_Signature:
		return Protocol_Error.Decrypt_Error
	case .None:
	}
	return Protocol_Error.Internal_Error
}

// Upstream's translation of a chain verification failure into its alert.
@(private, require_results)
socket_chain_error :: proc(failure: x509.Error) -> Error {
	alert: Alert_Description
	#partial switch failure {
	case .Signature_Invalid, .Unsupported_Algorithm, .Not_Yet_Valid, .Expired:
		alert = .Certificate_Expired
	case .Unknown_Authority:
		alert = .Unknown_Ca
	case .Unhandled_Critical_Extension, .Incompatible_Usage:
		alert = .Certificate_Unknown
	case:
		alert = .Bad_Certificate
	}
	return alert_to_error(.Fatal, alert)
}

// A failed recv. After the handshake upstream takes handshake records one
// at a time: a KeyUpdate has to be alone in its record and whole.
@(private, require_results)
socket_recv_error :: proc(conn: ^Conn, failure: IO_Error) -> Error {
	#partial switch failure.kind {
	case .Invalid_Post_Handshake:
		state := &conn.application
		if state.post_used >= 5 && state.post_expected == 5 && state.post_handshake[4] > 1 {
			return Protocol_Error.Illegal_Parameter
		}
		return Protocol_Error.Decode_Error
	case .Decryption_Failed:
		return socket_protection_error(failure.protection, .Decode_Error)
	}
	return socket_io_error(failure)
}

@(private, require_results)
socket_io_error :: proc(failure: IO_Error) -> Error {
	switch failure.kind {
	case .None:
		return nil
	case .EOF:
		return Protocol_Error.Close_Notify
	case .Closed:
		return io.Error.Closed
	case .Transport_Read_Failed, .Transport_Write_Failed, .Transport_Close_Failed, .Unexpected_EOF:
		return socket_transport_error(failure.transport)
	case .Peer_Alert:
		return socket_peer_alert_error(failure.alert_level, failure.alert_description)
	case .Decryption_Failed:
		return Protocol_Error.Bad_Record_Mac
	case .Invalid_Record:
		if failure.record == .Record_Oversized {
			return Protocol_Error.Record_Overflow
		}
		return Protocol_Error.Unexpected_Message
	case .Unexpected_Content_Type:
		return Protocol_Error.Unexpected_Message
	case .Interleaved_Record, .Record_Boundary_Violation, .Invalid_Post_Handshake, .Post_Handshake_Oversized:
		return Protocol_Error.Decode_Error
	case .No_Progress:
		return io.Error.No_Progress
	case .Handshake_Failed:
		return socket_handshake_error(failure.handshake)
	case .Invalid_State, .Encryption_Failed:
	}
	return Protocol_Error.Internal_Error
}
