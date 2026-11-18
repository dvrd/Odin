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

	// The engine's handshake allocations follow the caller's allocator.
	context.allocator = allocator

	names := make([]string, len(alpn_protocols), allocator) or_return
	defer delete(names, allocator)
	for protocol, i in alpn_protocols {
		names[i] = ALPN_STRINGS[protocol]
	}

	config := Config {
		server_name          = host_name,
		root_cas             = trust_roots,
		alpn_protocols       = names,
		offer                = .Upstream,
		unsafe_skip_verify   = unsafe_skip_verify,
		unsafe_secret_logger = unsafe_secret_logger,
		no_system_roots      = true,
	}
	if invalid := config_validate(config); invalid != .None {
		return socket_config_error(invalid)
	}

	conn := new(Conn, allocator) or_return
	conn.transport = {data = socket, read = socket_transport_read, write = socket_transport_write, close = socket_transport_close}
	conn.config = config
	conn.phase = .Handshake_Pending
	// A KeyUpdate request read by recv is left for the sender to answer.
	conn.defer_key_updates = true

	if failure := handshake(conn); failure.kind != .None {
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

	// Record by record, so that a KeyUpdate owed to the peer goes out in
	// the middle of a long send instead of after it.
	for n < len(buf) {
		socket_engine_owed_key_update(socket) or_return

		count := min(MAX_PLAINTEXT_SIZE, len(buf) - n)
		written, failure := application_write_records(state.conn, buf[n:][:count])
		n += written
		if failure.kind != .None {
			return n, socket_engine_failure(socket, failure)
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

	switch failure.kind {
	case .None:
		return received, nil
	case .EOF:
		// Not sticky: the socket can still send.
		return 0, Protocol_Error.Close_Notify
	case .Closed, .Invalid_State, .Handshake_Failed, .Transport_Read_Failed, .Transport_Write_Failed,
	     .Transport_Close_Failed, .Unexpected_EOF, .Invalid_Record, .Encryption_Failed, .Decryption_Failed,
	     .Unexpected_Content_Type, .Peer_Alert, .Interleaved_Record, .Record_Boundary_Violation,
	     .Invalid_Post_Handshake, .Post_Handshake_Oversized, .No_Progress:
	}
	return 0, socket_engine_failure(socket, failure)
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
		return socket_engine_failure(socket, failure)
	}
	return nil
}

// Records the engine's failure as the socket's error, unless close is what
// interrupted the call.
@(private, require_results)
socket_engine_failure :: proc(socket: ^Socket, failure: IO_Error) -> Error {
	if sync.atomic_load(&socket._state.closing) {
		return io.Error.Closed
	}
	return socket_set_error(socket, socket_io_error(failure))
}

// Sends close_notify, closes the TCP socket and frees the engine. A sender
// blocked in the TCP stack is waited for at most max_close_wait; after that
// the connection is shut down under it, which is what makes it return.
@(private)
socket_engine_close :: proc(socket: ^Socket, max_close_wait: time.Duration) {
	state := &socket._state

	sending := socket_lock_within(&state.tx_lock, max_close_wait)
	if sending && state.conn != nil {
		alert := [2]u8{u8(Alert_Level.Warning), u8(Alert_Description.Close_Notify)}
		application_record_write(state.conn, .Alert, alert[:])
	}

	sync.atomic_store(&state.closing, true)

	// Wakes a thread blocked in send or recv; the descriptor itself is
	// closed only once both directions have left the engine.
	net.shutdown(socket.fd, .Both)
	if !sending {
		sync.lock(&state.tx_lock)
	}
	sync.lock(&state.rx_lock)

	net.close(socket.fd)
	socket_engine_release(state.conn, state.allocator)
	state.conn = nil

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

// close owns the descriptor, as upstream's close does.
@(private)
socket_transport_close :: proc(data: rawptr) -> net.Connection_Error {
	return {}
}

// The engine's errors in upstream's Error. A TCP failure keeps its cause; a
// protocol failure becomes the alert upstream reports for it.

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

@(private, require_results)
socket_config_error :: proc(invalid: Client_Error) -> Error {
	#partial switch invalid {
	case .Missing_Server_Name, .Invalid_Server_Name:
		return General_Error.Invalid_SNI_Hostname
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
socket_handshake_error :: proc(failure: Handshake_Error) -> Error {
	switch failure.kind {
	case .None:
		return nil
	case .Client_Hello_Failed:
		return socket_client_hello_error(failure.client_hello)
	case .Server_Hello_Failed:
		return socket_server_hello_error(failure.server_hello)
	case .Key_Derivation_Failed:
		return Protocol_Error.Illegal_Parameter
	case .Server_Flight_Read_Failed:
		return socket_flight_read_error(failure.record)
	case .Unexpected_Handshake_Message:
		return Protocol_Error.Unexpected_Message
	case .Malformed_Message:
		return Protocol_Error.Decode_Error
	case .Unsupported_Extension, .Invalid_ALPN:
		return Protocol_Error.Illegal_Parameter
	case .Client_Authentication_Unsupported:
		return General_Error.Unsupported_Client_Certificate_Requested
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
	case .Invalid_State, .Server_Flight_Oversized, .Early_Data_Disabled:
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
		return General_Error.Invalid_SNI_Hostname
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
		return Protocol_Error.Decode_Error
	case .Peer_Alert:
		return socket_peer_alert_error(failure.alert_level, failure.alert_description)
	case .Invalid_Change_Cipher_Spec, .Too_Many_Change_Cipher_Specs, .Interleaved_Record, .Record_Boundary_Violation:
		return Protocol_Error.Unexpected_Message
	case .Message_Oversized:
		return Protocol_Error.Decode_Error
	case .Invalid_Server_Hello:
		return socket_server_hello_decode_error(failure.decode)
	case .Invalid_Key_Share:
		return Protocol_Error.Illegal_Parameter
	case .None, .Invalid_State:
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
socket_server_hello_decode_error :: proc(failure: Server_Hello_Error) -> Error {
	#partial switch failure {
	case .Truncated, .Length_Mismatch, .Extension_Length_Mismatch, .Invalid_Key_Share_Length:
		return Protocol_Error.Decode_Error
	case .Unexpected_Handshake_Type:
		return Protocol_Error.Unexpected_Message
	case .Invalid_Legacy_Version, .Unsupported_Version, .Missing_Supported_Versions:
		return Protocol_Error.Protocol_Version
	case .Unsupported_Extension:
		return Protocol_Error.Unsupported_Extension
	case .Missing_Key_Share, .Missing_Retry_Cookie:
		return Protocol_Error.Missing_Extension
	case .Repeated_Hello_Retry:
		return Protocol_Error.Unexpected_Message
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
		return Protocol_Error.Bad_Record_Mac
	case .Invalid_Header:
		if failure.record == .Record_Oversized {
			return Protocol_Error.Record_Overflow
		}
		return Protocol_Error.Decode_Error
	case .Unexpected_Content_Type, .Invalid_Change_Cipher_Spec, .Too_Many_Change_Cipher_Specs,
	     .Interleaved_Record, .Record_Boundary_Violation:
		return Protocol_Error.Unexpected_Message
	case .None, .Invalid_State, .Destination_Undersized:
	}
	return Protocol_Error.Internal_Error
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
	case .Empty_Certificate_List, .Invalid_Certificate_Context:
		return Protocol_Error.Illegal_Parameter
	case .Truncated, .Length_Mismatch, .Message_Oversized, .Too_Many_Certificates:
		return Protocol_Error.Decode_Error
	case .Unsupported_Certificate_Extension:
		return Protocol_Error.Unsupported_Extension
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
		return Protocol_Error.Decode_Error
	case .Unexpected_Content_Type, .Interleaved_Record, .Record_Boundary_Violation, .No_Progress:
		return Protocol_Error.Unexpected_Message
	case .Invalid_Post_Handshake, .Post_Handshake_Oversized:
		return Protocol_Error.Decode_Error
	case .Handshake_Failed:
		return socket_handshake_error(failure.handshake)
	case .Invalid_State, .Encryption_Failed:
	}
	return Protocol_Error.Internal_Error
}
