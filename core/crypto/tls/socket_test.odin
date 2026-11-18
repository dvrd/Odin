package tls

import "base:runtime"
import "core:crypto/x509"
import "core:io"
import "core:net"
import "core:os"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import credential_store "credentials/store"

// Upstream's Socket API against the server engine over loopback TCP. The
// server runs on its own thread: a blocking pump between the accepted socket
// and the test stream that the asynchronous server engine is driven through.

Socket_Test_Script :: enum {
	// Return every read until the client closes.
	Echo,
	// As Echo, after asking the client for new keys.
	Echo_After_Key_Update_Request,
	// close_notify right after the handshake.
	Close,
	// Read until the client closes; never write.
	Sink,
}

Socket_Test_Server :: struct {
	listener:     net.TCP_Socket,
	endpoint:     net.Endpoint,
	worker:       ^thread.Thread,
	script:       Socket_Test_Script,
	alpn:         []string,
	// Results, read after the join.
	established:  bool,
	server_name:  [64]u8,
	name_size:    int,
	suite:        Cipher_Suite,
	clean_close:  bool,
	key_updates:  int,
	echoed:       int,
}

Socket_Test_Peer :: struct {
	stream: TCP_Test_Stream,
	fd:     net.TCP_Socket,
	sent:   int,
	eof:    bool,
}

// Runs the server engine until an operation completes (calls > 0) or the
// client is gone, moving bytes between the socket and the test stream.
socket_test_pump :: proc(peer: ^Socket_Test_Peer, calls: ^int) {
	buffer: [16 * 1024]u8
	for {
		tcp_test_run(&peer.stream)

		for peer.sent < len(peer.stream.output) {
			n, err := net.send_tcp(peer.fd, peer.stream.output[peer.sent:])
			if err != nil {
				peer.eof = true
				break
			}
			peer.sent += n
		}

		if calls^ > 0 || peer.eof {
			return
		}

		n, err := net.recv_tcp(peer.fd, buffer[:])
		if err != nil || n == 0 {
			peer.eof = true
			peer.stream.read_error = {kind = .Peer_Closed}
		} else {
			append(&peer.stream.input, ..buffer[:n])
		}
		tcp_test_wake(&peer.stream)
		tcp_test_run(&peer.stream)
		if peer.eof {
			return
		}
	}
}

socket_test_serve :: proc(server: ^Socket_Test_Server) {
	fd, _, accept_error := net.accept_tcp(server.listener)
	if accept_error != nil {
		return
	}
	defer net.close(fd)

	store := matrix_server_store(nil, false)
	defer credential_store.destroy(&store)

	peer := new(Socket_Test_Peer)
	defer free(peer)
	defer tcp_test_destroy(&peer.stream)
	peer.fd = fd

	engine := new(Server_Async_Conn)
	defer free(engine)

	config := Server_Async_Config{store = store, credential_time = time.now()}
	config.handshake = SERVER_HANDSHAKE_DEFAULT_CONFIG
	config.handshake.offer = .Upstream
	config.parameters.alpn_protocols = server.alpn
	transport := net.Async_Connection{data = &peer.stream, submit = tcp_test_submit, cancel = tcp_test_cancel}
	executor := net.Async_Executor{data = &peer.stream, schedule = tcp_test_schedule}
	if server_async_server(engine, transport, executor, config, context.allocator) != .None {
		return
	}

	accepted: TCP_Test_Result
	accept := Server_Async_Handshake_Operation{callback = tcp_test_handshake, user_data = &accepted}
	server_async_handshake(engine, &accept)
	socket_test_pump(peer, &accepted.calls)

	if accepted.calls == 1 && accepted.error.kind == .None {
		state := server_async_connection_state(engine)
		server.established = true
		server.suite = state.cipher_suite
		server.name_size = copy(server.server_name[:], state.server_name)
		socket_test_script(server, engine, peer)
	}

	server.key_updates = server_async_stats(engine).received_key_updates
	server.clean_close = engine._peer_closed

	closed: TCP_Test_Result
	closing := tcp_test_op(&closed)
	net.async_close(server_async_connection(engine), &closing)
	peer.eof = false
	socket_test_pump(peer, &closed.calls)
}

socket_test_script :: proc(server: ^Socket_Test_Server, engine: ^Server_Async_Conn, peer: ^Socket_Test_Peer) {
	stream := server_async_connection(engine)
	if server.script == .Close {
		return
	}

	if server.script == .Echo_After_Key_Update_Request {
		server_async_key_update(engine, true)
	}

	storage := make([]u8, 16 * 1024)
	defer delete(storage)
	for {
		received: TCP_Test_Result
		reading := tcp_test_op(&received)
		if net.async_read(stream, &reading, storage).kind != .None {
			return
		}

		socket_test_pump(peer, &received.calls)
		if received.calls == 0 || received.error.kind != .None || received.count == 0 {
			return
		}

		if server.script == .Sink {
			continue
		}

		sent: TCP_Test_Result
		sending := tcp_test_op(&sent)
		if net.async_write(stream, &sending, storage[:received.count]).kind != .None {
			return
		}

		socket_test_pump(peer, &sent.calls)
		if sent.calls == 0 || sent.error.kind != .None {
			return
		}
		server.echoed += received.count
	}
}

socket_test_start :: proc(t: ^testing.T, server: ^Socket_Test_Server, script: Socket_Test_Script, alpn: []string = nil) -> bool {
	server.script = script
	server.alpn = alpn

	listener, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if !testing.expect(t, listen_error == nil) {
		return false
	}

	endpoint, endpoint_error := net.bound_endpoint(listener)
	testing.expect(t, endpoint_error == nil)
	server.listener = listener
	server.endpoint = endpoint
	// The server thread keeps to its own heap: the test's tracking allocator
	// belongs to the test thread.
	server.worker = thread.create_and_start_with_poly_data(server, socket_test_serve, runtime.default_context())
	return true
}

socket_test_join :: proc(server: ^Socket_Test_Server) {
	thread.join(server.worker)
	thread.destroy(server.worker)
	net.close(server.listener)
}

socket_test_dial :: proc(t: ^testing.T, server: ^Socket_Test_Server) -> net.TCP_Socket {
	fd, dial_error := net.dial_tcp_from_endpoint(server.endpoint)
	testing.expect(t, dial_error == nil)
	return fd
}

// Sends request and reads exactly as many bytes back.
socket_test_echo :: proc(t: ^testing.T, socket: ^Socket, request: string, loc := #caller_location) {
	sent, send_error := send(socket, transmute([]u8)request)
	testing.expect_value(t, send_error, nil, loc)
	testing.expect_value(t, sent, len(request), loc)

	answer: [256]u8
	used := 0
	for used < len(request) {
		n, recv_error := recv(socket, answer[used:len(request)])
		if !testing.expect_value(t, recv_error, nil, loc) {
			return
		}
		used += n
	}
	testing.expect_value(t, string(answer[:used]), request, loc)
}

@(test)
socket_handshake_transfers_and_closes :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	roots: Root_Pool
	matrix_roots(&roots, false)
	defer root_pool_destroy(&roots)

	server: Socket_Test_Server
	if !socket_test_start(t, &server, .Echo, {"http/1.1"}) {
		return
	}

	socket: Socket
	offered := [?]Alpn_Protocols{.Http_2, .Http_1_1}
	established := client_handshake(&socket, socket_test_dial(t, &server), "localhost", roots.roots[:roots.count], offered[:])
	testing.expect_value(t, established, nil)
	testing.expect_value(t, socket_error(&socket), nil)
	testing.expect_value(t, socket.alpn_protocol, Alpn_Protocols.Http_1_1)

	// Upstream's order: the server engine takes the client's first suite.
	expected := config_cipher_suites(&Config{offer = .Upstream})[0]
	testing.expect_value(t, socket.cipher_suite, expected)

	// An empty send is not a record.
	empty, empty_error := send(&socket, nil)
	testing.expect_value(t, empty, 0)
	testing.expect_value(t, empty_error, nil)

	socket_test_echo(t, &socket, "over the facade")

	// A short destination keeps the rest of the record for the next call.
	request := "partial reads"
	_, send_error := send(&socket, transmute([]u8)request)
	testing.expect_value(t, send_error, nil)
	head: [4]u8
	tail: [32]u8
	head_size, head_error := recv(&socket, head[:])
	tail_size, tail_error := recv(&socket, tail[:])
	testing.expect_value(t, head_error, nil)
	testing.expect_value(t, tail_error, nil)
	testing.expect_value(t, string(head[:head_size]), "part")
	testing.expect_value(t, string(tail[:tail_size]), "ial reads")

	close(&socket)
	testing.expect_value(t, socket_error(&socket), Error(io.Error.Closed))
	testing.expect_value(t, socket.fd, net.TCP_Socket{})
	testing.expect(t, socket._state.conn == nil)

	// Closed is terminal and idempotent.
	close(&socket)
	_, after_close := send(&socket, transmute([]u8)request)
	testing.expect_value(t, after_close, Error(io.Error.Closed))
	_, recv_after_close := recv(&socket, tail[:])
	testing.expect_value(t, recv_after_close, Error(io.Error.Closed))

	socket_test_join(&server)
	testing.expect(t, server.established)
	testing.expect_value(t, server.suite, expected)
	testing.expect_value(t, string(server.server_name[:server.name_size]), "localhost")
	// close sent close_notify before the TCP connection went away.
	testing.expect(t, server.clean_close)
	testing.expect_value(t, server.echoed, len("over the facade") + len(request))
}

@(test)
socket_recv_reports_the_peers_close_notify :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	roots: Root_Pool
	matrix_roots(&roots, false)
	defer root_pool_destroy(&roots)

	server: Socket_Test_Server
	if !socket_test_start(t, &server, .Close) {
		return
	}

	socket: Socket
	established := client_handshake(&socket, socket_test_dial(t, &server), "localhost", roots.roots[:roots.count])
	testing.expect_value(t, established, nil)
	testing.expect_value(t, socket.alpn_protocol, Alpn_Protocols.None)

	storage: [16]u8
	for _ in 0 ..< 2 {
		n, err := recv(&socket, storage[:])
		testing.expect_value(t, n, 0)
		testing.expect_value(t, err, Error(Protocol_Error.Close_Notify))
	}

	// The peer's close is not the socket's error, and a Stream reads it as EOF.
	testing.expect_value(t, socket_error(&socket), nil)
	_, stream_error := io.read(to_stream(&socket), storage[:])
	testing.expect_value(t, stream_error, io.Error.EOF)

	close(&socket)
	socket_test_join(&server)
}

@(test)
socket_verifies_the_chain_against_the_trust_roots :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	roots: Root_Pool
	matrix_roots(&roots, false)
	defer root_pool_destroy(&roots)

	// The ECDSA fixture is a self-signed leaf: an authority the server's
	// chain does not lead to.
	strangers: Root_Pool
	matrix_roots(&strangers, true)
	defer root_pool_destroy(&strangers)

	Case :: struct {
		host:     string,
		roots:    []^x509.Certificate,
		expected: Error,
	}
	cases := [?]Case {
		{"localhost", strangers.roots[:strangers.count], Protocol_Error.Unknown_Ca},
		{"localhost", nil, Protocol_Error.Unknown_Ca},
		{"other.example", roots.roots[:roots.count], Protocol_Error.Bad_Certificate},
		{"not a host name", roots.roots[:roots.count], General_Error.Invalid_SNI_Hostname},
		{strings.repeat("a", SNI_MAX_HOSTNAME_SIZE + 1, context.temp_allocator), roots.roots[:roots.count], General_Error.Invalid_SNI_Hostname},
	}

	for entry in cases {
		server: Socket_Test_Server
		if !socket_test_start(t, &server, .Close) {
			return
		}

		socket: Socket
		fd := socket_test_dial(t, &server)
		failure := client_handshake(&socket, fd, entry.host, entry.roots)
		testing.expectf(t, failure == entry.expected, "%q: %v", entry.host, failure)
		testing.expect_value(t, socket_error(&socket), entry.expected)
		testing.expect(t, socket._state.conn == nil)

		// A failed handshake leaves no connection to use.
		storage: [8]u8
		_, send_error := send(&socket, storage[:])
		_, recv_error := recv(&socket, storage[:])
		testing.expect_value(t, send_error, Error(io.Error.Closed))
		testing.expect_value(t, recv_error, Error(io.Error.Closed))

		// The caller's socket is closed by close alone; the error stays.
		if socket.fd == {} {
			net.close(fd)
		}
		close(&socket)
		testing.expect_value(t, socket.fd, net.TCP_Socket{})
		testing.expect_value(t, socket_error(&socket), entry.expected)

		socket_test_join(&server)
		testing.expect(t, !server.established)
	}
}

@(test)
socket_skips_verification_and_omits_sni_for_an_address :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	Case :: struct {
		host, sni: string,
	}
	for entry in ([?]Case{{"127.0.0.1", ""}, {"::1", ""}, {"unknown.example", "unknown.example"}}) {
		server: Socket_Test_Server
		if !socket_test_start(t, &server, .Echo) {
			return
		}

		socket: Socket
		established := client_handshake(&socket, socket_test_dial(t, &server), entry.host, nil, unsafe_skip_verify = true)
		testing.expectf(t, established == nil, "%q: %v", entry.host, established)
		if established == nil {
			socket_test_echo(t, &socket, "unverified")
		}

		close(&socket)
		socket_test_join(&server)
		testing.expect(t, server.established)
		testing.expect_value(t, string(server.server_name[:server.name_size]), entry.sni)
	}
}

@(test)
socket_stream_reads_writes_and_closes :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	roots: Root_Pool
	matrix_roots(&roots, false)
	defer root_pool_destroy(&roots)

	server: Socket_Test_Server
	if !socket_test_start(t, &server, .Echo) {
		return
	}

	socket: Socket
	established := client_handshake(&socket, socket_test_dial(t, &server), "localhost", roots.roots[:roots.count])
	testing.expect_value(t, established, nil)

	stream := to_stream(&socket)
	request := "through io.Stream"
	written, write_error := io.write_string(stream, request)
	testing.expect_value(t, write_error, nil)
	testing.expect_value(t, written, len(request))

	answer: [32]u8
	received, read_error := io.read_full(stream, answer[:len(request)])
	testing.expect_value(t, read_error, nil)
	testing.expect_value(t, string(answer[:received]), request)
	testing.expect_value(t, io.flush(stream), nil)

	testing.expect_value(t, io.close(stream), nil)
	testing.expect_value(t, socket_error(&socket), Error(io.Error.Closed))
	_, closed_error := io.write_string(stream, request)
	testing.expect_value(t, closed_error, io.Error.Closed)

	socket_test_join(&server)
	testing.expect(t, server.clean_close)
}

Socket_Test_Sender :: struct {
	socket:  ^Socket,
	payload: []u8,
	sent:    int,
	error:   Error,
}

socket_test_send_all :: proc(sender: ^Socket_Test_Sender) {
	sender.sent, sender.error = send(sender.socket, sender.payload)
}

@(test)
socket_sends_and_receives_on_two_threads :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)

	roots: Root_Pool
	matrix_roots(&roots, false)
	defer root_pool_destroy(&roots)

	server: Socket_Test_Server
	if !socket_test_start(t, &server, .Echo_After_Key_Update_Request) {
		return
	}

	socket: Socket
	established := client_handshake(&socket, socket_test_dial(t, &server), "localhost", roots.roots[:roots.count])
	testing.expect_value(t, established, nil)

	// More than the loopback buffers hold: the send only finishes because
	// this thread is receiving the echo meanwhile. The first record read is
	// the server's KeyUpdate request, answered under the sender's lock.
	payload := make([]u8, 4 * 1024 * 1024)
	defer delete(payload)
	for &b, i in payload {
		b = u8(i * 31 >> 3)
	}

	sender := Socket_Test_Sender{socket = &socket, payload = payload}
	worker := thread.create_and_start_with_poly_data(&sender, socket_test_send_all, runtime.default_context())

	echoed := make([]u8, len(payload))
	defer delete(echoed)
	used := 0
	for used < len(echoed) {
		n, err := recv(&socket, echoed[used:])
		if !testing.expect_value(t, err, nil) {
			break
		}
		used += n
	}

	thread.join(worker)
	thread.destroy(worker)
	testing.expect_value(t, sender.error, nil)
	testing.expect_value(t, sender.sent, len(payload))
	testing.expect_value(t, used, len(payload))
	testing.expect(t, string(echoed) == string(payload))

	close(&socket)
	socket_test_join(&server)
	// The request was answered among the sender's records.
	testing.expect_value(t, server.key_updates, 1)
	testing.expect(t, server.clean_close)
}

Socket_Test_Receiver :: struct {
	socket: ^Socket,
	error:  Error,
	done:   bool,
}

socket_test_recv_blocked :: proc(receiver: ^Socket_Test_Receiver) {
	storage: [8]u8
	_, receiver.error = recv(receiver.socket, storage[:])
	receiver.done = true
}

@(test)
socket_close_wakes_a_blocked_recv :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	roots: Root_Pool
	matrix_roots(&roots, false)
	defer root_pool_destroy(&roots)

	server: Socket_Test_Server
	if !socket_test_start(t, &server, .Sink) {
		return
	}

	socket: Socket
	established := client_handshake(&socket, socket_test_dial(t, &server), "localhost", roots.roots[:roots.count])
	testing.expect_value(t, established, nil)

	receiver := Socket_Test_Receiver{socket = &socket}
	worker := thread.create_and_start_with_poly_data(&receiver, socket_test_recv_blocked, runtime.default_context())

	// The server never writes: the receiver is inside the TCP stack by now.
	time.sleep(50 * time.Millisecond)
	testing.expect(t, !receiver.done)
	close(&socket)

	thread.join(worker)
	thread.destroy(worker)
	testing.expect(t, receiver.done)
	testing.expect_value(t, receiver.error, Error(io.Error.Closed))
	testing.expect_value(t, socket_error(&socket), Error(io.Error.Closed))

	socket_test_join(&server)
	testing.expect(t, server.clean_close)
}

@(test)
socket_logs_secrets_to_the_callers_file :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	server: Socket_Test_Server
	if !socket_test_start(t, &server, .Echo) {
		return
	}

	logger, create_error := os.create_temp_file("", "odin-tls-keylog-*.txt")
	if !testing.expect(t, create_error == nil) {
		socket_test_join(&server)
		return
	}
	path := strings.clone(os.name(logger))
	defer delete(path)
	defer os.remove(path)

	socket: Socket
	established := client_handshake(&socket, socket_test_dial(t, &server), "localhost", nil, unsafe_skip_verify = true, unsafe_secret_logger = logger)
	testing.expect_value(t, established, nil)
	if established == nil {
		socket_test_echo(t, &socket, "logged")
	}
	close(&socket)
	socket_test_join(&server)

	// The connection closed the file; all four secrets of the handshake are in it.
	log, read_error := os.read_entire_file(path, context.allocator)
	defer delete(log)
	testing.expect(t, read_error == nil)
	for label in ([?]string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET ", "SERVER_HANDSHAKE_TRAFFIC_SECRET ", "CLIENT_TRAFFIC_SECRET_0 ", "SERVER_TRAFFIC_SECRET_0 "}) {
		testing.expectf(t, strings.contains(string(log), label), "missing %s", label)
	}
}

@(test)
socket_errors_map_to_upstreams :: proc(t: ^testing.T) {
	refused := net.Connection_Error{kind = .Write_Failed, write_cause = net.TCP_Send_Error.Connection_Closed}
	reset := net.Connection_Error{kind = .Read_Failed, read_cause = net.TCP_Recv_Error.Connection_Closed}

	Handshake_Case :: struct {
		failure:  Handshake_Error,
		expected: Error,
	}
	handshakes := [?]Handshake_Case {
		{{kind = .Client_Hello_Failed, client_hello = {kind = .Entropy_Unavailable}}, General_Error.Failed_Key_Share_Generation},
		{{kind = .Client_Hello_Failed, client_hello = {kind = .Write_Failed, transport = refused}}, net.TCP_Send_Error.Connection_Closed},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Peer_Alert, alert_level = 2, alert_description = 40}}, Protocol_Error.Handshake_Failure},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Peer_Alert, alert_level = 2, alert_description = 70}}, Protocol_Error.Protocol_Version},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Record_Read_Failed, record = {transport = reset}}}, net.TCP_Recv_Error.Connection_Closed},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Record_Read_Failed, record = {transport = {kind = .Peer_Closed}}}}, net.TCP_Recv_Error.Connection_Closed},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Unsupported_Version}}, Protocol_Error.Protocol_Version},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Unoffered_Cipher}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Truncated}}, Protocol_Error.Decode_Error},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Missing_Key_Share}}, Protocol_Error.Missing_Extension},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Key_Share}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Key_Derivation_Failed}, Protocol_Error.Illegal_Parameter},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Decryption_Failed}}, Protocol_Error.Bad_Record_Mac},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Peer_Alert, alert_level = 2, alert_description = 80}}, Protocol_Error.Internal_Error},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Body_Read_Failed, transport = reset}}, net.TCP_Recv_Error.Connection_Closed},
		{{kind = .Unexpected_Handshake_Message}, Protocol_Error.Unexpected_Message},
		{{kind = .Malformed_Message}, Protocol_Error.Decode_Error},
		{{kind = .Unsupported_Extension}, Protocol_Error.Illegal_Parameter},
		{{kind = .Invalid_ALPN}, Protocol_Error.Illegal_Parameter},
		{{kind = .Client_Authentication_Unsupported}, General_Error.Unsupported_Client_Certificate_Requested},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Expired}}, Protocol_Error.Certificate_Expired},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Signature_Invalid}}, Protocol_Error.Certificate_Expired},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Unknown_Authority}}, Protocol_Error.Unknown_Ca},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Incompatible_Usage}}, Protocol_Error.Certificate_Unknown},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Hostname_Mismatch}}, Protocol_Error.Bad_Certificate},
		{{kind = .Authentication_Failed, authentication = {kind = .Invalid_Certificate}}, Protocol_Error.Bad_Certificate},
		{{kind = .Authentication_Failed, authentication = {kind = .Empty_Certificate_List}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Authentication_Failed, authentication = {kind = .Invalid_Signature}}, Protocol_Error.Decrypt_Error},
		{{kind = .Authentication_Failed, authentication = {kind = .Unsupported_Signature_Scheme}}, Protocol_Error.Decrypt_Error},
		{{kind = .Finished_Failed, finished = .Verification_Failed}, Protocol_Error.Decrypt_Error},
		{{kind = .Finished_Write_Failed, transport = refused}, net.TCP_Send_Error.Connection_Closed},
		{{kind = .Allocation_Failed, allocation = .Out_Of_Memory}, runtime.Allocator_Error.Out_Of_Memory},
	}
	for entry in handshakes {
		testing.expectf(t, socket_handshake_error(entry.failure) == entry.expected, "%v/%v: %v", entry.failure.kind, entry.expected, socket_handshake_error(entry.failure))
	}

	IO_Case :: struct {
		failure:  IO_Error,
		expected: Error,
	}
	transfers := [?]IO_Case {
		{{kind = .EOF}, Protocol_Error.Close_Notify},
		{{kind = .Closed}, io.Error.Closed},
		{{kind = .Unexpected_EOF, transport = {kind = .Peer_Closed}}, net.TCP_Recv_Error.Connection_Closed},
		{{kind = .Transport_Read_Failed, transport = reset}, net.TCP_Recv_Error.Connection_Closed},
		{{kind = .Transport_Write_Failed, transport = refused}, net.TCP_Send_Error.Connection_Closed},
		{{kind = .Peer_Alert, alert_level = 2, alert_description = 20}, Protocol_Error.Bad_Record_Mac},
		{{kind = .Peer_Alert, alert_level = 2, alert_description = 80}, Protocol_Error.Internal_Error},
		{{kind = .Peer_Alert, alert_level = 9, alert_description = 80}, Protocol_Error.Decode_Error},
		{{kind = .Decryption_Failed}, Protocol_Error.Bad_Record_Mac},
		{{kind = .Invalid_Record, record = .Record_Oversized}, Protocol_Error.Record_Overflow},
		{{kind = .Invalid_Record, record = .Unknown_Content_Type}, Protocol_Error.Decode_Error},
		{{kind = .Unexpected_Content_Type}, Protocol_Error.Unexpected_Message},
		{{kind = .Invalid_Post_Handshake}, Protocol_Error.Decode_Error},
	}
	for entry in transfers {
		testing.expectf(t, socket_io_error(entry.failure) == entry.expected, "%v/%v: %v", entry.failure.kind, entry.expected, socket_io_error(entry.failure))
	}

	testing.expect_value(t, socket_config_error(.Invalid_Server_Name), Error(General_Error.Invalid_SNI_Hostname))
	testing.expect_value(t, socket_config_error(.Invalid_ALPN), Error(Protocol_Error.Internal_Error))
}

// close is one name for both connection types.
@(test)
close_resolves_for_socket_and_conn :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	roots: Root_Pool
	matrix_roots(&roots, false)
	defer root_pool_destroy(&roots)

	// ^Socket, with and without upstream's max_close_wait.
	for wait in ([?]time.Duration{0, 10 * time.Millisecond}) {
		server: Socket_Test_Server
		if !socket_test_start(t, &server, .Sink) {
			return
		}

		socket: Socket
		established := client_handshake(&socket, socket_test_dial(t, &server), "localhost", roots.roots[:roots.count])
		testing.expect_value(t, established, nil)
		if wait == 0 {
			close(&socket)
		} else {
			close(&socket, wait)
		}
		testing.expect_value(t, socket_error(&socket), Error(io.Error.Closed))

		socket_test_join(&server)
		testing.expect(t, server.clean_close)
	}

	// ^Conn: conn_close under the shared name, result included.
	server: Socket_Test_Server
	if !socket_test_start(t, &server, .Sink) {
		return
	}

	conn := new(Conn)
	defer free(conn)
	config := Config{root_cas = roots.roots[:roots.count], offer = .Upstream}
	dialed := dial(conn, "localhost", server.endpoint.port, config)
	testing.expect_value(t, dialed.kind, Dial_Error_Kind.None)
	testing.expect_value(t, close(conn).kind, IO_Error_Kind.None)
	testing.expect_value(t, conn.phase, Conn_Phase.Closed)
	testing.expect_value(t, close(conn), conn_close(conn))

	socket_test_join(&server)
	testing.expect(t, server.clean_close)
}
