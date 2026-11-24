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
	// The alert the client ended the connection with, if any.
	peer_alert:   u8,
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
	if engine_server_async_server(engine, transport, executor, config, context.allocator) != .None {
		return
	}

	accepted: TCP_Test_Result
	accept := Server_Async_Handshake_Operation{callback = tcp_test_handshake, user_data = &accepted}
	engine_server_async_handshake(engine, &accept)
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
	if detail := engine_server_async_failure(engine); detail.kind == .Peer_Alert {
		server.peer_alert = detail.alert_description
	}

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
		engine_server_async_key_update(engine, true)
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

	// alert is what the server is told: upstream names its error to the peer.
	Case :: struct {
		host:     string,
		roots:    []^x509.Certificate,
		expected: Error,
		alert:    Alert_Description,
	}
	cases := [?]Case {
		{"localhost", strangers.roots[:strangers.count], Protocol_Error.Unknown_Ca, .Unknown_Ca},
		{"localhost", nil, Protocol_Error.Unknown_Ca, .Unknown_Ca},
		{"other.example", roots.roots[:roots.count], Protocol_Error.Bad_Certificate, .Bad_Certificate},
		// Refused before any I/O.
		{strings.repeat("a", SNI_MAX_HOSTNAME_SIZE + 1, context.temp_allocator), roots.roots[:roots.count], General_Error.Invalid_SNI_Hostname, .Close_Notify},
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
		testing.expectf(t, server.peer_alert == u8(entry.alert), "%q: alert %v", entry.host, server.peer_alert)
	}
}

@(test)
socket_skips_verification_and_omits_sni_for_an_address :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)

	Case :: struct {
		host, sni: string,
	}
	// The name is upstream's to send as given: none for an address or an
	// empty name, anything else verbatim.
	for entry in ([?]Case{{"127.0.0.1", ""}, {"::1", ""}, {"", ""}, {"unknown.example", "unknown.example"}}) {
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
	if !socket_test_start(t, &server, .Echo_After_Key_Update_Request) {
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

	// close closed the file. All four secrets of the handshake are in it,
	// and as upstream logs them, those of the key updates that followed.
	log, read_error := os.read_entire_file(path, context.allocator)
	defer delete(log)
	testing.expect(t, read_error == nil)
	labels := [?]string {
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
		"SERVER_HANDSHAKE_TRAFFIC_SECRET ",
		"CLIENT_TRAFFIC_SECRET_0 ",
		"SERVER_TRAFFIC_SECRET_0 ",
		"CLIENT_TRAFFIC_SECRET_1 ",
		"SERVER_TRAFFIC_SECRET_1 ",
	}
	for label in labels {
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
		// Upstream expects a handshake record: the peer's alert is not one.
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Peer_Alert, alert_level = 2, alert_description = 40}}, Protocol_Error.Unexpected_Message},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Too_Many_Change_Cipher_Specs}}, Protocol_Error.Unexpected_Message},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Record_Read_Failed, record = {kind = .Invalid_Header, record = .Record_Oversized}}}, Protocol_Error.Record_Overflow},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Record_Read_Failed, record = {kind = .Invalid_Header, record = .Unknown_Content_Type}}}, Protocol_Error.Unexpected_Message},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Record_Read_Failed, record = {transport = reset}}}, net.TCP_Recv_Error.Connection_Closed},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Record_Read_Failed, record = {transport = {kind = .Peer_Closed}}}}, net.TCP_Recv_Error.Connection_Closed},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Invalid_Legacy_Version}}, Protocol_Error.Protocol_Version},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Unsupported_Version}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Missing_Supported_Versions}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Session_ID_Mismatch}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Hello_Retry_Unsupported}}, Protocol_Error.Unexpected_Message},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Unsupported_Extension}}, Protocol_Error.Unsupported_Extension},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Unoffered_Group}}, Protocol_Error.General_Error},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Key_Share_Size_Mismatch}}, Protocol_Error.General_Error},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Invalid_Key_Share_Length}}, Protocol_Error.Decode_Error},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Unoffered_Cipher}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Truncated}}, Protocol_Error.Decode_Error},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Missing_Key_Share}}, Protocol_Error.Missing_Extension},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Key_Share}}, Protocol_Error.General_Error},
		{{kind = .Key_Derivation_Failed}, Protocol_Error.Illegal_Parameter},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Decryption_Failed}}, Protocol_Error.Bad_Record_Mac},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Decryption_Failed, protection = .Ciphertext_Too_Short}}, Protocol_Error.Decode_Error},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Decryption_Failed, protection = .Empty_Handshake}}, Protocol_Error.Unexpected_Message},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Invalid_Header, record = .Record_Oversized}}, Protocol_Error.Record_Overflow},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Too_Many_Change_Cipher_Specs}}, Protocol_Error.Unexpected_Message},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Invalid_Change_Cipher_Spec}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Invalid_Change_Cipher_Spec, record = .Invalid_Change_Cipher_Spec_Length}}, Protocol_Error.Decode_Error},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Peer_Alert, alert_level = 2, alert_description = 80}}, Protocol_Error.Internal_Error},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Body_Read_Failed, transport = reset}}, net.TCP_Recv_Error.Connection_Closed},
		{{kind = .Unexpected_Handshake_Message}, Protocol_Error.Unexpected_Message},
		{{kind = .Malformed_Message}, Protocol_Error.Decode_Error},
		{{kind = .Unsupported_Extension}, Protocol_Error.Illegal_Parameter},
		{{kind = .Invalid_ALPN}, Protocol_Error.Illegal_Parameter},
		{{kind = .Client_Authentication_Unsupported}, Protocol_Error.Unexpected_Message},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Expired}}, Protocol_Error.Certificate_Expired},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Signature_Invalid}}, Protocol_Error.Certificate_Expired},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Unknown_Authority}}, Protocol_Error.Unknown_Ca},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Incompatible_Usage}}, Protocol_Error.Certificate_Unknown},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Hostname_Mismatch}}, Protocol_Error.Bad_Certificate},
		{{kind = .Authentication_Failed, authentication = {kind = .Invalid_Certificate}}, Protocol_Error.Bad_Certificate},
		{{kind = .Authentication_Failed, authentication = {kind = .Empty_Certificate_List}}, Protocol_Error.Illegal_Parameter},
		{{kind = .Authentication_Failed, authentication = {kind = .Unsupported_Certificate_Extension}}, Protocol_Error.Illegal_Parameter},
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
		{{kind = .Invalid_Record, record = .Unknown_Content_Type}, Protocol_Error.Unexpected_Message},
		{{kind = .Record_Boundary_Violation}, Protocol_Error.Decode_Error},
		{{kind = .No_Progress}, io.Error.No_Progress},
		{{kind = .Unexpected_Content_Type}, Protocol_Error.Unexpected_Message},
		{{kind = .Invalid_Post_Handshake}, Protocol_Error.Decode_Error},
	}
	for entry in transfers {
		testing.expectf(t, socket_io_error(entry.failure) == entry.expected, "%v/%v: %v", entry.failure.kind, entry.expected, socket_io_error(entry.failure))
	}


	// The alert that goes with each failure: the error's own, except where
	// upstream sends none or another.
	Alert_Case :: struct {
		failure:   Handshake_Error,
		alert:     Alert_Description,
		plaintext: bool,
		send:      bool,
	}
	alerts := [?]Alert_Case {
		{{kind = .Client_Hello_Failed, client_hello = {kind = .Write_Failed, transport = refused}}, {}, false, false},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Record_Read_Failed, record = {transport = reset}}}, {}, false, false},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Peer_Alert, alert_level = 2, alert_description = 40}}, .Unexpected_Message, false, true},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Server_Hello, decode = .Hello_Retry_Unsupported}}, .Unexpected_Message, false, true},
		{{kind = .Server_Hello_Failed, server_hello = {kind = .Invalid_Key_Share}}, .General_Error, false, true},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Body_Read_Failed, transport = reset}}, {}, false, false},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Peer_Alert, alert_level = 2, alert_description = 80}}, {}, false, false},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Unexpected_Content_Type, content_type = .Alert}}, {}, false, false},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Unexpected_Content_Type, content_type = .Handshake}}, .Unexpected_Message, false, true},
		{{kind = .Server_Flight_Read_Failed, record = {kind = .Decryption_Failed}}, .Bad_Record_Mac, false, true},
		{{kind = .Malformed_Message}, .Decode_Error, false, true},
		{{kind = .Malformed_Message, plaintext_alert = true}, .Decode_Error, true, true},
		{{kind = .Unsupported_Extension}, .Illegal_Parameter, false, true},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Unknown_Authority}}, .Unknown_Ca, false, true},
		{{kind = .Authentication_Failed, authentication = {kind = .Certificate_Chain_Invalid, x509 = .Expired}}, .Certificate_Expired, false, true},
		{{kind = .Authentication_Failed, authentication = {kind = .Length_Mismatch}}, .Decode_Error, false, true},
		{{kind = .Authentication_Failed, authentication = {kind = .Length_Mismatch}, message_type = u8(Handshake_Type.Certificate_Verify)}, .Decrypt_Error, false, true},
		{{kind = .Finished_Failed, finished = .Verification_Failed}, .Decrypt_Error, false, true},
		{{kind = .Finished_Write_Failed, transport = refused}, {}, false, false},
		{{kind = .Allocation_Failed, allocation = .Out_Of_Memory}, .Internal_Error, false, true},
	}
	for entry in alerts {
		alert, plaintext, send := socket_handshake_alert(entry.failure)
		testing.expectf(t, send == entry.send && plaintext == entry.plaintext && (!send || alert == entry.alert), "%v: %v %v %v", entry.failure, alert, plaintext, send)
	}
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
	dialed := engine_dial(conn, "localhost", server.endpoint.port, config)
	testing.expect_value(t, dialed.kind, Dial_Error_Kind.None)
	testing.expect_value(t, close(conn), nil)
	testing.expect_value(t, conn.phase, Conn_Phase.Closed)
	testing.expect_value(t, close(conn), conn_close(conn))

	socket_test_join(&server)
	testing.expect(t, server.clean_close)
}

// The extension types of a ClientHello message, in order, and the size of
// its legacy session id.
socket_test_hello_shape :: proc(hello: []u8, types: ^[dynamic]u16) -> (session_size: int) {
	at := 4 + 2 + 32
	session_size = int(hello[at])
	at += 1 + session_size
	at += 2 + int(hello_u16(hello, at))
	at += 1 + int(hello[at])
	at += 2
	for at < len(hello) {
		append(types, hello_u16(hello, at))
		at += 4 + int(hello_u16(hello, at + 2))
	}
	return
}

@(test)
socket_offers_upstreams_client_hello :: proc(t: ^testing.T) {
	// More protocols than the engine's own limit, and a name it would refuse.
	protocols: [20]string
	for &protocol in protocols {
		protocol = "h2"
	}

	conn := new(Conn)
	defer free(conn)
	defer handshake_keys_clear(conn)
	conn.phase = .Handshake_Pending
	conn.upstream_client = true
	conn.config = {server_name = "under_score.example", offer = .Upstream, alpn_protocols = protocols[:]}
	testing.expect_value(t, engine_client_hello_prepare(conn).kind, Client_Hello_Send_Error_Kind.None)

	types: [dynamic]u16
	defer delete(types)
	hello := conn.client_hello[:conn.client_hello_size]
	testing.expect_value(t, socket_test_hello_shape(hello, &types), LEGACY_SESSION_ID_SIZE)
	testing.expect_value(t, len(handshake_session_id(conn)), LEGACY_SESSION_ID_SIZE)

	// supported_versions, server_name, signature_algorithms, supported_groups,
	// key_share, ALPN, renegotiation_info, ec_point_formats.
	expected := [?]u16{43, 0, 13, 10, 51, 16, 65281, 11}
	testing.expect_value(t, len(types), len(expected))
	for type, i in expected {
		if i < len(types) {
			testing.expect_value(t, types[i], type)
		}
	}
	testing.expect(t, strings.contains(string(hello), "under_score.example"))

	// The engine's own offer keeps an empty session id and sends no
	// compatibility ChangeCipherSpec.
	compatible := new(Conn)
	defer free(compatible)
	defer handshake_keys_clear(compatible)
	compatible.phase = .Handshake_Pending
	compatible.config = {server_name = "example.com"}
	testing.expect_value(t, engine_client_hello_prepare(compatible).kind, Client_Hello_Send_Error_Kind.None)
	clear(&types)
	testing.expect_value(t, socket_test_hello_shape(compatible.client_hello[:compatible.client_hello_size], &types), 0)
	storage: [8]u8
	testing.expect_value(t, handshake_ccs_encode(compatible, storage[:]), 0)
	testing.expect_value(t, handshake_ccs_encode(conn, storage[:]), len(CHANGE_CIPHER_SPEC_RECORD))
}

@(test)
socket_refuses_what_upstream_refuses :: proc(t: ^testing.T) {
	// A protocol without a name cannot be encoded; nothing is sent.
	socket: Socket
	unnamed := [?]Alpn_Protocols{.Http_2, .None}
	failure := client_handshake(&socket, net.TCP_Socket{}, "localhost", nil, unnamed[:])
	testing.expect_value(t, failure, Error(io.Error.Short_Buffer))

	Case :: struct {
		extensions: []u8,
		kind:       Handshake_Error_Kind,
		expected:   Error,
		plaintext:  bool,
	}

	// EncryptedExtensions, for the name "localhost" and an offer of h2.
	offers := [?]string{"h2"}
	encrypted := [?]Case {
		{{}, .None, nil, false},
		{{0, 0, 0, 0}, .None, nil, false},
		{{0, 16, 0, 5, 0, 3, 2, 'h', '2'}, .None, nil, false},
		{{0, 0, 0, 0, 0, 0, 0, 0}, .Unsupported_Extension, Protocol_Error.Illegal_Parameter, false},
		{{0, 0, 0, 1, 0}, .Unsupported_Extension, Protocol_Error.Illegal_Parameter, false},
		// supported_groups is legal there, and upstream refuses it.
		{{0, 10, 0, 4, 0, 2, 0, 29}, .Unsupported_Extension, Protocol_Error.Illegal_Parameter, false},
		{{0, 16, 0, 5, 0, 3, 2, 'h', '3'}, .Invalid_ALPN, Protocol_Error.Illegal_Parameter, false},
		{{0, 16, 0, 2, 0, 0}, .Malformed_Message, Protocol_Error.Decode_Error, false},
		{{0, 16, 0, 9, 0, 3, 2, 'h', '2'}, .Malformed_Message, Protocol_Error.Decode_Error, true},
		{{0, 0, 0}, .Malformed_Message, Protocol_Error.Decode_Error, false},
	}
	message: [64]u8
	for entry in encrypted {
		size := socket_test_message(message[:], .Encrypted_Extensions, nil, entry.extensions)
		got := socket_encrypted_extensions_check(message[:size], "localhost", offers[:])
		testing.expectf(t, got.kind == entry.kind && got.plaintext_alert == entry.plaintext, "%v: %v", entry.extensions, got)
		testing.expectf(t, socket_handshake_error(got) == entry.expected, "%v: %v", entry.extensions, socket_handshake_error(got))
	}

	// CertificateRequest.
	requests := [?]Case {
		{{0, 13, 0, 4, 0, 2, 8, 7}, .None, nil, false},
		{{0, 13, 0, 4, 0, 2, 8, 7, 0, 47, 0, 0, 119, 119, 0, 0, 119, 119, 0, 0}, .None, nil, false},
		{{}, .Malformed_Message, Protocol_Error.Missing_Extension, false},
		{{0, 13, 0, 4, 0, 2, 8, 7, 0, 13, 0, 4, 0, 2, 8, 7}, .Malformed_Message, Protocol_Error.Missing_Extension, false},
		{{0, 13, 0, 4, 0, 2, 8, 7, 0, 5, 0, 0, 0, 5, 0, 0}, .Malformed_Message, Protocol_Error.Illegal_Parameter, false},
		{{0, 13, 0, 4, 0, 2, 8, 7, 0, 10, 0, 0}, .Unsupported_Extension, Protocol_Error.Unsupported_Extension, false},
		{{0, 13, 0, 3, 0, 1, 8}, .Malformed_Message, Protocol_Error.Decode_Error, false},
		{{0, 13, 0, 4, 0, 2, 8, 7, 0}, .Malformed_Message, Protocol_Error.Decode_Error, false},
	}
	for entry in requests {
		size := socket_test_message(message[:], .Certificate_Request, {0}, entry.extensions)
		got := socket_certificate_request_check(message[:size])
		testing.expectf(t, got.kind == entry.kind, "%v: %v", entry.extensions, got)
		testing.expectf(t, socket_handshake_error(got) == entry.expected, "%v: %v", entry.extensions, socket_handshake_error(got))
	}

	// A request context is accepted and comes back in the client's Certificate,
	// as upstream's client sends it.
	size := socket_test_message(message[:], .Certificate_Request, {3, 7, 8, 9}, {0, 13, 0, 4, 0, 2, 8, 7})
	testing.expect_value(t, socket_certificate_request_check(message[:size]).kind, Handshake_Error_Kind.None)
	transcript: Handshake_Transcript
	transcript_init(&transcript)
	flight, flight_error := client_authentication_flight(nil, nil, &transcript, context.allocator, nil, {7, 8, 9})
	defer delete(flight)
	testing.expect_value(t, flight_error.kind, Handshake_Error_Kind.None)
	expected := [?]u8{11, 0, 0, 7, 3, 7, 8, 9, 0, 0, 0}
	testing.expectf(t, len(flight) == len(expected) && flight[4] == 3 && flight[7] == 9 && flight[3] == 7, "%v", flight)
	for b, i in expected {
		if i < len(flight) {
			testing.expect_value(t, flight[i], b)
		}
	}
}

// A handshake message of prefix and a vector of extensions.
socket_test_message :: proc(dst: []u8, type: Handshake_Type, prefix: []u8, extensions: []u8) -> int {
	at := 4
	at += copy(dst[at:], prefix)
	hello_put_u16(dst, &at, u16(len(extensions)))
	at += copy(dst[at:], extensions)
	dst[0] = u8(type)
	server_flight_put24(dst[1:4], at - 4)
	return at
}

// Upstream's receiver prods a peer that has not replaced its key in good time,
// once for each key, and never past the last key the suite allows.
@(test)
socket_asks_a_slow_peer_to_rekey_once_for_each_key :: proc(t: ^testing.T) {
	state: Socket_State
	receive: Record_Protection
	key: [16]u8
	iv: [12]u8
	record_protection_init(&receive, key, iv)
	defer record_protection_clear(&receive)

	limit := record_protection_limit(&receive)
	testing.expect_value(t, limit, AEAD_REKEY_SEQ[.AES_GCM_128])

	receive.seq = limit - 1
	testing.expect(t, !socket_peer_rekey_due(&state, &receive))
	receive.seq = limit
	testing.expect(t, socket_peer_rekey_due(&state, &receive))
	receive.seq = limit + 5
	testing.expect(t, !socket_peer_rekey_due(&state, &receive), "asked twice about one key")

	// The peer rekeyed and is slow again.
	receive.gen += 1
	receive.seq = 0
	testing.expect(t, !socket_peer_rekey_due(&state, &receive))
	receive.seq = limit
	testing.expect(t, socket_peer_rekey_due(&state, &receive))

	// AES-128-GCM has no key after its 2^48th.
	receive.gen = 1 << 48 - 1
	testing.expect(t, !socket_peer_rekey_due(&state, &receive))

	unused: Record_Protection
	testing.expect(t, !socket_peer_rekey_due(&state, &unused))
}
