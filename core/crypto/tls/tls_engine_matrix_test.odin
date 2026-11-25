package tls

import "core:net"
import "core:testing"
import "core:time"
import credential_store "credentials/store"

// The client engine (Conn, Upstream offer) against the server engine
// (Server_Async_Conn, Upstream offer) in one process and one thread: the
// client's blocking transport runs the server's executor whenever it has to
// wait, so every byte crosses both record layers.
Matrix_Loop :: struct {
	stream: TCP_Test_Stream,
	// Bytes of stream.output the client already read.
	taken:  int,
}

matrix_read :: proc(data: rawptr, dst: []u8) -> (int, net.Network_Error) {
	loop := cast(^Matrix_Loop)data
	tcp_test_run(&loop.stream)

	available := len(loop.stream.output) - loop.taken
	if available == 0 {
		return 0, net.Connection_Error.Peer_Closed
	}

	n := min(len(dst), available)
	copy(dst, loop.stream.output[loop.taken:loop.taken + n])
	loop.taken += n
	return n, {}
}

matrix_write :: proc(data: rawptr, src: []u8) -> (int, net.Network_Error) {
	loop := cast(^Matrix_Loop)data
	append(&loop.stream.input, ..src)
	tcp_test_wake(&loop.stream)
	tcp_test_run(&loop.stream)
	return len(src), {}
}

matrix_close :: proc(data: rawptr) -> net.Network_Error {
	return {}
}

Matrix_Case :: struct {
	suite:       Cipher_Suite,
	group:       Named_Group,
	// ECDSA P-256 server credential instead of RSA (RSA-PSS-SHA256).
	ecdsa:       bool,
	// Leave the client's offer unrestricted: the server's order decides.
	unrestricted: bool,
}

matrix_server_store :: proc(t: ^testing.T, ecdsa: bool) -> ^credential_store.Store {
	if ecdsa {
		return mtls_store(
			t,
			#load("../../../tests/core/crypto/tls/credentials/testdata/p256-valid.pem"),
			#load("../../../tests/core/crypto/tls/credentials/testdata/p256.pem"),
		)
	}
	return mtls_store(t, #load("testdata/mtls/server.pem"), #load("testdata/mtls/server-key.pem"))
}

matrix_roots :: proc(roots: ^Root_Pool, ecdsa: bool) {
	trust := #load("testdata/mtls/root.pem")
	if ecdsa {
		// A self-signed leaf, trusted as its own anchor.
		trust = #load("../../../tests/core/crypto/tls/credentials/testdata/p256-valid.pem")
	}

	parsed := engine_root_pool_parse(roots, trust)
	assert(parsed.kind == .None)
}

// One full connection: handshake, a record each way, a client KeyUpdate
// forced at the suite's limit, then another record each way.
matrix_connection :: proc(t: ^testing.T, entry: Matrix_Case, loc := #caller_location) {
	store := matrix_server_store(t, entry.ecdsa)
	defer credential_store.destroy(&store)

	roots: Root_Pool
	matrix_roots(&roots, entry.ecdsa)
	defer root_pool_destroy(&roots)

	loop := new(Matrix_Loop)
	defer free(loop)
	defer tcp_test_destroy(&loop.stream)

	audit := TCP_Test_Audit{backing = context.allocator}
	server := new(Server_Async_Conn)
	defer free(server)

	server_config := Server_Async_Config{store = store, credential_time = time.now()}
	server_config.handshake = SERVER_HANDSHAKE_DEFAULT_CONFIG
	server_config.handshake.offer = .Upstream
	transport := net.Async_Connection{data = &loop.stream, submit = tcp_test_submit, cancel = tcp_test_cancel}
	executor := net.Async_Executor{data = &loop.stream, schedule = tcp_test_schedule}
	testing.expect_value(t, engine_server_async_server(server, transport, executor, server_config, {tcp_test_allocate, &audit}), Server_Async_Init_Error.None, loc)

	accepted: TCP_Test_Result
	accept := Server_Async_Handshake_Operation{callback = tcp_test_handshake, user_data = &accepted}
	testing.expect_value(t, engine_server_async_handshake(server, &accept), nil, loc)

	suites := [1]Cipher_Suite{entry.suite}
	groups := [1]Named_Group{entry.group}
	config := Config{server_name = "localhost", root_cas = roots.roots[:roots.count], offer = .Upstream}
	if entry.ecdsa {
		config.server_name = "synthetic.invalid"
	}
	if !entry.unrestricted {
		config._cipher_suites = suites[:]
		config._groups = groups[:]
	}

	conn := new(Conn)
	defer free(conn)
	wire := net.Connection{data = loop, read = matrix_read, write = matrix_write, close = matrix_close}
	testing.expect_value(t, engine_client(conn, wire, config), Client_Error.None, loc)

	established := engine_handshake(conn)
	testing.expect_value(t, established.kind, Handshake_Error_Kind.None, loc)
	if established.kind != .None {
		testing.expectf(t, false, "handshake failed: %v / accept %v", established, accepted, loc = loc)
		engine_abort(conn)
		tcp_test_run(&loop.stream)
		return
	}

	tcp_test_run(&loop.stream)
	testing.expect_value(t, accepted.calls, 1, loc)
	testing.expect_value(t, accepted.error, nil, loc)

	state := connection_state(conn)
	testing.expect_value(t, state.handshake_complete, true, loc)
	testing.expect_value(t, state.version, VERSION_TLS_1_3, loc)
	testing.expect_value(t, server_async_connection_state(server).cipher_suite, state.cipher_suite, loc)
	if !entry.unrestricted {
		testing.expect_value(t, state.cipher_suite, entry.suite, loc)
		testing.expect_value(t, conn.server_parameters.group, entry.group, loc)
	}

	matrix_echo(t, conn, server, loop, "ping", "pong", loc)

	// The next client record must be a KeyUpdate under the old key.
	// Both ends of that direction jump to the last sequence number of the key.
	conn.application.send.seq = record_protection_limit(&conn.application.send) - 1
	server_async_keys(server).read.seq = conn.application.send.seq
	matrix_echo(t, conn, server, loop, "after update", "updated", loc)
	testing.expect_value(t, server_async_stats(server).received_key_updates, 1, loc)
	testing.expect_value(t, conn.application.send.seq < 4, true, loc)

	testing.expect_value(t, engine_close(conn).kind, IO_Error_Kind.None, loc)
	tcp_test_run(&loop.stream)

	closed: TCP_Test_Result
	closing := tcp_test_op(&closed)
	testing.expect_value(t, net.async_close(server_async_connection(server), &closing), nil, loc)
	tcp_test_run(&loop.stream)
	testing.expect_value(t, closed.calls, 1, loc)
	testing.expect_value(t, audit.live, 0, loc)
}

matrix_echo :: proc(
	t: ^testing.T,
	conn: ^Conn,
	server: ^Server_Async_Conn,
	loop: ^Matrix_Loop,
	request, response: string,
	loc := #caller_location,
) {
	written, write_error := engine_write(conn, transmute([]u8)request)
	testing.expect_value(t, write_error.kind, IO_Error_Kind.None, loc)
	testing.expect_value(t, written, len(request), loc)

	storage: [64]u8
	received: TCP_Test_Result
	reading := tcp_test_op(&received)
	testing.expect_value(t, net.async_read(server_async_connection(server), &reading, storage[:]), nil, loc)
	tcp_test_run(&loop.stream)
	testing.expect_value(t, received.calls, 1, loc)
	testing.expect_value(t, string(storage[:received.count]), request, loc)

	sent: TCP_Test_Result
	sending := tcp_test_op(&sent)
	testing.expect_value(t, net.async_write(server_async_connection(server), &sending, transmute([]u8)response), nil, loc)
	tcp_test_run(&loop.stream)
	testing.expect_value(t, sent.calls, 1, loc)

	answer: [64]u8
	count, read_error := engine_read(conn, answer[:])
	testing.expect_value(t, read_error.kind, IO_Error_Kind.None, loc)
	testing.expect_value(t, string(answer[:count]), response, loc)
}

@(test)
engine_matrix_every_suite_over_every_group :: proc(t: ^testing.T) {
	for suite in CIPHER_SUITES {
		for group in SUPPORTED_GROUPS {
			matrix_connection(t, {suite = suite, group = group})
		}
	}
}

@(test)
engine_matrix_ecdsa_credential_and_unrestricted_offer :: proc(t: ^testing.T) {
	for suite in CIPHER_SUITES {
		matrix_connection(t, {suite = suite, group = .X25519, ecdsa = true})
	}

	// Upstream's whole offer: the server takes the client's first suite and
	// its own first group, the hybrid.
	matrix_connection(t, {unrestricted = true})
}

// The asynchronous client (Async_Conn) against the same server: two test
// streams joined by a pump that carries each side's output to the other and
// runs both executors until neither has work.
Matrix_Pipe :: struct {
	client, server:             TCP_Test_Stream,
	client_taken, server_taken: int,
}

matrix_pump :: proc(pipe: ^Matrix_Pipe) {
	for {
		tcp_test_run(&pipe.client)
		tcp_test_run(&pipe.server)

		moved := false
		if len(pipe.client.output) > pipe.client_taken {
			append(&pipe.server.input, ..pipe.client.output[pipe.client_taken:])
			pipe.client_taken = len(pipe.client.output)
			tcp_test_wake(&pipe.server)
			moved = true
		}

		if len(pipe.server.output) > pipe.server_taken {
			append(&pipe.client.input, ..pipe.server.output[pipe.server_taken:])
			pipe.server_taken = len(pipe.server.output)
			tcp_test_wake(&pipe.client)
			moved = true
		}

		if !moved && pipe.client.at == len(pipe.client.work) && pipe.server.at == len(pipe.server.work) {
			return
		}
	}
}

Matrix_Async_Result :: struct {
	calls: int,
	error: net.Network_Error,
	cause: Handshake_Error,
}

matrix_async_handshake_done :: proc(op: ^Async_Handshake_Operation) {
	result := cast(^Matrix_Async_Result)op.user_data
	result.calls += 1
	result.error = op.err
	result.cause = op.result
}

// One byte stream exchange from side `from` to side `to`.
matrix_async_transfer :: proc(t: ^testing.T, pipe: ^Matrix_Pipe, from, to: net.Async_Connection, text: string, loc := #caller_location) {
	sent, received: TCP_Test_Result
	sending, receiving := tcp_test_op(&sent), tcp_test_op(&received)
	storage: [64]u8

	testing.expect_value(t, net.async_read(to, &receiving, storage[:]), nil, loc)
	testing.expect_value(t, net.async_write(from, &sending, transmute([]u8)text), nil, loc)
	matrix_pump(pipe)
	testing.expect_value(t, sent.calls, 1, loc)
	testing.expect_value(t, sent.error, nil, loc)
	testing.expect_value(t, received.calls, 1, loc)
	testing.expect_value(t, string(storage[:received.count]), text, loc)
}

matrix_async_connection :: proc(t: ^testing.T, suite: Cipher_Suite, group: Named_Group, loc := #caller_location) {
	store := matrix_server_store(t, false)
	defer credential_store.destroy(&store)

	roots: Root_Pool
	matrix_roots(&roots, false)
	defer root_pool_destroy(&roots)

	pipe := new(Matrix_Pipe)
	defer free(pipe)
	defer tcp_test_destroy(&pipe.client)
	defer tcp_test_destroy(&pipe.server)

	audit := TCP_Test_Audit{backing = context.allocator}
	server := new(Server_Async_Conn)
	defer free(server)

	server_config := Server_Async_Config{store = store, credential_time = time.now()}
	server_config.handshake = SERVER_HANDSHAKE_DEFAULT_CONFIG
	server_config.handshake.offer = .Upstream
	server_transport := net.Async_Connection{data = &pipe.server, submit = tcp_test_submit, cancel = tcp_test_cancel}
	server_executor := net.Async_Executor{data = &pipe.server, schedule = tcp_test_schedule}
	testing.expect_value(t, engine_server_async_server(server, server_transport, server_executor, server_config, {tcp_test_allocate, &audit}), Server_Async_Init_Error.None, loc)

	accepted: TCP_Test_Result
	accept := Server_Async_Handshake_Operation{callback = tcp_test_handshake, user_data = &accepted}
	testing.expect_value(t, engine_server_async_handshake(server, &accept), nil, loc)

	suites := [1]Cipher_Suite{suite}
	groups := [1]Named_Group{group}
	config := Config {
		server_name   = "localhost",
		root_cas      = roots.roots[:roots.count],
		offer         = .Upstream,
		_cipher_suites = suites[:],
		_groups        = groups[:],
	}

	conn := new(Async_Conn)
	defer free(conn)
	client_transport := net.Async_Connection{data = &pipe.client, submit = tcp_test_submit, cancel = tcp_test_cancel}
	client_executor := net.Async_Executor{data = &pipe.client, schedule = tcp_test_schedule}
	testing.expect_value(t, engine_async_client(conn, client_transport, client_executor, config), Client_Error.None, loc)

	connected: Matrix_Async_Result
	connect := Async_Handshake_Operation{callback = matrix_async_handshake_done, user_data = &connected}
	testing.expect_value(t, engine_async_handshake(conn, &connect), nil, loc)
	matrix_pump(pipe)

	testing.expect_value(t, connected.calls, 1, loc)
	testing.expectf(t, connected.error == nil, "%v over %v: %v", suite, group, connected.cause, loc = loc)
	testing.expect_value(t, accepted.calls, 1, loc)
	testing.expect_value(t, accepted.error, nil, loc)
	if connected.error == nil && accepted.error == nil {
		testing.expect_value(t, connection_state(&conn.protocol).cipher_suite, suite, loc)
		testing.expect_value(t, server_async_connection_state(server).cipher_suite, suite, loc)
		testing.expect_value(t, conn.protocol.server_parameters.group, group, loc)

		matrix_async_transfer(t, pipe, async_connection(conn), server_async_connection(server), "from the client", loc)
		matrix_async_transfer(t, pipe, server_async_connection(server), async_connection(conn), "from the server", loc)
	}

	client_closed, server_closed: TCP_Test_Result
	client_closing, server_closing := tcp_test_op(&client_closed), tcp_test_op(&server_closed)
	testing.expect_value(t, net.async_close(async_connection(conn), &client_closing), nil, loc)
	matrix_pump(pipe)
	testing.expect_value(t, net.async_close(server_async_connection(server), &server_closing), nil, loc)
	matrix_pump(pipe)
	testing.expect_value(t, client_closed.calls, 1, loc)
	testing.expect_value(t, server_closed.calls, 1, loc)
	testing.expect_value(t, audit.live, 0, loc)
}

@(test)
engine_matrix_async_client_every_suite_over_every_group :: proc(t: ^testing.T) {
	for suite in CIPHER_SUITES {
		for group in SUPPORTED_GROUPS {
			matrix_async_connection(t, suite, group)
		}
	}
}
