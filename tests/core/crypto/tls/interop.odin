package test_tls

import "core:bytes"
import "core:crypto/tls"
import "core:nbio"
import "core:net"
import "core:testing"
import "core:time"

TLS_TEST_ENDPOINT :: #config(TLS_TEST_ENDPOINT, "")

// Optional local Go/OpenSSL server; ordinary tests need no external programs.
@(test)
async_go_interoperability :: proc(t: ^testing.T) {
	if TLS_TEST_ENDPOINT == "" do return
	testing.set_fail_timeout(t, 10 * time.Second)
	testing.expect(t, nbio.acquire_thread_event_loop() == nil)
	defer nbio.release_thread_event_loop()
	ep, parse_err := net.parse_endpoint(TLS_TEST_ENDPOINT)
	testing.expect(t, parse_err)
	// Dial runs through nbio too; the client never creates blocking I/O threads.
	socket: net.TCP_Socket
	nbio.dial_poly(ep, &socket, proc(op: ^nbio.Operation, socket: ^net.TCP_Socket) {
		assert(op.dial.err == nil)
		socket^ = op.dial.socket
	})
	testing.expect(t, nbio.run() == nil)
	tcp: nbio.TCP_Async_Connection
	testing.expect(t, nbio.tcp_async_connection_init(&tcp, socket) == nil)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	conn := new(tls.Async_Conn)
	defer free(conn)
	testing.expect_value(t, tls.root_pool_parse(pool, #load("testdata/root.pem")).kind, .None)
	testing.expect_value(
		t,
		tls.async_client(
			conn,
			nbio.tcp_async_connection(&tcp),
			nbio.async_executor(),
			{server_name = "localhost", root_cas = pool.roots[:pool.count]},
		),
		.None,
	)
	State :: struct {
		done:      bool,
		error:     net.Connection_Error,
		handshake: tls.Handshake_Error,
	}
	hs_result: State
	hs := tls.Async_Handshake_Operation {
		user_data = &hs_result,
		callback = proc(op: ^tls.Async_Handshake_Operation) {
			s := cast(^State)op.user_data
			s.done = true
			s.error = op.err
			s.handshake = op.result
		},
	}
	testing.expect_value(t, tls.async_handshake(conn, &hs).kind, .None)
	testing.expect(t, nbio.run() == nil)
	testing.expect_value(t, hs_result.error.kind, .None)
	testing.expect_value(t, hs_result.handshake.kind, .None)
	if !hs_result.done || hs_result.error.kind != .None {
		result: Result
		op := net.Async_Operation {
			callback  = completed,
			user_data = &result,
		}
		net.async_close(tls.async_connection(conn), &op)
		nbio.run()
		return
	}
	stream := tls.async_connection(conn)
	payload := make([]u8, 40000)
	defer delete(payload)
	for &b, i in payload {b = u8(i % 251)}
	destination := make([]u8, len(payload))
	defer delete(destination)
	Reader :: struct {
		stream: net.Async_Connection,
		buffer: []u8,
		used:   int,
		error:  net.Connection_Error,
		calls:  int,
	}
	reader := Reader {
		stream = stream,
		buffer = destination,
	}
	read_op := net.Async_Operation {
		user_data = &reader,
		callback = proc(op: ^net.Async_Operation) {
			s := cast(^Reader)op.user_data
			s.calls += 1
			s.used += op.result.count
			s.error = op.result.err
			if s.error.kind == .None && s.used < len(s.buffer) {
				assert(
					net.async_read(s.stream, op, s.buffer[s.used:], time.time_add(time.now(), time.Second)).kind ==
					.None,
				)
			}
		},
	}
	written: Result
	write_op := net.Async_Operation {
		callback  = completed,
		user_data = &written,
	}
	deadline := time.time_add(time.now(), 2 * time.Second)
	testing.expect_value(t, net.async_read(stream, &read_op, destination, deadline).kind, .None)
	testing.expect_value(t, net.async_write(stream, &write_op, payload, deadline).kind, .None)
	testing.expect(t, nbio.run() == nil)
	testing.expect_value(t, written.error, .None)
	testing.expect_value(t, written.count, len(payload))
	testing.expect_value(t, reader.error.kind, .None)
	testing.expect_value(t, reader.used, len(payload))
	testing.expect(t, bytes.equal(payload, destination))
	closed: Result
	close_op := net.Async_Operation {
		callback  = completed,
		user_data = &closed,
	}
	testing.expect_value(t, net.async_close(stream, &close_op).kind, .None)
	testing.expect(t, nbio.run() == nil)
	testing.expect_value(t, closed.calls, 1)
	testing.expect_value(t, closed.error, .None)
}

@(test)
async_go_rejects_wrong_hostname :: proc(t: ^testing.T) {
	if TLS_TEST_ENDPOINT == "" do return
	testing.set_fail_timeout(t, 10 * time.Second)
	assert(nbio.acquire_thread_event_loop() == nil)
	defer nbio.release_thread_event_loop()
	ep, ok := net.parse_endpoint(TLS_TEST_ENDPOINT)
	assert(ok)
	socket: net.TCP_Socket
	nbio.dial_poly(ep, &socket, proc(op: ^nbio.Operation, socket: ^net.TCP_Socket) {
		assert(op.dial.err == nil)
		socket^ = op.dial.socket
	})
	assert(nbio.run() == nil)
	tcp: nbio.TCP_Async_Connection
	assert(nbio.tcp_async_connection_init(&tcp, socket) == nil)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	assert(tls.root_pool_parse(pool, #load("testdata/root.pem")).kind == .None)
	conn := new(tls.Async_Conn)
	defer free(conn)
	assert(
		tls.async_client(
			conn,
			nbio.tcp_async_connection(&tcp),
			nbio.async_executor(),
			{server_name = "wrong.example", root_cas = pool.roots[:pool.count]},
		) ==
		.None,
	)
	State :: struct {
		calls:     int,
		error:     net.Connection_Error_Kind,
		handshake: tls.Handshake_Error_Kind,
	}
	state: State
	op := tls.Async_Handshake_Operation {
		user_data = &state,
		callback = proc(op: ^tls.Async_Handshake_Operation) {
			s := cast(^State)op.user_data
			s.calls += 1
			s.error = op.err.kind
			s.handshake = op.result.kind
		},
	}
	tls.async_handshake(conn, &op)
	assert(nbio.run() == nil)
	testing.expect_value(t, state.calls, 1)
	testing.expect_value(t, state.error, .Protocol_Failed)
	testing.expect_value(t, state.handshake, .Authentication_Failed)
	r: Result
	close_op := net.Async_Operation {
		user_data = &r,
		callback  = completed,
	}
	net.async_close(tls.async_connection(conn), &close_op)
	assert(nbio.run() == nil)
	testing.expect_value(t, r.calls, 1)
}

@(test)
blocking_go_interoperability :: proc(t: ^testing.T) {
	if TLS_TEST_ENDPOINT == "" do return
	testing.set_fail_timeout(t, 10 * time.Second)
	ep, ok := net.parse_endpoint(TLS_TEST_ENDPOINT)
	assert(ok)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	assert(tls.root_pool_parse(pool, #load("testdata/root.pem")).kind == .None)
	conn := new(tls.Conn)
	defer free(conn)
	result := tls.dial(
		conn,
		"127.0.0.1",
		ep.port,
		{server_name = "localhost", root_cas = pool.roots[:pool.count], handshake_timeout = time.Second},
	)
	testing.expect_value(t, result.kind, .None)
	if result.kind != .None do return
	defer tls.abort(conn)
	testing.expect_value(t, tls.set_deadline(conn, time.time_add(time.now(), time.Second)).kind, .None)
	n, write_error := tls.write(conn, []u8{1, 2, 3})
	testing.expect_value(t, write_error.kind, .None)
	testing.expect_value(t, n, 3)
	buffer: [3]u8
	read, read_error := tls.read(conn, buffer[:])
	testing.expect_value(t, read_error.kind, .None)
	testing.expect_value(t, read, 3)
	testing.expect_value(t, buffer, [3]u8{1, 2, 3})
	testing.expect_value(t, tls.conn_close(conn).kind, .None)
}
