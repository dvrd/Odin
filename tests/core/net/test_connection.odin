package test_core_net

import "core:io"
import "core:net"
import "core:testing"
import "core:time"

Connection_Test_State :: struct {
	input:       []u8,
	output:      [32]u8,
	used:        int,
	closed:      bool,
	write_limit: int,
	read_error:  net.Connection_Error,
}

connection_test_read :: proc(data: rawptr, dst: []u8) -> (int, net.Connection_Error) {
	s := cast(^Connection_Test_State)data
	if s.closed do return 0, {kind = .Closed}
	if s.read_error.kind != .None do return 0, s.read_error
	n := copy(dst, s.input[:min(2, len(s.input))])
	s.input = s.input[n:]
	return n, net.Connection_Error{kind = .Peer_Closed} if len(s.input) == 0 else net.Connection_Error{}
}

connection_test_write :: proc(data: rawptr, src: []u8) -> (int, net.Connection_Error) {
	s := cast(^Connection_Test_State)data
	if s.closed do return 0, {kind = .Closed}
	limit := len(src)
	if s.write_limit > 0 do limit = min(limit, s.write_limit)
	n := copy(s.output[s.used:], src[:limit])
	s.used += n
	return n, {}
}

connection_test_close :: proc(data: rawptr) -> net.Connection_Error {
	s := cast(^Connection_Test_State)data
	s.closed = true
	return {}
}

connection_test_wrap :: proc(s: ^Connection_Test_State) -> net.Connection {
	return {data = s, read = connection_test_read, write = connection_test_write, close = connection_test_close}
}

@(test)
connection_io_copy_and_errors :: proc(t: ^testing.T) {
	source := Connection_Test_State {
		input = []u8{'h', 'e', 'l', 'l', 'o'},
	}
	destination: Connection_Test_State
	reader := net.Connection_Stream {
		connection = connection_test_wrap(&source),
	}
	writer := net.Connection_Stream {
		connection = connection_test_wrap(&destination),
	}
	r, w := net.connection_stream(&reader), net.connection_stream(&writer)
	testing.expect(t, io.query(r) == io.Stream_Mode_Set{.Read, .Write, .Close, .Query})
	n, err := io.copy(w, r)
	testing.expect_value(t, n, i64(5))
	testing.expect(t, err == nil)
	testing.expect_value(t, string(destination.output[:destination.used]), "hello")
	testing.expect_value(t, reader.last_error.kind, .Peer_Closed)
	_, seek_err := io.seek(r, 0, .Start)
	testing.expect_value(t, seek_err, .Unsupported)

	buffer: [4]u8
	source.read_error = {
		kind       = .Timeout,
		read_cause = .Timeout,
	}
	_, err = io.read(r, buffer[:])
	testing.expect_value(t, err, .Unknown)
	testing.expect_value(t, reader.last_error.kind, .Timeout)
	testing.expect_value(t, reader.last_error.read_cause, .Timeout)
	destination.write_limit = 1
	written, write_err := io.write(w, []u8{1, 2})
	testing.expect_value(t, written, 1)
	testing.expect_value(t, write_err, .Short_Write)
	testing.expect(t, io.close(r) == nil)
	_, err = io.read(r, buffer[:])
	testing.expect_value(t, err, .Closed)
	testing.expect(t, net.connection_stream(nil).procedure == nil)
}

@(test)
connection_exact_partial_io :: proc(t: ^testing.T) {
	s := Connection_Test_State {
		input       = []u8{'h', 'e', 'l', 'l', 'o'},
		write_limit = 2,
	}
	conn := connection_test_wrap(&s)
	buffer: [5]u8
	n, err := net.read_exact(conn, buffer[:])
	testing.expect_value(t, n, 5)
	testing.expect_value(t, err.kind, .None)
	testing.expect_value(t, string(buffer[:]), "hello")
	n, err = net.write_all(conn, buffer[:])
	testing.expect_value(t, n, 5)
	testing.expect_value(t, err.kind, .None)
	testing.expect_value(t, string(s.output[:s.used]), "hello")
	s.input = buffer[:2]
	n, err = net.read_exact(conn, buffer[:])
	testing.expect_value(t, n, 2)
	testing.expect_value(t, err.kind, .Peer_Closed)
	testing.expect_value(t, net.set_deadline(conn, {}).kind, .Deadline_Unsupported)
}

@(test)
connection_tcp_loopback :: proc(t: ^testing.T) {
	listener, listen_err := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	testing.expect(t, listen_err == nil)
	if listen_err != nil do return
	defer net.close(listener)
	endpoint, endpoint_err := net.bound_endpoint(listener)
	testing.expect(t, endpoint_err == nil)
	if endpoint_err != nil do return
	socket, dial_err := net.dial_tcp(endpoint)
	testing.expect(t, dial_err == nil)
	if dial_err != nil do return
	defer net.close(socket)
	peer, _, accept_err := net.accept_tcp(listener)
	testing.expect(t, accept_err == nil)
	if accept_err != nil do return
	tcp := net.TCP_Connection {
		socket = peer,
	}
	conn := net.tcp_connection(&tcp)
	defer conn.close(conn.data)
	when net.TCP_DEADLINES_SUPPORTED {
		setup_err := net.set_deadline(conn, time.time_add(time.now(), 2 * time.Second))
		testing.expect_value(t, setup_err.kind, .None)
	}
	_, send_err := net.send_tcp(socket, []u8{1, 2, 3})
	testing.expect(t, send_err == nil)
	testing.expect(t, net.shutdown(socket, .Send) == nil)
	buffer: [5]u8
	n, read_err := net.tcp_read_exact(peer, buffer[:2])
	testing.expect_value(t, n, 2)
	testing.expect_value(t, read_err.kind, .None)
	adapter := net.Connection_Stream {
		connection = conn,
	}
	stream := net.connection_stream(&adapter)
	remaining, err := io.read_full(stream, buffer[2:])
	testing.expect_value(t, remaining, 1)
	testing.expect_value(t, err, .Unexpected_EOF)
	when net.TCP_DEADLINES_SUPPORTED {
		deadline_err := net.set_read_deadline(conn, time.time_add(time.now(), -time.Second))
		testing.expect_value(t, deadline_err.kind, .None)
		_, err = io.read(stream, buffer[:])
		testing.expect_value(t, adapter.last_error.kind, .Timeout)
		testing.expect_value(t, err, .Unknown)
	}
	testing.expect(t, io.close(stream) == nil)
	testing.expect(t, io.close(stream) == nil)
}
