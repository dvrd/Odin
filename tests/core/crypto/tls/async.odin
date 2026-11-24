package test_tls

import "core:crypto/tls"
import "core:net"
import "core:testing"
import "core:time"

Work :: struct {
	callback: proc(_: rawptr),
	data:     rawptr,
}

Test_Stream :: struct {
	work:                    [dynamic]Work,
	at:                      int,
	input, output:           [dynamic]u8,
	input_at:                int,
	read:                    ^net.Async_Operation,
	destination:             []u8,
	closed:                  bool,
	fragment:                int,
	read_error, write_error: net.Connection_Error,
	cancel_error:            net.Connection_Error,
}

test_schedule :: proc(data: rawptr, cb: proc(_: rawptr), arg: rawptr) {
	s := cast(^Test_Stream)data
	append(&s.work, Work{cb, arg})
}

test_submit :: proc(
	data: rawptr,
	op: ^net.Async_Operation,
	kind: net.Async_Operation_Kind,
	buffer: []u8,
	deadline: time.Time,
) -> net.Connection_Error {
	s := cast(^Test_Stream)data
	op.kind, op.pending, op.result, op._owner = kind, true, {}, s
	if kind == .Read {
		assert(s.read == nil)
		s.read, s.destination = op, buffer
		if s.input_at < len(s.input) || s.read_error.kind != .None do test_schedule(s, test_receive, s)
	} else {
		if kind == .Write {
			n := len(buffer)
			if s.write_error.kind != .None do n = min(n, 1)
			append(&s.output, ..buffer[:n])
			op.result.count, op.result.err = n, s.write_error
		} else {
			s.closed = true
		}
		test_schedule(s, test_complete, op)
	}
	return {}
}

test_receive :: proc(data: rawptr) {
	s := cast(^Test_Stream)data
	if s.read == nil do return
	op := s.read
	n := min(len(s.destination), len(s.input) - s.input_at)
	if s.fragment > 0 do n = min(n, s.fragment)
	copy(s.destination, s.input[s.input_at:][:n])
	s.input_at += n
	s.read, s.destination = nil, nil
	op.result.count = n
	if s.input_at == len(s.input) do op.result.err = s.read_error
	test_complete(op)
}

test_complete :: proc(data: rawptr) {
	op := cast(^net.Async_Operation)data
	op.pending = false
	op._owner = nil
	op.callback(op)
}

test_cancel :: proc(data: rawptr, op: ^net.Async_Operation) -> net.Connection_Error {
	s := cast(^Test_Stream)data
	if s.read == op {
		s.read, s.destination = nil, nil
		op.result.err = s.cancel_error
		if op.result.err.kind == .None do op.result.err = {
			kind = .Cancelled,
		}
		test_schedule(s, test_complete, op)
	}
	return {}
}

test_run :: proc(s: ^Test_Stream) {
	for s.at < len(s.work) {
		assert(s.at < 10000, "event loop made no bounded progress")
		w := s.work[s.at]
		s.at += 1
		w.callback(w.data)
	}
}

test_destroy :: proc(s: ^Test_Stream) {
	delete(s.work)
	delete(s.input)
	delete(s.output)
}

test_client :: proc(t: ^testing.T, s: ^Test_Stream, pool: ^tls.Root_Pool, conn: ^tls.Async_Conn) {
	testing.expect_value(t, tls.root_pool_parse(pool, #load("testdata/root.pem")), nil)
	err := tls.async_client(
		conn,
		{data = s, submit = test_submit, cancel = test_cancel},
		{data = s, schedule = test_schedule},
		{server_name = "localhost", root_cas = pool.roots[:pool.count]},
	)
	testing.expect_value(t, err, nil)
}

Result :: struct {
	calls: int,
	count: int,
	error: net.Connection_Error_Kind,
}

completed :: proc(op: ^net.Async_Operation) {
	r := cast(^Result)op.user_data
	r.calls += 1
	r.count = op.result.count
	r.error = op.result.err.kind
}

@(test)
async_handshake_cancel_and_close :: proc(t: ^testing.T) {
	s: Test_Stream
	defer test_destroy(&s)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	conn := new(tls.Async_Conn)
	defer free(conn)
	test_client(t, &s, pool, conn)
	calls := 0
	hs := tls.Async_Handshake_Operation {
		user_data = &calls,
		callback = proc(op: ^tls.Async_Handshake_Operation) {
			calls := cast(^int)op.user_data
			calls^ += 1
			assert(op.err.kind == .Cancelled)
		},
	}
	testing.expect_value(t, tls.async_handshake(conn, &hs), nil)
	testing.expect_value(t, calls, 0)
	test_run(&s)
	testing.expect(t, len(s.output) > 5 && s.read != nil)
	testing.expect_value(t, tls.async_cancel_handshake(conn), nil)
	test_run(&s)
	testing.expect_value(t, calls, 1)
	result: Result
	close := net.Async_Operation {
		callback  = completed,
		user_data = &result,
	}
	testing.expect_value(t, net.async_close(tls.async_connection(conn), &close).kind, .None)
	test_run(&s)
	testing.expect_value(t, result.calls, 1)
	testing.expect(t, s.closed)
}

// Isolate record scheduling/lifetimes from certificate fixtures. Independent
// Go interoperability tests below cover actual authentication end to end.
test_established :: proc(conn: ^tls.Async_Conn) -> tls.Record_Protection {
	secrets: tls.Application_Secrets
	tls.application_init(&conn.protocol.application, secrets)
	conn.protocol.phase = .Established
	conn.protocol.handshake_complete = true
	peer: tls.Record_Protection
	tls.record_protection_init(&peer, secrets.server_key, secrets.server_iv)
	return peer
}

@(test)
async_buffered_plaintext_is_deferred :: proc(t: ^testing.T) {
	s := Test_Stream {
		fragment = 1,
	}
	defer test_destroy(&s)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	conn := new(tls.Async_Conn)
	defer free(conn)
	test_client(t, &s, pool, conn)
	peer := test_established(conn)
	wire: [256]u8
	n, err := tls.record_seal(&peer, wire[:], .Application_Data, []u8{1, 2, 3, 4})
	testing.expect_value(t, err, nil)
	append(&s.input, ..wire[:n])
	buffer: [2]u8
	r: Result
	op := net.Async_Operation {
		callback  = completed,
		user_data = &r,
	}
	stream := tls.async_connection(conn)
	testing.expect_value(t, net.async_read(stream, &op, buffer[:]).kind, .None)
	test_run(&s)
	testing.expect_value(t, r.count, 2)
	testing.expect_value(t, buffer, [2]u8{1, 2})
	testing.expect_value(t, net.async_read(stream, &op, buffer[:]).kind, .None)
	testing.expect_value(t, r.calls, 1) // Buffered read must still defer.
	test_run(&s)
	testing.expect_value(t, r.calls, 2)
	testing.expect_value(t, buffer, [2]u8{3, 4})
	testing.expect_value(t, net.async_close(stream, &op).kind, .None)
	test_run(&s)
	testing.expect(t, s.closed)
}

@(test)
async_partial_record_cancel_can_resume :: proc(t: ^testing.T) {
	for cancellation_result in ([]net.Connection_Error_Kind{.Cancelled, .Timeout}) {
		s := Test_Stream {
			cancel_error = {kind = cancellation_result},
		}
		defer test_destroy(&s)
		pool := new(tls.Root_Pool)
		defer free(pool)
		defer tls.root_pool_destroy(pool)
		conn := new(tls.Async_Conn)
		defer free(conn)
		test_client(t, &s, pool, conn)
		peer := test_established(conn)
		wire: [256]u8
		n, _ := tls.record_seal(&peer, wire[:], .Application_Data, []u8{7, 8})
		append(&s.input, ..wire[:7]) // Header and two ciphertext bytes.
		buffer: [2]u8
		r: Result
		op := net.Async_Operation {
			callback  = completed,
			user_data = &r,
		}
		stream := tls.async_connection(conn)
		testing.expect_value(t, net.async_read(stream, &op, buffer[:]).kind, .None)
		test_run(&s)
		testing.expect_value(t, r.calls, 0)
		testing.expect_value(t, net.async_cancel(stream, &op).kind, .None)
		test_run(&s)
		testing.expect_value(t, r.error, .Cancelled)
		append(&s.input, ..wire[7:n])
		testing.expect_value(t, net.async_read(stream, &op, buffer[:]).kind, .None)
		test_run(&s)
		testing.expect_value(t, r.calls, 2)
		testing.expect_value(t, r.error, .None)
		testing.expect_value(t, buffer, [2]u8{7, 8})
		testing.expect_value(t, net.async_close(stream, &op).kind, .None)
		test_run(&s)
	}
}

@(test)
async_tampered_record_never_releases_plaintext :: proc(t: ^testing.T) {
	s: Test_Stream
	defer test_destroy(&s)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	conn := new(tls.Async_Conn)
	defer free(conn)
	test_client(t, &s, pool, conn)
	peer := test_established(conn)
	wire: [256]u8
	n, _ := tls.record_seal(&peer, wire[:], .Application_Data, []u8{1, 2, 3})
	wire[n - 1] ~= 1
	append(&s.input, ..wire[:n])
	r: Result
	op := net.Async_Operation {
		callback  = completed,
		user_data = &r,
	}
	buffer := [3]u8{99, 99, 99}
	stream := tls.async_connection(conn)
	net.async_read(stream, &op, buffer[:])
	test_run(&s)
	testing.expect_value(t, r.error, .Protocol_Failed)
	testing.expect_value(t, r.count, 0)
	testing.expect_value(t, buffer, [3]u8{99, 99, 99})
	testing.expect_value(t, tls.async_failure(conn), tls.Error(tls.Protocol_Error.Bad_Record_Mac))
	testing.expect(t, s.closed)
	net.async_close(stream, &op)
	test_run(&s)
}

@(test)
async_authenticated_close_and_truncation :: proc(t: ^testing.T) {
	for authenticated in ([]bool{false, true}) {
		s := Test_Stream {
			read_error = {kind = .Peer_Closed},
		}
		pool := new(tls.Root_Pool)
		conn := new(tls.Async_Conn)
		test_client(t, &s, pool, conn)
		peer := test_established(conn)
		if authenticated {
			wire: [256]u8
			n, _ := tls.record_seal(&peer, wire[:], .Alert, []u8{1, 0})
			append(&s.input, ..wire[:n])
		}
		r: Result
		op := net.Async_Operation {
			callback  = completed,
			user_data = &r,
		}
		buffer: [1]u8
		stream := tls.async_connection(conn)
		net.async_read(stream, &op, buffer[:])
		test_run(&s)
		testing.expect_value(t, r.error, net.Connection_Error_Kind.Peer_Closed if authenticated else .Protocol_Failed)
		if !authenticated do testing.expect_value(t, tls.async_failure(conn), tls.Error(net.TCP_Recv_Error.Connection_Closed))
		net.async_close(stream, &op)
		test_run(&s)
		test_destroy(&s)
		free(conn)
		tls.root_pool_destroy(pool)
		free(pool)
	}
}

@(test)
async_failed_record_write_is_terminal :: proc(t: ^testing.T) {
	s := Test_Stream {
		write_error = {kind = .Write_Failed},
	}
	defer test_destroy(&s)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	conn := new(tls.Async_Conn)
	defer free(conn)
	test_client(t, &s, pool, conn)
	test_established(conn)
	r: Result
	op := net.Async_Operation {
		callback  = completed,
		user_data = &r,
	}
	stream := tls.async_connection(conn)
	net.async_write(stream, &op, []u8{1, 2, 3})
	test_run(&s)
	testing.expect_value(t, r.error, .Write_Failed)
	testing.expect_value(t, r.count, 0)
	testing.expect(t, s.closed && !conn.protocol.application.initialized)
	testing.expect_value(t, net.async_write(stream, &op, []u8{4}).kind, .Closed)
	net.async_close(stream, &op)
	test_run(&s)
}

@(test)
async_key_update_response_uses_old_key :: proc(t: ^testing.T) {
	s: Test_Stream
	defer test_destroy(&s)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	conn := new(tls.Async_Conn)
	defer free(conn)
	test_client(t, &s, pool, conn)
	peer := test_established(conn)
	wire: [256]u8
	n, _ := tls.record_seal(&peer, wire[:], .Handshake, []u8{24, 0, 0, 1, 1})
	append(&s.input, ..wire[:n])
	updated := tls.traffic_secret_update([32]u8{})
	key, iv := tls.traffic_key_iv(updated)
	tls.record_protection_init(&peer, key, iv)
	n, _ = tls.record_seal(&peer, wire[:], .Application_Data, []u8{9})
	append(&s.input, ..wire[:n])
	r: Result
	op := net.Async_Operation {
		callback  = completed,
		user_data = &r,
	}
	buffer: [1]u8
	stream := tls.async_connection(conn)
	net.async_read(stream, &op, buffer[:])
	test_run(&s)
	testing.expect_value(t, r.error, .None)
	testing.expect_value(t, buffer[0], u8(9))
	old: tls.Record_Protection
	tls.record_protection_init(&old, [16]u8{}, [12]u8{})
	plaintext: [128]u8
	kind, body, err := tls.record_open(&old, plaintext[:], s.output[:])
	testing.expect_value(t, err, nil)
	testing.expect_value(t, kind, .Handshake)
	testing.expect_value(t, len(body), 5)
	testing.expect_value(t, body[4], u8(0))
	testing.expect_value(t, conn.protocol.application.send.seq, u64(0))
	net.async_close(stream, &op)
	test_run(&s)
}

@(test)
async_partial_record_timeout_can_resume :: proc(t: ^testing.T) {
	s := Test_Stream {
		read_error = {kind = .Timeout},
	}
	defer test_destroy(&s)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	conn := new(tls.Async_Conn)
	defer free(conn)
	test_client(t, &s, pool, conn)
	peer := test_established(conn)
	wire: [256]u8
	n, _ := tls.record_seal(&peer, wire[:], .Application_Data, []u8{4, 5})
	append(&s.input, ..wire[:7])
	r: Result
	op := net.Async_Operation {
		callback  = completed,
		user_data = &r,
	}
	buffer: [2]u8
	stream := tls.async_connection(conn)
	net.async_read(stream, &op, buffer[:])
	test_run(&s)
	testing.expect_value(t, r.error, .Timeout)
	testing.expect_value(t, r.count, 0)
	s.read_error = {}
	append(&s.input, ..wire[7:n])
	net.async_read(stream, &op, buffer[:])
	test_run(&s)
	testing.expect_value(t, r.error, .None)
	testing.expect_value(t, buffer, [2]u8{4, 5})
	net.async_close(stream, &op)
	test_run(&s)
}

@(test)
async_close_drains_handshake_before_releasing_storage :: proc(t: ^testing.T) {
	s: Test_Stream
	defer test_destroy(&s)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	conn := new(tls.Async_Conn)
	test_client(t, &s, pool, conn)
	State :: struct {
		conn:            ^tls.Async_Conn,
		handshake_calls: int,
		close_calls:     int,
	}
	state := State {
		conn = conn,
	}
	hs := new(tls.Async_Handshake_Operation)
	hs^ = {
		user_data = &state,
		callback = proc(op: ^tls.Async_Handshake_Operation) {
			s := cast(^State)op.user_data
			s.handshake_calls += 1
			assert(op.err.kind == .Closed)
			free(op)
		},
	}
	_ = tls.async_handshake(conn, hs)
	test_run(&s)
	close := net.Async_Operation {
		user_data = &state,
		callback = proc(op: ^net.Async_Operation) {
			s := cast(^State)op.user_data
			assert(s.handshake_calls == 1)
			s.close_calls += 1
			free(s.conn)
		},
	}
	net.async_close(tls.async_connection(conn), &close)
	test_run(&s)
	testing.expect_value(t, state.handshake_calls, 1)
	testing.expect_value(t, state.close_calls, 1)
	testing.expect(t, s.closed)
}
