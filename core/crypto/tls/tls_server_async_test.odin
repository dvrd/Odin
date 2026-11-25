package tls

import "core:crypto/x25519"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:testing"
import "core:time"
import credential_store "credentials/store"

TCP_Test_Work :: struct {
	callback: proc(rawptr),
	data:     rawptr,
}

TCP_Test_Stream :: struct {
	work:                            [dynamic]TCP_Test_Work,
	at:                              int,
	input, output:                   [dynamic]u8,
	input_at:                        int,
	read, write:                     ^net.Async_Operation,
	destination, source:             []u8,
	read_queued, hold_write, closed: bool,
	fragment, max_write:             int,
	read_error, write_error:         net.Network_Error,
	close_calls:                     int,
}

TCP_Test_Audit :: struct {
	backing:                                   mem.Allocator,
	calls, fail_at, delta, delta_at, error_at: int,
	error_with_grant, dirty, bad_free:         bool,
	live, peak, freed:                         int,
	pointers:                                  [16]rawptr,
	sizes:                                     [16]int,
}

TCP_Test_Result :: struct {
	calls, count: int,
	error:        net.Network_Error,
	detail:       Server_Async_Failure,
}

tcp_test_allocate :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	a := cast(^TCP_Test_Audit)data
	#partial switch mode {
	case .Alloc:
		a.calls += 1
		if a.calls == a.fail_at {
			return nil, .Out_Of_Memory
		}
		delta := a.delta
		if a.delta_at != 0 && a.calls != a.delta_at {
			delta = 0
		}
		grant, e := a.backing.procedure(a.backing.data, mode, size + delta, alignment, nil, 0, loc)
		if e != nil {
			return grant, e
		}
		for &b in grant {b = 0xa5}
		found := false
		for i in 0 ..< 16 {
			if a.pointers[i] == nil {
				a.pointers[i], a.sizes[i] = raw_data(grant), len(grant)
				found = true
				break
			}
		}
		assert(found)
		a.live += len(grant)
		a.peak = max(a.peak, a.live)
		return grant, .Out_Of_Memory if a.error_with_grant || a.calls == a.error_at else .None
	case .Free:
		found := false
		for i in 0 ..< 16 {
			if a.pointers[i] == old && old != nil {
				found = true
				if old_size != a.sizes[i] {
					a.bad_free = true
				}
				a.dirty = a.dirty || !mem.check_zero_ptr(old, a.sizes[i])
				a.live -= a.sizes[i]
				a.freed += 1
				a.pointers[i], a.sizes[i] = nil, 0
				break
			}
		}
		if !found {
			a.bad_free = true
		}
		return a.backing.procedure(a.backing.data, mode, size, alignment, old, old_size, loc)
	case:
		return nil, .Mode_Not_Implemented
	}
}

tcp_test_schedule :: proc(data: rawptr, callback: proc(rawptr), argument: rawptr) {
	s := cast(^TCP_Test_Stream)data
	append(&s.work, TCP_Test_Work{callback, argument})
}

tcp_test_complete :: proc(data: rawptr) {
	op := cast(^net.Async_Operation)data
	op.pending, op._owner = false, nil
	op.callback(op)
}

tcp_test_receive :: proc(data: rawptr) {
	s := cast(^TCP_Test_Stream)data
	s.read_queued = false
	if s.read == nil {
		return
	}
	op := s.read
	n := min(len(s.destination), len(s.input) - s.input_at)
	if s.fragment > 0 {
		n = min(n, s.fragment)
	}
	copy(s.destination, s.input[s.input_at:s.input_at + n])
	s.input_at += n
	op.result.count = n
	if s.input_at == len(s.input) {
		op.result.err = s.read_error
	}
	s.read, s.destination = nil, nil
	tcp_test_complete(op)
}

tcp_test_wake :: proc(s: ^TCP_Test_Stream) {
	if s.read != nil && !s.read_queued && (s.input_at < len(s.input) || s.read_error != nil) {
		s.read_queued = true
		tcp_test_schedule(s, tcp_test_receive, s)
	}
}

tcp_test_send :: proc(s: ^TCP_Test_Stream) {
	op := s.write
	assert(op != nil)
	n := len(s.source)
	if s.max_write > 0 {
		n = min(n, s.max_write)
	}
	append(&s.output, ..s.source[:n])
	op.result = {
		count = n,
		err   = s.write_error,
	}
	s.write, s.source = nil, nil
	tcp_test_schedule(s, tcp_test_complete, op)
}

tcp_test_submit :: proc(
	data: rawptr,
	op: ^net.Async_Operation,
	kind: net.Async_Operation_Kind,
	buffer: []u8,
	deadline: time.Time,
) -> net.Network_Error {
	s := cast(^TCP_Test_Stream)data
	op.kind, op.pending, op.result, op._owner = kind, true, {}, s
	switch kind {
	case .Read:
		assert(s.read == nil)
		s.read, s.destination = op, buffer
		tcp_test_wake(s)
	case .Write:
		assert(s.write == nil)
		s.write, s.source = op, buffer
		if !s.hold_write {
			tcp_test_send(s)
		}
	case .Close:
		assert(s.read == nil && s.write == nil)
		s.close_calls += 1
		s.closed = true
		tcp_test_schedule(s, tcp_test_complete, op)
	}
	return {}
}

tcp_test_cancel :: proc(data: rawptr, op: ^net.Async_Operation) -> net.Network_Error {
	s := cast(^TCP_Test_Stream)data
	if op == s.read {
		s.read_error = net.Connection_Error.Cancelled
		tcp_test_wake(s)
	} else if op == s.write {
		s.max_write = 1
		s.write_error = net.Connection_Error.Cancelled
		tcp_test_send(s)
	}
	return {}
}

tcp_test_run :: proc(s: ^TCP_Test_Stream) {
	for s.at < len(s.work) {assert(s.at < 100000); w := s.work[s.at]; s.at += 1; w.callback(w.data)}
}

tcp_test_destroy :: proc(s: ^TCP_Test_Stream) {delete(s.work); delete(s.input); delete(s.output)}

tcp_test_io :: proc(op: ^net.Async_Operation) {
	r := cast(^TCP_Test_Result)op.user_data
	r.calls += 1
	r.count = op.result.count
	r.error = op.result.err
}

tcp_test_handshake :: proc(op: ^Server_Async_Handshake_Operation) {
	r := cast(^TCP_Test_Result)op.user_data
	r.calls += 1
	r.error = op.err
	r.detail = op.result
}

tcp_test_op :: proc(r: ^TCP_Test_Result) -> net.Async_Operation {return {callback = tcp_test_io, user_data = r}}

tcp_test_init :: proc(
	t: ^testing.T,
	s: ^Server_Async_Conn,
	stream: ^TCP_Test_Stream,
	a: ^TCP_Test_Audit,
	store: ^credential_store.Store,
	source := Server_Async_Config{},
) {
	config := source
	config.store = store
	config.credential_time = time.from_nanoseconds(1790000000 * 1000000000)
	testing.expect_value(
		t,
		engine_server_async_server(
			s,
			{data = stream, submit = tcp_test_submit, cancel = tcp_test_cancel},
			{data = stream, schedule = tcp_test_schedule},
			config,
			{tcp_test_allocate, a},
		),
		.None,
	)
}

tcp_test_clean :: proc(t: ^testing.T, s: ^Server_Async_Conn, a: ^TCP_Test_Audit) {
	testing.expect_value(t, a.live, 0)
	testing.expect(t, !a.dirty && !a.bad_free)
	testing.expect_value(t, server_async_stats(s).live_bytes, 0)
}

tcp_test_close :: proc(t: ^testing.T, s: ^Server_Async_Conn, stream: ^TCP_Test_Stream, a: ^TCP_Test_Audit) {
	r: TCP_Test_Result
	op := tcp_test_op(&r)
	testing.expect_value(t, net.async_close(server_async_connection(s), &op), nil)
	testing.expect_value(t, r.calls, 0)
	tcp_test_run(stream)
	testing.expect_value(t, r.calls, 1)
	tcp_test_clean(t, s, a)
}

tcp_test_plain :: proc(stream: ^TCP_Test_Stream, kind: TLS_Content_Type, body: []u8) {
	header := record_header_encode({content_type = kind, legacy_version = LEGACY_TLS_1_2, length = u16(len(body))})
	append(&stream.input, ..header[:])
	append(&stream.input, ..body)
	tcp_test_wake(stream)
}

tcp_test_record :: proc(stream: ^TCP_Test_Stream, protection: ^Record_Protection, kind: TLS_Content_Type, body: []u8) {
	wire: [RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE]u8
	n, e := engine_record_seal(protection, wire[:], kind, body)
	assert(e == .None)
	append(&stream.input, ..wire[:n])
	tcp_test_wake(stream)
}

// A separate client-side transcript/keys, using only emitted TLS records and
// the fixture's client key, constructs an actual Finished for driver tests.
tcp_test_establish :: proc(
	t: ^testing.T,
	s: ^Server_Async_Conn,
	stream: ^TCP_Test_Stream,
	a: ^TCP_Test_Audit,
	store: ^credential_store.Store,
	bad_finished := false,
) -> (
	write: Record_Protection,
	read: Record_Protection,
	secrets: Application_Secrets,
) {
	tcp_test_init(t, s, stream, a, store)
	storage: [1024]u8
	hello, private := flight_test_hello(storage[:])
	tcp_test_plain(stream, .Handshake, hello)
	result: TCP_Test_Result
	op := Server_Async_Handshake_Operation {
		callback  = tcp_test_handshake,
		user_data = &result,
	}
	testing.expect_value(t, engine_server_async_handshake(s, &op), nil)
	testing.expect_value(t, result.calls, 0)
	tcp_test_run(stream)
	testing.expect_value(t, result.calls, 0)
	assert(len(stream.output) > 5)
	size := 5 + (int(stream.output[3]) << 8 | int(stream.output[4]))
	sh := stream.output[5:size]
	key := private
	shared: [32]u8
	x25519.scalarmult(shared[:], key[:], sh[len(sh) - 32:])
	hs, e := handshake_secrets_derive(shared, hello, sh)
	assert(e == .None)
	transcript: Handshake_Transcript
	transcript_init(&transcript)
	transcript_update(&transcript, hello)
	transcript_update(&transcript, sh)
	server: Record_Protection
	record_protection_init(&server, hs.server_key, hs.server_iv)
	for at := size; at < len(stream.output); {
		n := 5 + (int(stream.output[at + 3]) << 8 | int(stream.output[at + 4]))
		plain: [MAX_CIPHERTEXT_SIZE]u8
		kind, body, error := engine_record_open(&server, plain[:], stream.output[at:at + n])
		assert(error == .None && kind == .Handshake)
		transcript_update(&transcript, body)
		at += n
	}
	secrets = application_secrets_derive(hs.handshake_secret, transcript_snapshot(&transcript))
	finished: [36]u8
	_, fe := finished_encode(finished[:], hs.client_traffic_secret, transcript_snapshot(&transcript))
	assert(fe == .None)
	client: Record_Protection
	record_protection_init(&client, hs.client_key, hs.client_iv)
	if bad_finished {
		finished[35] ~= 1
	}
	tcp_test_record(stream, &client, .Handshake, finished[:])
	tcp_test_run(stream)
	testing.expect_value(t, result.calls, 1)
	testing.expect_value(t, result.error, net.Network_Error(net.Connection_Error.Protocol_Failed) if bad_finished else nil)
	testing.expect_value(t, server_async_connection_state(s).handshake_complete, !bad_finished)
	testing.expect_value(t, server_async_stats(s).engine.live_bytes, 0)
	record_protection_init(&write, secrets.client_key, secrets.client_iv)
	record_protection_init(&read, secrets.server_key, secrets.server_iv)
	return
}

@(test)
server_async_initialization_size_and_deferred_close :: proc(t: ^testing.T) {
	fmt.printf(
		"async server owner=%d keys=%d record wire=%d default budget=%d\n",
		size_of(Server_Async_Conn),
		size_of(Server_Async_Keys),
		RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE,
		SERVER_ASYNC_MAX_OWNED_BYTES,
	)
	testing.expect(t, size_of(Server_Async_Conn) <= 4096)
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	stream: TCP_Test_Stream
	defer tcp_test_destroy(&stream)
	a := TCP_Test_Audit {
		backing = context.allocator,
	}
	s: Server_Async_Conn
	for config in ([]Server_Async_Config {
			{parameters = {mode = .QUIC}},
			{handshake_timeout = -1},
			{max_owned_bytes = 1023},
			{max_handshake_records = 65537},
			{parameters = {alpn_protocols = []string{"x", "x"}}},
		}) {
		c := config
		c.store = store
		testing.expect_value(
			t,
			engine_server_async_server(
				&s,
				{data = &stream, submit = tcp_test_submit, cancel = tcp_test_cancel},
				{data = &stream, schedule = tcp_test_schedule},
				c,
				{tcp_test_allocate, &a},
			),
			.Invalid_Config,
		)
		testing.expect(t, s._self == nil)
	}
	tcp_test_init(t, &s, &stream, &a, store)
	testing.expect_value(t, a.calls, 0)
	alias := s
	testing.expect(t, server_async_connection(&alias).submit == nil)
	tcp_test_close(t, &s, &stream, &a)
	testing.expect_value(t, a.calls, 0)
}

@(test)
server_async_authenticated_records_buffering_and_overlap :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	stream := TCP_Test_Stream {
		fragment = 1,
	}
	defer tcp_test_destroy(&stream)
	a := TCP_Test_Audit {
		backing = context.allocator,
	}
	s: Server_Async_Conn
	peer, receiver, _ := tcp_test_establish(t, &s, &stream, &a, store)
	ss, _ := credential_store.stats(store)
	testing.expect_value(t, ss.active_leases, 0)
	input: [40000]u8
	for &b, i in input[:] {b = u8(i)}
	read_result, write_result: TCP_Test_Result
	rop, wop := tcp_test_op(&read_result), tcp_test_op(&write_result)
	buffer: [3]u8
	testing.expect_value(t, net.async_read(server_async_connection(&s), &rop, buffer[:]), nil)
	testing.expect_value(t, net.async_write(server_async_connection(&s), &wop, input[:]), nil)
	start := len(stream.output)
	tcp_test_record(&stream, &peer, .Application_Data, []u8{1, 2, 3, 4, 5})
	tcp_test_run(&stream)
	testing.expect_value(t, read_result.calls, 1)
	testing.expect_value(t, buffer, [3]u8{1, 2, 3})
	testing.expect_value(t, write_result.calls, 1)
	testing.expect_value(t, write_result.count, 40000)
	copied := 0
	for at := start; at < len(stream.output); {
		n := 5 + (int(stream.output[at + 3]) << 8 | int(stream.output[at + 4]))
		plain: [MAX_CIPHERTEXT_SIZE]u8
		kind, body, e := engine_record_open(&receiver, plain[:], stream.output[at:at + n])
		testing.expect_value(t, e, .None)
		testing.expect_value(t, kind, .Application_Data)
		testing.expect_value(t, string(body), string(input[copied:copied + len(body)]))
		copied += len(body)
		at += n
	}
	testing.expect_value(t, copied, 40000)
	testing.expect_value(t, net.async_read(server_async_connection(&s), &rop, buffer[:]), nil)
	testing.expect_value(t, read_result.calls, 1)
	tcp_test_run(&stream)
	testing.expect_value(t, read_result.calls, 2)
	testing.expect_value(t, read_result.count, 2)
	testing.expect_value(t, string(buffer[:2]), "\x04\x05")
	tcp_test_close(t, &s, &stream, &a)
}

@(test)
server_async_partial_record_cancel_timeout_and_resume :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for mode in 0 ..< 3 {
		stream: TCP_Test_Stream
		defer tcp_test_destroy(&stream)
		a := TCP_Test_Audit {
			backing = context.allocator,
		}
		s: Server_Async_Conn
		peer, _, _ := tcp_test_establish(t, &s, &stream, &a, store)
		wire: [128]u8
		n, e := engine_record_seal(&peer, wire[:], .Application_Data, []u8{7, 8, 9})
		assert(e == .None)
		prefix := 3 if mode == 0 else 9
		append(&stream.input, ..wire[:prefix])
		r: TCP_Test_Result
		op := tcp_test_op(&r)
		buffer: [3]u8
		net.async_read(server_async_connection(&s), &op, buffer[:])
		tcp_test_run(&stream)
		if mode == 2 {
			stream.read_error = net.TCP_Recv_Error.Timeout
			tcp_test_wake(&stream)
		} else {
			net.async_cancel(server_async_connection(&s), &op)
		}
		tcp_test_run(&stream)
		testing.expect_value(t, r.calls, 1)
		testing.expect_value(t, r.error, net.Network_Error(net.TCP_Recv_Error.Timeout) if mode == 2 else net.Network_Error(net.Connection_Error.Cancelled))
		stream.read_error = {}
		append(&stream.input, ..wire[prefix:n])
		tcp_test_wake(&stream)
		net.async_read(server_async_connection(&s), &op, buffer[:])
		tcp_test_run(&stream)
		testing.expect_value(t, r.calls, 2)
		testing.expect_value(t, r.error, nil)
		testing.expect_value(t, buffer, [3]u8{7, 8, 9})
		tcp_test_close(t, &s, &stream, &a)
	}
}

@(test)
server_async_partial_write_is_terminal_and_full_record_wins :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for mode in 0 ..< 3 {
		stream: TCP_Test_Stream
		defer tcp_test_destroy(&stream)
		a := TCP_Test_Audit {
			backing = context.allocator,
		}
		s: Server_Async_Conn
		tcp_test_establish(t, &s, &stream, &a, store)
		stream.write_error = net.Connection_Error.Cancelled
		if mode < 2 {
			stream.max_write = 3
		}
		if mode == 1 {
			stream.write_error = {}
		}
		r: TCP_Test_Result
		op := tcp_test_op(&r)
		net.async_write(server_async_connection(&s), &op, []u8{1, 2, 3})
		tcp_test_run(&stream)
		testing.expect_value(t, r.calls, 1)
		if mode < 2 {
			testing.expect(t, r.error != nil)
			testing.expect_value(t, r.count, 0)
			testing.expect(t, stream.closed)
			tcp_test_clean(t, &s, &a)
		} else {
			testing.expect_value(t, r.error, nil)
			testing.expect_value(t, r.count, 3)
		}
		stream.write_error = {}
		stream.max_write = 0
		tcp_test_close(t, &s, &stream, &a)
	}
}

@(test)
server_async_key_update_role_order_and_boundaries :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	stream: TCP_Test_Stream
	defer tcp_test_destroy(&stream)
	a := TCP_Test_Audit {
		backing = context.allocator,
	}
	s: Server_Async_Conn
	peer, receiver, secrets := tcp_test_establish(t, &s, &stream, &a, store)
	r: TCP_Test_Result
	op := tcp_test_op(&r)
	buffer: [4]u8
	net.async_read(server_async_connection(&s), &op, buffer[:])
	at := len(stream.output)
	tcp_test_record(&stream, &peer, .Handshake, []u8{24, 0})
	tcp_test_record(&stream, &peer, .Handshake, []u8{0, 1, 1})
	new_read := traffic_secret_update(secrets.client_traffic_secret)
	key, iv := traffic_key_iv(new_read)
	record_protection_init(&peer, key, iv)
	tcp_test_record(&stream, &peer, .Application_Data, []u8{9, 8, 7, 6})
	tcp_test_run(&stream)
	testing.expect_value(t, r.error, nil)
	testing.expect_value(t, buffer, [4]u8{9, 8, 7, 6})
	plain: [128]u8
	kind, body, e := engine_record_open(&receiver, plain[:], stream.output[at:])
	testing.expect_value(t, e, .None)
	testing.expect_value(t, kind, .Handshake)
	testing.expect_value(t, string(body), "\x18\x00\x00\x01\x00")
	updated := traffic_secret_update(secrets.server_traffic_secret)
	key, iv = traffic_key_iv(updated)
	record_protection_init(&receiver, key, iv)
	at = len(stream.output)
	testing.expect_value(t, engine_server_async_key_update(&s, true), nil)
	tcp_test_run(&stream)
	kind, body, e = engine_record_open(&receiver, plain[:], stream.output[at:])
	testing.expect_value(t, e, .None)
	testing.expect_value(t, string(body), "\x18\x00\x00\x01\x01")
	testing.expect_value(t, server_async_stats(&s).sent_key_updates, 2)
	testing.expect_value(t, server_async_stats(&s).received_key_updates, 1)
	tcp_test_close(t, &s, &stream, &a)
}

@(test)
server_async_protocol_truncation_close_and_post_handshake_failure :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for mode in 0 ..< 5 {
		stream: TCP_Test_Stream
		defer tcp_test_destroy(&stream)
		a := TCP_Test_Audit {
			backing = context.allocator,
		}
		s: Server_Async_Conn
		peer, _, _ := tcp_test_establish(t, &s, &stream, &a, store)
		r: TCP_Test_Result
		op := tcp_test_op(&r)
		buffer: [4]u8
		net.async_read(server_async_connection(&s), &op, buffer[:])
		if mode == 0 {
			stream.read_error = net.Connection_Error.Peer_Closed
			tcp_test_wake(&stream)
		}
		if mode == 1 {
			tcp_test_record(&stream, &peer, .Alert, []u8{1, 0})
		}
		if mode == 2 {
			tcp_test_record(&stream, &peer, .Handshake, []u8{4, 0, 0, 1, 0})
		}
		if mode == 3 {
			tcp_test_record(&stream, &peer, .Handshake, []u8{24, 0, 0, 1, 2})
		}
		if mode == 4 {
			tcp_test_record(&stream, &peer, .Application_Data, []u8{1})
			stream.input[len(stream.input) - 1] ~= 1
		}
		tcp_test_run(&stream)
		testing.expect_value(t, r.calls, 1)
		testing.expect_value(t, r.error, net.Network_Error(net.Connection_Error.Peer_Closed) if mode == 1 else net.Network_Error(net.Connection_Error.Protocol_Failed))
		if mode != 1 {
			tcp_test_clean(t, &s, &a)
		}
		tcp_test_close(t, &s, &stream, &a)
	}
}

@(test)
server_async_allocation_failure_and_handshake_cancel :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for point in 1 ..= 6 {
		for fault in 0 ..< 4 {
			stream: TCP_Test_Stream
			defer tcp_test_destroy(&stream)
			a := TCP_Test_Audit {
				backing = context.allocator,
			}
			s: Server_Async_Conn
			if fault == 0 {
				a.fail_at = point
			} else if fault < 3 {
				a.delta_at = point
				a.delta = -1 if fault == 1 else 17
			} else {
				a.error_at = point
			}
			tcp_test_init(t, &s, &stream, &a, store)
			storage: [1024]u8
			hello, _ := flight_test_hello(storage[:])
			tcp_test_plain(&stream, .Handshake, hello)
			r: TCP_Test_Result
			op := Server_Async_Handshake_Operation {
				callback  = tcp_test_handshake,
				user_data = &r,
			}
			engine_server_async_handshake(&s, &op)
			tcp_test_run(&stream)
			if point == 6 && r.calls == 0 {
				secret: [32]u8
				copy(secret[:], s._engine._flight.client_handshake_secret[:32])
				key, iv := traffic_key_iv(secret)
				client: Record_Protection
				record_protection_init(&client, key, iv)
				bad: [36]u8
				tcp_test_record(&stream, &client, .Handshake, bad[:])
				tcp_test_run(&stream)
			}
			testing.expect_value(t, r.calls, 1)
			testing.expect(t, r.error != nil)
			tcp_test_clean(t, &s, &a)
			ss, _ := credential_store.stats(store)
			testing.expect_value(t, ss.active_leases, 0)
			tcp_test_close(t, &s, &stream, &a)
		}
	}
}

@(test)
server_async_handshake_policy_budget_deadline_and_bad_finished :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for mode in 0 ..< 7 {
		stream: TCP_Test_Stream
		defer tcp_test_destroy(&stream)
		a := TCP_Test_Audit {
			backing = context.allocator,
		}
		s: Server_Async_Conn
		config: Server_Async_Config
		if mode == 0 {
			config.max_owned_bytes = 1024
		}
		if mode == 1 {
			config.max_handshake_records = 1
		}
		tcp_test_init(t, &s, &stream, &a, store, config)
		storage: [1024]u8
		hello, _ := flight_test_hello(storage[:])
		if mode == 1 {
			tcp_test_plain(&stream, .Handshake, hello[:20])
			tcp_test_plain(&stream, .Handshake, hello[20:])
		} else if mode < 3 {
			tcp_test_plain(&stream, .Handshake, hello)
		}
		if mode == 3 {
			append(&stream.input, ..([]u8{22, 3, 3, 255, 255}))
		}
		if mode == 4 {
			tcp_test_plain(&stream, .Change_Cipher_Spec, []u8{1})
		}
		if mode == 5 {
			tcp_test_plain(&stream, .Handshake, []u8{2, 0, 0, 0})
		}
		r: TCP_Test_Result
		op := Server_Async_Handshake_Operation {
			callback  = tcp_test_handshake,
			user_data = &r,
		}
		deadline := time.Time{}
		if mode == 2 {
			deadline = time.time_add(time.now(), -time.Second)
		}
		engine_server_async_handshake(&s, &op, deadline)
		tcp_test_run(&stream)
		if mode == 6 {
			testing.expect_value(t, engine_server_async_cancel_handshake(&s), nil)
			tcp_test_run(&stream)
		}
		testing.expect_value(t, r.calls, 1)
		testing.expect(t, r.error != nil)
		if mode == 2 {
			testing.expect_value(t, r.error, net.Network_Error(net.TCP_Recv_Error.Timeout))
		}
		if mode == 3 {
			testing.expect_value(t, server_async_stats(&s).engine.allocation_attempts, 0)
			testing.expect_value(t, a.calls, 1)
			testing.expect_value(t, string(stream.output[:]), "\x15\x03\x03\x00\x02\x02\x16")
		}
		tcp_test_clean(t, &s, &a)
		tcp_test_close(t, &s, &stream, &a)
	}
	stream: TCP_Test_Stream
	defer tcp_test_destroy(&stream)
	a := TCP_Test_Audit {
		backing = context.allocator,
	}
	s: Server_Async_Conn
	_, reader, _ := tcp_test_establish(t, &s, &stream, &a, store, true)
	plain: [64]u8
	kind, body, error := engine_record_open(&reader, plain[:], stream.output[len(stream.output) - 24:])
	testing.expect_value(t, error, .None)
	testing.expect_value(t, kind, .Alert)
	testing.expect_value(t, string(body), "\x02\x33")
	testing.expect_value(t, engine_server_async_failure(&s).engine, .Finished_Failed)
	tcp_test_clean(t, &s, &a)
	tcp_test_close(t, &s, &stream, &a)
}

TCP_Test_Free :: struct {
	result: TCP_Test_Result,
	owner:  ^Server_Async_Conn,
}

tcp_test_free_close :: proc(op: ^net.Async_Operation) {
	state := cast(^TCP_Test_Free)op.user_data
	state.result.calls += 1
	state.result.error = op.result.err
	assert(server_async_stats(state.owner).live_bytes == 0)
	free(state.owner)
	state.owner = nil
}

@(test)
server_async_pending_close_callback_can_free_owner :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for established in ([]bool{true, false}) {
		stream: TCP_Test_Stream
		defer tcp_test_destroy(&stream)
		a := TCP_Test_Audit {
			backing = context.allocator,
		}
		s := new(Server_Async_Conn)
		if established {
			tcp_test_establish(t, s, &stream, &a, store)
		} else {
			tcp_test_init(t, s, &stream, &a, store)
		}
		hr: TCP_Test_Result
		hs := Server_Async_Handshake_Operation {
			callback  = tcp_test_handshake,
			user_data = &hr,
		}
		r, w: TCP_Test_Result
		rop, wop := tcp_test_op(&r), tcp_test_op(&w)
		buffer: [8]u8
		if established {
			net.async_read(server_async_connection(s), &rop, buffer[:])
			stream.hold_write = true
			net.async_write(server_async_connection(s), &wop, []u8{1, 2, 3, 4})
		} else {
			engine_server_async_handshake(s, &hs)
		}
		tcp_test_run(&stream)
		state := TCP_Test_Free {
			owner = s,
		}
		op := net.Async_Operation {
			callback  = tcp_test_free_close,
			user_data = &state,
		}
		net.async_close(server_async_connection(s), &op)
		tcp_test_run(&stream)
		testing.expect_value(t, state.result.calls, 1)
		testing.expect(t, state.owner == nil)
		testing.expect_value(t, a.live, 0)
		testing.expect(t, !a.dirty && !a.bad_free)
		if established {
			testing.expect_value(t, r.calls, 1)
			testing.expect_value(t, w.calls, 1)
		} else {
			testing.expect_value(t, hr.calls, 1)
		}
	}
}

@(test)
server_async_key_usage_reservation_and_control_caps :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for mode in 0 ..< 3 {
		stream: TCP_Test_Stream
		defer tcp_test_destroy(&stream)
		a := TCP_Test_Audit {
			backing = context.allocator,
		}
		s: Server_Async_Conn
		peer, receiver, secrets := tcp_test_establish(t, &s, &stream, &a, store)
		r: TCP_Test_Result
		op := tcp_test_op(&r)
		buffer: [8]u8
		if mode == 0 {
			server_async_keys(&s).write.seq = AEAD_REKEY_SEQ[.AES_GCM_128] - 1
			receiver.seq = AEAD_REKEY_SEQ[.AES_GCM_128] - 1
			at := len(stream.output)
			net.async_write(server_async_connection(&s), &op, []u8{9, 8})
			tcp_test_run(&stream)
			testing.expect_value(t, r.error, nil)
			first := 5 + (int(stream.output[at + 3]) << 8 | int(stream.output[at + 4]))
			plain: [128]u8
			kind, body, e := engine_record_open(&receiver, plain[:], stream.output[at:at + first])
			testing.expect_value(t, e, .None)
			testing.expect_value(t, kind, .Handshake)
			testing.expect_value(t, string(body), "\x18\x00\x00\x01\x00")
			secret := traffic_secret_update(secrets.server_traffic_secret)
			key, iv := traffic_key_iv(secret)
			record_protection_init(&receiver, key, iv)
			kind, body, e = engine_record_open(&receiver, plain[:], stream.output[at + first:])
			testing.expect_value(t, e, .None)
			testing.expect_value(t, kind, .Application_Data)
			testing.expect_value(t, string(body), "\x09\x08")
		} else {
			net.async_read(server_async_connection(&s), &op, buffer[:])
			if mode == 1 {
				tcp_test_record(&stream, &peer, .Handshake, []u8{24, 0, 0, 1, 0, 24, 0, 0, 1, 0})
			} else {
				s._non_application_records = MAX_NON_APPLICATION_RECORDS
				tcp_test_record(&stream, &peer, .Application_Data, nil)
			}
			tcp_test_run(&stream)
			testing.expect_value(t, r.error, net.Network_Error(net.Connection_Error.Protocol_Failed))
		}
		tcp_test_close(t, &s, &stream, &a)
	}
}

@(test)
server_async_maximum_retry_budget_is_charged_and_erased :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	first, second: [65536]u8
	ch1 := retry_test_hello(first[:], .Secp256r1, false)
	retry_test_pad(first[:], ch1)
	ch2 := retry_test_hello(second[:], .Secp256r1, true)
	retry_test_pad(second[:], ch2)
	for limited in ([]bool{false, true}) {
		stream: TCP_Test_Stream
		defer tcp_test_destroy(&stream)
		a := TCP_Test_Audit {
			backing = context.allocator,
		}
		s: Server_Async_Conn
		config: Server_Async_Config
		if limited {
			config.max_owned_bytes = 166409
		}
		tcp_test_init(t, &s, &stream, &a, store, config)
		for at := 0;
		    at < len(first);
		    at += MAX_PLAINTEXT_SIZE {tcp_test_plain(&stream, .Handshake, first[at:at + MAX_PLAINTEXT_SIZE])}
		r: TCP_Test_Result
		op := Server_Async_Handshake_Operation {
			callback  = tcp_test_handshake,
			user_data = &r,
		}
		engine_server_async_handshake(&s, &op)
		tcp_test_run(&stream)
		testing.expect_value(t, r.calls, 0)
		for at := 0;
		    at < len(second);
		    at += MAX_PLAINTEXT_SIZE {tcp_test_plain(&stream, .Handshake, second[at:at + MAX_PLAINTEXT_SIZE])}
		tcp_test_run(&stream)
		if limited {
			testing.expect_value(t, r.calls, 1)
			testing.expect(t, r.error != nil)
			testing.expect(t, server_async_stats(&s).peak_bytes <= 166409)
		} else {
			testing.expect_value(t, server_async_stats(&s).peak_bytes, 166410)
			fmt.printf(
				"async server max retry+record buffers=%d accepted bytes; owner=%d\n",
				server_async_stats(&s).peak_bytes,
				size_of(s),
			)
			engine_server_async_cancel_handshake(&s)
			tcp_test_run(&stream)
		}
		tcp_test_clean(t, &s, &a)
		tcp_test_close(t, &s, &stream, &a)
	}
}
