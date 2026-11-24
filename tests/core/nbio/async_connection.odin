package tests_nbio

import "core:nbio"
import "core:net"
import "core:testing"
import "core:time"
import "core:thread"
import "core:sync"

async_test_pair :: proc(t: ^testing.T) -> (client, peer: net.TCP_Socket, ok: bool) {
	listener, listen_err := net.listen_tcp({net.IP4_Loopback, 0})
	ev(t, listen_err, nil)
	if listen_err != nil do return
	defer net.close(listener)
	ep, endpoint_err := net.bound_endpoint(listener)
	ev(t, endpoint_err, nil)
	if endpoint_err != nil do return
	dial_err: net.Network_Error
	client, dial_err = net.dial_tcp(ep)
	ev(t, dial_err, nil)
	if dial_err != nil do return
	accept_err: net.Accept_Error
	peer, _, accept_err = net.accept_tcp(listener)
	ev(t, accept_err, nil)
	if accept_err != nil {
		net.close(client)
		return
	}
	return client, peer, true
}

Async_Test_Result :: struct {
	calls: int,
	count: int,
	err:   net.Connection_Error_Kind,
}

async_test_done :: proc(op: ^net.Async_Operation) {
	s := cast(^Async_Test_Result)op.user_data
	s.calls += 1
	s.count = op.result.count
	s.err = op.result.err.kind
	assert(!op.pending)
}

@(test)
async_connection_read_write_overlap :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		client, peer, ok := async_test_pair(t)
		if !ok do return
		defer net.close(client)
		tcp: nbio.TCP_Async_Connection
		ev(t, nbio.tcp_async_connection_init(&tcp, peer), nil)
		conn := nbio.tcp_async_connection(&tcp)
		r, w, c: Async_Test_Result
		read_op := net.Async_Operation {
			callback  = async_test_done,
			user_data = &r,
		}
		write_op := net.Async_Operation {
			callback  = async_test_done,
			user_data = &w,
		}
		close_op := net.Async_Operation {
			callback  = async_test_done,
			user_data = &c,
		}
		buffer: [4]u8
		deadline := time.time_add(time.now(), time.Second)
		ev(t, net.async_read(conn, &read_op, buffer[:], deadline).kind, .None)
		ev(t, net.async_write(conn, &write_op, []u8{9}, deadline).kind, .None)
		// Write completion can run while the read remains pending.
		for w.calls == 0 {ev(t, nbio.tick(time.Millisecond), nil)}
		ev(t, w.err, .None)
		ev(t, w.count, 1)
		ev(t, r.calls, 0)
		ev(t, net.async_cancel(conn, &read_op).kind, .None)
		ev(t, net.async_cancel(conn, &read_op).kind, .None)
		ev(t, nbio.run(), nil)
		ev(t, r.calls, 1)
		ev(t, r.err, .Cancelled)
		// Reuse the same operation from the caller after its callback.
		_, send_err := net.send_tcp(client, []u8{7})
		ev(t, send_err, nil)
		ev(t, net.async_read(conn, &read_op, buffer[:], deadline).kind, .None)
		ev(t, nbio.run(), nil)
		ev(t, r.calls, 2)
		ev(t, r.err, .None)
		ev(t, buffer[0], u8(7))
		ev(t, net.async_close(conn, &close_op).kind, .None)
		ev(t, nbio.run(), nil)
		ev(t, c.calls, 1)
		ev(t, c.err, .None)
	}
}

@(test)
async_connection_close_drains_read :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		client, peer, ok := async_test_pair(t)
		if !ok do return
		defer net.close(client)
		tcp: nbio.TCP_Async_Connection
		ev(t, nbio.tcp_async_connection_init(&tcp, peer), nil)
		conn := nbio.tcp_async_connection(&tcp)
		State :: struct {
			calls:     int,
			read_done: bool,
		}
		state: State
		read_op := net.Async_Operation {
			user_data = &state,
			callback = proc(op: ^net.Async_Operation) {
				s := cast(^State)op.user_data
				assert(op.result.err.kind == .Closed)
				s.read_done = true
				s.calls += 1
			},
		}
		close_op := net.Async_Operation {
			user_data = &state,
			callback = proc(op: ^net.Async_Operation) {
				s := cast(^State)op.user_data
				assert(s.read_done && s.calls == 1)
				assert(op.result.err.kind == .None)
				s.calls += 1
			},
		}
		buffer: [1]u8
		ev(t, net.async_read(conn, &read_op, buffer[:]).kind, .None)
		ev(t, net.async_close(conn, &close_op).kind, .None)
		ev(t, state.calls, 0)
		rejected := net.Async_Operation {
			callback = async_test_done,
		}
		ev(t, net.async_read(conn, &rejected, buffer[:]).kind, .Closed)
		e(t, !rejected.pending)
		ev(t, nbio.run(), nil)
		ev(t, state.calls, 2)
	}
}

@(test)
async_connection_deadline_and_admission :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		client, peer, ok := async_test_pair(t)
		if !ok do return
		defer net.close(client)
		tcp: nbio.TCP_Async_Connection
		ev(t, nbio.tcp_async_connection_init(&tcp, peer), nil)
		conn := nbio.tcp_async_connection(&tcp)
		r, c: Async_Test_Result
		read_op := net.Async_Operation {
			callback  = async_test_done,
			user_data = &r,
		}
		other := net.Async_Operation {
			callback = async_test_done,
		}
		close_op := net.Async_Operation {
			callback  = async_test_done,
			user_data = &c,
		}
		buffer: [1]u8
		ev(t, net.async_read(conn, &read_op, buffer[:], time.time_add(time.now(), 10 * time.Millisecond)).kind, .None)
		ev(t, net.async_read(conn, &read_op, buffer[:]).kind, .Operation_Pending)
		ev(t, net.async_read(conn, &other, buffer[:]).kind, .Operation_Pending)
		e(t, !other.pending)
		ev(t, nbio.run(), nil)
		ev(t, r.calls, 1)
		ev(t, r.err, .Timeout)
		ev(t, net.async_close(conn, &close_op).kind, .None)
		ev(t, nbio.run(), nil)
	}
}

@(test)
async_connection_close_drains_blocked_write :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		client, peer, ok := async_test_pair(t)
		if !ok do return
		defer net.close(client)
		ev(t, net.set_option(peer, .Send_Buffer_Size, 4096), nil)
		ev(t, net.set_option(client, .Receive_Buffer_Size, 4096), nil)
		tcp: nbio.TCP_Async_Connection
		ev(t, nbio.tcp_async_connection_init(&tcp, peer), nil)
		conn := nbio.tcp_async_connection(&tcp)
		// Match the existing nbio saturation test: exceed loopback autotuning.
		payload := make([]u8, 64 << 20)
		defer delete(payload)
		State :: struct {
			write_done: bool,
			close_done: bool,
			count:      int,
			err:        net.Connection_Error_Kind,
		}
		state: State
		write_op := net.Async_Operation {
			user_data = &state,
			callback = proc(op: ^net.Async_Operation) {
				s := cast(^State)op.user_data
				s.err = op.result.err.kind
				s.write_done = true
				s.count = op.result.count
			},
		}
		close_op := net.Async_Operation {
			user_data = &state,
			callback = proc(op: ^net.Async_Operation) {
				s := cast(^State)op.user_data
				assert(s.write_done)
				assert(op.result.err.kind == .None)
				s.close_done = true
			},
		}
		ev(t, net.async_write(conn, &write_op, payload).kind, .None)
		ev(t, nbio.tick(0), nil)
		e(t, write_op.pending)
		ev(t, net.async_close(conn, &close_op).kind, .None)
		ev(t, nbio.run(), nil)
		e(t, state.write_done && state.close_done)
		ev(t, state.err, .Closed)
		e(t, state.count < len(payload))
	}
}

@(test)
async_connection_callback_can_free_storage :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		client, peer, ok := async_test_pair(t)
		if !ok do return
		defer net.close(client)
		tcp := new(nbio.TCP_Async_Connection)
		ev(t, nbio.tcp_async_connection_init(tcp, peer), nil)
		conn := nbio.tcp_async_connection(tcp)
		State :: struct {
			tcp:      ^nbio.TCP_Async_Connection,
			conn:     net.Async_Connection,
			close_op: net.Async_Operation,
			buffer:   []u8,
		}
		state := new(State)
		state.tcp, state.conn = tcp, conn
		state.buffer = make([]u8, 1024)
		state.close_op = {
			user_data = state,
			callback = proc(op: ^net.Async_Operation) {
				s := cast(^State)op.user_data
				assert(op.result.err.kind == .None)
				free(s.tcp)
				free(s)
			},
		}
		read_op := new(net.Async_Operation)
		read_op^ = {
			user_data = state,
			callback = proc(op: ^net.Async_Operation) {
				s := cast(^State)op.user_data
				assert(op.result.err.kind == .Cancelled && op.result.count == 0)
				delete(s.buffer)
				assert(net.async_close(s.conn, &s.close_op).kind == .None)
				free(op)
			},
		}
		ev(t, net.async_read(conn, read_op, state.buffer).kind, .None)
		ev(t, net.async_cancel(conn, read_op).kind, .None)
		ev(t, nbio.run(), nil)
	}
}

@(test)
async_connections_share_one_loop :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		N :: 64
		tcps: [N]nbio.TCP_Async_Connection
		clients: [N]net.TCP_Socket
		reads, closes: [N]net.Async_Operation
		buffers: [N][1]u8
		closed := 0
		for i in 0 ..< N {
			client, peer, ok := async_test_pair(t)
			assert(ok)
			clients[i] = client
			ev(t, nbio.tcp_async_connection_init(&tcps[i], peer), nil)
			reads[i] = {
				callback = proc(op: ^net.Async_Operation) {assert(op.result.err.kind == .Closed)},
			}
			closes[i] = {
				user_data = &closed,
				callback = proc(op: ^net.Async_Operation) {
					assert(op.result.err.kind == .None)
					count := cast(^int)op.user_data
					count^ += 1
				},
			}
			conn := nbio.tcp_async_connection(&tcps[i])
			ev(t, net.async_read(conn, &reads[i], buffers[i][:]).kind, .None)
		}
		ev(t, nbio.tick(0), nil)
		for i in 0 ..< N {
			e(t, reads[i].pending)
			conn := nbio.tcp_async_connection(&tcps[i])
			ev(t, net.async_close(conn, &closes[i]).kind, .None)
		}
		ev(t, nbio.run(), nil)
		ev(t, closed, N)
		for client in clients do net.close(client)
	}
}

@(test)
executor_defers_local_completion :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		calls := 0
		executor := nbio.async_executor()
		executor.schedule(executor.data, proc(data: rawptr) {
				count := cast(^int)data
				count^ += 1
			}, &calls)
		ev(t, calls, 0)
		ev(t, nbio.run(), nil)
		ev(t, calls, 1)
	}
}

@(test)
async_connection_reuses_io_record_inside_completion :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		client, peer, ok := async_test_pair(t)
		if !ok do return
		defer net.close(client)
		tcp: nbio.TCP_Async_Connection
		ev(t, nbio.tcp_async_connection_init(&tcp, peer), nil)
		State :: struct {
			t:        ^testing.T,
			conn:     net.Async_Connection,
			close_op: net.Async_Operation,
			buffer:   [1]u8,
			phase:    int,
			closed:   bool,
		}
		state := State {
			t    = t,
			conn = nbio.tcp_async_connection(&tcp),
		}
		state.close_op = {
			user_data = &state,
			callback = proc(op: ^net.Async_Operation) {
				s := cast(^State)op.user_data
				ev(s.t, s.phase, 2)
				ev(s.t, op.result.err.kind, .None)
				s.closed = true
			},
		}
		op := net.Async_Operation {
			user_data = &state,
			callback = proc(op: ^net.Async_Operation) {
				s := cast(^State)op.user_data
				e(s.t, !op.pending)
				ev(s.t, op.result.err.kind, .None)
				ev(s.t, op.result.count, 1)
				if s.phase == 0 {
					ev(s.t, op.kind, .Read)
					ev(s.t, s.buffer[0], u8(7))
					s.phase = 1
					ev(s.t, net.async_write(s.conn, op, s.buffer[:]).kind, .None)
				} else {
					ev(s.t, op.kind, .Write)
					s.phase = 2
					ev(s.t, net.async_close(s.conn, &s.close_op).kind, .None)
				}
			},
		}
		_, send_err := net.send_tcp(client, []u8{7})
		ev(t, send_err, nil)
		ev(t, net.async_read(state.conn, &op, state.buffer[:]).kind, .None)
		ev(t, nbio.run(), nil)
		e(t, state.closed)
		response: [1]u8
		n, recv_err := net.recv_tcp(client, response[:])
		ev(t, recv_err, nil)
		ev(t, n, 1)
		ev(t, response[0], u8(7))
	}
}

@(test)
cross_thread_exec_publishes_each_operation_once :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		N :: 512
		State :: struct {
			calls: int,
		}
		Item :: struct {
			op:    ^nbio.Operation,
			state: ^State,
			seen:  bool,
		}
		state: State
		items: [N]Item
		for &item in items {
			item.state = &state
			item.op = nbio.prep_next_tick(proc(op: ^nbio.Operation) {
				item := cast(^Item)op.user_data[0]
				assert(!item.seen)
				item.seen = true
				item.state.calls += 1
			})
			item.op.user_data[0] = &item
		}
		start: sync.Sema
		producers: [4]^thread.Thread
		for &producer, index in producers {
			producer = thread.create_and_start_with_poly_data3(
			&items,
			index,
			&start,
			proc(items: ^[N]Item, index: int, start: ^sync.Sema) {
				assert(sync.sema_wait_with_timeout(start, 2 * time.Second))
				for i := index; i < N; i += 4 {
					// The owner may recycle op immediately after publication. Only exec's
					// captured loop pointer may be used after its enqueue succeeds.
					nbio.exec(items[i].op)
				}
			},
			)
		}
		sync.post(&start, len(producers))
		deadline := time.time_add(time.now(), 2 * time.Second)
		for state.calls < N {
			assert(time.diff(time.now(), deadline) > 0)
			ev(t, nbio.tick(0), nil)
		}
		for producer in producers do thread.destroy(producer)
		for item in items do e(t, item.seen)
		ev(t, state.calls, N)
	}
}
