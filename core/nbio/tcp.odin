package nbio

import "core:net"
import "core:time"

// One pending read and one pending write; no unbounded internal operation queue.
// All calls belong to the owning loop thread. Keep at a stable address until
// the close callback. Socket ownership transfers only when init succeeds.
// Do not mix direct socket operations with this adapter after initialization.
TCP_Async_Connection :: struct {
	socket:                                           TCP_Socket,
	loop:                                             ^Event_Loop,
	initialized:                                      bool,
	closing, closed:                                  bool,
	read_operation, write_operation, close_operation: ^net.Async_Operation,
	close_started:                                    bool,
	_read_buffers, _write_buffers:                    [1][]byte,
}

tcp_async_connection_init :: proc(tcp: ^TCP_Async_Connection, socket: TCP_Socket) -> Association_Error {
	assert(tcp != nil && !tcp.initialized)
	loop := current_thread_event_loop()
	assert(loop != nil, "acquire the event loop before initializing a connection")
	associate_socket(socket, loop) or_return
	tcp^ = {
		socket      = socket,
		loop        = loop,
		initialized = true,
	}
	return nil
}

tcp_async_connection :: proc(tcp: ^TCP_Async_Connection) -> net.Async_Connection {
	if tcp == nil || !tcp.initialized do return {}
	return {data = tcp, submit = tcp_async_submit, cancel = tcp_async_cancel}
}

@(private)
tcp_async_submit :: proc(
	data: rawptr,
	request: ^net.Async_Operation,
	kind: net.Async_Operation_Kind,
	buffer: []u8,
	deadline: time.Time,
) -> net.Network_Error {
	tcp := cast(^TCP_Async_Connection)data
	assert(tcp.loop == current_thread_event_loop(), "connection used from a different event loop")
	if tcp.closing || tcp.closed do return net.Connection_Error.Closed
	switch kind {
	case .Read:
		if tcp.read_operation != nil do return net.Connection_Error.Operation_Pending
		tcp.read_operation = request
	case .Write:
		if tcp.write_operation != nil do return net.Connection_Error.Operation_Pending
		tcp.write_operation = request
	case .Close:
		tcp.close_operation = request
		tcp.closing = true
	}
	request.kind = kind
	request.pending = true
	request.result = {}
	request._owner = tcp
	request._backend = nil
	if kind == .Close {
		if tcp.read_operation != nil do tcp_async_cancel(tcp, tcp.read_operation)
		if tcp.write_operation != nil do tcp_async_cancel(tcp, tcp.write_operation)
		tcp_async_finish_close(tcp)
		return nil
	}

	op: ^Operation
	buffers := &tcp._read_buffers
	if kind == .Write do buffers = &tcp._write_buffers
	buffers^ = {buffer}
	// Empty operations and already-expired deadlines still complete later.
	if len(buffer) == 0 || deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {
		op = prep_next_tick(tcp_async_io_done, tcp.loop)
		if len(buffer) > 0 do request.result.err = net.Connection_Error.Timeout
	} else if kind == .Read {
		op = prep_recv(tcp.socket, buffers^[:], tcp_async_io_done, l = tcp.loop)
		op.recv.expires = deadline
	} else {
		op = prep_send(tcp.socket, buffers^[:], tcp_async_io_done, all = true, l = tcp.loop)
		op.send.expires = deadline
	}
	op.user_data[0] = request
	op.user_data[1] = tcp
	request._backend = op
	exec(op)
	return nil
}

@(private)
tcp_async_cancel :: proc(data: rawptr, request: ^net.Async_Operation) -> net.Network_Error {
	tcp := cast(^TCP_Async_Connection)data
	assert(tcp.loop == current_thread_event_loop(), "connection used from a different event loop")
	if !request.pending do return nil
	if request._owner != tcp || request.kind == .Close do return net.Connection_Error.Invalid_Operation
	if cancel(cast(^Operation)request._backend) != nil do return net.Connection_Error.Invalid_Operation
	return nil
}

@(private)
tcp_async_io_done :: proc(op: ^Operation) {
	request := cast(^net.Async_Operation)op.user_data[0]
	tcp := cast(^TCP_Async_Connection)op.user_data[1]
	if op.type == .Recv {
		request.result.count = op.recv.received
		err, _ := op.recv.err.(net.TCP_Recv_Error)
		if err == .Timeout {
			request.result.err = net.Connection_Error.Timeout
		} else if err != nil {
			request.result.err = err
		} else if op.recv.received == 0 {
			request.result.err = net.Connection_Error.Peer_Closed
		}
	} else if op.type == .Send {
		request.result.count = op.send.sent
		err, _ := op.send.err.(net.TCP_Send_Error)
		if err == .Timeout {
			request.result.err = net.Connection_Error.Timeout
		} else if err != nil {
			request.result.err = err
		}
	}
	if op.cancelled {
		request.result.err = net.Connection_Error.Closed if tcp.closing else net.Connection_Error.Cancelled
	}
	if request.kind == .Read {
		tcp.read_operation = nil
		tcp._read_buffers = {}
	} else {
		tcp.write_operation = nil
		tcp._write_buffers = {}
	}
	request.pending = false
	request._backend, request._owner = nil, nil
	request.callback(request)
	// The user can close in callback, but cannot free tcp until close completes.
	tcp_async_finish_close(tcp)
}

@(private)
tcp_async_finish_close :: proc(tcp: ^TCP_Async_Connection) {
	if !tcp.closing || tcp.close_started || tcp.read_operation != nil || tcp.write_operation != nil do return
	tcp.close_started = true
	close_poly(tcp.socket, tcp, tcp_async_close_done, l = tcp.loop)
}

@(private)
tcp_async_close_done :: proc(op: ^Operation, tcp: ^TCP_Async_Connection) {
	request := tcp.close_operation
	tcp.close_operation = nil
	tcp.closed = true
	request.pending = false
	request._owner = nil
	if op.close.err != nil do request.result.err = net.Connection_Error.Close_Failed
	request.callback(request)
	// Both request and tcp can have been freed by callback.
}
