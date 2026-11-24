package tls

import "core:mem"
import "core:net"
import "core:time"

/*
The non-blocking client and server behind the package's `Error`.

An `Async_Conn` and a `Server_Async_Conn` never block: they run on the caller's
executor over a `net.Async_Connection`, and each operation completes through
its callback.
*/

// async_client prepares `conn` to speak TLS over a non-blocking transport.
@(require_results)
async_client :: proc(
	conn: ^Async_Conn,
	underlying: net.Async_Connection,
	executor: net.Async_Executor,
	config: Config,
	allocator := context.allocator,
) -> Error {
	return client_error(engine_async_client(conn, underlying, executor, config, allocator))
}

// async_handshake starts the handshake; `op` completes on the executor.
@(require_results)
async_handshake :: proc(conn: ^Async_Conn, op: ^Async_Handshake_Operation, deadline := time.Time{}) -> Error {
	return transport_error(engine_async_handshake(conn, op, deadline))
}

// async_cancel_handshake cancels a handshake in progress.
@(require_results)
async_cancel_handshake :: proc(conn: ^Async_Conn) -> Error {
	return transport_error(engine_async_cancel_handshake(conn))
}

// async_failure returns the error status of an Async_Conn.
@(require_results)
async_failure :: proc(conn: ^Async_Conn) -> Error {
	return io_error(engine_async_failure(conn))
}

// server_async_server prepares `s` to accept TLS over a non-blocking transport.
@(require_results)
server_async_server :: proc(
	s: ^Server_Async_Conn,
	transport: net.Async_Connection,
	executor: net.Async_Executor,
	source: Server_Async_Config,
	allocator: mem.Allocator,
) -> Error {
	return server_async_init_error(engine_server_async_server(s, transport, executor, source, allocator))
}

// server_async_handshake starts the handshake; `op` completes on the executor.
@(require_results)
server_async_handshake :: proc(
	s: ^Server_Async_Conn,
	op: ^Server_Async_Handshake_Operation,
	deadline := time.Time{},
) -> Error {
	return transport_error(engine_server_async_handshake(s, op, deadline))
}

// server_async_cancel_handshake cancels a handshake in progress.
@(require_results)
server_async_cancel_handshake :: proc(s: ^Server_Async_Conn) -> Error {
	return transport_error(engine_server_async_cancel_handshake(s))
}

// server_async_key_update rekeys the sending direction, and asks the peer to rekey when `request_peer` is set.
@(require_results)
server_async_key_update :: proc(s: ^Server_Async_Conn, request_peer := false) -> Error {
	return transport_error(engine_server_async_key_update(s, request_peer))
}

// server_async_failure returns the error status of a Server_Async_Conn.
@(require_results)
server_async_failure :: proc(s: ^Server_Async_Conn) -> Error {
	return server_async_failure_error(engine_server_async_failure(s))
}

@(private, require_results)
server_async_init_error :: proc(failure: Server_Async_Init_Error) -> Error {
	switch failure {
	case .None:
		return nil
	case .Invalid_Owner, .Invalid_State, .Invalid_Transport:
		return General_Error.Invalid_State
	case .Invalid_Config:
		return General_Error.Invalid_Config
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
server_async_failure_error :: proc(failure: Server_Async_Failure) -> Error {
	switch failure.kind {
	case .None:
		return nil
	case .Invalid_State:
		return General_Error.Invalid_State
	case .Handshake:
		return failed(server_handshake_error(failure.engine))
	case .Record:
		if failure.record == .Record_Oversized {
			return Protocol_Error.Record_Overflow
		}
		if failure.protection != .None {
			return Protocol_Error.Bad_Record_Mac
		}
		return Protocol_Error.Unexpected_Message
	case .Transport:
		return failed(transport_error(failure.transport))
	case .Limit:
		return General_Error.Limit_Exceeded
	case .Unexpected_EOF:
		return net.TCP_Recv_Error.Connection_Closed
	case .Peer_Alert:
		return failed(socket_peer_alert_error(failure.alert_level, failure.alert_description))
	case .Post_Handshake:
		return Protocol_Error.Decode_Error
	}
	return Protocol_Error.Internal_Error
}
