package tls

import "core:net"
import "core:time"

/*
The client connection, `Conn`, behind the same `Error` as `Socket`.

A `Conn` runs the handshake and the record layer on the caller's thread over
any `net.Connection`, where a `Socket` is tied to a TCP socket. Like a Socket
it reports every failure as one `Error`: a `Protocol_Error` for an alert or a
violation of the protocol, a `General_Error` for a local condition, and the
transport's or the allocator's own error otherwise. An error from the handshake
or from `read` and `write` is fatal: close the connection.
*/

// config_validate reports whether a Config can start a connection.
@(require_results)
config_validate :: proc(config: Config) -> Error {
	return client_error(engine_config_validate(config))
}

// client prepares `conn` to speak TLS over `underlying`. No bytes are
// exchanged until `handshake`.
@(require_results)
client :: proc(conn: ^Conn, underlying: net.Connection, config: Config, allocator := context.allocator) -> Error {
	return client_error(engine_client(conn, underlying, config, allocator))
}

// dial connects to `host`:`port` over TCP and completes the handshake.
@(require_results)
dial :: proc(conn: ^Conn, host: string, port: int, config: Config, allocator := context.allocator) -> Error {
	failure := engine_dial(conn, host, port, config, allocator)
	switch failure.kind {
	case .None:
		return nil
	case .Invalid_State:
		return General_Error.Invalid_State
	case .Invalid_Config:
		return client_error(failure.config)
	case .TCP_Dial_Failed:
		if dial_error, is_dial := failure.network.(net.Dial_Error); is_dial {
			return dial_error
		}
		return General_Error.Name_Resolution_Failed
	case .Handshake_Failed:
		return handshake_error(failure.handshake)
	}
	return Protocol_Error.Internal_Error
}

// handshake completes the handshake. It blocks on the transport.
@(require_results)
handshake :: proc(conn: ^Conn) -> Error {
	return handshake_error(engine_handshake(conn))
}

// handshake_until is `handshake` with an absolute deadline for the whole of it.
@(require_results)
handshake_until :: proc(conn: ^Conn, deadline: time.Time) -> Error {
	return handshake_error(engine_handshake_until(conn, deadline))
}

// read receives application data, and returns the number of bytes read and
// an error if any.
//
// Notes: Partial reads are to be expected, so `received` MUST be checked.
// An error of `Protocol_Error.Close_Notify` indicates that the peer will
// not send anymore data.
@(require_results)
read :: proc(conn: ^Conn, dst: []u8) -> (received: int, err: Error) {
	failure: IO_Error
	received, failure = engine_read(conn, dst)
	if failure.kind != .None {
		err = failed(socket_recv_error(conn, failure))
	}
	return
}

// write transmits application data, and returns the number of bytes written
// and an error if any.
@(require_results)
write :: proc(conn: ^Conn, src: []u8) -> (written: int, err: Error) {
	failure: IO_Error
	written, failure = engine_write(conn, src)
	return written, io_error(failure)
}

// conn_close sends close_notify and closes the transport.
conn_close :: proc(conn: ^Conn) -> Error {
	return io_error(engine_close(conn))
}

// abort closes the transport without telling the peer.
abort :: proc(conn: ^Conn) -> Error {
	return io_error(engine_abort(conn))
}

// set_read_deadline bounds every later read by an absolute time. The zero
// time removes the bound.
@(require_results)
set_read_deadline :: proc(conn: ^Conn, deadline: time.Time) -> Error {
	return transport_error(engine_set_read_deadline(conn, deadline))
}

// set_write_deadline is `set_read_deadline` for writes.
@(require_results)
set_write_deadline :: proc(conn: ^Conn, deadline: time.Time) -> Error {
	return transport_error(engine_set_write_deadline(conn, deadline))
}

// set_deadline sets both the read and the write deadline.
@(require_results)
set_deadline :: proc(conn: ^Conn, deadline: time.Time) -> Error {
	return transport_error(engine_set_deadline(conn, deadline))
}

// conn_error returns the error status of a Conn: the failure that ended it,
// or nil.
@(require_results)
conn_error :: proc(conn: ^Conn) -> Error {
	if conn == nil {
		return General_Error.Invalid_State
	}
	if conn.handshake_error.kind != .None {
		return handshake_error(conn.handshake_error)
	}
	return io_error(conn.application.failure)
}

// A handshake failure as a Conn reports it. A Socket names an extension the
// client did not ask for the way upstream's client does, as an illegal
// parameter; everywhere else it is the alert RFC 8446 gives it.
@(private, require_results)
handshake_error :: proc(failure: Handshake_Error) -> Error {
	if failure.kind == .None {
		return nil
	}
	if failure.kind == .Unsupported_Extension && failure.upstream_alert == .Close_Notify {
		return Protocol_Error.Unsupported_Extension
	}
	return failed(socket_handshake_error(failure))
}

// A failure as a Conn reports it from `read`, `write` and `conn_close`.
@(private, require_results)
io_error :: proc(failure: IO_Error) -> Error {
	if failure.kind == .None {
		return nil
	}
	return failed(socket_io_error(failure))
}

// A failure is never reported as no error: where its cause was not recorded,
// it is an internal error.
@(private, require_results)
failed :: proc(err: Error) -> Error {
	if err == nil {
		return Protocol_Error.Internal_Error
	}
	return err
}

@(private, require_results)
client_error :: proc(failure: Client_Error) -> Error {
	switch failure {
	case .None:
		return nil
	case .Nil_Connection, .Already_Initialized, .Invalid_Transport:
		return General_Error.Invalid_State
	case .Missing_Server_Name, .Invalid_Server_Name:
		return General_Error.Invalid_SNI_Hostname
	case .Missing_Trust_Roots, .Invalid_Trust_Root:
		return General_Error.Invalid_Trust_Roots
	case .Invalid_Timeout, .Invalid_ALPN, .Invalid_Client_Credentials, .Invalid_Offer:
		return General_Error.Invalid_Config
	}
	return General_Error.Invalid_Config
}

// A transport failure outside the handshake and the record layer.
@(private, require_results)
transport_error :: proc(failure: net.Network_Error) -> Error {
	if failure == nil {
		return nil
	}

	#partial switch e in failure {
	case net.Connection_Error:
		#partial switch e {
		case .Cancelled:
			return General_Error.Cancelled
		case .Deadline_Unsupported:
			return General_Error.Deadline_Unsupported
		case .Invalid_Connection, .Invalid_Count, .Invalid_Operation, .Operation_Pending:
			return General_Error.Invalid_State
		}
	case net.Socket_Option_Error:
		// A deadline the transport could not set.
		return General_Error.Deadline_Unsupported
	}
	return failed(socket_transport_error(failure))
}
