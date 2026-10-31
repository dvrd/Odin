package net

import "core:io"
import "core:time"

// Connection contracts, exact I/O and core:io interoperability.

Connection_Error_Kind :: enum {
	None,
	Peer_Closed,
	Closed,
	Invalid_Connection,
	Invalid_Count,
	No_Progress,
	Read_Failed,
	Write_Failed,
	Timeout,
	Deadline_Unsupported,
	Deadline_Failed,
	Cancelled,
	Operation_Pending,
	Invalid_Operation,
	Close_Failed,
}

Connection_Error :: struct {
	kind:           Connection_Error_Kind,
	read_cause:     TCP_Recv_Error,
	write_cause:    TCP_Send_Error,
	deadline_cause: Socket_Option_Error,
}

// Callbacks are blocking. A read may return bytes together with an error;
// callers must account for those bytes before handling the error.
// Copies borrow the same backing state; they do not transfer ownership. The
// implementation defines close ownership. Operations must be serialized; this
// interface does not provide asynchronous execution or concurrent cancellation.
Connection :: struct {
	data:               rawptr,
	read:               proc(
		data: rawptr,
		dst: []u8,
	) -> (
		int,
		Connection_Error,
	),
	write:              proc(
		data: rawptr,
		src: []u8,
	) -> (
		int,
		Connection_Error,
	),
	close:              proc(data: rawptr) -> Connection_Error,
	// Optional. A zero time removes the deadline. As with other operations on
	// this initial blocking transport, setters must be serialized with I/O.
	set_read_deadline:  proc(
		data: rawptr,
		deadline: time.Time,
	) -> Connection_Error,
	set_write_deadline: proc(
		data: rawptr,
		deadline: time.Time,
	) -> Connection_Error,
}

connection_valid :: proc(conn: Connection) -> bool {
	return conn.read != nil && conn.write != nil && conn.close != nil
}

read_exact :: proc(
	conn: Connection,
	dst: []u8,
) -> (
	received: int,
	err: Connection_Error,
) {
	if !connection_valid(conn) {
		return 0, {kind = .Invalid_Connection}
	}

	return read_exact_callback(Connection_Error, conn.data, dst, conn.read)
}

write_all :: proc(
	conn: Connection,
	src: []u8,
) -> (
	written: int,
	err: Connection_Error,
) {
	if !connection_valid(conn) {
		return 0, {kind = .Invalid_Connection}
	}

	return write_all_callback(Connection_Error, conn.data, src, conn.write)
}

// Transport deadline callbacks

set_read_deadline :: proc(conn: Connection, deadline: time.Time) -> Connection_Error {
	if !connection_valid(conn) do return {kind = .Invalid_Connection}

	if conn.set_read_deadline == nil {
		return {kind = .Deadline_Unsupported}
	}

	return conn.set_read_deadline(conn.data, deadline)
}

set_write_deadline :: proc(
	conn: Connection,
	deadline: time.Time,
) -> Connection_Error {
	if !connection_valid(conn) do return {kind = .Invalid_Connection}

	if conn.set_write_deadline == nil {
		return {kind = .Deadline_Unsupported}
	}

	return conn.set_write_deadline(conn.data, deadline)
}

// Checks callback support before either setter is called. Operational errors
// can still leave only the read deadline changed; callers must handle errors.
set_deadline :: proc(conn: Connection, deadline: time.Time) -> Connection_Error {
	if !connection_valid(conn) do return {kind = .Invalid_Connection}

	if conn.set_read_deadline == nil ||
	   conn.set_write_deadline == nil {
		return {kind = .Deadline_Unsupported}
	}

	if err := conn.set_read_deadline(conn.data, deadline);
	   err.kind != .None {
		return err
	}

	return conn.set_write_deadline(conn.data, deadline)
}


// Exact I/O callbacks

// The error type preserves adapter diagnostics without a transport-to-TLS dependency.
// Each successful iteration consumes bytes, bounding calls by buffer length.
read_exact_callback :: proc(
	$E: typeid,
	data: rawptr,
	dst: []u8,
	callback: proc(rawptr, []u8) -> (int, E),
) -> (received: int, err: E) {
	assert(callback != nil)
	for received < len(dst) {
		count, read_err := callback(data, dst[received:])
		if count < 0 || count > len(dst) - received {
			return received, {kind = .Invalid_Count}
		}

		received += count
		// The request is satisfied even if the final bytes accompany EOF.
		if received == len(dst) do return received, {}

		if read_err.kind != .None {
			return received, read_err
		}

		if count == 0 {
			return received, {kind = .No_Progress}
		}

	}
	return received, {}
}

// The error type preserves adapter diagnostics without a transport-to-TLS dependency.
// Each successful iteration consumes bytes, bounding calls by buffer length.
write_all_callback :: proc(
	$E: typeid,
	data: rawptr,
	src: []u8,
	callback: proc(rawptr, []u8) -> (int, E),
) -> (written: int, err: E) {
	assert(callback != nil)
	for written < len(src) {
		count, write_err := callback(data, src[written:])
		if count < 0 || count > len(src) - written {
			return written, {kind = .Invalid_Count}
		}

		written += count
		if write_err.kind != .None {
			return written, write_err
		}

		if count == 0 {
			return written, {kind = .No_Progress}
		}

	}
	return written, {}
}


// core:io adapter

// Borrows a Connection and its backing state. Keep both at stable addresses
// and serialize operations, including direct use of the underlying connection.
// last_error preserves diagnostics that cannot be represented by io.Error.
Connection_Stream :: struct {
	connection: Connection,
	last_error: Connection_Error,
}

// The stream does not allocate or own adapter storage. Close delegates to the
// connection; Destroy does not free storage. io.destroy also calls Close.
// Initialize adapter.connection before calling this procedure.
//
// Example (socket ownership transfers to the TCP adapter):
//     tcp := net.TCP_Connection{socket = socket}
//     adapter := net.Connection_Stream{connection = net.tcp_connection(&tcp)}
//     stream := net.connection_stream(&adapter)
//     defer io.close(stream)
//     n, err := io.read(stream, buffer[:])
//
// Use the Connection API when deadlines or full network diagnostics are needed.
connection_stream :: proc(adapter: ^Connection_Stream) -> io.Stream {
	if adapter == nil || !connection_valid(adapter.connection) do return {}
	return {procedure = connection_stream_proc, data = adapter}
}

@(private)
connection_stream_proc :: proc(
	data: rawptr, mode: io.Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From,
) -> (n: i64, err: io.Error) {
	adapter := cast(^Connection_Stream)data
	conn := adapter.connection
	#partial switch mode {
	case .Query:
		return io.query_utility({.Read, .Write, .Close})
	case .Read, .Write:
		adapter.last_error = {}
		if !connection_valid(conn) {
			adapter.last_error = {kind = .Invalid_Connection}
			return 0, .Unsupported
		}
		if len(p) == 0 do return 0, nil
		count: int
		if mode == .Read {
			count, adapter.last_error = conn.read(conn.data, p)
		} else {
			count, adapter.last_error = conn.write(conn.data, p)
		}
		if count < 0 || count > len(p) {
			adapter.last_error = {kind = .Invalid_Count}
			return 0, .Unknown if mode == .Read else .Invalid_Write
		}
		err = connection_io_error(adapter.last_error)
		if err == nil {
			if mode == .Write && count < len(p) {
				err = .Short_Write
			} else if mode == .Read && count == 0 {
				adapter.last_error = {kind = .No_Progress}
				err = .No_Progress
			}
		}
		return i64(count), err
	case .Close:
		if !connection_valid(conn) {
			adapter.last_error = {kind = .Invalid_Connection}
		} else {
			adapter.last_error = conn.close(conn.data)
		}
		return 0, connection_io_error(adapter.last_error)
	case:
		return 0, .Unsupported
	}
}

@(private)
connection_io_error :: proc(err: Connection_Error) -> io.Error {
	#partial switch err.kind {
	case .None: return nil
	case .Peer_Closed: return .EOF
	case .Closed: return .Closed
	case .Invalid_Connection, .Deadline_Unsupported: return .Unsupported
	case .No_Progress: return .No_Progress
	case: return .Unknown
	}
}


// Asynchronous connections

Async_Operation_Kind :: enum { Read, Write, Close }

Async_Result :: struct {
	count: int,
	err: Connection_Error,
}

// Caller-owned; keep the operation, its buffer and callback state alive until
// callback. Result and kind are valid in callback. An operation can be reused
// or freed there. Do not copy or mutate it while pending.
Async_Operation :: struct {
	callback: proc(operation: ^Async_Operation),
	user_data: rawptr,
	kind: Async_Operation_Kind,
	result: Async_Result,
	pending: bool,
	// Implementation-owned while pending.
	_owner: rawptr,
	_backend: rawptr,
}

// Asynchronous byte stream. Calls and callbacks belong to one owning event-loop
// thread. Read and write can be pending simultaneously. Implementations reject
// excess operations rather than silently growing queues. Other threads must
// submit work through the owning loop's scheduling mechanism.
//
// A successful submission (err.kind == .None) guarantees one deferred
// terminal callback, including cancellation/close. A rejected operation gets no
// callback. The application must keep driving the loop until close completes.
// Buffers are borrowed through completion; cancellation never rolls back I/O.
// Deadlines are absolute (zero disables) and bound this operation only.
//
// Close rejects new I/O, drains accepted operations, releases the connection,
// then calls its callback. State may be freed in that callback. A completed
// operation may succeed even when cancellation or close was requested.
Async_Connection :: struct {
	data: rawptr,
	submit: proc(data: rawptr, op: ^Async_Operation, kind: Async_Operation_Kind, buffer: []u8, deadline: time.Time) -> Connection_Error,
	cancel: proc(data: rawptr, op: ^Async_Operation) -> Connection_Error,
}

async_read :: proc(conn: Async_Connection, op: ^Async_Operation, dst: []u8, deadline := time.Time{}) -> Connection_Error {
	return async_submit(conn, op, .Read, dst, deadline)
}

// Completes when all bytes are written or a terminal error occurs. count
// includes any bytes transferred before cancellation, close or timeout.
async_write :: proc(conn: Async_Connection, op: ^Async_Operation, src: []u8, deadline := time.Time{}) -> Connection_Error {
	return async_submit(conn, op, .Write, src, deadline)
}

async_close :: proc(conn: Async_Connection, op: ^Async_Operation) -> Connection_Error {
	return async_submit(conn, op, .Close, nil, {})
}

// Requests cancellation. Does not imply completion or allow buffer reuse.
// Repeating a request while pending is harmless. Close operations cannot be
// cancelled. Request storage must still be alive when calling this procedure.
async_cancel :: proc(conn: Async_Connection, op: ^Async_Operation) -> Connection_Error {
	if conn.cancel == nil do return {kind = .Invalid_Connection}
	if op == nil do return {kind = .Invalid_Operation}
	return conn.cancel(conn.data, op)
}

@(private)
async_submit :: proc(conn: Async_Connection, op: ^Async_Operation, kind: Async_Operation_Kind, buffer: []u8, deadline: time.Time) -> Connection_Error {
	if conn.submit == nil do return {kind = .Invalid_Connection}
	if op == nil || op.callback == nil do return {kind = .Invalid_Operation}
	if op.pending do return {kind = .Operation_Pending}
	return conn.submit(conn.data, op, kind, buffer, deadline)
}
