package net

import "core:time"

// TCP connection adapter

// Keep this value at a stable address while a Connection refers to it.
// After wrapping, use the adapter to close the socket exactly once.
TCP_Connection :: struct {
	socket:         TCP_Socket,
	closed:         bool,
	read_deadline:  time.Time,
	write_deadline: time.Time,
}

tcp_connection :: proc(tcp: ^TCP_Connection) -> Connection {
	if tcp == nil do return {}

	return {
		data = tcp,
		read = tcp_conn_read,
		write = tcp_conn_write,
		close = tcp_conn_close,
		set_read_deadline = tcp_set_read_deadline,
		set_write_deadline = tcp_set_write_deadline,
	}
}

@(private)
tcp_conn_read :: proc(data: rawptr, dst: []u8) -> (int, Connection_Error) {
	tcp := cast(^TCP_Connection)data
	if tcp.closed do return 0, {kind = .Closed}

	if len(dst) == 0 do return 0, {}

	for {
		if err := tcp_deadline_apply(
			tcp,
			.Receive_Timeout,
			tcp.read_deadline,
		); err.kind != .None {
			return 0, err
		}

		count, err := recv_tcp(tcp.socket, dst)
		if err == .Interrupted && count == 0 do continue

		if err == .Timeout ||
		   err == .Would_Block &&
			   tcp.read_deadline != (time.Time{}) {
			if err == .Would_Block &&
			   !tcp_deadline_expired(tcp.read_deadline) {
				continue
			}

			return count, {kind = .Timeout, read_cause = err}
		}

		if err != nil {
			return count, {kind = .Read_Failed, read_cause = err}
		}

		if count == 0 do return 0, {kind = .Peer_Closed}

		return count, {}
	}
}

@(private)
tcp_conn_write :: proc(data: rawptr, src: []u8) -> (int, Connection_Error) {
	tcp := cast(^TCP_Connection)data
	if tcp.closed do return 0, {kind = .Closed}

	if len(src) == 0 do return 0, {}

	for {
		if err := tcp_deadline_apply(
			tcp,
			.Send_Timeout,
			tcp.write_deadline,
		); err.kind != .None {
			return 0, err
		}

		count, err := tcp_send_once(tcp.socket, src)
		if err == .Interrupted && count == 0 do continue

		if err == .Timeout ||
		   err == .Would_Block &&
			   tcp.write_deadline != (time.Time{}) {
			if err == .Would_Block &&
			   !tcp_deadline_expired(tcp.write_deadline) {
				continue
			}

			return count, {kind = .Timeout, write_cause = err}
		}

		if err != nil {
			return count, {kind = .Write_Failed, write_cause = err}
		}

		return count, {}
	}
}

@(private)
tcp_conn_close :: proc(data: rawptr) -> Connection_Error {
	tcp := cast(^TCP_Connection)data
	if !tcp.closed {
		tcp.closed = true
		close(tcp.socket)
	}

	return {}
}

when !TCP_DEADLINES_SUPPORTED {
	// Nonzero deadlines are explicitly unsupported on this fallback path.
	@(private)
	tcp_send_once :: proc(
		socket: TCP_Socket,
		src: []u8,
	) -> (
		int,
		TCP_Send_Error,
	) {
		return send_tcp(socket, src)
	}
}

// Exact reads from caller-owned sockets

TCP_Read_Error_Kind :: enum {
	None,
	Peer_Closed,
	Read_Failed,
}

TCP_Read_Error :: struct {
	kind:  TCP_Read_Error_Kind,
	cause: TCP_Recv_Error,
}

tcp_read_exact :: proc(
	socket: TCP_Socket,
	dst: []u8,
) -> (
	received: int,
	err: TCP_Read_Error,
) {
	for received < len(dst) {
		count, read_err := recv_tcp(socket, dst[received:])
		received += count

		if read_err == .Interrupted do continue

		if read_err != nil {
			return received, {kind = .Read_Failed, cause = read_err}
		}

		if count == 0 {
			return received, {kind = .Peer_Closed}
		}

	}

	return received, {}
}

// TCP deadline implementation

TCP_DEADLINES_SUPPORTED ::
	(ODIN_OS in bit_set[type_of(ODIN_OS)]{.Darwin, .Linux})

@(private)
tcp_set_read_deadline :: proc(
	data: rawptr,
	deadline: time.Time,
) -> Connection_Error {
	tcp := cast(^TCP_Connection)data
	if err := tcp_deadline_set(tcp, .Receive_Timeout, deadline);
	   err.kind != .None {
		return err
	}

	tcp.read_deadline = deadline
	return {}
}

@(private)
tcp_set_write_deadline :: proc(
	data: rawptr,
	deadline: time.Time,
) -> Connection_Error {
	tcp := cast(^TCP_Connection)data
	if err := tcp_deadline_set(tcp, .Send_Timeout, deadline);
	   err.kind != .None {
		return err
	}

	tcp.write_deadline = deadline
	return {}
}

@(private)
tcp_deadline_set :: proc(
	tcp: ^TCP_Connection,
	option: Socket_Option,
	deadline: time.Time,
) -> Connection_Error {
	if tcp == nil do return {kind = .Invalid_Connection}

	if tcp.closed do return {kind = .Closed}

	when !TCP_DEADLINES_SUPPORTED {
		if deadline != (time.Time{}) {
			return {kind = .Deadline_Unsupported}
		}

	}
	timeout: time.Duration
	if deadline != (time.Time{}) {
		timeout = time.Millisecond
		current := time.now()
		if deadline._nsec > current._nsec {
			timeout = max(
				time.diff(current, deadline),
				time.Millisecond,
			)
		}

	}

	if err := set_option(tcp.socket, option, timeout);
	   err != nil {
		return {kind = .Deadline_Failed, deadline_cause = err}
	}

	return {}
}

// Recompute remaining time per syscall, rather than extending the operation's
// absolute deadline each time bytes are transferred. Never pass a sub-tick
// positive timeout that the OS could truncate to zero (infinite blocking).
@(private)
tcp_deadline_apply :: proc(
	tcp: ^TCP_Connection,
	option: Socket_Option,
	deadline: time.Time,
) -> Connection_Error {
	if deadline == (time.Time{}) do return {}

	current := time.now()
	if deadline._nsec <= current._nsec {
		return {kind = .Timeout}
	}

	timeout: time.Duration = max(
		time.diff(current, deadline),
		time.Millisecond,
	)
	if err := set_option(tcp.socket, option, timeout);
	   err != nil {
		return {kind = .Deadline_Failed, deadline_cause = err}
	}

	return {}
}

@(private)
tcp_deadline_expired :: proc(deadline: time.Time) -> bool {
	return(
		deadline != (time.Time{}) &&
		deadline._nsec <= time.now()._nsec \
	)
}
