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
tcp_conn_read :: proc(data: rawptr, dst: []u8) -> (n: int, err: Network_Error) {
	tcp := cast(^TCP_Connection)data
	if tcp.closed {
		return 0, Connection_Error.Closed
	}

	if len(dst) == 0 {
		return 0, nil
	}

	for {
		tcp_deadline_apply(tcp, .Receive_Timeout, tcp.read_deadline) or_return

		count, recv_err := recv_tcp(tcp.socket, dst)
		if recv_err == .Interrupted && count == 0 {
			continue
		}

		if recv_err == .Timeout || recv_err == .Would_Block && tcp.read_deadline != (time.Time{}) {
			if recv_err == .Would_Block && !tcp_deadline_expired(tcp.read_deadline) {
				continue
			}
			return count, TCP_Recv_Error.Timeout
		}

		if recv_err != nil {
			return count, recv_err
		}

		if count == 0 {
			return 0, Connection_Error.Peer_Closed
		}
		return count, nil
	}
}

@(private)
tcp_conn_write :: proc(data: rawptr, src: []u8) -> (n: int, err: Network_Error) {
	tcp := cast(^TCP_Connection)data
	if tcp.closed {
		return 0, Connection_Error.Closed
	}

	if len(src) == 0 {
		return 0, nil
	}

	for {
		tcp_deadline_apply(tcp, .Send_Timeout, tcp.write_deadline) or_return

		count, send_err := tcp_send_once(tcp.socket, src)
		if send_err == .Interrupted && count == 0 {
			continue
		}

		if send_err == .Timeout || send_err == .Would_Block && tcp.write_deadline != (time.Time{}) {
			if send_err == .Would_Block && !tcp_deadline_expired(tcp.write_deadline) {
				continue
			}
			return count, TCP_Send_Error.Timeout
		}
		return count, send_err
	}
}

@(private)
tcp_conn_close :: proc(data: rawptr) -> Network_Error {
	tcp := cast(^TCP_Connection)data
	if !tcp.closed {
		tcp.closed = true
		close(tcp.socket)
	}
	return nil
}

when !TCP_DEADLINES_SUPPORTED {
	// Nonzero deadlines are explicitly unsupported on this fallback path.
	@(private)
	tcp_send_once :: proc(socket: TCP_Socket, src: []u8) -> (int, TCP_Send_Error) {
		return send_tcp(socket, src)
	}
}

// Exact reads from caller-owned sockets

// tcp_read_exact reads until `dst` is full. The peer closing first is
// `Connection_Error.Peer_Closed`.
tcp_read_exact :: proc(socket: TCP_Socket, dst: []u8) -> (received: int, err: Network_Error) {
	for received < len(dst) {
		count, read_err := recv_tcp(socket, dst[received:])
		received += count

		if read_err == .Interrupted {
			continue
		}

		if read_err != nil {
			return received, read_err
		}

		if count == 0 {
			return received, Connection_Error.Peer_Closed
		}
	}
	return received, nil
}

// TCP deadline implementation

TCP_DEADLINES_SUPPORTED :: ODIN_OS == .Darwin || ODIN_OS == .Linux

@(private)
tcp_set_read_deadline :: proc(data: rawptr, deadline: time.Time) -> Network_Error {
	tcp := cast(^TCP_Connection)data
	tcp_deadline_set(tcp, .Receive_Timeout, deadline) or_return
	tcp.read_deadline = deadline
	return nil
}

@(private)
tcp_set_write_deadline :: proc(data: rawptr, deadline: time.Time) -> Network_Error {
	tcp := cast(^TCP_Connection)data
	tcp_deadline_set(tcp, .Send_Timeout, deadline) or_return
	tcp.write_deadline = deadline
	return nil
}

@(private)
tcp_deadline_set :: proc(tcp: ^TCP_Connection, option: Socket_Option, deadline: time.Time) -> Network_Error {
	if tcp == nil {
		return Connection_Error.Invalid_Connection
	}

	if tcp.closed {
		return Connection_Error.Closed
	}

	when !TCP_DEADLINES_SUPPORTED {
		if deadline != (time.Time{}) {
			return Connection_Error.Deadline_Unsupported
		}
	}

	timeout: time.Duration
	if deadline != (time.Time{}) {
		timeout = time.Millisecond
		current := time.now()
		if deadline._nsec > current._nsec {
			timeout = max(time.diff(current, deadline), time.Millisecond)
		}
	}
	return set_option(tcp.socket, option, timeout)
}

// Recompute remaining time per syscall, rather than extending the operation's
// absolute deadline each time bytes are transferred. Never pass a sub-tick
// positive timeout that the OS could truncate to zero (infinite blocking).
@(private)
tcp_deadline_apply :: proc(tcp: ^TCP_Connection, option: Socket_Option, deadline: time.Time) -> Network_Error {
	if deadline == (time.Time{}) {
		return nil
	}

	current := time.now()
	if deadline._nsec <= current._nsec {
		if option == .Send_Timeout {
			return TCP_Send_Error.Timeout
		}
		return TCP_Recv_Error.Timeout
	}
	return set_option(tcp.socket, option, max(time.diff(current, deadline), time.Millisecond))
}

@(private)
tcp_deadline_expired :: proc(deadline: time.Time) -> bool {
	return deadline != (time.Time{}) && deadline._nsec <= time.now()._nsec
}
