#+build darwin, linux
package net

import "core:sys/posix"

// send_tcp loops internally until all bytes are sent, resetting the
// OS timeout after each partial send. One syscall lets write_all refresh an
// absolute deadline between partial sends. Keep core:net for socket setup.
@(private)
tcp_send_once :: proc(
	socket: TCP_Socket,
	src: []u8,
) -> (
	int,
	TCP_Send_Error,
) {

	count := posix.send(
		cast(posix.FD)socket,
		raw_data(src),
		cast(uint)min(len(src), cast(int)max(i32)),
		{.NOSIGNAL},
	)
	if count >= 0 do return count, nil

	#partial switch posix.errno() {
	case .EACCES,
	     .EBADF,
	     .EFAULT,
	     .EMSGSIZE,
	     .ENOTSOCK,
	     .EOPNOTSUPP,
	     .EINVAL:
		return 0, .Invalid_Argument
	case .ENOBUFS, .ENOMEM:
		return 0, .Insufficient_Resources
	case .ECONNRESET, .EPIPE:
		return 0, .Connection_Closed
	case .ENOTCONN:
		return 0, .Not_Connected
	case .EHOSTUNREACH:
		return 0, .Host_Unreachable
	case .ENETDOWN, .ENETUNREACH:
		return 0, .Network_Unreachable
	case .ETIMEDOUT:
		return 0, .Timeout
	case .EAGAIN:
		return 0, .Would_Block
	case .EINTR:
		return 0, .Interrupted
	case:
		return 0, .Unknown
	}
}
