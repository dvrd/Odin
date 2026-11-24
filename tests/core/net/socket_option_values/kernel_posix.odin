#+build darwin
package socket_option_values

import "core:net"
import "core:sys/posix"

kernel_set :: proc(socket: net.TCP_Socket, option: net.Socket_Option, value: i32) -> bool {
	level := i32(posix.SOL_SOCKET if option != .TCP_Nodelay else posix.IPPROTO_TCP)
	payload := value
	return posix.setsockopt(
			posix.FD(socket),
			level,
			posix.Sock_Option(option),
			&payload,
			posix.socklen_t(size_of(payload)),
		) ==
		.OK
}

kernel_get :: proc(socket: net.TCP_Socket, option: net.Socket_Option) -> (i32, bool) {
	level := i32(posix.SOL_SOCKET if option != .TCP_Nodelay else posix.IPPROTO_TCP)
	value: i32
	length := posix.socklen_t(size_of(value))
	result := posix.getsockopt(posix.FD(socket), level, posix.Sock_Option(option), &value, &length)
	return value, result == .OK && length == size_of(value)
}
