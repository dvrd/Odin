#+build linux
package socket_option_values

import "core:net"
import "core:sys/linux"

kernel_set :: proc(socket: net.TCP_Socket, option: net.Socket_Option, value: i32) -> bool {
	level := int(linux.SOL_SOCKET) if option != .TCP_Nodelay else int(linux.SOL_TCP)
	payload := value
	error := linux.setsockopt_base(linux.Fd(socket), level, int(option), &payload)
	return error == .NONE
}

kernel_get :: proc(socket: net.TCP_Socket, option: net.Socket_Option) -> (i32, bool) {
	level := int(linux.SOL_SOCKET) if option != .TCP_Nodelay else int(linux.SOL_TCP)
	value: i32
	length, error := linux.getsockopt_base(linux.Fd(socket), level, linux.Socket_Option(option), &value)
	return value, error == .NONE && length == size_of(value)
}
