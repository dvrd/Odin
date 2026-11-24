#+build windows
package socket_option_values

import "core:net"
import "core:sys/windows"

kernel_set :: proc(socket: net.TCP_Socket, option: net.Socket_Option, value: i32) -> bool {
	level := i32(windows.SOL_SOCKET) if option != .TCP_Nodelay else i32(windows.IPPROTO_TCP)
	payload := value
	return windows.setsockopt(windows.SOCKET(socket), level, i32(option), &payload, i32(size_of(payload))) == 0
}

kernel_get :: proc(socket: net.TCP_Socket, option: net.Socket_Option) -> (i32, bool) {
	level := i32(windows.SOL_SOCKET) if option != .TCP_Nodelay else i32(windows.IPPROTO_TCP)
	value: i32
	length := i32(size_of(value))
	result := windows.getsockopt(windows.SOCKET(socket), level, i32(option), cast([^]windows.c_char)&value, &length)
	return value, result == 0 && length == size_of(value)
}
