#+build linux
package net

import "core:sys/linux"
import "core:time"

@(private)
_dial_tcp_until :: proc(endpoint: Endpoint, deadline: time.Time, options: TCP_Options) -> (TCP_Socket, Network_Error) {
	any_socket, create_error := create_socket(family_from_endpoint(endpoint), .TCP)
	if create_error != .None {return 0, create_error}
	socket := any_socket.(TCP_Socket)
	success := false
	defer if !success {close(socket)}
	if error := set_blocking(socket, false); error != .None {return 0, error}
	address := _unwrap_os_addr(endpoint)
	cause := linux.connect(linux.Fd(socket), &address)
	if cause != .NONE {
		if cause != .EINPROGRESS && cause != .EINTR && cause != .EALREADY {return 0, _dial_error(cause)}
		for {
			wait := dial_poll_timeout(deadline)
			if wait == 0 {return 0, Dial_Error.Timeout}
			poll_fd := [1]linux.Poll_Fd{{fd = linux.Fd(socket), events = {.OUT}}}
			ready, poll_error := linux.poll(poll_fd[:], wait)
			if poll_error != .NONE {
				if poll_error == .EINTR {continue}
				return 0, _dial_error(poll_error)
			}
			if ready == 0 {return 0, Dial_Error.Timeout}
			pending: linux.Errno
			length := u32(size_of(pending))
			result := linux.syscall(linux.SYS_getsockopt, linux.Fd(socket), linux.SOL_SOCKET, linux.Socket_Option.ERROR, &pending, &length)
			option_error := linux.Errno(-result)
			if option_error != .NONE {return 0, _dial_error(option_error)}
			if pending != .NONE {return 0, _dial_error(pending)}
			break
		}
	}
	if time.diff(time.now(), deadline) <= 0 {return 0, Dial_Error.Timeout}
	if error := set_blocking(socket, true); error != .None {return 0, error}
	_ = set_option(socket, .TCP_Nodelay, options.no_delay)
	success = true
	return socket, nil
}
