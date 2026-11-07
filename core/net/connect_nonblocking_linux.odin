#+build linux
package net
import "core:sys/linux"

@(private)
_begin_tcp_connect :: proc(
	endpoint: Endpoint,
	options: TCP_Options,
) -> (
	TCP_Socket,
	bool,
	Network_Error,
) {
	any_socket, create_error := create_socket(family_from_endpoint(endpoint), .TCP)
	if create_error != .None {
		return 0, false, create_error
	}
	socket := any_socket.(TCP_Socket)
	success := false
	defer if !success {
		close(socket)
	}
	if error := set_blocking(socket, false); error != .None {
		return 0, false, error
	}
	_ = set_option(socket, .TCP_Nodelay, options.no_delay)
	address := _unwrap_os_addr(endpoint)
	cause := linux.connect(linux.Fd(socket), &address)
	if cause == .NONE {
		success = true; return socket, true, nil
	}
	if cause == .EINPROGRESS || cause == .EINTR || cause == .EALREADY {
		success = true; return socket, false, nil
	}
	return 0, false, _dial_error(cause)
}

@(private)
_poll_tcp_connect :: proc(socket: TCP_Socket) -> (bool, Network_Error) {
	descriptor := [1]linux.Poll_Fd{{fd = linux.Fd(socket), events = {.OUT}}}
	ready, cause := linux.poll(descriptor[:], 0)
	if cause != .NONE {
		if cause == .EINTR {
			return false, nil
		}
		return false, _dial_error(cause)
	}
	if ready == 0 {
		return false, nil
	}
	pending: linux.Errno
	size := u32(size_of(pending))
	result := linux.syscall(
		linux.SYS_getsockopt,
		linux.Fd(socket),
		linux.SOL_SOCKET,
		linux.Socket_Option.ERROR,
		&pending,
		&size,
	)
	option_error := linux.Errno(-result)
	if option_error != .NONE {
		return false, _dial_error(option_error)
	}
	if pending == .EINPROGRESS || pending == .EALREADY {
		return false, nil
	}
	if pending != .NONE {
		return false, _dial_error(pending)
	}
	return true, nil
}
