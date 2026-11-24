#+build darwin
package net
import "core:sys/posix"

@(private)
_begin_tcp_connect :: proc(endpoint: Endpoint, options: TCP_Options) -> (TCP_Socket, bool, Network_Error) {
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
	address := _endpoint_to_sockaddr(endpoint)
	if posix.connect(posix.FD(socket), cast(^posix.sockaddr)&address, posix.socklen_t(address.ss_len)) == .OK {
		success = true
		return socket, true, nil
	}
	cause := posix.errno()
	if cause == .EINPROGRESS || cause == .EINTR || cause == .EALREADY {
		success = true
		return socket, false, nil
	}
	return 0, false, _dial_error()
}

@(private)
_poll_tcp_connect :: proc(socket: TCP_Socket) -> (bool, Network_Error) {
	poll_fd := posix.pollfd {
		fd     = posix.FD(socket),
		events = {.OUT},
	}
	ready := posix.poll(&poll_fd, 1, 0)
	if ready < 0 {
		if posix.errno() == .EINTR {
			return false, nil
		}
		return false, _dial_error()
	}
	if ready == 0 {
		return false, nil
	}
	pending: posix.Errno
	size := posix.socklen_t(size_of(pending))
	if posix.getsockopt(posix.FD(socket), posix.SOL_SOCKET, .ERROR, &pending, &size) != .OK {
		return false, _dial_error()
	}
	if pending == .EINPROGRESS || pending == .EALREADY {
		return false, nil
	}
	if pending != .NONE {
		posix.errno(pending)
		return false, _dial_error()
	}
	return true, nil
}
