#+build darwin
package net

import "core:sys/posix"
import "core:time"

@(private)
_dial_tcp_until :: proc(endpoint: Endpoint, deadline: time.Time, options: TCP_Options) -> (TCP_Socket, Network_Error) {
	any_socket, create_error := create_socket(family_from_endpoint(endpoint), .TCP)
	if create_error != .None {return 0, create_error}
	socket := any_socket.(TCP_Socket)
	success := false
	defer if !success {close(socket)}
	if error := set_blocking(socket, false); error != .None {return 0, error}
	address := _endpoint_to_sockaddr(endpoint)
	if posix.connect(posix.FD(socket), cast(^posix.sockaddr)&address, posix.socklen_t(address.ss_len)) != .OK {
		cause := posix.errno()
		if cause != .EINPROGRESS && cause != .EINTR && cause != .EALREADY {return 0, _dial_error()}
		for {
			wait := dial_poll_timeout(deadline)
			if wait == 0 {return 0, Dial_Error.Timeout}
			poll_fd := posix.pollfd{fd = posix.FD(socket), events = {.OUT}}
			ready := posix.poll(&poll_fd, 1, wait)
			if ready < 0 {
				if posix.errno() == .EINTR {continue}
				return 0, _dial_error()
			}
			if ready == 0 {return 0, Dial_Error.Timeout}
			pending: posix.Errno
			length := posix.socklen_t(size_of(pending))
			if posix.getsockopt(posix.FD(socket), posix.SOL_SOCKET, .ERROR, &pending, &length) != .OK {return 0, _dial_error()}
			if pending != .NONE {posix.errno(pending); return 0, _dial_error()}
			break
		}
	}
	if time.diff(time.now(), deadline) <= 0 {return 0, Dial_Error.Timeout}
	if error := set_blocking(socket, true); error != .None {return 0, error}
	// Match the legacy option's best-effort behavior; this is not a dial failure.
	_ = set_option(socket, .TCP_Nodelay, options.no_delay)
	success = true
	return socket, nil
}
