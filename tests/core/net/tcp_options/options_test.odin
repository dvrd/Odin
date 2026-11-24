#+build darwin, netbsd, openbsd
package tcp_options

import "core:fmt"
import "core:net"
import "core:sys/posix"
import "core:testing"

kernel_set :: proc(socket: net.TCP_Socket, enabled: bool) {
	value := i32(1) if enabled else i32(0)
	assert(
		posix.setsockopt(
			posix.FD(socket),
			i32(posix.IPPROTO_TCP),
			posix.Sock_Option(posix.TCP_NODELAY),
			&value,
			posix.socklen_t(size_of(value)),
		) ==
		.OK,
	)
}

kernel_get :: proc(socket: net.TCP_Socket) -> i32 {
	value: i32
	length := posix.socklen_t(size_of(value))
	assert(
		posix.getsockopt(
			posix.FD(socket),
			i32(posix.IPPROTO_TCP),
			posix.Sock_Option(posix.TCP_NODELAY),
			&value,
			&length,
		) ==
		.OK,
	)
	assert(length == size_of(value))
	return value
}

listener :: proc() -> (net.TCP_Socket, net.Endpoint) {
	socket, error := net.listen_tcp({net.IP4_Loopback, 0})
	assert(error == nil)
	endpoint, info := net.bound_endpoint(socket)
	assert(info == nil)
	return socket, endpoint
}

check :: proc(t: ^testing.T, socket: net.TCP_Socket, expected: bool, label: string) {
	// Independent native control; Darwin can return 4 for enabled, not 1.
	control, error := net.create_socket(.IP4, .TCP)
	assert(error == nil)
	tcp := control.(net.TCP_Socket)
	defer net.close(tcp)
	kernel_set(tcp, expected)
	actual, native := kernel_get(socket), kernel_get(tcp)
	fmt.printf("READBACK %s actual=%d native=%d expected=%v\n", label, actual, native, expected)
	testing.expect_value(t, actual != 0, native != 0)
	testing.expect_value(t, actual != 0, expected)
}

check_dial :: proc(t: ^testing.T, options: net.TCP_Options, use_default: bool, label: string) {
	server, endpoint := listener()
	defer net.close(server)
	socket: net.TCP_Socket
	error: net.Network_Error
	if use_default {
		socket, error = net.dial_tcp(endpoint)
	} else {
		socket, error = net.dial_tcp(endpoint, options)
	}
	assert(error == nil)
	defer net.close(socket)
	check(t, socket, options.no_delay, label)
}

check_accept :: proc(t: ^testing.T, options: net.TCP_Options, use_default: bool, label: string) {
	server, endpoint := listener()
	defer net.close(server)
	// Deliberately opposite inheritance: true must enable, false must disable.
	kernel_set(server, !options.no_delay)
	peer, error := net.dial_tcp(endpoint, {no_delay = false})
	assert(error == nil)
	defer net.close(peer)
	socket: net.TCP_Socket
	source: net.Endpoint
	cause: net.Accept_Error
	if use_default {
		socket, source, cause = net.accept_tcp(server)
	} else {
		socket, source, cause = net.accept_tcp(server, options)
	}
	assert(cause == .None)
	defer net.close(socket)
	check(t, socket, options.no_delay, label)
	testing.expect(t, source.port > 0)
}

@(test)
public_dial_default_matches_kernel :: proc(t: ^testing.T) {
	check_dial(t, net.DEFAULT_TCP_OPTIONS, true, "dial-default")
}

@(test)
public_dial_explicit_true_matches_kernel :: proc(t: ^testing.T) {
	check_dial(t, {no_delay = true}, false, "dial-true")
}

@(test)
public_dial_explicit_false_matches_kernel :: proc(t: ^testing.T) {
	check_dial(t, {no_delay = false}, false, "dial-false")
}

@(test)
public_accept_default_overrides_listener :: proc(t: ^testing.T) {
	check_accept(t, net.DEFAULT_TCP_OPTIONS, true, "accept-default")
}

@(test)
public_accept_explicit_true_overrides_listener :: proc(t: ^testing.T) {
	check_accept(t, {no_delay = true}, false, "accept-true")
}

@(test)
public_accept_explicit_false_disables_inherited_true :: proc(t: ^testing.T) {
	check_accept(t, {no_delay = false}, false, "accept-false")
}

@(test)
independent_kernel_accept_inherits_enabled_listener :: proc(t: ^testing.T) {
	server, endpoint := listener()
	defer net.close(server)
	kernel_set(server, true)
	peer, error := net.dial_tcp(endpoint, {no_delay = false})
	assert(error == nil)
	defer net.close(peer)
	raw := posix.accept(posix.FD(server), nil, nil)
	assert(raw >= 0)
	socket := net.TCP_Socket(raw)
	defer net.close(socket)
	check(t, socket, true, "native-accept-inheritance")
}

@(test)
public_signatures_and_invalid_inputs_preserved :: proc(t: ^testing.T) {
	dial: proc(net.Endpoint, net.TCP_Options) -> (net.TCP_Socket, net.Network_Error) = net.dial_tcp_from_endpoint
	accept: proc(net.TCP_Socket, net.TCP_Options) -> (net.TCP_Socket, net.Endpoint, net.Accept_Error) =
		net.accept_tcp
	_, error := dial({net.IP4_Loopback, 0}, {})
	testing.expect_value(t, error, net.Network_Error(net.Dial_Error.Port_Required))
	_, _, cause := accept(net.TCP_Socket(-1), {})
	testing.expect(t, cause != .None)
}
