#+build darwin,linux
package net

import "core:testing"
import "core:thread"
import "core:time"

@(test)
numeric_connect_is_nonblocking_and_preserves_native_ownership :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Second)
	for address in ([]Address{IP4_Loopback, IP6_Loopback}) {
		listener, error := listen_tcp({address, 0})
		assert(error == nil)
		endpoint, be := bound_endpoint(listener); assert(be == .None)
		socket, connected, cause := begin_tcp_connect(endpoint)
		testing.expect(t, cause == nil)
		started := time.tick_now()
		for !connected && cause == nil {
			connected, cause = poll_tcp_connect(socket)
			assert(time.tick_since(started) < time.Second)
			if !connected {
				thread.yield()
			}
		}
		testing.expect(t, connected && cause == nil)
		peer, _, accept_error := accept_tcp(listener); assert(accept_error == .None)
		buffer: [1]u8
		_, read_error := recv_tcp(socket, buffer[:])
		testing.expect_value(t, read_error, .Would_Block)
		close(peer); close(socket); close(listener)
	}
}

@(test)
numeric_connect_refusal_is_terminal_but_poll_does_not_close :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Second)
	listener, error := listen_tcp({IP4_Loopback, 0}); assert(error == nil)
	endpoint, be := bound_endpoint(listener); assert(be == .None)
	close(listener)
	socket, connected, cause := begin_tcp_connect(endpoint)
	if cause == nil {
		defer close(socket)
		started := time.tick_now()
		for !connected && cause == nil {
			connected, cause = poll_tcp_connect(socket)
			assert(time.tick_since(started) < time.Second)
			thread.yield()
		}
		_, still_open := bound_endpoint(socket)
		testing.expect_value(t, still_open, .None)
	}
	testing.expect(t, !connected && cause != nil)
	_, _, invalid := begin_tcp_connect({IP4_Loopback, 0})
	testing.expect(t, invalid == Network_Error(Dial_Error.Port_Required))
	_, _, invalid = begin_tcp_connect({IP4_Loopback, 65536})
	testing.expect(t, invalid == Network_Error(Dial_Error.Invalid_Argument))
	_, _, invalid = begin_tcp_connect({port = 80})
	testing.expect(t, invalid == Network_Error(Dial_Error.Invalid_Argument))
}
