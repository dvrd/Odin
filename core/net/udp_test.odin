#+build darwin, linux
package net

import "core:testing"
import "core:time"

@(private)
udp_fixture_socket :: proc() -> (UDP_Socket, Endpoint) {
	socket, error := make_unbound_udp_socket(.IP4); assert(error == nil)
	assert(bind(socket, {IP4_Loopback, 0}) == .None)
	assert(set_option(socket, .Receive_Timeout, 100 * time.Millisecond) == nil)
	endpoint, cause := bound_endpoint(socket); assert(cause == .None)
	return socket, endpoint
}

@(test)
udp_empty_send_is_a_real_datagram :: proc(t: ^testing.T) {
	sender, source := udp_fixture_socket(); defer close(sender)
	receiver, target := udp_fixture_socket(); defer close(receiver)
	n, error := send_udp(sender, nil, target)
	testing.expect(t, error == nil && n == 0)
	buffer: [8]u8
	got, peer, cause := recv_udp(receiver, buffer[:])
	testing.expect(t, cause == nil && got == 0 && peer == source)
}

@(test)
udp_truncation_preserves_source_and_discards_only_current_message :: proc(t: ^testing.T) {
	sender, source := udp_fixture_socket(); defer close(sender)
	receiver, target := udp_fixture_socket(); defer close(receiver)
	large: [32]u8
	for &b in large {b = 42}
	_, error := send_udp(sender, large[:], target); assert(error == nil)
	_, error = send_udp(sender, []u8{99}, target); assert(error == nil)
	buffer: [8]u8
	n, peer, cause := recv_udp(receiver, buffer[:])
	testing.expect(t, cause == .Excess_Truncated && n == 8 && peer == source && buffer[0] == 42)
	n, peer, cause = recv_udp(receiver, buffer[:])
	testing.expect(t, cause == nil && n == 1 && peer == source && buffer[0] == 99)
}
