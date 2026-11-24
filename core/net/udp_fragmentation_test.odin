#+build darwin, linux
package net

import "core:testing"
import "core:time"

@(test)
udp_fragmentation_policy_sets_queries_and_preserves_ecn :: proc(t: ^testing.T) {
	for endpoint in ([]Endpoint{{IP4_Loopback, 0}, {IP6_Loopback, 0}}) {
		family := family_from_endpoint(endpoint)
		sender, se := make_unbound_udp_socket(family)
		assert(se == nil)
		defer close(sender)
		receiver, re := make_unbound_udp_socket(family)
		assert(re == nil)
		defer close(receiver)
		level: i32 = 0
		option: i32 = 28
		if family == .IP6 {
			level = 41
			option = 62
		}
		when ODIN_OS == .Linux {
			if family == .IP6 {
				option = 23
			}
			else {
				option = 10
			}
		}
		assert(udp_fragmentation_set(sender, level, option, 0) == 0)
		testing.expect(t, udp_fragmentation_policy(sender, family).status == .Not_Configured)
		configured := udp_disable_fragmentation(sender, family)
		testing.expect(t, configured.status == .Configured && configured.native_error == 0)
		testing.expect(t, (family == .IP4 && configured.ipv4) || (family == .IP6 && configured.ipv6))
		testing.expect(t, udp_fragmentation_policy(sender, family) == configured)
		testing.expect(t, udp_disable_fragmentation(sender, family) == configured)
		assert(bind(receiver, endpoint) == .None)
		assert(set_option(receiver, .Receive_Timeout, 100 * time.Millisecond) == nil)
		target, te := bound_endpoint(receiver)
		assert(te == .None)
		testing.expect(t, udp_enable_ecn(receiver, family))
		payload: [1200]u8
		for &b, i in payload {b = u8(i % 251)}
		n, send_error := send_udp_ecn(sender, payload[:], target, .ECT_0)
		testing.expect(t, n == len(payload) && send_error == nil)
		buffer: [1200]u8
		got, _, metadata, receive_error := recv_udp_metadata(receiver, buffer[:])
		testing.expect(t, got == len(payload) && receive_error == nil && buffer == payload)
		testing.expect(t, metadata.ecn_valid && metadata.ecn == .ECT_0 && !metadata.control_truncated)
		testing.expect(t, udp_fragmentation_policy(sender, family).status == .Configured)
	}
}

@(test)
udp_fragmentation_ipv6_preserves_explicit_single_and_dual_stack :: proc(t: ^testing.T) {
	for only in ([]i32{0, 1}) {
		socket, e := make_unbound_udp_socket(.IP6)
		assert(e == nil)
		defer close(socket)
		option: i32 = 27
		when ODIN_OS == .Linux {option = 26}
		assert(udp_fragmentation_set(socket, 41, option, only) == 0)
		result := udp_disable_fragmentation(socket, .IP6)
		testing.expect(t, result.status == .Configured && result.ipv6 && result.dual_stack == (only == 0))
		testing.expect(t, result.ipv4 == (only == 0))
		value, cause := udp_fragmentation_get(socket, 41, option)
		testing.expect(t, cause == 0 && value == only)
	}
}

@(test)
udp_fragmentation_rejects_invalid_family_descriptor_and_tcp :: proc(t: ^testing.T) {
	socket, e := make_unbound_udp_socket(.IP4)
	assert(e == nil)
	defer close(socket)
	testing.expect(t, udp_disable_fragmentation(socket, Address_Family(17)).status == .Invalid_Family)
	testing.expect(t, udp_disable_fragmentation(socket, .IP6).status == .Invalid_Family)
	testing.expect(t, udp_fragmentation_policy(UDP_Socket(-1), .IP4).status == .Failed)
	testing.expect(t, udp_disable_fragmentation(UDP_Socket(-1), .IP4).native_error != 0)
	any, tcp_error := create_socket(.IP4, .TCP)
	assert(tcp_error == nil)
	tcp := any.(TCP_Socket)
	defer close(tcp)
	option: i32 = 28
	when ODIN_OS == .Linux {option = 10}
	before, before_error := udp_fragmentation_get(UDP_Socket(tcp), 0, option)
	result := udp_disable_fragmentation(UDP_Socket(tcp), .IP4)
	after, after_error := udp_fragmentation_get(UDP_Socket(tcp), 0, option)
	testing.expect(t, result.status == .Invalid_Socket && before_error == after_error && before == after)
}

@(test)
udp_fragmentation_mapped_ipv4_ecn_send_and_receive :: proc(t: ^testing.T) {
	sender, se := make_unbound_udp_socket(.IP6)
	assert(se == nil)
	defer close(sender)
	configured := udp_disable_fragmentation(sender, .IP6)
	assert(configured.status == .Configured && configured.dual_stack)
	receiver, re := make_bound_udp_socket(IP4_Loopback, 0)
	assert(re == nil)
	defer close(receiver)
	assert(set_option(receiver, .Receive_Timeout, 100 * time.Millisecond) == nil)
	target, te := bound_endpoint(receiver)
	assert(te == .None)
	target.address = IP6_Address{0, 0, 0, 0, 0, 0xffff, 0x7f00, 1}
	assert(udp_enable_ecn(receiver, .IP4))
	for mark in ([]ECN_Codepoint{.Not_ECT, .ECT_1, .ECT_0, .CE}) {
		sent, e := send_udp_ecn(sender, []u8{42}, target, mark)
		assert(e == nil && sent == 1)
		buffer: [8]u8
		got, _, metadata, cause := recv_udp_metadata(receiver, buffer[:])
		testing.expect(t, cause == nil && got == 1 && metadata.ecn_valid && metadata.ecn == mark)
	}
	dual, de := make_unbound_udp_socket(.IP6)
	assert(de == nil)
	defer close(dual)
	only_option: i32 = 27
	when ODIN_OS == .Linux {only_option = 26}
	assert(udp_fragmentation_set(dual, 41, only_option, 0) == 0)
	assert(bind(dual, {IP6_Any, 0}) == .None && udp_enable_ecn(dual, .IP6))
	assert(set_option(dual, .Receive_Timeout, 100 * time.Millisecond) == nil)
	dual_target, dte := bound_endpoint(dual)
	assert(dte == .None)
	dual_target.address = IP4_Loopback
	four, fe := make_unbound_udp_socket(.IP4)
	assert(fe == nil)
	defer close(four)
	for mark in ([]ECN_Codepoint{.Not_ECT, .ECT_1, .ECT_0, .CE}) {
		sent, e := send_udp_ecn(four, []u8{42}, dual_target, mark)
		assert(e == nil && sent == 1)
		buffer: [8]u8
		got, _, metadata, cause := recv_udp_metadata(dual, buffer[:])
		testing.expect(t, cause == nil && got == 1 && metadata.ecn_valid && metadata.ecn == mark)
	}
	testing.expect(t, udp_fragmentation_policy(sender, .IP6) == configured)
}
