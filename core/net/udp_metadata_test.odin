#+build darwin, linux
package net
import "core:testing"
import "core:time"

@(test)
udp_ecn_ipv4_ipv6_codepoints_are_per_datagram :: proc(t: ^testing.T) {
	for endpoint in ([]Endpoint{{IP4_Loopback, 0}, {IP6_Loopback, 0}}) {
		family := family_from_endpoint(endpoint)
		sender, se := make_unbound_udp_socket(family)
		assert(se == nil)
		defer close(sender)
		receiver, re := make_unbound_udp_socket(family)
		assert(re == nil)
		defer close(receiver)
		assert(bind(receiver, endpoint) == .None)
		assert(set_option(receiver, .Receive_Timeout, 100 * time.Millisecond) == nil)
		target, te := bound_endpoint(receiver)
		assert(te == .None)
		testing.expect(t, udp_enable_ecn(receiver, family))
		for mark in ([]ECN_Codepoint{.ECT_0, .CE, .ECT_1, .Not_ECT}) {
			n, e := send_udp_ecn(sender, []u8{42}, target, mark)
			testing.expect(t, e == nil && n == 1)
			buffer: [8]u8
			got, _, metadata, cause := recv_udp_metadata(receiver, buffer[:])
			testing.expect(
				t,
				cause == nil &&
				got == 1 &&
				buffer[0] == 42 &&
				metadata.ecn_valid &&
				metadata.ecn == mark &&
				!metadata.control_truncated,
			)
		}
		// Legacy send remains unmarked after marked sends; empty datagrams stay real.
		_, e := send_udp(sender, nil, target)
		assert(e == nil)
		buffer: [8]u8
		got, _, metadata, cause := recv_udp_metadata(receiver, buffer[:])
		testing.expect(t, cause == nil && got == 0 && metadata.ecn_valid && metadata.ecn == .Not_ECT)
		large: [16]u8
		_, e = send_udp_ecn(sender, large[:], target, .CE)
		assert(e == nil)
		got, _, metadata, cause = recv_udp_metadata(receiver, buffer[:])
		testing.expect(t, cause == .Excess_Truncated && got == 8 && metadata.ecn_valid && metadata.ecn == .CE)
	}
}

@(test)
udp_ecn_control_parser_rejects_malformed_and_truncated :: proc(t: ^testing.T) {
	control: [4]u64
	raw := (cast([^]u8)(&control))[:size_of(control)]
	header := cast(^ECN_Control)(&control)
	head := ecn_align(size_of(ECN_Control))
	header.length = type_of(header.length)(head + 1)
	header.level = 0
	when ODIN_OS == .Linux {header.kind = 1} else {header.kind = 27}
	raw[head] = 0xbb // DSCP bits must not leak into ECN.
	m := ecn_control_parse(raw[:int(header.length)], false)
	testing.expect(t, m.ecn_valid && m.ecn == .CE)
	m = ecn_control_parse(raw, true)
	testing.expect(t, !m.ecn_valid && m.control_truncated)
	header.length = 1
	m = ecn_control_parse(raw, false)
	testing.expect(t, !m.ecn_valid)
	header.length = 999
	m = ecn_control_parse(raw, false)
	testing.expect(t, !m.ecn_valid)
	header.length = type_of(header.length)(head)
	m = ecn_control_parse(raw, false)
	testing.expect(t, !m.ecn_valid)
}
