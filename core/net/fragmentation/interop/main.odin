package main

import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:time"

receive_mapped :: proc() {
	socket, error := net.make_bound_udp_socket(net.IP6_Any, 0)
	assert(error == nil)
	defer net.close(socket)
	assert(net.udp_disable_fragmentation(socket, .IP6).status == .Configured)
	assert(net.udp_enable_ecn(socket, .IP6))
	assert(net.set_option(socket, .Receive_Timeout, 2 * time.Second) == nil)
	endpoint, ee := net.bound_endpoint(socket)
	assert(ee == .None)
	fmt.printf("READY %d\n", endpoint.port)
	os.flush(os.stdout)
	buffer: [1200]u8
	n, from, metadata, cause := net.recv_udp_metadata(socket, buffer[:])
	assert(
		cause == nil && n == len(buffer) && metadata.ecn_valid && metadata.ecn == .CE && !metadata.control_truncated,
	)
	expected: [1200]u8
	for &b, i in expected {b = u8(i % 251)}
	copy(expected[:], transmute([]u8)string("webtools400"))
	assert(buffer == expected)
	ip, ok := from.address.(net.IP6_Address)
	assert(ok && ip[5] == 0xffff)
	fmt.printf("%s\"native_receive\":\"mapped\",\"ecn\":%d,\"received\":%d%s\n", "{", u8(metadata.ecn), n, "}")
}

main :: proc() {
	assert(len(os.args) == 3)
	if os.args[1] == "receive-mapped" {
		receive_mapped()
		return
	}
	mode := os.args[1]
	port, ok := strconv.parse_int(os.args[2])
	assert(ok && port > 0 && port <= 65535)
	family := net.Address_Family.IP4
	target := net.Endpoint{net.IP4_Loopback, port}
	if mode == "ipv6" {
		family = .IP6
		target.address = net.IP6_Loopback
	}
	if mode == "mapped" {
		family = .IP6
		target.address = net.IP6_Address{0, 0, 0, 0, 0, 0xffff, 0x7f00, 1}
	}
	socket, error := net.make_unbound_udp_socket(family)
	assert(error == nil)
	defer net.close(socket)
	before := net.udp_fragmentation_policy(socket, family)
	policy := net.udp_disable_fragmentation(socket, family)
	assert(policy.status == .Configured && policy.native_error == 0)
	assert(net.udp_fragmentation_policy(socket, family) == policy)
	if mode == "mapped" {
		assert(policy.dual_stack && policy.ipv4 && policy.ipv6)
	}
	payload: [1200]u8
	for &b, i in payload {b = u8(i % 251)}
	copy(payload[:], transmute([]u8)string("webtools400"))
	sent, cause := net.send_udp_ecn(socket, payload[:], target, .CE)
	assert(cause == nil && sent == len(payload))
	fmt.printf(
		"%s\"native_mode\":\"%s\",\"before\":\"%v\",\"policy\":\"%v\",\"ipv4\":%v,\"ipv6\":%v,\"dual_stack\":%v,\"sent\":%d%s\n",
		"{",
		mode,
		before.status,
		policy.status,
		policy.ipv4,
		policy.ipv6,
		policy.dual_stack,
		sent,
		"}",
	)
}
