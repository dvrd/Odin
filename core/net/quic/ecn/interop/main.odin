package main
import "core:fmt"
import "core:net"
import "core:os"
import "core:time"

main :: proc() {
	family: net.Address_Family = .IP4
	endpoint := net.Endpoint{net.IP4_Loopback, 0}
	if len(os.args) > 1 && os.args[1] == "6" {
		family = .IP6
		endpoint = {net.IP6_Loopback, 0}
	}
	socket, e := net.make_unbound_udp_socket(family)
	assert(e == nil)
	defer net.close(socket)
	assert(net.bind(socket, endpoint) == .None)
	assert(net.set_option(socket, .Receive_Timeout, 2 * time.Second) == nil)
	assert(net.udp_enable_ecn(socket, family))
	actual, ae := net.bound_endpoint(socket)
	assert(ae == .None)
	fmt.println(actual.port)
	for _ in 0 ..< 4 {
		data: [16]u8
		n, from, metadata, re := net.recv_udp_metadata(socket, data[:])
		assert(re == nil && n == 1 && metadata.ecn_valid)
		assert(u8(metadata.ecn) == data[0])
		sent, se := net.send_udp_ecn(socket, data[:n], from, metadata.ecn)
		assert(se == nil && sent == n)
	}
}
