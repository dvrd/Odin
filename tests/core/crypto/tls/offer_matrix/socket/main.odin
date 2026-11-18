// One connection through upstream's Socket API against an external TLS 1.3
// server that reverses each line it receives (openssl s_server -rev), with
// h2 and http/1.1 offered.
//
//	socket <host> <port> <roots.pem> <server-name>
package main

import tls "../../../../../../core/crypto/tls"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"

fail :: proc(format: string, args: ..any) -> ! {
	fmt.eprintf(format, ..args)
	fmt.eprintln()
	os.exit(1)
}

main :: proc() {
	if len(os.args) != 5 {
		fail("usage: socket <host> <port> <roots.pem> <server-name>")
	}

	port, port_ok := strconv.parse_int(os.args[2])
	address := net.parse_address(os.args[1])
	if !port_ok || address == nil {
		fail("unknown address or port")
	}

	pem, read_error := os.read_entire_file(os.args[3], context.allocator)
	if read_error != nil {
		fail("roots: %v", read_error)
	}

	roots := new(tls.Root_Pool)
	if parsed := tls.root_pool_parse(roots, pem); parsed.kind != .None {
		fail("roots: %v", parsed)
	}

	fd, dial_error := net.dial_tcp_from_endpoint({address = address, port = port})
	if dial_error != nil {
		fail("dial: %v", dial_error)
	}

	socket: tls.Socket
	offered := [?]tls.Alpn_Protocols{.Http_2, .Http_1_1}
	if err := tls.client_handshake(&socket, fd, os.args[4], roots.roots[:roots.count], offered[:]); err != nil {
		fail("handshake: %v", err)
	}

	request := "odin\n"
	if _, err := tls.send(&socket, transmute([]u8)request); err != nil {
		fail("send: %v", err)
	}

	answer: [16]u8
	used := 0
	for used < len(request) {
		n, err := tls.recv(&socket, answer[used:])
		if err != nil {
			fail("recv: %v", err)
		}
		used += n
	}

	if string(answer[:used]) != "nido\n" {
		fail("answer %q", string(answer[:used]))
	}

	fmt.printf("OK %v %v\n", socket.cipher_suite, socket.alpn_protocol)
	tls.close(&socket)
}
