// One blocking client connection with the Upstream offer restricted to a
// single suite and group, against an external TLS 1.3 server that reverses
// each line it receives (openssl s_server -rev).
//
//	client <host> <port> <roots.pem> <server-name> <suite> <group>
package main

import tls "../../../../../../core/crypto/tls"
import "core:fmt"
import "core:os"
import "core:strconv"

// tls keeps upstream's wire enumerations package-private: their types are
// taken from the Config fields and their values written as implicit selectors.
Suite :: type_of(tls.Config{}._cipher_suites[0])
Group :: type_of(tls.Config{}._groups[0])

suite_named :: proc(name: string) -> (Suite, bool) {
	switch name {
	case "TLS_AES_128_GCM_SHA256":
		return .TLS_AES_128_GCM_SHA256, true
	case "TLS_AES_256_GCM_SHA384":
		return .TLS_AES_256_GCM_SHA384, true
	case "TLS_CHACHA20_POLY1305_SHA256":
		return .TLS_CHACHA20_POLY1305_SHA256, true
	}
	return {}, false
}

group_named :: proc(name: string) -> (Group, bool) {
	switch name {
	case "X25519MLKEM768":
		return .X25519MLKEM768, true
	case "X448":
		return .X448, true
	case "P-384":
		return .Secp384r1, true
	case "X25519":
		return .X25519, true
	case "P-256":
		return .Secp256r1, true
	}
	return {}, false
}

fail :: proc(format: string, args: ..any) -> ! {
	fmt.eprintf(format, ..args)
	fmt.eprintln()
	os.exit(1)
}

main :: proc() {
	if len(os.args) != 7 {
		fail("usage: client <host> <port> <roots.pem> <server-name> <suite> <group>")
	}

	port, port_ok := strconv.parse_int(os.args[2])
	if !port_ok {
		fail("unknown port")
	}

	pem, read_error := os.read_entire_file(os.args[3], context.allocator)
	if read_error != nil {
		fail("roots: %v", read_error)
	}

	roots := new(tls.Root_Pool)
	if parsed := tls.root_pool_parse(roots, pem); parsed.kind != .None {
		fail("roots: %v", parsed)
	}

	suite, suite_ok := suite_named(os.args[5])
	group, group_ok := group_named(os.args[6])
	if !suite_ok || !group_ok {
		fail("unknown suite or group")
	}

	suites := [1]Suite{suite}
	groups := [1]Group{group}
	config := tls.Config {
		server_name   = os.args[4],
		root_cas      = roots.roots[:roots.count],
		offer         = .Upstream,
		_cipher_suites = suites[:],
		_groups        = groups[:],
	}

	conn := new(tls.Conn)
	if dialed := tls.dial(conn, os.args[1], port, config); dialed != nil {
		fail("dial: %v", dialed)
	}

	state := tls.connection_state(conn)
	if state.cipher_suite != suite || conn.server_parameters.group != group {
		fail("negotiated %v over %v", state.cipher_suite, conn.server_parameters.group)
	}

	request := "odin\n"
	if _, write_error := tls.write(conn, transmute([]u8)request); write_error != nil {
		fail("write: %v", write_error)
	}

	answer: [16]u8
	used := 0
	for used < len(request) {
		count, read_failure := tls.read(conn, answer[used:])
		if read_failure != nil {
			fail("read: %v", read_failure)
		}
		used += count
	}

	if string(answer[:used]) != "nido\n" {
		fail("answer %q", string(answer[:used]))
	}

	tls.conn_close(conn)
	fmt.printf("OK %v %v\n", state.cipher_suite, conn.server_parameters.group)
}
