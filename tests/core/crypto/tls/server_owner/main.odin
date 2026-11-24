// A public-API shell consumer, deliberately without records or network I/O.
package main

import "core:crypto/tls"
import "core:fmt"

main :: proc() {
	wire := transmute([]u8)#load("../../../../../core/crypto/tls/testdata/server_go_client_hello.wire")
	owner: tls.Server_Handshake
	assert(tls.server_handshake_init(&owner, tls.SERVER_HANDSHAKE_DEFAULT_CONFIG, context.allocator) == .None)
	defer assert(tls.server_handshake_destroy(&owner) == .None)
	for i in 0 ..< len(wire) {
		n, status, error := tls.server_handshake_feed(&owner, .Initial, wire[i:i + 1])
		assert(n == 1 && error == .None)
		assert(status == (.Need_Event_Drain if i == len(wire) - 1 else .Need_Input))
	}
	event, error := tls.server_handshake_peek(&owner)
	assert(error == .None && event.kind == .Peer_Parameters)
	assert(string(event.peer.server_name) == "fixture.invalid")
	again, _ := tls.server_handshake_peek(&owner)
	assert(again.id == event.id)
	n, status, _ := tls.server_handshake_feed(&owner, .Handshake, ([]u8){20, 0, 0, 32})
	assert(n == 0 && status == .Need_Event_Drain)
	assert(tls.server_handshake_accept(&owner, event.id) == .None)
	assert(tls.server_handshake_accept(&owner, event.id) == .Invalid_Event)
	n, status, _ = tls.server_handshake_feed(&owner, .Handshake, ([]u8){20, 0, 0, 32})
	assert(n == 0 && status == .Await_Flight)
	assert(tls.server_handshake_abort(&owner) == .None)
	stats, _ := tls.server_handshake_stats(&owner)
	assert(stats.live_bytes == 0 && stats.peak_bytes == len(wire))
	fmt.printf(
		"recordless shell public consumer pass: owner=%d bytes; CH peak=%d; no handshake completion\n",
		size_of(owner),
		stats.peak_bytes,
	)
}
