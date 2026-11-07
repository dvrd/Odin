package main
import tls "../../../../../core/crypto/tls"
import credentials "../../../../../core/crypto/tls/credentials"
import store "../../../../../core/crypto/tls/credentials/store"
import "core:fmt"
import "core:os"
import "core:time"

main :: proc() {
	assert(len(os.args) == 5)
	ch, re := os.read_entire_file(os.args[1], context.allocator); assert(re == nil)
	defer delete(ch)
	cp, ce := os.read_entire_file(os.args[2], context.allocator); assert(ce == nil)
	defer delete(cp)
	kp, ke := os.read_entire_file(os.args[3], context.allocator); assert(ke == nil)
	defer delete(kp)
	credential, ec := credentials.create(cp, kp, {}, context.allocator); assert(ec == .None)
	s, es := store.create({}, context.allocator); assert(es.kind == .None); defer store.destroy(&s)
	assert(store.replace(s, &credential).kind == .None)
	o: tls.Server_Handshake
	assert(
		tls.server_handshake_init(&o, tls.SERVER_HANDSHAKE_DEFAULT_CONFIG, context.allocator) ==
		.None,
	)
	defer tls.server_handshake_destroy(&o)
	// Exercise one-byte ClientHello delivery through the public API.
	for at in 0 ..< len(ch) {
		n, _, e := tls.server_handshake_feed(&o, .Initial, ch[at:at + 1])
		assert(n == 1 && e == .None)
	}
	peer, _ := tls.server_handshake_peek(&o); assert(peer.kind == .Peer_Parameters)
	assert(tls.server_handshake_accept(&o, peer.id) == .None)
	assert(
		tls.server_handshake_start_flight(&o, s, time.from_nanoseconds(1790000000 * 1000000000)) ==
		.None,
	)
	output: [dynamic]u8; defer delete(output)
	for _ in 0 ..< 1000 {
		event, e := tls.server_handshake_peek(&o); assert(e == .None)
		if event.kind == .None {
			break
		}
		assert(event.kind == .Handshake_Bytes || event.kind == .Traffic_Secret)
		bytes := event.bytes; if event.kind == .Traffic_Secret {
			bytes = event.secret
		}
		n := len(bytes)
		append(
			&output,
			u8(event.kind),
			u8(event.level),
			u8(event.direction),
			u8(n >> 24),
			u8(n >> 16),
			u8(n >> 8),
			u8(n),
		)
		append(&output, ..bytes)
		same, _ := tls.server_handshake_peek(&o); assert(same.id == event.id)
		assert(tls.server_handshake_accept(&o, event.id) == .None)
	}
	_, status, e := tls.server_handshake_feed(&o, .Handshake, nil)
	assert(status == .Await_Client_Finished && e == .None)
	assert(os.write_entire_file(os.args[4], output[:]) == nil)
	stats, _ := tls.server_handshake_stats(&o)
	fmt.eprintf(
		"public flight: owner=%d peak=%d allocations=%d\n",
		size_of(o),
		stats.peak_bytes,
		stats.allocation_attempts,
	)
	tls.server_handshake_destroy(&o)
	final, _ := tls.server_handshake_stats(&o); assert(final.live_bytes == 0)
	ss, _ := store.stats(s); assert(ss.active_leases == 0)
}
