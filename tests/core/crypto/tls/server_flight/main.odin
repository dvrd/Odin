package main
import tls "../../../../../core/crypto/tls"
import credentials "../../../../../core/crypto/tls/credentials"
import store "../../../../../core/crypto/tls/credentials/store"
import "core:fmt"
import "core:os"
import "core:time"

main :: proc() {
	assert(len(os.args) == 5 || len(os.args) == 6)
	bad := len(os.args) == 6 && os.args[5] == "bad"
	reject := len(os.args) == 6 && os.args[5] == "reject"
	select_parameters := len(os.args) == 6 && (os.args[5] == "alpn" || os.args[5] == "quic")
	quic := select_parameters && os.args[5] == "quic"
	ch, re := os.read_entire_file(os.args[1], context.allocator)
	assert(re == nil)
	defer delete(ch)
	cp, ce := os.read_entire_file(os.args[2], context.allocator)
	assert(ce == nil)
	defer delete(cp)
	kp, ke := os.read_entire_file(os.args[3], context.allocator)
	assert(ke == nil)
	defer delete(kp)
	credential, ec := credentials.create(cp, kp, {}, context.allocator)
	assert(ec == .None)
	s, es := store.create({}, context.allocator)
	assert(es.kind == .None)
	defer store.destroy(&s)
	assert(store.replace(s, &credential).kind == .None)
	o: tls.Server_Handshake
	assert(tls.server_handshake_init(&o, tls.SERVER_HANDSHAKE_DEFAULT_CONFIG, context.allocator) == nil)
	defer tls.server_handshake_destroy(&o)
	// Exercise one-byte ClientHello delivery through the public API.
	for at in 0 ..< len(ch) {
		n, _, e := tls.server_handshake_feed(&o, .Initial, ch[at:at + 1])
		assert(n == 1 && e == nil)
	}
	peer, _ := tls.server_handshake_peek(&o)
	if peer.kind == .Handshake_Bytes {
		assert(peer.level == .Initial && len(peer.bytes) <= 88)
		n := len(peer.bytes)
		retry_wire: [95]u8
		retry_wire[0], retry_wire[1] = u8(peer.kind), u8(peer.level)
		retry_wire[3], retry_wire[4], retry_wire[5], retry_wire[6] = u8(n >> 24), u8(n >> 16), u8(n >> 8), u8(n)
		copy(retry_wire[7:], peer.bytes)
		assert(os.write_entire_file(os.args[4], retry_wire[:7 + n]) == nil)
		assert(tls.server_handshake_accept(&o, peer.id) == nil)
		fmt.println("RETRY")
		length: [4]u8
		for at := 0; at < 4; {n, e := os.read(os.stdin, length[at:]); assert(e == nil && n > 0); at += n}
		size := int(length[0]) << 24 | int(length[1]) << 16 | int(length[2]) << 8 | int(length[3])
		assert(size > 0 && size <= 65536)
		second := make([]u8, size)
		defer delete(second)
		for at := 0; at < size; {n, e := os.read(os.stdin, second[at:]); assert(e == nil && n > 0); at += n}
		for at in 0 ..< size {
			n, _, e := tls.server_handshake_feed(&o, .Initial, second[at:at + 1])
			assert(n == 1 && e == nil)
		}
		peer, _ = tls.server_handshake_peek(&o)
	}
	assert(peer.kind == .Peer_Parameters)
	if select_parameters {
		config := tls.Server_Handshake_Parameters_Config {
			alpn_protocols = []string{"opaque\x00\xff", "http/1.1", "h2", "h3"},
			require_alpn   = true,
		}
		if quic {
			assert(peer.peer.has_quic_transport_parameters)
			assert(string(peer.peer.quic_transport_parameters) == "\x00\x01\x02")
			config.mode = .QUIC
			config.quic_transport_parameters = []u8{9, 8, 7}
		}
		assert(tls.server_handshake_select_parameters(&o, peer.id, config) == nil)
		p, pe := tls.server_handshake_parameters(&o)
		assert(pe == nil && !p.authenticated)
	} else {
		assert(tls.server_handshake_accept(&o, peer.id) == nil)
	}
	assert(tls.server_handshake_start_flight(&o, s, time.from_nanoseconds(1790000000 * 1000000000)) == nil)
	output: [dynamic]u8
	defer delete(output)
	for _ in 0 ..< 1000 {
		event, e := tls.server_handshake_peek(&o)
		assert(e == nil)
		if event.kind == .None {
			break
		}
		assert(event.kind == .Handshake_Bytes || event.kind == .Traffic_Secret)
		bytes := event.bytes
		if event.kind == .Traffic_Secret {
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
		same, _ := tls.server_handshake_peek(&o)
		assert(same.id == event.id)
		assert(tls.server_handshake_accept(&o, event.id) == nil)
	}
	_, status, e := tls.server_handshake_feed(&o, .Handshake, nil)
	assert(status == .Need_Input && e == nil)
	assert(os.write_entire_file(os.args[4], output[:]) == nil)
	fmt.println("READY")
	if reject {
		control: [1]u8
		n, e := os.read(os.stdin, control[:])
		assert(e == nil && n == 1 && control[0] == 1)
		event, _ := tls.server_handshake_peek(&o)
		assert(event.kind == .None)
		assert(tls.server_handshake_abort(&o) == nil)
		stats, _ := tls.server_handshake_stats(&o)
		assert(stats.live_bytes == 0)
		ss, _ := store.stats(s)
		assert(ss.active_leases == 0)
		fmt.eprintf(
			"public rejection: owner=%d peak=%d allocations=%d live=%d\n",
			size_of(o),
			stats.peak_bytes,
			stats.allocation_attempts,
			stats.live_bytes,
		)
		fmt.println("REJECTED")
		return
	}
	// The independent peer returns its actual Finished over a bounded pipe.
	finished: [36]u8
	for at := 0; at < len(finished); {
		n, re := os.read(os.stdin, finished[at:])
		assert(re == nil && n > 0)
		at += n
	}
	for at in 0 ..< len(finished) {
		n, st, fe := tls.server_handshake_feed(&o, .Handshake, finished[at:at + 1])
		assert(n == 1)
		if bad && at == 35 {
			assert(fe == tls.Error(tls.Protocol_Error.Decrypt_Error) && st == .Terminal)
		} else {
			assert(fe == nil && st == (.Need_Event_Drain if at == 35 else .Need_Input))
		}
	}
	complete, _ := tls.server_handshake_peek(&o)
	assert(complete.kind == (.Fatal if bad else .Complete))
	clean, _ := tls.server_handshake_stats(&o)
	if select_parameters {
		p, pe := tls.server_handshake_parameters(&o)
		assert(pe == nil && p.authenticated)
		assert(string(p.alpn) == ("h3" if quic else "http/1.1") || string(p.alpn) == "opaque\x00\xff")
		if quic {
			assert(string(p.local_quic) == "\x09\x08\x07" && string(p.peer_quic) == "\x00\x01\x02")
		}
		assert(clean.live_bytes == len(p.alpn) + len(p.local_quic) + len(p.peer_quic))
	} else {
		assert(clean.live_bytes == 0)
	}
	assert(tls.server_handshake_accept(&o, complete.id) == nil)
	none, _ := tls.server_handshake_peek(&o)
	assert(none.kind == .None)
	clean, _ = tls.server_handshake_stats(&o)
	assert(clean.live_bytes == 0)
	if select_parameters {
		_, pe := tls.server_handshake_parameters(&o)
		assert(pe == .Invalid_State)
	}
	fmt.println("REJECTED" if bad else "COMPLETE")
	stats, _ := tls.server_handshake_stats(&o)
	fmt.eprintf(
		"public flight: owner=%d peak=%d allocations=%d\n",
		size_of(o),
		stats.peak_bytes,
		stats.allocation_attempts,
	)
	tls.server_handshake_destroy(&o)
	final, _ := tls.server_handshake_stats(&o)
	assert(final.live_bytes == 0)
	ss, _ := store.stats(s)
	assert(ss.active_leases == 0)
}
