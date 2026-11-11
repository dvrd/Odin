package tests

import "core:bytes"
import "core:crypto/ed25519"
import "core:crypto/sha2"
import "core:crypto/tls"
import "core:crypto/x509"
import "core:encoding/pem"
import "core:mem"
import "core:net/quic"
import "core:net/quic/conn"
import "core:net/quic/harness"
import "core:net/quic/sim"
import "core:testing"
import "core:time"

// Two conn endpoints on the sim. This is not an independent QUIC peer.
// Linux is not run from this suite.

Flight :: struct {
	ch, sh:               [128]u8,
	flight:               [2048]u8,
	ch_n, sh_n, flight_n: int,
	params:               [3]u8,
	shared:               [32]u8,
	pool:                 tls.Root_Pool,
	roots:                []^x509.Certificate,
	now:                  time.Time,
}

put_u16 :: proc(dst: []u8, v: int) {
	dst[0] = u8(v >> 8)
	dst[1] = u8(v)
}

put_u24 :: proc(dst: []u8, v: int) {
	dst[0] = u8(v >> 16)
	dst[1] = u8(v >> 8)
	dst[2] = u8(v)
}

flight_client_hello :: proc(dst: []u8, params: []u8) -> []u8 {
	names := 1 + len("h3")
	ext_len := 4 + 2 + names + 4 + len(params)
	body := 43 + ext_len
	if len(dst) < 4 + body {
		return nil
	}
	dst[0] = 1
	put_u24(dst[1:], body)
	dst[4], dst[5] = 3, 3
	for i in 6 ..< 38 {
		dst[i] = 0x11
	}
	dst[38] = 0
	dst[39], dst[40] = 0, 2
	dst[41], dst[42] = 0x13, 0x01
	dst[43], dst[44] = 1, 0
	put_u16(dst[45:], ext_len)
	at := 47
	put_u16(dst[at:], 16)
	put_u16(dst[at + 2:], 2 + names)
	put_u16(dst[at + 4:], names)
	at += 6
	dst[at] = u8(len("h3"))
	at += 1
	dst[at] = 'h'
	dst[at + 1] = '3'
	at += 2
	put_u16(dst[at:], 0x0039)
	put_u16(dst[at + 2:], len(params))
	at += 4
	at += copy(dst[at:], params)
	return dst[:at]
}

flight_server_hello :: proc(dst: []u8) -> []u8 {
	if len(dst) < 90 {
		return nil
	}
	dst[0] = 2
	put_u24(dst[1:], 86)
	dst[4], dst[5] = 3, 3
	for i in 6 ..< 38 {
		dst[i] = 0x11
	}
	dst[38] = 0
	dst[39], dst[40] = 0x13, 0x01
	dst[41] = 0
	dst[42], dst[43] = 0x00, 0x2e
	prefix := [?]u8{0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20}
	copy(dst[44:], prefix[:])
	for i in 52 ..< 84 {
		dst[i] = 0x22
	}
	versions := [?]u8{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	copy(dst[84:], versions[:])
	return dst[:90]
}

flight_extensions :: proc(dst: []u8, params, extra: []u8) -> []u8 {
	alpn := [?]u8{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33}
	ext_len := len(alpn) + 4 + len(params) + len(extra)
	body := 2 + ext_len
	if len(dst) < 4 + body {
		return nil
	}
	dst[0] = 8
	put_u24(dst[1:], body)
	put_u16(dst[4:], ext_len)
	at := 6
	at += copy(dst[at:], alpn[:])
	put_u16(dst[at:], 0x0039)
	put_u16(dst[at + 2:], len(params))
	at += 4
	at += copy(dst[at:], params)
	at += copy(dst[at:], extra)
	return dst[:at]
}

flight_certificate :: proc(dst: []u8) -> []u8 {
	block, _, decode_error := pem.decode(
		#load("../../../../../tests/core/crypto/tls/testdata/leaf.pem"),
	)
	if decode_error != nil || block == nil {
		return nil
	}
	defer pem.block_delete(block)
	der := pem.block_bytes(block)
	size := 13 + len(der)
	if len(dst) < size {
		return nil
	}
	dst[0] = 11
	put_u24(dst[1:], size - 4)
	dst[4] = 0
	put_u24(dst[5:], len(der) + 5)
	put_u24(dst[8:], len(der))
	copy(dst[11:], der)
	dst[size - 2], dst[size - 1] = 0, 0
	return dst[:size]
}

flight_hash :: proc(parts: ..[]u8) -> [32]u8 {
	t: sha2.Context_256
	sha2.init_256(&t)
	for part in parts {
		sha2.update(&t, part)
	}
	out: [32]u8
	sha2.final(&t, out[:])
	return out
}

flight_sign :: proc(dst: []u8, transcript: [32]u8) -> []u8 {
	if len(dst) < 8 + ed25519.SIGNATURE_SIZE {
		return nil
	}
	seed: [32]u8
	seed[0] = 1
	key: ed25519.Private_Key
	if !ed25519.private_key_set_bytes(&key, seed[:]) {
		return nil
	}
	defer ed25519.private_key_clear(&key)
	CONTEXT :: tls.SERVER_CERTIFICATE_VERIFY_CONTEXT
	context_string := CONTEXT
	signed: [64 + len(CONTEXT) + 1 + 32]u8
	for i in 0 ..< 64 {
		signed[i] = 0x20
	}
	copy(signed[64:], transmute([]u8)context_string)
	digest := transcript
	copy(signed[len(signed) - 32:], digest[:])
	dst[0] = 15
	put_u24(dst[1:], 68)
	dst[4], dst[5] = 0x08, 0x07
	dst[6], dst[7] = 0, 64
	ed25519.sign(&key, signed[:], dst[8:8 + ed25519.SIGNATURE_SIZE])
	return dst[:8 + ed25519.SIGNATURE_SIZE]
}

build_flight :: proc(t: ^testing.T) -> ^Flight {
	f := new(Flight)
	f.params = {1, 2, 3}
	f.shared[0] = 0x42
	f.now = time.unix(1893456000, 0)
	ch := flight_client_hello(f.ch[:], f.params[:])
	sh := flight_server_hello(f.sh[:])
	testing.expect(t, len(ch) == 63 && len(sh) == 90)
	f.ch_n = len(ch)
	f.sh_n = len(sh)
	hs, he := tls.quic_handshake_secrets(f.shared, f.ch[:f.ch_n], f.sh[:f.sh_n], f.params[:])
	defer tls.quic_handshake_keys_clear(&hs)
	testing.expect_value(t, he.kind, .None)
	ee_storage: [64]u8
	groups := [?]u8{0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d}
	ee := flight_extensions(ee_storage[:], f.params[:], groups[:])
	cert_storage: [1024]u8
	cert := flight_certificate(cert_storage[:])
	testing.expect(t, len(cert) > 13)
	through_cert := flight_hash(f.ch[:f.ch_n], f.sh[:f.sh_n], ee, cert)
	cv_storage: [80]u8
	cv := flight_sign(cv_storage[:], through_cert)
	through_cv := flight_hash(f.ch[:f.ch_n], f.sh[:f.sh_n], ee, cert, cv)
	server_finished: [tls.FINISHED_MESSAGE_SIZE]u8
	fn, ferr := tls.finished_encode(server_finished[:], hs.server.secret, through_cv)
	testing.expect(t, ferr == .None && fn == len(server_finished))
	at := 0
	at += copy(f.flight[at:], ee)
	at += copy(f.flight[at:], cert)
	at += copy(f.flight[at:], cv)
	at += copy(f.flight[at:], server_finished[:])
	f.flight_n = at
	if tls.root_pool_parse(&f.pool, #load("../../../../../tests/core/crypto/tls/testdata/root.pem")).kind !=
	   .None {
		testing.expect(t, false)
		return f
	}
	f.roots = f.pool.roots[:f.pool.count]
	return f
}

free_flight :: proc(f: ^Flight) {
	if f == nil {
		return
	}
	tls.root_pool_destroy(&f.pool)
	free(f)
}

wide_limits :: proc() -> harness.Limits {
	return {
		max_data = 1 << 20,
		max_stream_data = 1 << 20,
		max_streams = 32,
		recv_max_data = 1 << 20,
		recv_max_stream_data = 1 << 20,
		recv_max_streams = 32,
	}
}

material_of :: proc(f: ^Flight) -> conn.Material {
	return {
		shared = f.shared,
		client_hello = f.ch[:f.ch_n],
		server_hello = f.sh[:f.sh_n],
		server_flight = f.flight[:f.flight_n],
		params = f.params[:],
		server_name = "localhost",
		roots = f.roots,
		now = f.now,
	}
}

Pair :: struct {
	client, server: ^conn.Connection,
	link:           sim.Link,
	slots:          []sim.Packet_Slot,
	payloads:       []u8,
	timers:         []sim.Timer_Slot,
	flight:         ^Flight,
}

open_pair :: proc(t: ^testing.T, limits: harness.Limits, full_size: bool) -> ^Pair {
	p := new(Pair)
	p.flight = build_flight(t)
	p.client = new(conn.Connection)
	p.server = new(conn.Connection)
	local := [?]u8{1, 2, 3, 4, 5, 6, 7, 8}
	peer := [?]u8{8, 7, 6, 5, 4, 3, 2, 1}
	testing.expect_value(
		t,
		conn.init(
			p.client,
			{
				role = .Client,
				local_cid = local[:],
				peer_cid = peer[:],
				material = material_of(p.flight),
				limits = limits,
				max_datagram = 1200,
				full_size = full_size,
			},
		),
		.None,
	)
	testing.expect_value(
		t,
		conn.init(
			p.server,
			{
				role = .Server,
				local_cid = peer[:],
				peer_cid = local[:],
				material = material_of(p.flight),
				limits = limits,
				max_datagram = 1200,
				full_size = full_size,
			},
		),
		.None,
	)
	testing.expect_value(t, conn.refuse_zero_rtt(p.client), .None)
	testing.expect_value(t, conn.refuse_zero_rtt(p.server), .None)
	p.slots = make([]sim.Packet_Slot, 64)
	p.payloads = make([]u8, 64 * 1200)
	p.timers = make([]sim.Timer_Slot, 16)
	testing.expect_value(t, sim.init(&p.link, p.slots, p.payloads, 1200, p.timers), .None)
	return p
}

close_pair :: proc(p: ^Pair) {
	if p == nil {
		return
	}
	sim.destroy(&p.link)
	delete(p.slots)
	delete(p.payloads)
	delete(p.timers)
	conn.destroy(p.client)
	conn.destroy(p.server)
	free(p.client)
	free(p.server)
	free_flight(p.flight)
	free(p)
}

endpoint :: proc(c: ^conn.Connection, p: ^Pair) -> (sim.Address, sim.Address) {
	if c == p.client {
		return {peer = 1, path = 1}, {peer = 2, path = 2}
	}
	return {peer = 2, path = 2}, {peer = 1, path = 1}
}

post :: proc(p: ^Pair, c: ^conn.Connection, plan: sim.Plan) -> (int, conn.Error) {
	buf: [conn.MAX_DATAGRAM]u8
	n, err := conn.pump(c, i64(p.link.now), buf[:])
	if err != .None || n == 0 {
		return n, err
	}
	src, dst := endpoint(c, p)
	if sim.send(&p.link, src, dst, buf[:n], plan) != .None {
		return n, .Failed
	}
	return n, .None
}

deliver :: proc(p: ^Pair, until: i64) -> conn.Error {
	buf: [conn.MAX_DATAGRAM]u8
	for {
		ev, ok, err := sim.step(&p.link, sim.Tick(until), buf[:])
		if err != .None {
			return .Failed
		}
		if !ok {
			return .None
		}
		if ev.kind != .Datagram {
			continue
		}
		target := p.server if ev.destination.peer == 2 else p.client
		e := conn.ingest(target, i64(ev.at), ev.source.path, buf[:ev.size])
		if e != .None && e != .Discarded {
			return e
		}
	}
}

settle :: proc(t: ^testing.T, p: ^Pair) {
	for _ in 0 ..< 48 {
		if conn.established(p.client) && conn.established(p.server) && p.link.stats.packets == 0 {
			cn, ce := post(p, p.client, {})
			sn, se := post(p, p.server, {})
			if ce != .None || se != .None {
				testing.expect(t, false, p.client.reason)
				return
			}
			if cn == 0 && sn == 0 {
				return
			}
		} else {
			_, ce := post(p, p.client, {})
			_, se := post(p, p.server, {})
			if ce != .None || se != .None {
				testing.expect(t, false, p.client.reason)
				return
			}
		}
		de := deliver(p, i64(p.link.now))
		if de != .None {
			testing.expect(t, false, p.client.reason)
			return
		}
	}
	testing.expect(t, false, "settle")
}

@(test)
conn_establishes_and_exchanges_streams :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	p := open_pair(t, wide_limits(), false)
	defer close_pair(p)
	settle(t, p)
	testing.expect(t, conn.established(p.client) && conn.established(p.server))
	payload := [?]u8{'p', 'i', 'n', 'g'}
	reply := [?]u8{'p', 'o', 'n', 'g'}
	n, we := conn.write(p.client, 0, payload[:], true)
	testing.expect(t, we == .None && n == len(payload))
	n, we = conn.write(p.server, 1, reply[:], true)
	testing.expect(t, we == .None && n == len(reply))
	settle(t, p)
	got: [8]u8
	rn, fin, re := conn.read(p.server, 0, got[:])
	testing.expect(
		t,
		re == .None && fin && rn == len(payload) && bytes.equal(got[:rn], payload[:]),
	)
	rn, fin, re = conn.read(p.client, 1, got[:])
	testing.expect(t, re == .None && fin && rn == len(reply) && bytes.equal(got[:rn], reply[:]))
}

@(test)
conn_loss_duplicate_reorder_stall_and_timers :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	p := open_pair(t, wide_limits(), false)
	defer close_pair(p)
	// Drop the first ClientHello. The PTO resends it and the handshake completes.
	_, ce := post(p, p.client, {drop = true})
	testing.expect_value(t, ce, .None)
	timer := conn.timer(p.client, i64(p.link.now))
	testing.expect(t, timer.armed)
	early_buf: [1200]u8
	_, early := conn.on_timeout(p.client, timer.at - 1, early_buf[:])
	testing.expect_value(t, early, .Not_Ready)
	buf: [conn.MAX_DATAGRAM]u8
	n, te := conn.on_timeout(p.client, timer.at, buf[:])
	testing.expect(t, te == .None && n > 0)
	src, dst := endpoint(p.client, p)
	testing.expect_value(t, sim.send(&p.link, src, dst, buf[:n], {}), .None)
	p.link.now = sim.Tick(timer.at)
	for _ in 0 ..< 48 {
		if conn.established(p.client) && conn.established(p.server) {
			break
		}
		_, ce = post(p, p.client, {})
		_, se := post(p, p.server, {})
		testing.expect(t, ce == .None && se == .None, p.server.reason)
		testing.expect_value(t, deliver(p, i64(p.link.now)), .None)
	}
	testing.expect(t, conn.established(p.client) && conn.established(p.server), p.client.reason)
	settle(t, p)

	// The dropped ClientHello already entered recovery at this tick.
	// A later loss reduces the window only after that epoch.
	p.link.now += 1000
	before := conn.stats(p.client)
	testing.expect_value(t, conn.queue_ping(p.client), .None)
	_, ce = post(p, p.client, {delay = 100000})
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, conn.queue_ping(p.client), .None)
	_, ce = post(p, p.client, {})
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, deliver(p, i64(p.link.now)), .None)
	_, se := post(p, p.server, {})
	testing.expect_value(t, se, .None)
	testing.expect_value(t, deliver(p, i64(p.link.now)), .None)
	loss := conn.timer(p.client, i64(p.link.now))
	testing.expect(t, loss.armed && loss.kind == .Loss)
	_, early = conn.on_timeout(p.client, loss.at - 1, buf[:])
	testing.expect_value(t, early, .Not_Ready)
	_, te = conn.on_timeout(p.client, loss.at, buf[:])
	testing.expect_value(t, te, .None)
	after := conn.stats(p.client)
	testing.expect(t, after.in_recovery && after.congestion_window < before.congestion_window)

	// Duplication counts both datagrams and does not double the stream bytes.
	wn, we := conn.write(p.client, 0, []u8{9, 9}, true)
	testing.expect(t, we == .None && wn == 2)
	received := conn.stats(p.server).path_received
	_, ce = post(p, p.client, {duplicate = true, duplicate_delay = 0})
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, deliver(p, i64(p.link.now)), .None)
	got: [4]u8
	rn, fin, re := conn.read(p.server, 0, got[:])
	testing.expect(t, re == .None && fin && rn == 2 && got[0] == 9 && got[1] == 9)
	rn, _, re = conn.read(p.server, 0, got[:])
	testing.expect(t, re == .None && rn == 0)
	testing.expect(t, conn.stats(p.server).path_received >= received + 2)

	// Reordering still produces one contiguous ACK range.
	testing.expect_value(t, conn.queue_ping(p.client), .None)
	_, ce = post(p, p.client, {delay = 30})
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, conn.queue_ping(p.client), .None)
	_, ce = post(p, p.client, {delay = 5})
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, deliver(p, i64(p.link.now) + 30), .None)
	lo, hi, ready := conn.pending_ack(p.server, .Application)
	testing.expect(t, ready && hi >= lo && hi - lo >= 1)

	// A stalled peer arms a PTO probe.
	testing.expect_value(t, conn.queue_ping(p.server), .None)
	_, se = post(p, p.server, {drop = true})
	testing.expect_value(t, se, .None)
	pto := conn.timer(p.server, i64(p.link.now))
	testing.expect(t, pto.armed)
	model_timer := harness.loss_detection_timer(&p.server.model, i64(p.link.now))
	testing.expect(
		t,
		model_timer.armed && model_timer.at == pto.at && model_timer.kind == pto.kind,
	)
	_, te = conn.on_timeout(p.server, pto.at, buf[:])
	testing.expect(t, te == .None && conn.stats(p.server).pto_count >= 1)

	handle, serr := sim.schedule(&p.link, 1, p.link.now, 7)
	testing.expect_value(t, serr, .None)
	testing.expect(t, sim.cancel(&p.link, handle))
	_, bad := sim.schedule(&p.link, 1, p.link.now - 1, 0)
	testing.expect_value(t, bad, .Invalid_Time)
}

@(test)
conn_flow_reset_close_congestion_and_bounds :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	tight := wide_limits()
	tight.max_data = 4
	tight.max_stream_data = 4
	p := open_pair(t, tight, false)
	n, fe := conn.write(p.client, 0, []u8{1, 2, 3, 4, 5}, false)
	testing.expect(t, fe == .Flow_Control && n == 0 && conn.stats(p.client).bytes_in_flight == 0)
	wn, we := conn.write(p.client, 0, []u8{1, 2, 3, 4}, false)
	testing.expect(t, we == .None && wn == 4)
	close_pair(p)

	p = open_pair(t, wide_limits(), false)
	settle(t, p)
	wn, we = conn.write(p.client, 0, []u8{'a', 'b'}, false)
	testing.expect(t, we == .None && wn == 2)
	settle(t, p)
	testing.expect_value(t, conn.reset_stream(p.client, 0), .None)
	settle(t, p)
	reset_buf: [8]u8
	_, _, re := conn.read(p.server, 0, reset_buf[:])
	testing.expect_value(t, re, .Protocol)
	testing.expect_value(t, conn.close(p.client), .None)
	_, ce := post(p, p.client, {})
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, deliver(p, i64(p.link.now)), .None)
	testing.expect(t, p.server.phase == .Draining)
	sn, se := post(p, p.server, {})
	testing.expect(t, se == .None && sn == 0)
	st := conn.stats(p.server)
	testing.expect(t, st.closed && st.retained == 0)
	drain := conn.timer(p.server, i64(p.link.now))
	testing.expect(t, drain.armed)
	drain_buf: [8]u8
	_, se = conn.on_timeout(p.server, drain.at - 1, drain_buf[:])
	testing.expect(t, se == .None && p.server.phase == .Draining)
	_, se = conn.on_timeout(p.server, drain.at, drain_buf[:])
	testing.expect(t, se == .None && p.server.phase == .Closed)
	_, se = conn.pump(p.server, drain.at, drain_buf[:])
	testing.expect_value(t, se, .Closed)
	close_pair(p)

	p = open_pair(t, wide_limits(), true)
	settle(t, p)
	hit := false
	cwnd := conn.stats(p.client).congestion_window
	for id: u64 = 0; id < 128; id += 4 {
		_, we := conn.write(p.client, id, []u8{1}, true)
		if we != .None {
			break
		}
		_, pe := post(p, p.client, {drop = true})
		if pe == .Congestion {
			hit = true
			break
		}
		testing.expect_value(t, pe, .None)
		flight := conn.stats(p.client)
		testing.expect(t, flight.bytes_in_flight <= flight.congestion_window)
		if flight.bytes_in_flight > cwnd {
			cwnd = flight.congestion_window
		}
	}
	testing.expect(
		t,
		hit && conn.stats(p.client).bytes_in_flight <= conn.stats(p.client).congestion_window,
	)
	close_pair(p)

	p = open_pair(t, wide_limits(), false)
	_, ce = post(p, p.client, {})
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, deliver(p, 0), .None)
	testing.expect(t, !p.server.model.address_validated)
	buf: [conn.MAX_DATAGRAM]u8
	now: i64
	limited := false
	for _ in 0 ..< 24 {
		n, err := conn.pump(p.server, now, buf[:])
		if err == .Anti_Amplification {
			limited = true
			break
		}
		testing.expect_value(t, err, .None)
		timer := conn.timer(p.server, now)
		if !timer.armed || timer.at <= now {
			now += 1
			continue
		}
		_, err = conn.on_timeout(p.server, timer.at - 1, buf[:])
		testing.expect_value(t, err, .Not_Ready)
		_, err = conn.on_timeout(p.server, timer.at, buf[:])
		now = timer.at
		if err == .Anti_Amplification {
			limited = true
			break
		}
		testing.expect_value(t, err, .None)
	}
	testing.expect(t, limited && !p.server.model.address_validated)
	testing.expect(t, p.server.model.path_sent <= 3 * p.server.model.path_received)

	big: [conn.STREAM_BYTES + 1]u8
	werr: conn.Error
	wn, werr = conn.write(p.client, 0, big[:], false)
	testing.expect(t, werr == .Capacity && wn == 0)
	live := conn.stats(p.client).live_packets
	testing.expect_value(t, conn.inject_allocation_failure(p.client, 1), .None)
	due := conn.timer(p.client, now)
	testing.expect(t, due.armed)
	fire_at := due.at if due.at > now else now
	_, aerr := conn.on_timeout(p.client, fire_at, buf[:])
	testing.expect_value(t, aerr, .Allocation)
	testing.expect_value(t, conn.stats(p.client).live_packets, live)

	prev := context.allocator
	context.allocator = mem.nil_allocator()
	_, werr = conn.write(p.client, 0, []u8{1, 2, 3}, false)
	testing.expect_value(t, werr, .None)
	rn, _, rerr := conn.read(p.client, 1, buf[:4])
	testing.expect(t, rerr == .None && rn == 0)
	context.allocator = prev
	close_pair(p)
}

@(test)
conn_cancel_version_path_and_key_update :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	p := open_pair(t, wide_limits(), false)
	defer close_pair(p)
	settle(t, p)
	saved: [1200]u8
	sn, se := conn.pump(p.client, i64(p.link.now), saved[:])
	if se != .None || sn == 0 {
		testing.expect_value(t, conn.queue_ping(p.client), .None)
		sn, se = conn.pump(p.client, i64(p.link.now), saved[:])
	}
	testing.expect(t, se == .None && sn > 0)
	phase := p.server.phase
	vn: [64]u8
	vn_n, ve := quic.version_negotiation_encode(
		vn[:],
		p.server.local_cid[:p.server.local_cid_len],
		p.client.local_cid[:p.client.local_cid_len],
		[]u32{0x00000001},
		0,
	)
	testing.expect_value(t, ve, .None)
	same := p.server.model.path
	testing.expect_value(t, conn.ingest(p.server, i64(p.link.now), same, vn[:vn_n]), .Discarded)
	testing.expect(t, p.server.phase == phase)
	// Long header, version 2, current path. A short header has no version field.
	dcid := p.server.local_cid[:p.server.local_cid_len]
	scid := p.client.local_cid[:p.client.local_cid_len]
	v2: [40]u8
	v2[0] = 0xc0
	v2[1], v2[2], v2[3], v2[4] = 0, 0, 0, 2
	v2[5] = u8(len(dcid))
	copy(v2[6:], dcid)
	at := 6 + len(dcid)
	v2[at] = u8(len(scid))
	copy(v2[at + 1:], scid)
	v2n := at + 1 + len(scid)
	testing.expect_value(t, conn.ingest(p.server, i64(p.link.now), same, v2[:v2n]), .Discarded)
	testing.expect(t, p.server.phase == phase && p.server.model.address_validated)

	validated := p.server.model.address_validated
	testing.expect(t, validated)
	testing.expect_value(t, conn.ingest(p.server, i64(p.link.now), 99, saved[:sn]), .None)
	testing.expect(t, !p.server.model.address_validated)

	testing.expect_value(t, conn.update_keys(p.client), .None)
	testing.expect(t, p.client.hs.one_rtt_write.update_pending)
	testing.expect_value(t, conn.queue_ping(p.client), .None)
	_, ce := post(p, p.client, {})
	testing.expect_value(t, ce, .None)
	testing.expect_value(t, deliver(p, i64(p.link.now)), .None)
	testing.expect(t, !p.server.hs.one_rtt_read.update_pending)
	_, se = post(p, p.server, {})
	testing.expect_value(t, se, .None)
	testing.expect_value(t, deliver(p, i64(p.link.now)), .None)
	testing.expect(t, !p.client.hs.one_rtt_write.update_pending)

	conn.cancel(p.client)
	_, ce = conn.pump(p.client, i64(p.link.now), saved[:])
	testing.expect_value(t, ce, .Cancelled)
	_, _, re := conn.read(p.client, 0, saved[:1])
	testing.expect_value(t, re, .Cancelled)
}

@(test)
review_stream_loss_must_retransmit_data :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false); defer close_pair(p); settle(t, p)
	data := [?]u8{'l', 'o', 's', 't'}
	n, e := conn.write(p.client, 0, data[:], true); assert(n == 4 && e == .None)
	sent, se := post(p, p.client, {drop = true}); assert(sent > 0 && se == .None)
	for _ in 0 ..< 8 {
		timer := conn.timer(p.client, i64(p.link.now)); if !timer.armed {
			break
		}
		p.link.now = sim.Tick(timer.at)
		packet: [conn.MAX_DATAGRAM]u8
		n, err := conn.on_timeout(p.client, timer.at, packet[:]); assert(err == .None)
		if n > 0 {
			src, dst := endpoint(p.client, p)
			assert(sim.send(&p.link, src, dst, packet[:n], {}) == .None)
		}
		assert(deliver(p, i64(p.link.now)) == .None); settle(t, p)
	}
	got: [8]u8; rn, fin, re := conn.read(p.server, 0, got[:])
	testing.expect(t, rn == 4 && fin && re == .None, "lost STREAM must be retransmitted")
}
@(test)
review_stream_reordering_must_not_fail_connection :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false); defer close_pair(p); settle(t, p)
	a := [?]u8{'a'}; b := [?]u8{'b'}
	n, e := conn.write(p.client, 0, a[:], false); assert(n == 1 && e == .None)
	_, se := post(p, p.client, {delay = 100}); assert(se == .None)
	n, e = conn.write(p.client, 0, b[:], true); assert(n == 1 && e == .None)
	_, se = post(p, p.client, {}); assert(se == .None)
	re := deliver(p, i64(p.link.now)); testing.expect_value(t, re, .None)
}

@(test)
review_stream_can_continue_after_ack_and_consume :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false); defer close_pair(p); settle(t, p)
	a: [256]u8; for &v in a {v = 'a'}
	n, e := conn.write(p.client, 0, a[:], false); assert(n == 256 && e == .None); settle(t, p)
	got: [256]u8; rn, fin, re := conn.read(p.server, 0, got[:])
	assert(rn == 256 && !fin && re == .None); settle(t, p)
	b := [?]u8{'b'}; n, e = conn.write(p.client, 0, b[:], true)
	testing.expect(
		t,
		n == 1 && e == .None,
		"acknowledged consumed stream must regain bounded buffer capacity",
	)
}

@(test)
conn_incremental_sliding_credit_and_bidi_response :: proc(t: ^testing.T) {
	limits := wide_limits(); limits.max_stream_data = 256; limits.recv_max_stream_data = 256
	limits.max_data = 256; limits.recv_max_data = 256
	p := open_pair(t, limits, false); defer close_pair(p); settle(t, p)
	data: [256]u8; got: [256]u8
	for round in 0 ..< 16 {
		for &v, i in data {v = u8((round + i) % 251)}
		n, e := conn.write(p.client, 0, data[:], round == 15)
		testing.expect(t, n == 256 && e == .None)
		settle(t, p)
		rn, fin, re := conn.read(p.server, 0, got[:])
		testing.expect(t, rn == 256 && re == .None && fin == (round == 15))
		testing.expect(t, bytes.equal(data[:], got[:]))
		settle(t, p)
		testing.expect_value(t, conn.stats(p.client).retained, 0)
		testing.expect_value(t, conn.stats(p.server).retained, 0)
	}
	response := [?]u8{'o', 'k'}
	n, e := conn.write(p.server, 0, response[:], true); testing.expect(t, n == 2 && e == .None)
	settle(t, p)
	rn, fin, re := conn.read(p.client, 0, got[:]); testing.expect(t, rn == 2 && fin && re == .None)
	// Uni streams use their own stream-ID kind and never permit reverse writes.
	n, e = conn.write(p.client, 2, response[:], true); testing.expect(t, n == 2 && e == .None)
	settle(t, p); rn, fin, re = conn.read(p.server, 2, got[:])
	testing.expect(t, rn == 2 && fin && re == .None)
	_, e = conn.write(p.server, 2, response[:], true); testing.expect_value(t, e, .Protocol)
}

@(test)
conn_reorder_duplicate_fin_and_reset_recovery :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false); defer close_pair(p); settle(t, p)
	a := [?]u8{'a', 'b'}; b := [?]u8{'c', 'd'}
	n, e := conn.write(p.client, 0, a[:], false); assert(n == 2 && e == .None)
	_, e = post(p, p.client, {delay = 100, duplicate = true, duplicate_delay = 150})
	assert(e == .None)
	n, e = conn.write(p.client, 0, b[:], true); assert(n == 2 && e == .None)
	_, e = post(p, p.client, {}); assert(e == .None)
	assert(deliver(p, i64(p.link.now)) == .None)
	got: [8]u8; rn, fin, re := conn.read(p.server, 0, got[:])
	testing.expect(t, rn == 0 && !fin && re == .None)
	p.link.now += 100; assert(deliver(p, i64(p.link.now)) == .None)
	rn, fin, re = conn.read(p.server, 0, got[:]); testing.expect(t, rn == 4 && fin && re == .None)
	testing.expect(t, bytes.equal(got[:4], []u8{'a', 'b', 'c', 'd'}))
	p.link.now += 50; assert(deliver(p, i64(p.link.now)) == .None); settle(t, p)
	rn, fin, re = conn.read(p.server, 0, got[:]); testing.expect(t, rn == 0 && fin && re == .None)
	// Lost empty FIN must retry even though it has no payload bytes.
	n, e = conn.write(p.client, 4, nil, true); assert(n == 0 && e == .None)
	_, e = post(p, p.client, {drop = true}); assert(e == .None)
	due := conn.timer(p.client, i64(p.link.now)); assert(due.armed); p.link.now = sim.Tick(due.at)
	packet: [conn.MAX_DATAGRAM]u8; n, e = conn.on_timeout(p.client, due.at, packet[:])
	assert(e == .None)
	if n > 0 {
		src, dst := endpoint(p.client, p)
		assert(sim.send(&p.link, src, dst, packet[:n], {}) == .None)
	}
	assert(deliver(p, i64(p.link.now)) == .None); settle(t, p)
	rn, fin, re = conn.read(p.server, 4, got[:]); testing.expect(t, rn == 0 && fin && re == .None)
	// Reset delivery and sender retention survive a dropped RESET packet.
	n, e = conn.write(p.client, 8, a[:], false); assert(n == 2 && e == .None); settle(t, p)
	assert(conn.reset_stream(p.client, 8) == .None)
	_, e = post(p, p.client, {drop = true}); assert(e == .None)
	due = conn.timer(p.client, i64(p.link.now)); assert(due.armed); p.link.now = sim.Tick(due.at)
	n, e = conn.on_timeout(p.client, due.at, packet[:]); assert(e == .None)
	if n > 0 {
		src, dst := endpoint(p.client, p)
		assert(sim.send(&p.link, src, dst, packet[:n], {}) == .None)
	}
	assert(deliver(p, i64(p.link.now)) == .None); settle(t, p)
	_, _, re = conn.read(p.server, 8, got[:]); testing.expect_value(t, re, .Protocol)
	testing.expect_value(t, conn.stats(p.client).retained, 0)
	conn.cancel(p.client); testing.expect_value(t, conn.stats(p.client).retained, 0)
}

// Encode a real protected application packet with an independently selected
// set of frames. No transport model helper constructs or parses its payload.
raw_application_packet :: proc(t: ^testing.T, p: ^Pair, content: []u8) -> []u8 {
	packet := make([]u8, conn.MAX_DATAGRAM)
	pn := p.client.model.spaces[2].next_send
	hn, _, he := quic.short_header_encode_v1(
		packet,
		{
			destination_id = p.server.local_cid[:p.server.local_cid_len],
			packet_number = u32(pn),
			packet_number_length = 2,
			key_phase = p.client.hs.one_rtt_write.phase != 0,
		},
	)
	assert(he == .None)
	n, e := quic.handshake_payload_seal(
		&p.client.hs,
		packet[hn:],
		packet[:hn],
		content,
		.One_RTT,
		pn,
	); assert(e == .None)
	assert(
		quic.handshake_header_protection_apply(
			&p.client.hs,
			packet[:hn + n],
			.One_RTT,
			p.server.local_cid_len,
		) ==
		.None,
	)
	return packet[:hn + n]
}

@(test)
conn_mixed_frames_reassemble_overlaps_and_preserve_credit :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false); defer close_pair(p); settle(t, p)
	frame: [512]u8
	at, ok := conn.encode_ack(frame[:], 0, p.server.model.spaces[2].next_send - 1, 0); assert(ok)
	at, ok = conn.encode_stream(frame[:], at, 0, 1, []u8{'b', 'c'}, true); assert(ok)
	at, ok = conn.encode_stream(frame[:], at, 0, 0, []u8{'a', 'b'}, false); assert(ok)
	at, ok = conn.encode_stream(frame[:], at, 2, 0, []u8{'u'}, true); assert(ok)
	at, ok = conn.encode_credit(frame[:], at, 1, 7777, 9999); assert(ok)
	packet := raw_application_packet(t, p, frame[:at]); defer delete(packet)
	testing.expect_value(
		t,
		conn.ingest(p.server, i64(p.link.now), p.server.model.path, packet),
		.None,
	)
	got: [8]u8; rn, fin, e := conn.read(p.server, 0, got[:])
	testing.expect(t, rn == 3 && fin && e == .None)
	testing.expect(t, bytes.equal(got[:3], []u8{'a', 'b', 'c'}))
	rn, fin, e = conn.read(p.server, 2, got[:])
	testing.expect(t, rn == 1 && fin && e == .None && got[0] == 'u')
	testing.expect_value(t, conn.stats(p.server).retained, 0)
}

@(test)
conn_adoption_rejects_oversized_window_without_moving_owner :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false); defer close_pair(p); settle(t, p)
	candidate := new(conn.Connection); defer free(candidate)
	cfg := conn.Adopt_Config {
		role         = .Client,
		local_cid    = p.client.local_cid[:p.client.local_cid_len],
		peer_cid     = p.client.peer_cid[:p.client.peer_cid_len],
		limits       = wide_limits(),
		next_send_pn = p.client.model.spaces[2].next_send,
	}
	testing.expect_value(t, conn.adopt_established(candidate, &p.client.hs, cfg), .Invalid)
	testing.expect(t, p.client.hs.have_one_rtt && !candidate.initialized)
	cfg.limits.recv_max_stream_data = 256
	testing.expect_value(t, conn.adopt_established(candidate, &p.client.hs, cfg), .None)
	testing.expect(t, !p.client.hs.have_one_rtt && candidate.hs.have_one_rtt)
	defer conn.destroy(candidate)
	// The moved connection uses the real transferred packet key and packet number.
	n, e := conn.write(candidate, 0, []u8{'m'}, true); testing.expect(t, n == 1 && e == .None)
	packet: [conn.MAX_DATAGRAM]u8
	for _ in 0 ..< 3 {
		n, e = conn.pump(candidate, i64(p.link.now), packet[:])
		testing.expect(t, n > 0 && e == .None)
		re := conn.ingest(p.server, i64(p.link.now), p.server.model.path, packet[:n])
		testing.expect(t, re == .None || re == .Discarded)
		if re == .None {
			break
		}
	}
	got: [1]u8; rn, fin, re := conn.read(p.server, 0, got[:])
	testing.expect(t, rn == 1 && fin && re == .None && got[0] == 'm')
}

@(test)
conn_tiny_independent_ack_needs_no_shadow_padding :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false); defer close_pair(p); settle(t, p)
	frame: [16]u8
	largest := p.server.model.spaces[2].next_send - 1
	n, ok := conn.encode_ack(frame[:], 0, largest, largest); assert(ok)
	packet := raw_application_packet(t, p, frame[:n]); defer delete(packet)
	testing.expect_value(
		t,
		conn.ingest(p.server, i64(p.link.now), p.server.model.path, packet),
		.None,
	)
	testing.expect(t, p.server.phase != .Failed)
}
