package main

import tls "../../../../../core/crypto/tls"
import credentials "../../../../../core/crypto/tls/credentials"
import store "../../../../../core/crypto/tls/credentials/store"
import "core:fmt"
import "core:nbio"
import "core:net"
import "core:os"
import "core:strconv"
import "core:time"

PAYLOAD :: 40960

Session :: struct {
	server:                                                          tls.Server_Async_Conn,
	tcp:                                                             nbio.TCP_Async_Connection,
	handshake:                                                       tls.Server_Async_Handshake_Operation,
	read, write, close:                                              net.Async_Operation,
	input, output:                                                   [PAYLOAD]u8,
	used:                                                            int,
	read_done, write_done, closed, failed, closing, check_scheduled: bool,
	mode:                                                            string,
	hs_calls, read_calls, write_calls, close_calls:                  int,
	hook:                                                            Hook,
}

Rotation :: struct {
	store:      ^store.Store,
	credential: ^credentials.Credential,
	done:       bool,
}

Hook :: struct {
	underlying: net.Async_Connection,
	rotation:   ^Rotation,
}

hook_submit :: proc(
	data: rawptr,
	op: ^net.Async_Operation,
	kind: net.Async_Operation_Kind,
	buffer: []u8,
	deadline: time.Tick,
) -> net.Network_Error {
	h := cast(^Hook)data
	if kind == .Write &&
	   h.rotation != nil &&
	   !h.rotation.done &&
	   len(buffer) > 5 &&
	   buffer[0] == 22 &&
	   buffer[5] == 2 {
		stats, _ := store.stats(h.rotation.store)
		assert(stats.active_leases > 0)
		assert(store.replace(h.rotation.store, &h.rotation.credential).kind == .None)
		h.rotation.done = true
	}
	return h.underlying.submit(h.underlying.data, op, kind, buffer, deadline)
}

hook_cancel :: proc(data: rawptr, op: ^net.Async_Operation) -> net.Network_Error {
	h := cast(^Hook)data
	return h.underlying.cancel(h.underlying.data, op)
}

closed :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	s.close_calls += 1
	s.closed = true
	assert(op.result.err == nil)
	assert(tls.server_async_stats(&s.server).live_bytes == 0)
}

close_session :: proc(s: ^Session) {
	if s.closing {
		return
	}
	s.closing = true
	s.close = {
		callback  = closed,
		user_data = s,
	}
	assert(net.async_close(tls.server_async_connection(&s.server), &s.close) == nil)
}

finish_check :: proc(op: ^nbio.Operation, s: ^Session) {
	s.check_scheduled = false
	if s.closed || s.closing {
		return
	}
	finish(s)
}

finish :: proc(s: ^Session) {
	if !s.read_done || !s.write_done {
		return
	}
	if (s.mode == "key-update" || s.mode == "key-update-peer") {
		stats := tls.server_async_stats(&s.server)
		required := 1
		if stats.sent_key_updates < required || stats.received_key_updates < required {
			if !s.check_scheduled {
				s.check_scheduled = true
				nbio.timeout_poly(10 * time.Millisecond, s, finish_check)
			}
			return
		}
	}
	close_session(s)
}

read_done :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	s.read_calls += 1
	assert(op.result.err == nil && op.result.count > 0)
	for b, i in s.input[s.used:s.used + op.result.count] {assert(b == u8(s.used + i))}
	s.used += op.result.count
	if s.used == PAYLOAD {
		s.read_done = true
		finish(s)
	} else {
		assert(
			net.async_read(tls.server_async_connection(&s.server), &s.read, s.input[s.used:], time.tick_add(time.tick_now(), 10 * time.Second)) ==
			nil,
		)
	}
}

write_done :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	s.write_calls += 1
	assert(op.result.err == nil && op.result.count == PAYLOAD)
	s.write_done = true
	finish(s)
}

handshake_done :: proc(op: ^tls.Server_Async_Handshake_Operation) {
	s := cast(^Session)op.user_data
	s.hs_calls += 1
	if op.err != nil {
		fmt.eprintf(
			"handshake failure: mode=%s transport=%v kind=%v engine=%v protection=%v cause=%v\n",
			s.mode,
			op.err,
			op.result.kind,
			op.result.engine,
			op.result.protection,
			op.result.transport,
		)
		assert(
			s.mode == "reject" ||
			s.mode == "timeout" ||
			s.mode == "cancel" ||
			s.mode == "close-active" ||
			s.mode == "peer-reject",
		)
		s.failed = true
		close_session(s)
		return
	}
	assert(
		s.mode != "reject" &&
		s.mode != "timeout" &&
		s.mode != "cancel" &&
		s.mode != "close-active" &&
		s.mode != "peer-reject",
	)
	state := tls.server_async_connection_state(&s.server)
	assert(state.handshake_complete)
	assert(state.negotiated_protocol == "http/1.1")
	if s.mode == "key-update" {
		assert(tls.server_async_key_update(&s.server, true) == nil)
	}
	s.read = {
		callback  = read_done,
		user_data = s,
	}
	s.write = {
		callback  = write_done,
		user_data = s,
	}
	assert(
		net.async_read(tls.server_async_connection(&s.server), &s.read, s.input[:], time.tick_add(time.tick_now(), 10 * time.Second)) ==
		nil,
	)
	assert(
		net.async_write(tls.server_async_connection(&s.server), &s.write, s.output[:], time.tick_add(time.tick_now(), 10 * time.Second)) ==
		nil,
	)
}

cancel_timer :: proc(op: ^nbio.Operation, s: ^Session) {
	assert(tls.server_async_cancel_handshake(&s.server) == nil)
}

close_timer :: proc(op: ^nbio.Operation, s: ^Session) {close_session(s)}

load_credential :: proc(cert, key: string) -> ^credentials.Credential {
	cp, ce := os.read_entire_file(cert, context.allocator)
	assert(ce == nil)
	defer delete(cp)
	kp, ke := os.read_entire_file(key, context.allocator)
	assert(ke == nil)
	defer delete(kp)
	result, e := credentials.create(cp, kp, {}, context.allocator)
	assert(e == .None)
	return result
}

main :: proc() {
	assert(len(os.args) == 5 || len(os.args) == 7)
	count, valid := strconv.parse_int(os.args[3])
	assert(valid && count > 0 && count <= 16)
	mode := os.args[4]
	credential := load_credential(os.args[1], os.args[2])
	credentials_store, ce := store.create({}, context.allocator)
	assert(ce.kind == .None)
	defer store.destroy(&credentials_store)
	assert(store.replace(credentials_store, &credential).kind == .None)
	rotation := Rotation {
		store = credentials_store,
	}
	if mode == "rotate" {
		assert(len(os.args) == 7)
		rotation.credential = load_credential(os.args[5], os.args[6])
	}
	listener, le := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	assert(le == nil)
	defer net.close(listener)
	ep, ee := net.bound_endpoint(listener)
	assert(ee == nil)
	fmt.printf("READY 127.0.0.1:%d\n", ep.port)
	assert(nbio.acquire_thread_event_loop() == nil)
	defer nbio.release_thread_event_loop()
	sessions := make([]Session, count)
	defer delete(sessions)
	for &s in sessions {
		s.mode = mode
		for &b, i in s.output[:] {b = u8(255 - i)}
		socket, _, ae := net.accept_tcp(listener)
		assert(ae == nil)
		assert(nbio.tcp_async_connection_init(&s.tcp, socket) == nil)
		s.hook.underlying = nbio.tcp_async_connection(&s.tcp)
		if mode == "rotate" {
			s.hook.rotation = &rotation
		}
		source := net.Async_Connection {
			data   = &s.hook,
			submit = hook_submit,
			cancel = hook_cancel,
		}
		config := tls.Server_Async_Config {
			store = credentials_store,
			credential_time = time.from_nanoseconds(1790000000 * 1000000000),
			parameters = {alpn_protocols = []string{"http/1.1", "h2"}, require_alpn = true},
		}
		if mode == "timeout" {
			config.handshake_timeout = 50 * time.Millisecond
		}
		if mode == "rotate" {
			config.handshake_timeout = 45 * time.Second
		}
		assert(tls.server_async_server(&s.server, source, nbio.async_executor(), config, context.allocator) == nil)
		s.handshake = {
			callback  = handshake_done,
			user_data = &s,
		}
		assert(tls.server_async_handshake(&s.server, &s.handshake) == nil)
		if mode == "cancel" {
			nbio.timeout_poly(50 * time.Millisecond, &s, cancel_timer)
		}
		if mode == "close-active" {
			nbio.timeout_poly(50 * time.Millisecond, &s, close_timer)
		}
	}
	assert(nbio.run() == nil)
	for &s in sessions {
		assert(s.closed && s.hs_calls == 1 && s.close_calls == 1)
		if s.failed {
			assert(s.read_calls == 0 && s.write_calls == 0)
		} else {
			assert(s.read_done && s.write_done && s.write_calls == 1)
		}
		stats := tls.server_async_stats(&s.server)
		fmt.printf(
			"SESSION owner=%d peak=%d live=%d allocs=%d reads=%d writes=%d ku_in=%d ku_out=%d failed=%v\n",
			size_of(s.server),
			stats.peak_bytes,
			stats.live_bytes,
			stats.allocation_attempts,
			s.read_calls,
			s.write_calls,
			stats.received_key_updates,
			stats.sent_key_updates,
			s.failed,
		)
	}
	if mode == "rotate" {
		assert(rotation.done)
	}
	assert(store.close(credentials_store).kind == .None)
	stats, _ := store.stats(credentials_store)
	assert(stats.active_leases == 0 && stats.generations == 0)
	fmt.println("DONE", count)
}
