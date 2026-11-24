package main

import "core:crypto/tls"
import credentials "core:crypto/tls/credentials"
import store "core:crypto/tls/credentials/store"
import "core:fmt"
import "core:nbio"
import "core:net"
import "core:os"
import "core:sync"
import "core:thread"
import "core:time"
import surf "shared:surf"
import saba "shared:saba/core"

load_store :: proc(dir, name: string) -> ^store.Store {
	cert, e := os.read_entire_file(fmt.tprintf("%s/%s.pem", dir, name), context.allocator)
	assert(e == nil)
	defer delete(cert)
	key, ke := os.read_entire_file(fmt.tprintf("%s/%s-key.pem", dir, name), context.allocator)
	assert(ke == nil)
	defer delete(key)
	credential, ce := credentials.create(cert, key, {}, context.allocator)
	assert(ce == .None)
	owner, se := store.create({}, context.allocator)
	assert(se.kind == .None)
	assert(store.replace(owner, &credential).kind == .None)
	return owner
}

State :: struct {
	control:              saba.Server_Control,
	observed:             bool,
	expect, identity, ok: bool,
	expected:             [32]u8,
	config:               saba.Server,
}

event :: proc(data: rawptr, e: ^saba.TLS_Event) {
	s := cast(^State)data
	if e.kind == .Handshake && e.error.kind != .None {
		assert(!s.expect)
		sync.atomic_store(&s.observed, true)
	}
}

handler :: proc(data: rawptr, conn: ^saba.Connection, req: ^saba.Request) -> saba.Response {
	s := cast(^State)data
	assert(s.expect)
	identity := saba.tls_peer_identity(conn)
	assert(identity.authenticated == s.identity && identity.certificate_sha256 == s.expected)
	sync.atomic_store(&s.observed, true)
	return {status = .OK, body = transmute([]u8)string("OK")}
}

Client :: struct {
	owner:          tls.Async_Conn,
	tcp:            nbio.TCP_Async_Connection,
	hs:             tls.Async_Handshake_Operation,
	read, close:    net.Async_Operation,
	bytes:          [2]u8,
	n:              int,
	expect, closed: bool,
}

close_done :: proc(op: ^net.Async_Operation) {s := cast(^Client)op.user_data; s.closed = true}

close_client :: proc(s: ^Client) {
	s.close = {
		callback  = close_done,
		user_data = s,
	}
	assert(net.async_close(tls.async_connection(&s.owner), &s.close).kind == .None)
}

read_done :: proc(op: ^net.Async_Operation) {
	s := cast(^Client)op.user_data
	if !s.expect {
		assert(op.result.err.kind != .None)
		close_client(s)
		return
	}
	assert(op.result.err.kind == .None && op.result.count > 0)
	s.n += op.result.count
	if s.n == 2 {
		assert(string(s.bytes[:]) == "OK")
		close_client(s)
	} else {
		assert(net.async_read(tls.async_connection(&s.owner), &s.read, s.bytes[s.n:]).kind == .None)
	}
}

hs_done :: proc(op: ^tls.Async_Handshake_Operation) {
	s := cast(^Client)op.user_data
	if op.err.kind != .None {
		assert(!s.expect)
		close_client(s)
		return
	}
	s.read = {
		callback  = read_done,
		user_data = s,
	}
	assert(
		net.async_read(tls.async_connection(&s.owner), &s.read, s.bytes[:], time.time_add(time.now(), 3 * time.Second)).kind ==
		.None,
	)
}

main :: proc() {
	assert(len(os.args) == 7)
	mode, dir, endpoint, identity, policy, want :=
		os.args[1], os.args[2], os.args[3], os.args[4], os.args[5], os.args[6]
	expect := want == "pass"
	roots: tls.Root_Pool
	assert(tls.root_pool_load_file(&roots, fmt.tprintf("%s/root.pem", dir)) == nil)
	defer tls.root_pool_destroy(&roots)
	auth := tls.Client_Auth_Config {
		mode  = .Require,
		roots = roots.roots[:roots.count],
	}
	if policy == "request" {
		auth.mode = .Request
	}
	if mode == "server" || mode == "server-h3" {
		server := load_store(dir, "server")
		defer store.destroy(&server)
		s := State {
			expect   = expect,
			identity = identity != "none",
		}
		if s.identity {
			client := load_store(dir, identity)
			lease, e := store.acquire(client)
			assert(e.kind == .None)
			fingerprint, fe := store.fingerprint(client, lease)
			assert(fe.kind == .None)
			s.expected = fingerprint
			_ = store.release(client, &lease)
			store.destroy(&client)
		}
		config := saba.TLS_Config {
			store       = server,
			client_auth = &auth,
			on_event    = event,
			data        = &s,
		}
		s.config = {
			handler      = handler,
			handler_data = &s,
			control      = &s.control,
			tls          = &config,
			workers      = 2,
			port         = 0,
		}
		if mode == "server-h3" {
			s.config.http3 = {
				enabled     = true,
				endpoint    = {net.IP4_Loopback, 0},
				credentials = server,
			}
		}
		worker := thread.create_and_start_with_poly_data(&s, proc(s: ^State) {s.ok = saba.serve(s.config)})
		deadline := time.tick_add(time.tick_now(), 5 * time.Second)
		for !saba.server_ready(&s.control) && time.tick_diff(time.tick_now(), deadline) > 0 {thread.yield()}
		address, ready := saba.server_endpoint(&s.control)
		if mode == "server-h3" {
			address, ready = saba.server_http3_endpoint(&s.control)
		}
		assert(ready)
		fmt.printf("READY 127.0.0.1:%d\n", address.port)
		until := time.tick_add(time.tick_now(), 5 * time.Second)
		for !sync.atomic_load(&s.observed) && time.tick_diff(time.tick_now(), until) > 0 {thread.yield()}
		if expect || mode == "server" {
			assert(sync.atomic_load(&s.observed))
		} else {
			assert(!sync.atomic_load(&s.observed))
		}
		assert(saba.drain_server(&s.control, time.Second))
		thread.join(worker)
		thread.destroy(worker)
		assert(s.ok)
	} else {
		owner: ^store.Store
		if identity != "none" {
			owner = load_store(dir, identity)
		}
		defer if owner != nil {
			store.destroy(&owner)
		}
		config := tls.Config {
			root_cas           = roots.roots[:roots.count],
			client_credentials = owner,
			server_name        = "localhost",
			handshake_timeout  = 3 * time.Second,
		}
		if mode == "surf" || mode == "surf-h3" {
			response, e := surf.execute(
				{method = .GET, url = fmt.tprintf("https://%s/", endpoint)},
				{tls = config, http3 = mode == "surf-h3", timeout = 4 * time.Second},
			)
			if expect {
				assert(e.kind == .None && response.status == 200 && string(response.body) == "OK")
			} else {
				assert(e.kind != .None)
			}
			surf.response_destroy(&response)
		} else {
			assert(mode == "async")
			assert(nbio.acquire_thread_event_loop() == nil)
			defer nbio.release_thread_event_loop()
			socket, e := net.dial_tcp(endpoint)
			assert(e == nil)
			s := Client {
				expect = expect,
			}
			assert(nbio.tcp_async_connection_init(&s.tcp, socket) == nil)
			assert(
				tls.async_client(&s.owner, nbio.tcp_async_connection(&s.tcp), nbio.async_executor(), config) == nil,
			)
			s.hs = {
				callback  = hs_done,
				user_data = &s,
			}
			assert(tls.async_handshake(&s.owner, &s.hs) == nil)
			assert(nbio.run() == nil)
			assert(s.closed)
		}
	}
	fmt.println("PASS", mode, identity, policy, want)
}
