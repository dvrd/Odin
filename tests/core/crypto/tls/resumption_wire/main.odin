package main
import "core:crypto/tls"
import credentials "core:crypto/tls/credentials"
import store "core:crypto/tls/credentials/store"
import "core:fmt"
import "core:net"
import "core:nbio"
import "core:os"
import "core:sync"
import "core:thread"
import "core:time"
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
	count, full, resumed: i32,
	ok:                   bool,
	keys:                 ^tls.Server_Ticket_Keys,
	mode:                 string,
	identity:             bool,
	expected:             [32]u8,
	store:                ^store.Store,
	dir:                  string,
	ticket:               ^tls.Server_Ticket_Config,
}

event :: proc(data: rawptr, e: ^saba.TLS_Event) {
	s := cast(^State)data
	if e.kind == .Handshake && e.handshake_complete {
		assert(e.peer_identity.authenticated == s.identity && e.peer_identity.certificate_sha256 == s.expected)
		if e.resumed {
			sync.atomic_add(&s.resumed, 1)
		} else {
			sync.atomic_add(&s.full, 1)
		}
	}
}

handler :: proc(data: rawptr, conn: ^saba.Connection, req: ^saba.Request) -> saba.Response {
	s := cast(^State)data
	n := sync.atomic_add(&s.count, 1)
	if s.mode == "rotate" && n == 0 {
		assert(tls.server_ticket_keys_rotate(s.keys, time.now()) == nil)
	}
	if s.mode == "credential" && n == 0 {
		replacement := load_store(s.dir, "server")
		lease, e := store.acquire(replacement)
		assert(e.kind == .None)
		_ = store.release(replacement, &lease)
		store.destroy(&replacement)
		cert, ce := os.read_entire_file(fmt.tprintf("%s/server.pem", s.dir), context.allocator)
		assert(ce == nil)
		defer delete(cert)
		key, ke := os.read_entire_file(fmt.tprintf("%s/server-key.pem", s.dir), context.allocator)
		assert(ke == nil)
		defer delete(key)
		next, error := credentials.create(cert, key, {}, context.allocator)
		assert(error == .None)
		assert(store.replace(s.store, &next).kind == .None)
	}
	if s.mode == "policy" && n == 0 {
		s.ticket.policy_epoch += 1
	}
	return {status = .OK, body = transmute([]u8)string("OK")}
}

Async_Client :: struct {
	owner:           tls.Async_Conn,
	tcp:             nbio.TCP_Async_Connection,
	hs:              tls.Async_Handshake_Operation,
	read, close:     net.Async_Operation,
	bytes:           [2]u8,
	n:               int,
	resumed, closed: bool,
}

async_closed :: proc(op: ^net.Async_Operation) {
	s := cast(^Async_Client)op.user_data
	assert(op.result.err == nil)
	s.closed = true
}

async_read :: proc(op: ^net.Async_Operation) {
	s := cast(^Async_Client)op.user_data
	assert(op.result.err == nil && op.result.count > 0)
	s.n += op.result.count
	if s.n == 2 {
		assert(string(s.bytes[:]) == "OK")
		s.close = {
			callback  = async_closed,
			user_data = s,
		}
		assert(net.async_close(tls.async_connection(&s.owner), &s.close) == nil)
	} else {
		assert(net.async_read(tls.async_connection(&s.owner), &s.read, s.bytes[s.n:]) == nil)
	}
}

async_handshake :: proc(op: ^tls.Async_Handshake_Operation) {
	s := cast(^Async_Client)op.user_data
	assert(op.err == nil)
	assert(tls.async_connection_state(&s.owner).resumed == s.resumed)
	s.read = {
		callback  = async_read,
		user_data = s,
	}
	assert(
		net.async_read(tls.async_connection(&s.owner), &s.read, s.bytes[:], time.tick_add(time.tick_now(), 5 * time.Second)) ==
		nil,
	)
}

main :: proc() {
	assert(len(os.args) == 4)
	dir, mode, policy := os.args[1], os.args[2], os.args[3]
	root: tls.Root_Pool
	assert(tls.root_pool_load_file(&root, fmt.tprintf("%s/root.pem", dir)) == nil)
	defer tls.root_pool_destroy(&root)
	if mode == "client" || mode == "client-mtls" || mode == "client-async" || mode == "client-async-mtls" {
		client_store: ^store.Store
		if mode == "client-mtls" || mode == "client-async-mtls" {
			client_store = load_store(dir, "client")
		}
		defer if client_store != nil {
			store.destroy(&client_store)
		}
		endpoint, valid := net.parse_endpoint(policy)
		assert(valid)
		session: tls.Session
		defer tls.session_clear(&session)
		for i in 0 ..< 2 {
			if mode == "client-async" || mode == "client-async-mtls" {
				assert(nbio.acquire_thread_event_loop() == nil)
				socket, e := net.dial_tcp(policy)
				assert(e == nil)
				s := Async_Client {
					resumed = i == 1,
				}
				assert(nbio.tcp_async_connection_init(&s.tcp, socket) == nil)
				config := tls.Config {
					client_credentials = client_store,
					server_name        = "localhost",
					root_cas           = root.roots[:root.count],
					session            = &session,
					remember_tickets   = true,
					alpn_protocols     = []string{"http/1.1"},
				}
				assert(
					tls.async_client(&s.owner, nbio.tcp_async_connection(&s.tcp), nbio.async_executor(), config) ==
					nil,
				)
				s.hs = {
					callback  = async_handshake,
					user_data = &s,
				}
				assert(tls.async_handshake(&s.owner, &s.hs) == nil)
				assert(nbio.run() == nil)
				assert(s.closed)
				nbio.release_thread_event_loop()
				fmt.println("PASS native async", i)
				continue
			}
			client: tls.Conn
			error := tls.dial(
				&client,
				"127.0.0.1",
				int(endpoint.port),
				{
					client_credentials = client_store,
					server_name = "localhost",
					root_cas = root.roots[:root.count],
					session = &session,
					remember_tickets = true,
					alpn_protocols = []string{"http/1.1"},
				},
			)
			assert(error == nil)
			assert(tls.connection_state(&client).resumed == (i == 1))
			buffer: [2]u8
			at := 0
			for at < 2 {n, re := tls.read(&client, buffer[at:]); assert(re == nil && n > 0); at += n}
			assert(string(buffer[:]) == "OK")
			tls.conn_close(&client)
			fmt.println("PASS native client", i)
		}
		return
	}
	owner := load_store(dir, "server")
	defer store.destroy(&owner)
	keys: tls.Server_Ticket_Keys
	assert(tls.server_ticket_keys_init(&keys) == nil)
	defer tls.server_ticket_keys_close(&keys)
	ticket := tls.Server_Ticket_Config {
		keys         = &keys,
		lifetime     = time.Hour,
		policy_epoch = 1,
	}
	s := State {
		keys     = &keys,
		mode     = mode,
		store    = owner,
		dir      = dir,
		ticket   = &ticket,
		identity = policy == "mtls",
	}
	if s.identity {
		client := load_store(dir, "client")
		lease, e := store.acquire(client)
		assert(e.kind == .None)
		fingerprint, fe := store.fingerprint(client, lease)
		assert(fe.kind == .None)
		s.expected = fingerprint
		_ = store.release(client, &lease)
		store.destroy(&client)
	}
	auth := tls.Client_Auth_Config {
		mode  = .Require,
		roots = root.roots[:root.count],
	}
	config := saba.TLS_Config {
		store    = owner,
		tickets  = &ticket,
		on_event = event,
		data     = &s,
	}
	if policy == "mtls" {
		config.client_auth = &auth
	}
	server := saba.Server {
		handler      = handler,
		handler_data = &s,
		control      = &s.control,
		tls          = &config,
		workers      = 2,
		port         = 0,
	}
	worker := thread.create_and_start_with_poly_data(&server, proc(server: ^saba.Server) {assert(saba.serve(server^))})
	deadline := time.tick_add(time.tick_now(), 10 * time.Second)
	for !saba.server_ready(&s.control) && time.tick_diff(time.tick_now(), deadline) > 0 {thread.yield()}
	address, ready := saba.server_endpoint(&s.control)
	assert(ready)
	fmt.printf("READY 127.0.0.1:%d\n", address.port)
	deadline = time.tick_add(time.tick_now(), 20 * time.Second)
	for sync.atomic_load(&s.count) < 2 && time.tick_diff(time.tick_now(), deadline) > 0 {thread.yield()}
	assert(saba.drain_server(&s.control, time.Second))
	thread.join(worker)
	thread.destroy(worker)
	fmt.printf("RESULT requests=%d full=%d resumed=%d\n", s.count, s.full, s.resumed)
	if mode == "credential" || mode == "policy" {
		assert(s.count == 2 && s.full == 2 && s.resumed == 0)
	} else {
		assert(s.count == 2 && s.full == 1 && s.resumed == 1)
	}
}
