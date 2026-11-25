package main

import "core:crypto/tls"
import "core:crypto/x509"
import "core:fmt"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:os"
import "core:time"
import surf "shared:surf"

Case :: struct {
	label, endpoint, hostname, selected: string,
	offers:                              []string,
	roots:                               []^x509.Certificate,
	failure, no_overlap:                 bool,
	owned_offer:                         []u8,
}

sync_case :: proc(c: Case) -> int {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	previous := context.allocator
	context.allocator = mem.tracking_allocator(&tracker)
	conn := new(tls.Conn)
	ep, valid := net.parse_endpoint(c.endpoint)
	assert(valid)
	socket, error := net.dial_tcp_until(ep, time.time_add(time.now(), time.Second))
	assert(error == nil)
	tcp := net.TCP_Connection {
		socket = socket,
	}
	assert(
		tls.client(
			conn,
			net.tcp_connection(&tcp),
			{server_name = c.hostname, root_cas = c.roots, alpn_protocols = c.offers},
		) ==
		nil,
	)
	assert(tls.connection_state(conn).negotiated_protocol == "")
	handshake_error := tls.handshake_until(conn, time.time_add(time.now(), 2 * time.Second))
	if c.failure {
		assert(handshake_error != nil)
		if c.no_overlap {
			assert(handshake_error == tls.Error(tls.Protocol_Error.No_Application_Protocol))
		}
		assert(tls.connection_state(conn).negotiated_protocol == "")
	} else {
		assert(handshake_error == nil)
		assert(tls.connection_state(conn).negotiated_protocol == c.selected)
		if len(c.owned_offer) > 0 {
			c.owned_offer[0] = 'x'
			assert(tls.connection_state(conn).negotiated_protocol == c.selected)
			c.owned_offer[0] = 'h'
		}
		assert(tls.set_deadline(conn, time.time_add(time.now(), time.Second)) == nil)
		count, write_error := tls.write(conn, transmute([]u8)string("ping\n"))
		assert(write_error == nil && count == 5)
		buffer: [5]u8
		used := 0
		for used <
		    len(
			    buffer,
		    ) {n, read_error := tls.read(conn, buffer[used:]); assert(read_error == nil && n > 0); used += n}
		assert(string(buffer[:]) == "ping\n")
	}
	assert(tls.abort(conn) == nil)
	assert(tls.connection_state(conn).negotiated_protocol == "")
	free(conn)
	context.allocator = previous
	assert(tracker.current_memory_allocated == 0)
	fmt.println("sync", c.label, "peak", tracker.peak_memory_allocated, "retained", tracker.current_memory_allocated)
	return int(tracker.peak_memory_allocated)
}

Completion :: struct {
	done:  bool,
	error: tls.Error,
}

handshake_done :: proc(op: ^tls.Async_Handshake_Operation) {
	state := cast(^Completion)op.user_data
	state.done = true
	state.error = tls.async_handshake_error(op)
}

IO_Completion :: struct {
	done:  bool,
	count: int,
	error: net.Network_Error,
}

io_done :: proc(op: ^net.Async_Operation) {
	state := cast(^IO_Completion)op.user_data
	state.done = true
	state.error = op.result.err
	state.count = op.result.count
}

async_case :: proc(c: Case) -> int {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	previous := context.allocator
	context.allocator = mem.tracking_allocator(&tracker)
	conn := new(tls.Async_Conn)
	ep, valid := net.parse_endpoint(c.endpoint)
	assert(valid)
	socket, error := net.dial_tcp_until(ep, time.time_add(time.now(), time.Second))
	assert(error == nil)
	tcp := new(nbio.TCP_Async_Connection)
	assert(nbio.tcp_async_connection_init(tcp, socket) == nil)
	assert(
		tls.async_client(
			conn,
			nbio.tcp_async_connection(tcp),
			nbio.async_executor(),
			{server_name = c.hostname, root_cas = c.roots, alpn_protocols = c.offers},
		) ==
		nil,
	)
	assert(tls.async_connection_state(conn).negotiated_protocol == "")
	state: Completion
	op := tls.Async_Handshake_Operation {
		callback  = handshake_done,
		user_data = &state,
	}
	assert(tls.async_handshake(conn, &op, time.time_add(time.now(), 2 * time.Second)) == nil)
	assert(tls.async_connection_state(conn).negotiated_protocol == "")
	assert(nbio.run() == nil && state.done)
	if c.failure {
		assert(state.error != nil)
		if c.no_overlap {
			assert(state.error == tls.Error(tls.Protocol_Error.No_Application_Protocol))
		}
		assert(tls.async_connection_state(conn).negotiated_protocol == "")
	} else {
		assert(state.error == nil)
		assert(tls.async_connection_state(conn).negotiated_protocol == c.selected)
		if len(c.owned_offer) > 0 {
			c.owned_offer[0] = 'x'
			assert(tls.async_connection_state(conn).negotiated_protocol == c.selected)
			c.owned_offer[0] = 'h'
		}
		// The shared server-flight buffer has already been freed by this point.
		written: IO_Completion
		write_op := net.Async_Operation {
			callback  = io_done,
			user_data = &written,
		}
		assert(
			net.async_write(tls.async_connection(conn), &write_op, transmute([]u8)string("ping\n"), time.tick_add(time.tick_now(), time.Second)) ==
			nil,
		)
		assert(nbio.run() == nil && written.done && written.error == nil && written.count == 5)
		buffer: [5]u8
		used := 0
		for used < len(buffer) {
			read: IO_Completion
			read_op := net.Async_Operation {
				callback  = io_done,
				user_data = &read,
			}
			assert(
				net.async_read(tls.async_connection(conn), &read_op, buffer[used:], time.tick_add(time.tick_now(), time.Second)) ==
				nil,
			)
			assert(nbio.run() == nil && read.done && read.error == nil && read.count > 0)
			used += read.count
		}
		assert(string(buffer[:]) == "ping\n")
	}
	closed: IO_Completion
	close_op := net.Async_Operation {
		callback  = io_done,
		user_data = &closed,
	}
	assert(net.async_close(tls.async_connection(conn), &close_op) == nil)
	assert(nbio.run() == nil && closed.done)
	assert(tls.async_connection_state(conn).negotiated_protocol == "")
	free(conn)
	free(tcp)
	context.allocator = previous
	assert(tracker.current_memory_allocated == 0)
	fmt.println("async", c.label, "peak", tracker.peak_memory_allocated, "retained", tracker.current_memory_allocated)
	return int(tracker.peak_memory_allocated)
}

main :: proc() {
	assert(len(os.args) == 5)
	ordered, none, incompatible, http1 := os.args[1], os.args[2], os.args[3], os.args[4]
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	assert(tls.root_pool_parse(pool, #load("../root.pem")) == nil)
	wrong_root, parse_error := x509.parse(#load("../../../x509/testdata/chain_ed_root.der"))
	assert(parse_error == .None)
	defer x509.destroy(&wrong_root)
	assert(nbio.acquire_thread_event_loop() == nil)
	defer nbio.release_thread_event_loop()
	mutable_offer := [2]u8{'h', '2'}
	cases := []Case {
		{label = "legacy-no-offer", endpoint = none, hostname = "localhost", roots = pool.roots[:pool.count]},
		{
			label = "server-preference",
			endpoint = ordered,
			hostname = "localhost",
			roots = pool.roots[:pool.count],
			offers = {"http/1.1", string(mutable_offer[:])},
			selected = "h2",
			owned_offer = mutable_offer[:],
		},
		{
			label = "http1",
			endpoint = http1,
			hostname = "localhost",
			roots = pool.roots[:pool.count],
			offers = {"http/1.1"},
			selected = "http/1.1",
		},
		{
			label = "missing-fallback",
			endpoint = none,
			hostname = "localhost",
			roots = pool.roots[:pool.count],
			offers = {"http/1.1"},
		},
		{
			label = "no-overlap",
			endpoint = incompatible,
			hostname = "localhost",
			roots = pool.roots[:pool.count],
			offers = {"private/client"},
			failure = true,
			no_overlap = true,
		},
		{
			label = "wrong-host",
			endpoint = ordered,
			hostname = "wrong.invalid",
			roots = pool.roots[:pool.count],
			offers = {"h2"},
			failure = true,
		},
		{
			label = "wrong-trust",
			endpoint = ordered,
			hostname = "localhost",
			roots = {&wrong_root},
			offers = {"h2"},
			failure = true,
		},
	}
	sync_baseline, async_baseline: int
	for c, i in cases {
		sync_peak := sync_case(c)
		async_peak := async_case(c)
		if i == 0 {
			sync_baseline = sync_peak
			async_baseline = async_peak
		}
		if i == 1 {
			assert(
				sync_peak == sync_baseline && async_peak == async_baseline,
				"ALPN added transfer heap beyond fixed connection storage",
			)
		}
	}
	for endpoint, i in ([?]string{http1, none}) {
		url := fmt.aprintf("https://%s/", endpoint)
		response, error := surf.execute(
			{method = .GET, url = url},
			{tls = {root_cas = pool.roots[:pool.count], alpn_protocols = {"http/1.1"}}},
		)
		assert(error.kind == .None && response.status == 200 && string(response.body) == "ok")
		surf.response_destroy(&response)
		delete(url)
		fmt.println("SurfHTTP1", i, "passed")
	}
	fmt.println("14 sync/async native TLS +2 Surf ALPN cases passed; h2 token is negotiation only")
}
