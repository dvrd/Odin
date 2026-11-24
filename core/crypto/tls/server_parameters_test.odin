package tls

import "core:crypto/x25519"
import "core:fmt"
import "core:mem"
import "core:testing"
import "core:time"
import credential_store "credentials/store"

parameters_test_hello :: proc(
	dst: []u8,
	names: []string,
	quic := false,
	params: []u8 = nil,
	session: []u8 = nil,
) -> []u8 {
	private: [32]u8
	private[0] = 91
	public: [32]u8
	x25519.scalarmult_basepoint(public[:], private[:])
	share := hello_test_share()
	copy(share[6:], public[:])
	base := hello_test_extensions(share[:])
	extensions: [8]Hello_Test_Extension
	copy(extensions[:], base[:])
	signatures := [4]u8{0, 2, 4, 1}
	extensions[5] = {50, signatures[:]}
	n := 6
	alpn: [33000]u8
	at := 2
	for name in names {alpn[at] = u8(len(name)); at += 1; copy(alpn[at:], name); at += len(name)}
	alpn[0], alpn[1] = u8((at - 2) >> 8), u8(at - 2)
	if len(names) > 0 {
		extensions[n] = {16, alpn[:at]}
		n += 1
	}
	if quic {
		extensions[n] = {57, params}
		n += 1
	}
	return hello_test_wire(dst, extensions[:n], session)
}

parameters_test_ready :: proc(t: ^testing.T, o: ^Server_Handshake, a: ^Owner_Test_Audit, wire: []u8) -> u64 {
	testing.expect_value(t, server_handshake_init(o, SERVER_HANDSHAKE_DEFAULT_CONFIG, owner_test_allocator(a)), .None)
	n, _, e := server_handshake_feed(o, .Initial, wire)
	testing.expect_value(t, n, len(wire))
	testing.expect_value(t, e, .None)
	event, _ := server_handshake_peek(o)
	testing.expect_value(t, event.kind, .Peer_Parameters)
	return event.id
}

@(test)
server_parameters_policy_and_opaque_preference :: proc(t: ^testing.T) {
	for mode in 0 ..< 10 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		storage: [2048]u8
		client := []string{"h2", "\x00\xff", "H2"}
		if mode == 2 || mode == 3 {
			client = nil
		}
		wire := parameters_test_hello(storage[:], client)
		id := parameters_test_ready(t, &o, &a, wire)
		config := Server_Handshake_Parameters_Config {
			alpn_protocols = []string{"\x00\xff", "h2"},
		}
		want := Server_Handshake_Error.None
		if mode == 1 {
			config.alpn_protocols = []string{"H2", "h2"}
		}
		if mode == 3 {
			config.require_alpn = true
			want = .No_Application_Protocol
		}
		if mode == 4 {
			config.alpn_protocols = []string{"http/1.1"}
			want = .No_Application_Protocol
		}
		if mode == 5 {
			config.alpn_protocols = nil
		} 	// Explicitly disabled extension support.
		if mode == 6 {
			config.alpn_protocols = []string{"h2", "h2"}
			want = .Invalid_Config
		}
		if mode == 7 {
			config.alpn_protocols = []string{""}
			want = .Invalid_Config
		}
		if mode == 8 {
			config.require_alpn = true
			config.alpn_protocols = nil
			want = .Invalid_Config
		}
		if mode == 9 {
			config.quic_transport_parameters = []u8{1}
			want = .Invalid_Config
		}
		testing.expect_value(t, server_handshake_select_parameters(&o, id + 1, config), .Invalid_Event)
		testing.expect_value(t, server_handshake_select_parameters(&o, id, config), want)
		if want == .None {
			p, e := server_handshake_parameters(&o)
			testing.expect_value(t, e, .None)
			expected := "\x00\xff"
			if mode == 1 {
				expected = "H2"
			}
			if mode == 2 || mode == 5 {
				expected = ""
			}
			testing.expect_value(t, string(p.alpn), expected)
			testing.expect(t, !p.authenticated)
			testing.expect_value(t, server_handshake_select_parameters(&o, id, config), .Invalid_State)
		} else {
			event, _ := server_handshake_peek(&o)
			testing.expect_value(t, event.kind, .Peer_Parameters if want == .Invalid_Config else .Fatal)
			_, e := server_handshake_parameters(&o)
			testing.expect_value(t, e, .Invalid_State)
		}
		server_handshake_abort(&o)
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
	}
}

@(test)
server_parameters_offer_validation_and_config_bounds :: proc(t: ^testing.T) {
	storage: [40000]u8
	for names in ([][]string{{"dup", "dup"}, {""}, {"a", "b", "a"}}) {
		_, status := server_client_hello_decode(parameters_test_hello(storage[:], names))
		testing.expect_value(t, status, .Malformed)
	}
	// The decoder caps peer list work at 128 opaque names; local preferences
	// reuse the existing 16-name / 1024 encoded-byte client policy.
	name_bytes: [129][3]u8
	names: [129]string
	for &name, i in names {name_bytes[i] = {u8(i), 0, 255}; name = string(name_bytes[i][:])}
	for count in ([]int{128, 129}) {
		_, status := server_client_hello_decode(parameters_test_hello(storage[:], names[:count]))
		testing.expect_value(t, status, .None if count == 128 else .Limit)
	}
	for mode in 0 ..< 6 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		id := parameters_test_ready(t, &o, &a, parameters_test_hello(storage[:], []string{"x"}))
		list: [17]string
		buffers: [17][256]u8
		count := 16
		length := 1
		if mode == 1 {
			count = 17
		}
		if mode == 2 {
			count = 1
			length = 256
		}
		if mode == 3 {
			count = 1
			length = 255
		}
		if mode == 4 || mode == 5 {
			count = 4
			length = 255
		}
		if mode == 5 {
			count = 5
			length = 204
		}
		for &name, i in list {for &b in buffers[i][:] {b = u8(i + 1)}; name = string(buffers[i][:length])}
		config := Server_Handshake_Parameters_Config {
			alpn_protocols = list[:count],
		}
		e := server_handshake_select_parameters(&o, id, config)
		testing.expect_value(
			t,
			e,
			.Invalid_Config if mode == 1 || mode == 2 || mode == 5 else .No_Application_Protocol,
		)
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
	}
}

@(test)
server_parameters_quic_mode_limits_and_owned_storage :: proc(t: ^testing.T) {
	for mode in 0 ..< 10 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		storage: [4096]u8
		peer, local: [1025]u8
		for &b, i in peer[:] {b = u8(i)}; for &b, i in local[:] {b = u8(255 - i)}
		name: [255]u8
		for &b in name[:] {b = 0xfe}
		names := []string{string(name[:])}
		if mode == 4 {
			names = nil
		}
		n := 1024
		if mode == 1 || mode == 2 {
			n = 1025
		}
		if mode == 8 {
			n = 0
		}
		session: []u8
		if mode == 5 {
			session = []u8{1}
		}
		wire := parameters_test_hello(storage[:], names, mode != 3, peer[:n], session)
		id := parameters_test_ready(t, &o, &a, wire)
		config := Server_Handshake_Parameters_Config {
			mode                      = .QUIC,
			alpn_protocols            = []string{string(name[:])},
			quic_transport_parameters = local[:n],
		}
		if mode == 2 {
			config.quic_transport_parameters = local[:1024]
		}
		if mode == 6 {
			config.mode = .TCP
			config.quic_transport_parameters = nil
		}
		if mode == 7 {
			config.alpn_protocols = []string{"other"}
		}
		if mode == 9 {
			a.fail_at = 2
		}
		want := Server_Handshake_Error.None
		if mode == 1 {
			want = .Invalid_Config
		}
		if mode == 2 {
			want = .Limit
		}
		if mode == 3 || mode == 5 {
			want = .Malformed
		}
		if mode == 4 || mode == 7 {
			want = .No_Application_Protocol
		}
		if mode == 6 {
			want = .Unsupported
		}
		if mode == 9 {
			want = .Allocation_Failed
		}
		testing.expect_value(t, server_handshake_select_parameters(&o, id, config), want)
		if want == .None {
			p, e := server_handshake_parameters(&o)
			testing.expect_value(t, e, .None)
			testing.expect_value(t, len(p.alpn), 255)
			testing.expect_value(t, len(p.peer_quic), n)
			testing.expect_value(t, len(p.local_quic), n)
			testing.expect(t, !p.authenticated && p.mode == .QUIC)
			// Caller configuration and incoming buffer can change immediately.
			for &b in storage[:] {b = 0}; for &b in local[:] {b = 0}; for &b in name[:] {b = 0}
			testing.expect_value(t, p.alpn[0], u8(0xfe))
			if n > 0 {
				testing.expect_value(t, p.local_quic[0], u8(255))
				testing.expect_value(t, p.peer_quic[1], u8(1))
			}
			// Encoder output is exact and hashed only when accepted.
			before := transcript_snapshot(&o._transcript)
			testing.expect_value(t, server_parameters_extensions(&o), .None)
			event, _ := server_handshake_peek(&o)
			testing.expect_value(t, event.kind, .Handshake_Bytes)
			testing.expect_value(t, len(event.bytes), 1296 if n == 1024 else 272)
			testing.expect_value(t, hello_u16(event.bytes, 6), u16(16))
			testing.expect_value(t, hello_u16(event.bytes, 268), u16(57))
			testing.expect_value(t, int(hello_u16(event.bytes, 270)), n)
			testing.expect_value(t, string(event.bytes[272:]), string(p.local_quic))
			testing.expect_value(t, transcript_snapshot(&o._transcript), before)
			expected := o._transcript
			transcript_update(&expected, event.bytes)
			testing.expect_value(t, server_handshake_accept(&o, event.id), .None)
			testing.expect_value(t, transcript_snapshot(&o._transcript), transcript_snapshot(&expected))
			fmt.printf(
				"parameters: owner=%d parameter bytes=%d peak=%d allocations=%d\n",
				size_of(o),
				len(o._parameters.storage),
				a.peak,
				a.calls,
			)
		}
		server_handshake_abort(&o)
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
	}
}

@(test)
server_parameters_finished_authentication_and_cleanup :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for mode in 0 ..< 8 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		storage: [2048]u8
		hello := parameters_test_hello(storage[:], []string{"opaque"}, true, []u8{0, 1, 2})
		id := parameters_test_ready(t, &o, &a, hello)
		testing.expect_value(
			t,
			server_handshake_select_parameters(
				&o,
				id,
				{mode = .QUIC, alpn_protocols = []string{"opaque"}, quic_transport_parameters = []u8{9, 8}},
			),
			.None,
		)
		if mode == 4 {
			a.fail_at = 3
		}
		if mode == 5 {
			a.delta = 17
		}
		testing.expect_value(
			t,
			server_handshake_start_flight(&o, store, time.from_nanoseconds(1790000000 * 1000000000)),
			.None,
		)
		transcript: Handshake_Transcript
		transcript_init(&transcript)
		transcript_update(&transcript, hello)
		secret: [32]u8
		for _ in 0 ..< 100 {
			event, _ := server_handshake_peek(&o)
			if event.kind == .None {
				break
			}
			if mode == 4 || mode == 5 {
				testing.expect_value(t, event.kind, .Fatal)
				break
			}
			testing.expect(t, event.kind != .Fatal)
			if event.kind == .Handshake_Bytes {
				transcript_update(&transcript, event.bytes)
			}
			if event.kind == .Traffic_Secret && event.level == .Handshake && event.direction == .Read {
				copy(secret[:], event.secret)
			}
			server_handshake_accept(&o, event.id)
		}
		if mode != 4 && mode != 5 {
			p, e := server_handshake_parameters(&o)
			testing.expect_value(t, e, .None)
			testing.expect(t, !p.authenticated)
			if mode == 2 {
				server_handshake_abort(&o)
			} else if mode == 3 {
				server_handshake_destroy(&o)
			} else {
				finished: [36]u8
				_, fe := finished_encode(finished[:], secret, transcript_snapshot(&transcript))
				assert(fe == .None)
				if mode == 1 {
					finished[35] ~= 1
				}
				_, _, he := server_handshake_feed(&o, .Handshake, finished[:])
				testing.expect_value(t, he, .Finished_Failed if mode == 1 else .None)
				if mode != 1 {
					p, e = server_handshake_parameters(&o)
					testing.expect_value(t, e, .None)
					testing.expect(t, p.authenticated)
					testing.expect_value(t, string(p.alpn), "opaque")
					testing.expect_value(t, a.live, 11)
					testing.expect(t, mem.check_zero_ptr(&o._transcript, size_of(o._transcript)))
					event, _ := server_handshake_peek(&o)
					testing.expect_value(t, event.kind, .Complete)
					if mode == 6 {
						server_handshake_abort(&o)
					} else if mode == 7 {
						server_handshake_destroy(&o)
					} else {
						server_handshake_accept(&o, event.id)
					}
				}
			}
		}
		_, e := server_handshake_parameters(&o)
		testing.expect_value(t, e, .Invalid_State)
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
		ss, _ := credential_store.stats(store)
		testing.expect_value(t, ss.active_leases, 0)
	}
}

@(test)
server_parameters_allocation_faults_and_pending_event_cancel :: proc(t: ^testing.T) {
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for stop in 0 ..< 19 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		storage: [2048]u8
		id := parameters_test_ready(t, &o, &a, parameters_test_hello(storage[:], []string{"h3"}, true, []u8{1}))
		testing.expect_value(
			t,
			server_handshake_select_parameters(
				&o,
				id,
				{mode = .QUIC, alpn_protocols = []string{"h3"}, quic_transport_parameters = []u8{2}},
			),
			.None,
		)
		server_handshake_start_flight(&o, store, time.from_nanoseconds(1790000000 * 1000000000))
		for _ in 0 ..< stop {
			event, _ := server_handshake_peek(&o)
			if event.kind == .None {
				break
			}
			assert(event.kind != .Fatal)
			server_handshake_accept(&o, event.id)
		}
		event, _ := server_handshake_peek(&o)
		if stop % 2 == 0 {
			server_handshake_abort(&o)
		} else {
			server_handshake_destroy(&o)
		}
		testing.expect_value(t, server_handshake_accept(&o, event.id), .Invalid_Event)
		_, e := server_handshake_parameters(&o)
		testing.expect_value(t, e, .Invalid_State)
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
		ss, _ := credential_store.stats(store)
		testing.expect_value(t, ss.active_leases, 0)
	}
	for mode in 0 ..< 5 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		storage: [2048]u8
		id := parameters_test_ready(t, &o, &a, parameters_test_hello(storage[:], []string{"h3"}))
		if mode == 0 {
			a.fail_at = 2
		}
		if mode == 1 {
			a.delta = -1
		}
		if mode == 2 {
			a.delta = 17
		}
		if mode == 3 {
			a.error_with_grant = true
		}
		if mode == 4 {
			o._next_id = max(u64)
		}
		e := server_handshake_select_parameters(&o, id, {alpn_protocols = []string{"h3"}})
		// Selecting parameters accepts an existing event, without allocating a
		// new identity. Exhaustion is detected at the next producer event.
		testing.expect_value(t, e, .None if mode == 4 else .Allocation_Failed)
		if mode == 4 {
			server_handshake_start_flight(&o, store, time.from_nanoseconds(1790000000 * 1000000000))
			event, _ := server_handshake_peek(&o)
			testing.expect_value(t, event.kind, .None)
			testing.expect_value(t, o._error, .Identity_Exhausted)
		}
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
	}
}

@(test)
server_parameters_maximum_simultaneous_grants :: proc(t: ^testing.T) {
	a := Owner_Test_Audit {
		backing = context.allocator,
	}
	o: Server_Handshake
	storage: [65536]u8
	name: [255]u8
	peer, local: [1024]u8
	for &b in name[:] {b = 0xff}
	wire := parameters_test_hello(storage[:], []string{string(name[:])}, true, peer[:])
	// Extend the structurally valid hello with one unknown padding extension.
	at := len(wire)
	hello_put_u16(storage[:], &at, 0xbeef)
	hello_put_u16(storage[:], &at, u16(len(storage) - at - 2))
	server_flight_put24(storage[1:4], len(storage) - 4)
	x := 47
	hello_put_u16(storage[:], &x, u16(len(storage) - 49))
	id := parameters_test_ready(t, &o, &a, storage[:])
	testing.expect_value(
		t,
		server_handshake_select_parameters(
			&o,
			id,
			{mode = .QUIC, alpn_protocols = []string{string(name[:])}, quic_transport_parameters = local[:]},
		),
		.None,
	)
	testing.expect_value(t, server_parameters_extensions(&o), .None)
	testing.expect_value(t, a.peak, 69887)
	testing.expect_value(t, a.calls, 3)
	fmt.printf("parameters maximum CH+owned selections+scratch: %d bytes, %d allocations\n", a.peak, a.calls)
	server_handshake_destroy(&o)
	owner_test_clean(t, &a)
}
