package tls

import "core:crypto/ecdh"
import "core:fmt"
import "core:testing"
import "core:time"
import credential_store "credentials/store"

retry_test_hello :: proc(
	dst: []u8,
	group: Named_Group,
	share: bool,
	extra: []Hello_Test_Extension = nil,
	session: []u8 = nil,
) -> []u8 {
	private: ecdh.Private_Key
	defer ecdh.private_key_clear(&private)
	key: [32]u8
	key[31] = 7
	curve := ecdh.Curve.X25519 if group == .X25519 else .SECP256R1
	assert(ecdh.private_key_set_bytes(&private, curve, key[:]))
	shares: [71]u8
	size := 32 if group == .X25519 else 65
	at := 0
	if share {
		hello_put_u16(shares[:], &at, u16(4 + size))
		hello_put_u16(shares[:], &at, u16(group))
		hello_put_u16(shares[:], &at, u16(size))
		ecdh.private_key_public_bytes(&private, shares[at:at + size])
		at += size
	} else {
		at = 2
	}
	extensions: [16]Hello_Test_Extension
	base := hello_test_extensions(shares[:at])
	copy(extensions[:], base[:])
	groups := [4]u8{0, 2, u8(u16(group) >> 8), u8(group)}
	extensions[1] = {10, groups[:]}
	signatures := [4]u8{0, 2, 4, 1}
	extensions[5] = {50, signatures[:]}
	copy(extensions[6:], extra)
	return hello_test_wire(dst, extensions[:6 + len(extra)], session)
}

retry_test_begin :: proc(
	t: ^testing.T,
	o: ^Server_Handshake,
	a: ^Owner_Test_Audit,
	wire: []u8,
) -> Server_Handshake_Event {
	testing.expect_value(t, server_handshake_init(o, SERVER_HANDSHAKE_DEFAULT_CONFIG, owner_test_allocator(a)), .None)
	n, status, e := server_handshake_feed(o, .Initial, wire)
	testing.expect_value(t, n, len(wire))
	testing.expect_value(t, status, .Need_Event_Drain)
	testing.expect_value(t, e, .None)
	event, _ := server_handshake_peek(o)
	testing.expect_value(t, event.kind, .Handshake_Bytes)
	testing.expect_value(t, event.level, .Initial)
	return event
}

retry_test_mutate_extension :: proc(hello: Server_Client_Hello_View, kind: u16) -> []u8 {
	at := server_retry_extensions_at(hello)
	for at < len(hello.wire) {
		n := int(hello_u16(hello.wire, at + 2))
		if hello_u16(hello.wire, at) == kind {
			return hello.wire[at + 4:at + 4 + n]
		}
		at += 4 + n
	}
	return nil
}

@(test)
server_retry_owner_size_every_split_and_transcript :: proc(t: ^testing.T) {
	// Retry storage replaces application secrets, never enlarges them.
	testing.expect_value(t, size_of(type_of(Server_Flight{}.transient)), size_of(Server_Application_Secrets))
	fmt.printf(
		"retry fixed owner=%d event=%d flight transient=%d\n",
		size_of(Server_Handshake),
		size_of(Server_Handshake_Event),
		size_of(Server_Application_Secrets),
	)
	for group in ([]Named_Group{.X25519, .Secp256r1}) {
		first, second: [1024]u8
		ch1 := retry_test_hello(first[:], group, false, nil, []u8{1, 2, 3})
		ch2 := retry_test_hello(second[:], group, true, nil, []u8{1, 2, 3})
		for split in 0 ..= len(ch2) {
			a := Owner_Test_Audit {
				backing = context.allocator,
			}
			o: Server_Handshake
			event := retry_test_begin(t, &o, &a, ch1)
			reference: Handshake_Transcript
			transcript_init(&reference)
			transcript_update(&reference, ch1)
			transcript_retry(&reference)
			testing.expect_value(t, transcript_snapshot(&o._transcript), transcript_snapshot(&reference))
			testing.expect_value(t, int(event.bytes[38]), 3)
			testing.expect_value(t, hello_u16(event.bytes, len(event.bytes) - 2), u16(group))
			testing.expect_value(t, len(event.bytes), 59)
			for _ in 0 ..< 3 {
				again, _ := server_handshake_peek(&o)
				testing.expect_value(t, again.id, event.id)
				n, st, e := server_handshake_feed(&o, .Initial, ch2)
				testing.expect_value(t, n, 0)
				testing.expect_value(t, st, .Need_Event_Drain)
				testing.expect_value(t, e, .None)
				testing.expect_value(t, server_handshake_start_flight(&o, nil, time.Time{}), .Invalid_State)
			}
			transcript_update(&reference, event.bytes)
			testing.expect_value(t, server_handshake_accept(&o, event.id), .None)
			testing.expect_value(t, transcript_snapshot(&o._transcript), transcript_snapshot(&reference))
			prefix := make([]u8, split)
			copy(prefix, ch2[:split])
			n, _, e := server_handshake_feed(&o, .Initial, prefix)
			testing.expect_value(t, n, split)
			testing.expect_value(t, e, .None)
			for &b in prefix {b = 0xee}; delete(prefix)
			if split < len(ch2) {
				suffix := make([]u8, len(ch2) - split + 2)
				copy(suffix, ch2[split:])
				consumed, st, feed_error := server_handshake_feed(&o, .Initial, suffix)
				testing.expect_value(t, consumed, len(ch2) - split)
				testing.expect_value(t, st, .Need_Event_Drain)
				testing.expect_value(t, feed_error, .None)
				for &b in suffix {b = 0xdd}; delete(suffix)
			}
			transcript_update(&reference, ch2)
			testing.expect_value(t, transcript_snapshot(&o._transcript), transcript_snapshot(&reference))
			peer, _ := server_handshake_peek(&o)
			testing.expect_value(t, peer.kind, .Peer_Parameters)
			testing.expect_value(t, o._selection.group, group)
			testing.expect(t, !server_retry_active(&o))
			testing.expect_value(t, a.live, len(ch2) + 2048)
			server_handshake_destroy(&o)
			owner_test_clean(t, &a)
		}
	}
}

@(test)
server_retry_rejects_changed_or_second_retry_hellos :: proc(t: ^testing.T) {
	for mode in 0 ..< 15 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		first, second: [2048]u8
		original := []Hello_Test_Extension{{0xbaba, []u8{1, 2, 3}}}
		ch1 := retry_test_hello(first[:], .Secp256r1, false, original, []u8{1, 2})
		event := retry_test_begin(t, &o, &a, ch1)
		server_handshake_accept(&o, event.id)
		extra := original
		if mode == 5 {
			extra = []Hello_Test_Extension{{0xbaba, []u8{1, 2, 3}}, {16, []u8{0, 2, 1, 'x'}}}
		}
		if mode == 8 {
			extra = []Hello_Test_Extension{{0xbaba, []u8{1, 2, 3}}, {44, []u8{0, 1, 1}}}
		}
		if mode == 9 {
			extra = []Hello_Test_Extension{{0xbaba, []u8{1, 2, 4}}}
		}
		if mode == 10 {
			extra = nil
		}
		if mode == 11 {
			extra = []Hello_Test_Extension{{0xbaba, []u8{1, 2, 3}}, {21, []u8{1}}}
		}
		if mode == 12 {
			extra = []Hello_Test_Extension{{0xbaba, []u8{1, 2, 3}}, {0xcccc, nil}}
		}
		group := Named_Group.Secp256r1
		if mode == 7 {
			group = .X25519
		}
		ch2 := retry_test_hello(second[:], group, mode != 6, extra, []u8{1, 2})
		hello, decoded := server_client_hello_decode(ch2)
		if decoded == .None {
			switch mode {
			case 0:
				ch2[6] ~= 1
			case 1:
				ch2[40] ~= 1 // Session ID.
			case 2:
				ch2[45] ~= 1 // Actually change the selected cipher byte.
			case 3:
				d := retry_test_mutate_extension(hello, 43)
				d[len(d) - 1] = 3
			case 4:
				d := retry_test_mutate_extension(hello, 13)
				d[len(d) - 1] = 7
			case 13:
				d := retry_test_mutate_extension(hello, 50)
				d[len(d) - 1] = 2
			case 14:
				d := retry_test_mutate_extension(hello, 51)
				d[3] = 0x18
			}
		}
		n, st, e := server_handshake_feed(&o, .Initial, ch2)
		testing.expect_value(t, n, len(ch2))
		testing.expect_value(t, st, .Terminal)
		testing.expect_value(t, e, .Malformed)
		fatal, _ := server_handshake_peek(&o)
		testing.expect_value(t, fatal.kind, .Fatal)
		testing.expect(t, !server_retry_active(&o))
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
	}
}

@(test)
server_retry_partial_cancel_allocation_failure_and_limits :: proc(t: ^testing.T) {
	first, second: [1024]u8
	ch1 := retry_test_hello(first[:], .Secp256r1, false)
	ch2 := retry_test_hello(second[:], .Secp256r1, true)
	for stop in 0 ..= len(ch2) {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		event := retry_test_begin(t, &o, &a, ch1)
		if stop > 0 {
			server_handshake_accept(&o, event.id)
			n, _, e := server_handshake_feed(&o, .Initial, ch2[:stop])
			testing.expect_value(t, n, stop)
			testing.expect_value(t, e, .None)
		}
		server_handshake_abort(&o)
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
	}
	for point in 1 ..= 3 {
		for fault in 0 ..< 4 {
			a := Owner_Test_Audit {
				backing = context.allocator,
			}
			o: Server_Handshake
			server_handshake_init(&o, SERVER_HANDSHAKE_DEFAULT_CONFIG, owner_test_allocator(&a))
			if point == 1 {
				if fault == 0 {
					a.fail_at = 1
				} else if fault == 1 {
					a.delta = -1
				} else if fault == 2 {
					a.delta = 17
				} else {
					a.error_with_grant = true
				}
			}
			if point == 2 { 	// Inject only after ordinary ClientHello allocation.
				n, _, e := server_handshake_feed(&o, .Initial, ch1[:len(ch1) - 1])
				assert(n == len(ch1) - 1 && e == .None)
				if fault == 0 {
					a.fail_at = 2
				} else if fault == 1 {
					a.delta = -1
				} else if fault == 2 {
					a.delta = 17
				} else {
					a.error_with_grant = true
				}
				server_handshake_feed(&o, .Initial, ch1[len(ch1) - 1:])
			} else {
				server_handshake_feed(&o, .Initial, ch1)
				if point == 3 {
					event, _ := server_handshake_peek(&o)
					server_handshake_accept(&o, event.id)
					if fault == 0 {
						a.fail_at = 3
					} else if fault == 1 {
						a.delta = -1
					} else if fault == 2 {
						a.delta = 17
					} else {
						a.error_with_grant = true
					}
					server_handshake_feed(&o, .Initial, ch2)
				}
			}
			fatal, _ := server_handshake_peek(&o)
			testing.expect_value(t, fatal.kind, .Fatal)
			testing.expect_value(t, fatal.error, .Allocation_Failed)
			server_handshake_destroy(&o)
			owner_test_clean(t, &a)
		}
	}
	for mode in 0 ..< 3 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		event := retry_test_begin(t, &o, &a, ch1)
		server_handshake_accept(&o, event.id)
		if mode == 0 {
			_, _, e := server_handshake_feed(&o, .Handshake, ch2)
			testing.expect_value(t, e, .Wrong_Level)
		}
		if mode == 1 {
			_, _, e := server_handshake_feed(&o, .Initial, []u8{1, 1, 0, 0})
			testing.expect_value(t, e, .Limit)
		}
		if mode == 2 {
			o._next_id = max(u64)
			_, _, e := server_handshake_feed(&o, .Initial, ch2)
			testing.expect_value(t, e, .Identity_Exhausted)
		}
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
	}
}

retry_test_pad :: proc(storage: []u8, wire: []u8) {
	at := len(wire)
	hello_put_u16(storage, &at, 21)
	hello_put_u16(storage, &at, u16(len(storage) - at - 2))
	server_flight_put24(storage[1:4], len(storage) - 4)
	x := 47
	hello_put_u16(storage, &x, u16(len(storage) - 49))
}

@(test)
server_retry_maximum_grants_and_invalid_p256_point :: proc(t: ^testing.T) {
	a := Owner_Test_Audit {
		backing = context.allocator,
	}
	o: Server_Handshake
	first, second: [65536]u8
	ch1 := retry_test_hello(first[:], .Secp256r1, false)
	retry_test_pad(first[:], ch1)
	ch2 := retry_test_hello(second[:], .Secp256r1, true)
	retry_test_pad(second[:], ch2)
	event := retry_test_begin(t, &o, &a, first[:])
	server_handshake_accept(&o, event.id)
	n, _, e := server_handshake_feed(&o, .Initial, second[:])
	testing.expect_value(t, n, 65536)
	testing.expect_value(t, e, .None)
	testing.expect_value(t, a.peak, 133120)
	testing.expect_value(t, a.calls, 3)
	fmt.printf("retry max first+second hello+scratch=%d bytes/%d grants; live after CH2=%d\n", a.peak, a.calls, a.live)
	server_handshake_destroy(&o)
	owner_test_clean(t, &a)
	store := flight_test_store(t)
	defer credential_store.destroy(&store)
	for mode in 0 ..< 3 {
		b := Owner_Test_Audit {
			backing = context.allocator,
		}
		p: Server_Handshake
		storage: [1024]u8
		wire := retry_test_hello(storage[:], .Secp256r1, true)
		hello, _ := server_client_hello_decode(wire)
		point := retry_test_mutate_extension(hello, 51)[6:]
		if mode == 0 {
			for &b in point[1:] {b = 0}
		}
		if mode == 1 {
			for &b in point[1:] {b = 0xff}
		}
		if mode == 2 {
			point[0] = 2
		}
		server_handshake_init(&p, SERVER_HANDSHAKE_DEFAULT_CONFIG, owner_test_allocator(&b))
		_, _, feed_error := server_handshake_feed(&p, .Initial, wire)
		if mode < 2 {
			testing.expect_value(t, feed_error, .None)
			peer, _ := server_handshake_peek(&p)
			server_handshake_accept(&p, peer.id)
			testing.expect_value(
				t,
				server_handshake_start_flight(&p, store, time.from_nanoseconds(1790000000 * 1000000000)),
				.None,
			)
			fatal, _ := server_handshake_peek(&p)
			testing.expect_value(t, fatal.kind, .Fatal)
			testing.expect_value(t, fatal.error, .Malformed)
		} else {
			testing.expect_value(t, feed_error, .Malformed)
		}
		server_handshake_destroy(&p)
		owner_test_clean(t, &b)
		ss, _ := credential_store.stats(store)
		testing.expect_value(t, ss.active_leases, 0)
	}
}

retry_test_psk :: proc(dst: []u8, names: []u8, sizes: []int, changed := false) -> []u8 {
	at := 2
	for name in names {
		hello_put_u16(dst, &at, 1)
		dst[at] = name
		at += 1
		for _ in 0 ..< 4 {dst[at] = 17 if changed else 0; at += 1}
	}
	x := 0
	hello_put_u16(dst, &x, u16(at - 2))
	start := at
	at += 2
	for size in sizes {dst[at] = u8(size); at += 1; for _ in 0 ..< size {dst[at] = 0xaa if changed else 0xbb; at += 1}}
	x = start
	hello_put_u16(dst, &x, u16(at - start - 2))
	return dst[:at]
}

@(test)
server_retry_psk_age_binder_removal_and_padding_rules :: proc(t: ^testing.T) {
	for mode in 0 ..< 12 {
		first, second: [2048]u8
		psk1, psk2: [256]u8
		first_names := []u8{'a', 'b'}
		first_sizes := []int{48, 32}
		second_names := []u8{'a', 'b'}
		second_sizes := []int{48, 32}
		if mode == 1 {
			second_names = []u8{'b'}
			second_sizes = []int{32}
		}
		if mode == 3 {
			second_names = []u8{'a'}
			second_sizes = []int{48}
		}
		if mode == 4 {
			second_names = []u8{'a', 'c'}
		}
		if mode == 5 {
			second_names = []u8{'b', 'a'}
			second_sizes = []int{32, 48}
		}
		if mode == 6 {
			second_sizes = []int{48, 48}
		}
		if mode == 10 {
			first_names = []u8{'a'}
			first_sizes = []int{48}
		}
		if mode == 11 {
			first_names = []u8{'b'}
			first_sizes = []int{32}
		}
		body1 := retry_test_psk(psk1[:], first_names, first_sizes)
		body2 := retry_test_psk(psk2[:], second_names, second_sizes, true)
		ext1 := []Hello_Test_Extension{{45, []u8{1, 1}}, {42, nil}, {41, body1}}
		ext2 := []Hello_Test_Extension{{45, []u8{1, 1}}, {21, []u8{0, 0, 0}}, {41, body2}}
		if mode == 2 || mode == 10 || mode == 11 {
			ext2 = []Hello_Test_Extension{{45, []u8{1, 1}}, {21, nil}}
		}
		if mode == 7 {
			ext2 = []Hello_Test_Extension{{45, []u8{1, 1}}, {42, nil}, {41, body2}}
		}
		if mode == 8 {
			ext2 = []Hello_Test_Extension{{45, []u8{1, 1}}, {21, []u8{1}}, {41, body2}}
		}
		if mode == 9 {
			ext1 = []Hello_Test_Extension{{45, []u8{1, 1}}}
		}
		ch1 := retry_test_hello(first[:], .Secp256r1, false, ext1)
		ch2 := retry_test_hello(second[:], .Secp256r1, true, ext2)
		h1, e1 := server_client_hello_decode(ch1)
		h2, e2 := server_client_hello_decode(ch2)
		testing.expect_value(t, e1, .None)
		if mode == 8 {
			testing.expect_value(t, e2, .Malformed)
			continue
		}
		testing.expect_value(t, e2, .None)
		testing.expect_value(t, server_retry_invariants(h1, h2, .Secp256r1), mode == 0 || mode == 1 || mode == 10)
	}
}

@(test)
server_retry_failure_preserves_last_available_event_identity :: proc(t: ^testing.T) {
	for retry in ([]bool{true, false}) {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		storage: [1024]u8
		wire := retry_test_hello(storage[:], .Secp256r1, !retry)
		server_handshake_init(&o, SERVER_HANDSHAKE_DEFAULT_CONFIG, owner_test_allocator(&a))
		if retry {
			server_handshake_feed(&o, .Initial, wire[:len(wire) - 1])
			o._next_id = max(u64) - 1
			a.fail_at = 2
			_, _, e := server_handshake_feed(&o, .Initial, wire[len(wire) - 1:])
			testing.expect_value(t, e, .Allocation_Failed)
		} else {
			store := flight_test_store(t)
			server_handshake_feed(&o, .Initial, wire)
			peer, _ := server_handshake_peek(&o)
			server_handshake_accept(&o, peer.id)
			server_handshake_start_flight(&o, store, time.from_nanoseconds(1790000000 * 1000000000))
			o._next_id = max(u64) - 1
			a.fail_at = 2
			server_handshake_peek(&o)
			credential_store.destroy(&store)
		}
		fatal, _ := server_handshake_peek(&o)
		testing.expect_value(t, fatal.kind, .Fatal)
		testing.expect_value(t, fatal.id, max(u64))
		again, _ := server_handshake_peek(&o)
		testing.expect_value(t, again.id, fatal.id)
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
	}
}
