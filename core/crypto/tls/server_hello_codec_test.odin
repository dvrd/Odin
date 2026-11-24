package tls

import "core:mem"
import "core:testing"

Hello_Test_Extension :: struct {
	kind: u16,
	data: []u8,
}

hello_test_wire :: proc(dst: []u8, extensions: []Hello_Test_Extension, session: []u8 = nil) -> []u8 {
	at := 4
	hello_put_u16(dst, &at, 0x0303)
	for i in 0 ..< 32 {dst[at + i] = u8(i)}
	at += 32
	dst[at] = u8(len(session))
	at += 1
	copy(dst[at:], session)
	at += len(session)
	hello_put_u16(dst, &at, 4)
	hello_put_u16(dst, &at, 0x0a0a) // GREASE cipher.
	hello_put_u16(dst, &at, 0x1301)
	dst[at], dst[at + 1] = 1, 0
	at += 2
	extensions_at := at
	at += 2
	for extension in extensions {
		hello_put_u16(dst, &at, extension.kind)
		hello_put_u16(dst, &at, u16(len(extension.data)))
		copy(dst[at:], extension.data)
		at += len(extension.data)
	}
	x := extensions_at
	hello_put_u16(dst, &x, u16(at - extensions_at - 2))
	body := at - 4
	dst[0], dst[1], dst[2], dst[3] = 1, u8(body >> 16), u8(body >> 8), u8(body)
	return dst[:at]
}

hello_test_versions := [?]u8{4, 0x7a, 0x7a, 3, 4}
hello_test_groups := [?]u8{0, 4, 0x1a, 0x1a, 0, 0x1d}
hello_test_signatures := [?]u8{0, 4, 0x2a, 0x2a, 8, 4}
hello_test_unknown := [?]u8{0xff}

hello_test_extensions :: proc(share: []u8) -> [5]Hello_Test_Extension {
	return {
		{43, hello_test_versions[:]},
		{10, hello_test_groups[:]},
		{13, hello_test_signatures[:]},
		{51, share},
		{0xaaaa, hello_test_unknown[:]},
	}
}

hello_test_share :: proc() -> [38]u8 {
	share: [38]u8
	share[0], share[1], share[2], share[3], share[4], share[5] = 0, 36, 0, 0x1d, 0, 32
	for i in 6 ..< 38 {share[i] = u8(i)}
	return share
}

@(test)
server_client_hello_borrow_and_conservative_selection :: proc(t: ^testing.T) {
	storage: [1024]u8
	share := hello_test_share()
	exts := hello_test_extensions(share[:])
	wire := hello_test_wire(storage[:], exts[:], ([]u8){1, 2, 3})
	// Any allocator call during decoding/negotiation would panic.
	old := context.allocator
	context.allocator = mem.panic_allocator()
	hello, status := server_client_hello_decode(wire)
	selection, negotiation := server_client_hello_negotiate(hello)
	context.allocator = old
	testing.expect_value(t, status, .None)
	testing.expect_value(t, negotiation, .None)
	testing.expect_value(t, selection.version, u16(0x0304))
	testing.expect_value(t, len(hello.session_id), 3)
	testing.expect_value(t, len(selection.peer_key_share), 32)
	testing.expect(t, raw_data(hello.wire) == raw_data(wire))
	testing.expect(t, raw_data(selection.peer_key_share) >= raw_data(wire))
	// Every prefix is final-message malformed, while the independent header
	// probe accepts complete framing and ignores any coalesced body suffix.
	for split in 0 ..< len(wire) {
		_, bad := server_client_hello_decode(wire[:split])
		testing.expect_value(t, bad, .Malformed)
		_, probe := server_client_hello_size(wire[:split])
		if split < 4 {
			testing.expect_value(t, probe, .Need_Input)
		} else {
			testing.expect_value(t, probe, .None)
		}
	}
	storage[len(wire)] = 1
	_, trailing := server_client_hello_decode(storage[:len(wire) + 1])
	testing.expect_value(t, trailing, .Malformed)
	_, cap := server_client_hello_size(([]u8){1, 0xff, 0xff, 0xff})
	testing.expect_value(t, cap, .Limit)
	_, bound := server_client_hello_decode(wire, {max_wire_bytes = len(wire) - 1, max_extensions = 128})
	testing.expect_value(t, bound, .Limit)
	_, entries := server_client_hello_decode(wire, {max_wire_bytes = 65536, max_extensions = 4})
	testing.expect_value(t, entries, .Limit)
}

@(test)
server_client_hello_vectors_duplicates_and_retry :: proc(t: ^testing.T) {
	storage: [1024]u8
	share := hello_test_share()
	exts := hello_test_extensions(share[:])
	for index in 0 ..< len(exts) {
		original := exts[index]
		// Every recognized vector's length is checked, even if unsupported
		// values are mixed into the list. Unknown contents remain opaque.
		if index < 4 {
			bad: [64]u8
			copy(bad[:], original.data)
			bad[0] = 0xff
			exts[index].data = bad[:len(original.data)]
			_, status := server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
			testing.expect_value(t, status, .Malformed)
		}
		exts[index] = original
	}
	exts[4] = exts[0]
	_, duplicate := server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
	testing.expect_value(t, duplicate, .Malformed)
	exts[4] = {0xaaaa, ([]u8){1}}
	exts[3].data = ([]u8){0, 0}
	hello, ok := server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
	testing.expect_value(t, ok, .None)
	_, retry := server_client_hello_negotiate(hello)
	testing.expect_value(t, retry, .Retry_Required)
	_, missing_share := server_client_hello_decode(hello_test_wire(storage[:], exts[:3]))
	testing.expect_value(t, missing_share, .Malformed)
	exts[0].data = ([]u8){2, 3, 3}
	_, version := server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
	testing.expect_value(t, version, .Unsupported)
}

@(test)
server_client_hello_opaque_alpn_sni_and_psk :: proc(t: ^testing.T) {
	storage: [2048]u8
	share := hello_test_share()
	base := hello_test_extensions(share[:])
	exts: [10]Hello_Test_Extension
	copy(exts[:], base[:])
	exts[5] = {16, ([]u8){0, 5, 2, 0, 0xff, 1, 'x'}}
	exts[6] = {0, ([]u8){0, 6, 0, 0, 3, 'a', '.', 'b'}}
	exts[7] = {45, ([]u8){1, 1}}
	exts[8] = {42, nil}
	psk: [44]u8
	psk[0], psk[1], psk[2], psk[3], psk[4] = 0, 7, 0, 1, 'x'
	psk[9], psk[10], psk[11] = 0, 33, 32
	exts[9] = {41, psk[:]}
	wire := hello_test_wire(storage[:], exts[:])
	old := context.allocator
	context.allocator = mem.nil_allocator()
	hello, status := server_client_hello_decode(wire)
	_, negotiation := server_client_hello_negotiate(hello)
	context.allocator = old
	testing.expect_value(t, status, .None)
	if status != .None {
		return
	}
	testing.expect_value(t, negotiation, .None)
	testing.expect(t, hello.early_data && hello.has_psk)
	testing.expect_value(t, hello.alpn_protocols[2], u8(0xff))
	testing.expect_value(t, string(hello.server_name), "a.b")
	// PSK must be last, binders match identities, early_data requires PSK.
	exts[8], exts[9] = exts[9], exts[8]
	_, not_last := server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
	testing.expect_value(t, not_last, .Malformed)
	exts[8], exts[9] = exts[9], exts[8]
	psk[11] = 31
	_, binder := server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
	testing.expect_value(t, binder, .Malformed)
	_, early := server_client_hello_decode(hello_test_wire(storage[:], exts[:9]))
	testing.expect_value(t, early, .Malformed)
	invalid_names := []string{"a.", "-a.b", "a..b", "127.0.0.1", "a:b"}
	for invalid in invalid_names {
		testing.expect(t, !server_hello_dns_name_valid(transmute([]u8)invalid))
	}
	name: [254]u8
	for &c in name[:] {c = 'a'}
	testing.expect(t, !server_hello_dns_name_valid(name[:]))
}

@(test)
server_client_hello_independent_go_and_openssl :: proc(t: ^testing.T) {
	fixtures := []string {
		#load("testdata/server_go_client_hello.wire"),
		#load("testdata/server_openssl_client_hello.wire"),
	}
	for fixture in fixtures {
		wire := transmute([]u8)fixture
		hello, status := server_client_hello_decode(wire)
		testing.expect_value(t, status, .None)
		if status != .None {
			continue
		}
		selection, negotiation := server_client_hello_negotiate(hello)
		testing.expect_value(t, negotiation, .None)
		testing.expect_value(t, len(selection.peer_key_share), 32)
		testing.expect_value(t, string(hello.server_name), "fixture.invalid")
		testing.expect_value(t, len(hello.session_id), 32)
		// Model a caller's bounded copied-message accumulator at every split
		// and one byte at a time. The codec itself never owns partial storage.
		for split in 0 ..= len(wire) {
			copied: [1024]u8
			copy(copied[:], wire[:split])
			copy(copied[split:], wire[split:])
			_, assembled := server_client_hello_decode(copied[:len(wire)])
			testing.expect_value(t, assembled, .None)
		}
		copied: [1024]u8
		for value, i in wire {copied[i] = value}
		_, one_byte := server_client_hello_decode(copied[:len(wire)])
		testing.expect_value(t, one_byte, .None)
	}
}

@(test)
server_client_hello_limits_legacy_and_relationships :: proc(t: ^testing.T) {
	storage: [65537]u8
	padding: [65536]u8
	share := hello_test_share()
	base := hello_test_extensions(share[:])
	exts: [6]Hello_Test_Extension
	copy(exts[:], base[:])
	ordinary := len(hello_test_wire(storage[:], base[:]))
	exts[5] = {0xcccc, padding[:65536 - ordinary - 4]}
	wire := hello_test_wire(storage[:], exts[:])
	testing.expect_value(t, len(wire), 65536)
	_, exact := server_client_hello_decode(wire)
	testing.expect_value(t, exact, .None)
	exts[5].data = padding[:65537 - ordinary - 4]
	_, oversize := server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
	testing.expect_value(t, oversize, .Limit)
	wire = hello_test_wire(storage[:], base[:])
	legacy_offsets := []int{4, 38, 45, 46}
	for at in legacy_offsets { 	// legacy version, session length, compression length/value
		original := wire[at]
		wire[at] = 0xff
		_, bad := server_client_hello_decode(wire)
		testing.expect_value(t, bad, .Malformed)
		wire[at] = original
	}
	session: [33]u8
	_, long_session := server_client_hello_decode(hello_test_wire(storage[:], base[:], session[:]))
	testing.expect_value(t, long_session, .Malformed)
	// Duplicate and unoffered shares are malformed, even if not selected.
	duplicate: [74]u8
	duplicate[0], duplicate[1] = 0, 72
	copy(duplicate[2:], share[2:])
	copy(duplicate[38:], share[2:])
	base[3].data = duplicate[:]
	_, dup_share := server_client_hello_decode(hello_test_wire(storage[:], base[:]))
	testing.expect_value(t, dup_share, .Malformed)
	share[3] = 0x17
	base[3].data = share[:]
	_, unoffered := server_client_hello_decode(hello_test_wire(storage[:], base[:]))
	testing.expect_value(t, unoffered, .Malformed)
	// A well-framed PSK-only CH is parsed, but this full-handshake profile
	// cannot negotiate it. Signature presence is conditional on PSK absence.
	psk: [44]u8
	psk[0], psk[1], psk[2], psk[3], psk[4] = 0, 7, 0, 1, 'x'
	psk[9], psk[10], psk[11] = 0, 33, 32
	psk_only := []Hello_Test_Extension{{43, hello_test_versions[:]}, {45, ([]u8){1, 0}}, {41, psk[:]}}
	hello, parsed := server_client_hello_decode(hello_test_wire(storage[:], psk_only))
	testing.expect_value(t, parsed, .None)
	_, unsupported := server_client_hello_negotiate(hello)
	testing.expect_value(t, unsupported, .Unsupported)
	psk_only[1] = {42, nil}
	_, missing_modes := server_client_hello_decode(hello_test_wire(storage[:], psk_only))
	testing.expect_value(t, missing_modes, .Malformed)
	// Extension count is capped even for empty unknown extensions.
	many: [129]Hello_Test_Extension
	copy(many[:], base[:])
	share[3] = 0x1d
	for i in 5 ..< len(many) {many[i] = {u16(0x1000 + i), nil}}
	_, count_limit := server_client_hello_decode(hello_test_wire(storage[:], many[:]))
	testing.expect_value(t, count_limit, .Limit)
}

@(test)
server_client_hello_entry_caps_and_optional_offers :: proc(t: ^testing.T) {
	storage: [4096]u8
	share := hello_test_share()
	base := hello_test_extensions(share[:])
	many: [129]Hello_Test_Extension
	copy(many[:], base[:])
	for i in 5 ..< len(many) {many[i] = {u16(0x1000 + i), nil}}
	_, exact_extensions := server_client_hello_decode(hello_test_wire(storage[:], many[:128]))
	testing.expect_value(t, exact_extensions, .None)
	_, over_extensions := server_client_hello_decode(hello_test_wire(storage[:], many[:]))
	testing.expect_value(t, over_extensions, .Limit)

	// Check all 128 group/share entries, not just the selected final X25519.
	groups: [2 + 129 * 2]u8
	shares: [2 + 129 * 5 + 31]u8
	ga, sa := 2, 2
	for i in 0 ..< 128 {
		group := u16(0x2000 + i)
		length := 1
		if i == 127 {
			group = u16(Named_Group.X25519)
			length = 32
		}
		hello_put_u16(groups[:], &ga, group)
		hello_put_u16(shares[:], &sa, group)
		hello_put_u16(shares[:], &sa, u16(length))
		for j in 0 ..< length {shares[sa + j] = u8(j + 1)}
		sa += length
	}
	a := 0
	hello_put_u16(groups[:], &a, u16(ga - 2))
	a = 0
	hello_put_u16(shares[:], &a, u16(sa - 2))
	base[1].data, base[3].data = groups[:ga], shares[:sa]
	hello, exact_groups := server_client_hello_decode(hello_test_wire(storage[:], base[:]))
	testing.expect_value(t, exact_groups, .None)
	_, selection := server_client_hello_negotiate(hello)
	testing.expect_value(t, selection, .None)
	hello_put_u16(groups[:], &ga, 0x3000)
	a = 0
	hello_put_u16(groups[:], &a, u16(ga - 2))
	base[1].data = groups[:ga]
	_, over_groups := server_client_hello_decode(hello_test_wire(storage[:], base[:]))
	testing.expect_value(t, over_groups, .Limit)

	// Unknown future SNI types still count toward the bounded entry scan.
	names: [2 + 129 * 4]u8
	na := 2
	for i in 0 ..< 129 {
		names[na], names[na + 1], names[na + 2], names[na + 3] = u8(i), 0, 1, 'a'
		na += 4
	}
	base = hello_test_extensions(share[:])
	a = 0
	hello_put_u16(names[:], &a, 128 * 4)
	base[4] = {0, names[:2 + 128 * 4]}
	_, exact_names := server_client_hello_decode(hello_test_wire(storage[:], base[:]))
	testing.expect_value(t, exact_names, .None)
	a = 0
	hello_put_u16(names[:], &a, 129 * 4)
	base[4].data = names[:]
	_, over_names := server_client_hello_decode(hello_test_wire(storage[:], base[:]))
	testing.expect_value(t, over_names, .Limit)

	base = hello_test_extensions(share[:])
	exts: [7]Hello_Test_Extension
	copy(exts[:], base[:])
	exts[5] = {50, ([]u8){0, 2, 4, 1}}
	exts[6] = {57, ([]u8){0xff, 0, 1}}
	optional: Server_Hello_Codec_Status
	hello, optional = server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
	testing.expect_value(t, optional, .None)
	testing.expect(t, server_hello_offer_contains(hello.signature_algorithms_cert, 0x0401))
	testing.expect(t, hello.has_quic_transport_parameters && len(hello.quic_transport_parameters) == 3)
	// Handshake scheme selection does not imply chain-signature admission.
	_, selection = server_client_hello_negotiate(hello)
	testing.expect_value(t, selection, .None)
	exts[5].data = ([]u8){0, 1, 4}
	_, bad_cert_vector := server_client_hello_decode(hello_test_wire(storage[:], exts[:]))
	testing.expect_value(t, bad_cert_vector, .Malformed)
	base[2].data = ([]u8){0, 2, 4, 1}
	hello, optional = server_client_hello_decode(hello_test_wire(storage[:], base[:]))
	testing.expect_value(t, optional, .None)
	_, selection = server_client_hello_negotiate(hello)
	testing.expect_value(t, selection, .Unsupported)
}

@(test)
server_client_hello_mutation_corpus_without_allocators :: proc(t: ^testing.T) {
	fixtures := []string {
		#load("testdata/server_go_client_hello.wire"),
		#load("testdata/server_openssl_client_hello.wire"),
	}
	count := 0
	{
		context.allocator = mem.panic_allocator()
		context.temp_allocator = mem.panic_allocator()
		for fixture in fixtures {
			storage: [1024]u8
			wire := storage[:len(fixture)]
			copy(wire, transmute([]u8)fixture)
			for at in 0 ..< len(wire) {
				original := wire[at]
				for value in 0 ..< 256 {
					wire[at] = u8(value)
					hello, status := server_client_hello_decode(wire)
					if status == .None {
						assert(raw_data(hello.wire) == raw_data(wire))
						selected, result := server_client_hello_negotiate(hello)
						if result == .None {
							assert(len(selected.peer_key_share) == 32)
							assert(server_hello_offer_contains(hello.versions, selected.version))
							assert(server_hello_offer_contains(hello.cipher_suites, u16(selected.cipher)))
							assert(server_hello_offer_contains(hello.groups, u16(selected.group)))
							assert(server_hello_offer_contains(hello.signature_algorithms, u16(selected.signature)))
						} else {
							assert(len(selected.peer_key_share) == 0)
						}
					} else {
						assert(len(hello.wire) == 0 && len(hello.versions) == 0 && len(hello.key_shares) == 0)
					}
					count += 1
				}
				wire[at] = original
			}
		}
	}
	testing.expect_value(t, count, (260 + 268) * 256)
}
