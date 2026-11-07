package tests

import "core:bytes"
import "core:crypto/aes"
import "core:mem"
import "core:net/quic"
import "core:testing"

// Published RFC9001 Appendix A.2/A.3 packet protection vectors, not generated
// expected values. Whitespace is ignored by the test-only hex decoder.
CLIENT_HEADER :: "c300000001088394c8f03e5157080000449e00000002"
CLIENT_CRYPTO :: `
060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868
04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578
616d706c652e636f6dff01000100000a00080006001d00170018001000070005
04616c706e000500050100000000003300260024001d00209370b2c9caa47fba
baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400
0d0010000e0403050306030203080408050806002d00020101001c0002400100
3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000
75300901100f088394c8f03e51570806048000ffff`
CLIENT_PACKET :: `
c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934`
SERVER_HEADER :: "c1000000010008f067a5502a4262b50040750001"
SERVER_PAYLOAD :: `
02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739
88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94
0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00
020304`
SERVER_PACKET :: `
cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a
5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3
dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84
022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4
2158407dd074ee`

vector_pair :: proc() -> quic.Initial_Key_Pair {
	cid: [8]u8
	hex(cid[:], "8394c8f03e515708")
	pair, e := quic.initial_keys_derive_v1(cid[:])
	assert(e == .None)
	return pair
}

@(test)
rfc9001_initial_key_vectors :: proc(t: ^testing.T) {
	pair := vector_pair()
	defer quic.initial_key_pair_clear(&pair)
	expected: [32]u8
	testing.expect(
		t,
		bytes.equal(
			pair.client.secret[:],
			hex(expected[:], "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
		),
	)
	testing.expect(
		t,
		bytes.equal(pair.client.key[:], hex(expected[:], "1f369613dd76d5467730efcbe3b1a22d")),
	)
	testing.expect(t, bytes.equal(pair.client.iv[:], hex(expected[:], "fa044b2f42a3fd3b46fb255c")))
	testing.expect(
		t,
		bytes.equal(pair.client.hp[:], hex(expected[:], "9f50449e04a0e810283a1e9933adedd2")),
	)
	testing.expect(
		t,
		bytes.equal(
			pair.server.secret[:],
			hex(expected[:], "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"),
		),
	)
	testing.expect(
		t,
		bytes.equal(pair.server.key[:], hex(expected[:], "cf3a5331653c364c88f0f379b6067e37")),
	)
	testing.expect(t, bytes.equal(pair.server.iv[:], hex(expected[:], "0ac1493ca1905853b0bba03e")))
	testing.expect(
		t,
		bytes.equal(pair.server.hp[:], hex(expected[:], "c206b8d9b9f0f37644430b490eeaa314")),
	)
	nonce, e := quic.initial_nonce(&pair.client, 2)
	testing.expect(
		t,
		e == .None && bytes.equal(nonce[:], hex(expected[:], "fa044b2f42a3fd3b46fb255e")),
	)
}

@(test)
rfc9001_full_initial_packets_both_aes_backends :: proc(t: ^testing.T) {
	pair := vector_pair()
	defer quic.initial_key_pair_clear(&pair)
	for implementation in ([?]aes.Implementation{.Portable, .Hardware}) {
		for server in ([?]bool{false, true}) {
			header_storage: [22]u8
			payload: [1162]u8
			expected_storage: [1200]u8
			header := hex(header_storage[:], CLIENT_HEADER)
			plaintext := payload[:]
			hex(payload[:], CLIENT_CRYPTO)
			expected := hex(expected_storage[:], CLIENT_PACKET)
			keys := &pair.client
			pn: u64 = 2
			if server {
				header = hex(header_storage[:], SERVER_HEADER)
				plaintext = hex(payload[:], SERVER_PAYLOAD)
				expected = hex(expected_storage[:], SERVER_PACKET)
				keys = &pair.server
				pn = 1
			}
			packet_storage: [1200]u8
			copy(packet_storage[:], header)
			n, e := quic.initial_payload_seal(
				packet_storage[len(header):],
				header,
				plaintext,
				keys,
				pn,
				implementation,
			)
			testing.expect(t, e == .None && n == len(plaintext) + 16)
			packet := packet_storage[:len(header) + n]
			hp := quic.initial_header_protection_apply(packet, keys, implementation)
			testing.expect(
				t,
				hp == .None && bytes.equal(packet, expected),
				"full published protected packet",
			)
			// Open the independent published bytes, not merely our own generated output.
			view, _, ve := quic.packet_decode_v1(expected)
			testing.expect_value(t, ve, .None)
			testing.expect_value(t, view.packet_number_offset, 18)
			remove := quic.initial_header_protection_remove(expected, keys, implementation)
			testing.expect(t, remove == .None && bytes.equal(expected[:len(header)], header))
			out: [1162]u8
			opened, oe := quic.initial_payload_open(
				out[:],
				expected[:len(header)],
				expected[len(header):],
				keys,
				pn,
				implementation,
			)
			testing.expect(
				t,
				oe == .None && opened == len(plaintext) && bytes.equal(out[:opened], plaintext),
			)
		}
	}
}

@(test)
initial_authentication_failures_zero_only_produced_plaintext :: proc(t: ^testing.T) {
	pair := vector_pair()
	defer quic.initial_key_pair_clear(&pair)
	for implementation in ([?]aes.Implementation{.Portable, .Hardware}) {
		original: [1200]u8
		packet := hex(original[:], CLIENT_PACKET)
		testing.expect_value(
			t,
			quic.initial_header_protection_remove(packet, &pair.client, implementation),
			.None,
		)
		// Every protected byte (ciphertext or tag) is authenticated.
		for index in 22 ..< len(packet) {
			altered := original
			altered[index] ~= 1
			out: [1164]u8
			for &b in out[:] {b = 0xa5}
			n, e := quic.initial_payload_open(
				out[:],
				altered[:22],
				altered[22:],
				&pair.client,
				2,
				implementation,
			)
			testing.expect(t, n == 0 && e == .Authentication_Failed)
			for b in out[:1162] {testing.expect_value(t, b, u8(0))}
			testing.expect(t, out[1162] == 0xa5 && out[1163] == 0xa5)
		}
		// Each header byte is either structurally rejected before decryption or
		// rejected by the GCM tag; no altered header produces usable plaintext.
		for index in 0 ..< 22 {
			altered := original
			altered[index] ~= 1
			out: [1162]u8
			for &b in out[:] {b = 0xa5}
			n, e := quic.initial_payload_open(
				out[:],
				altered[:22],
				altered[22:],
				&pair.client,
				2,
				implementation,
			)
			testing.expect(t, n == 0 && e != .None)
			want: u8 = 0xa5
			if e == .Authentication_Failed {
				want = 0
			}
			for b in out {testing.expect_value(t, b, want)}
		}
		out: [1162]u8
		// Same truncated32-bit PN, wrong reconstructed high bits: AEAD must fail.
		_, e := quic.initial_payload_open(
			out[:],
			packet[:22],
			packet[22:],
			&pair.client,
			(u64(1) << 32) + 2,
			implementation,
		)
		testing.expect_value(t, e, .Authentication_Failed)
		for b in out {testing.expect_value(t, b, u8(0))}
		_, e = quic.initial_payload_open(
			out[:],
			packet[:22],
			packet[22:],
			&pair.server,
			2,
			implementation,
		)
		testing.expect_value(t, e, .Authentication_Failed)
	}
}

@(test)
initial_preflight_truncation_and_alias_failures_preserve_storage :: proc(t: ^testing.T) {
	pair := vector_pair()
	defer quic.initial_key_pair_clear(&pair)
	packet_storage: [1200]u8
	packet := hex(packet_storage[:], CLIENT_PACKET)
	testing.expect_value(t, quic.initial_header_protection_remove(packet, &pair.client), .None)
	header := packet[:22]
	ciphertext := packet[22:]
	out: [1180]u8
	for &b in out[:] {b = 0xa5}
	initial := out
	for cut in 0 ..< 22 {
		n, e := quic.initial_payload_open(out[:], header[:cut], ciphertext, &pair.client, 2)
		testing.expect(t, n == 0 && e != .None && out == initial)
	}
	for cut in 0 ..< len(ciphertext) {
		n, e := quic.initial_payload_open(out[:], header, ciphertext[:cut], &pair.client, 2)
		testing.expect(t, n == 0 && e == .Invalid_Length && out == initial)
	}
	_, e := quic.initial_payload_open(out[:1161], header, ciphertext, &pair.client, 2)
	testing.expect(t, e == .Destination_Undersized && out == initial)
	_, e = quic.initial_payload_seal(out[:1177], header, initial[:1162], &pair.client, 2)
	testing.expect(t, e == .Destination_Undersized && out == initial)
	_, e = quic.initial_payload_open(out[:], header, ciphertext, &pair.client, 3)
	testing.expect(t, e == .Invalid_Packet_Number && out == initial)
	_, e = quic.initial_payload_open(out[:], header, ciphertext, &pair.client, quic.MAX_VARINT + 1)
	testing.expect(t, e == .Invalid_Packet_Number && out == initial)
	before := packet_storage
	_, e = quic.initial_payload_open(packet[1:], header, ciphertext, &pair.client, 2)
	testing.expect(t, e == .Overlapping_Buffers && packet_storage == before)
	_, e = quic.initial_payload_open(packet[23:], header, ciphertext, &pair.client, 2)
	testing.expect(t, e == .Overlapping_Buffers && packet_storage == before)
	_, e = quic.initial_payload_seal(out[:], header, out[1:1163], &pair.client, 2)
	testing.expect(t, e == .Overlapping_Buffers && out == initial)
	_, e = quic.initial_payload_seal(out[:], header, out[16:1178], &pair.client, 2)
	testing.expect(t, e == .Overlapping_Buffers && out == initial)
	// Dest overlapping live keys must never erase or encrypt those keys.
	key_before := pair.client
	key_bytes := (cast([^]u8)&pair.client)[:size_of(quic.Initial_Keys)]
	tiny_header: [32]u8
	hn, _, he := quic.long_header_encode_v1(
		tiny_header[:],
		{kind = .Initial, packet_number_length = 4, ciphertext_length = 16},
	)
	testing.expect_value(t, he, .None)
	_, e = quic.initial_payload_seal(key_bytes, tiny_header[:hn], nil, &pair.client, 0)
	testing.expect(t, e == .Overlapping_Buffers && pair.client == key_before)
}

@(test)
initial_hp_sample_boundaries_and_offset_are_explicit :: proc(t: ^testing.T) {
	pair := vector_pair()
	defer quic.initial_key_pair_clear(&pair)
	original: [1200]u8
	full := hex(original[:], CLIENT_PACKET)
	for cut in 0 ..< len(full) {
		candidate := original
		before := candidate
		e := quic.initial_header_protection_remove(candidate[:cut], &pair.client)
		testing.expect(t, e != .None && candidate == before)
	}
	// Make validly delimited packets whose sample is either one byte short or
	// exactly at the boundary. Structural Length, not trailing bytes, bounds HP.
	for pnlen in 1 ..= 4 {
		for bodylen in 19 ..= 20 {
			packet: [64]u8
			n, p, e := quic.long_header_encode_v1(
				packet[:],
				{
					kind = .Initial,
					packet_number_length = pnlen,
					ciphertext_length = u64(bodylen - pnlen),
				},
			)
			testing.expect_value(t, e, .None)
			end := n + bodylen - pnlen
			before := packet
			hp := quic.initial_header_protection_apply(packet[:end], &pair.client)
			if bodylen == 19 {
				testing.expect(t, hp == .Sample_Too_Short && packet == before)
			} else {
				testing.expect_value(t, hp, .None)
				testing.expect_value(
					t,
					quic.initial_header_protection_remove(packet[:end], &pair.client),
					.None,
				)
				testing.expect(t, packet == before && p == n - pnlen)
			}
		}
	}
	// Token and longer CIDs move the sample. Roundtrip must use decoded PN offset.
	cid: [20]u8
	token := []u8{4, 3, 2, 1, 0}
	packet: [128]u8
	n, p, e := quic.long_header_encode_v1(
		packet[:],
		{
			kind = .Initial,
			destination_id = cid[:],
			source_id = cid[:],
			token = token,
			token_length_width = 2,
			length_width = 4,
			packet_number_length = 2,
			packet_number = 17,
			ciphertext_length = 32,
		},
	)
	testing.expect_value(t, e, .None)
	testing.expect(t, p != 18)
	before := packet
	testing.expect_value(
		t,
		quic.initial_header_protection_apply(packet[:n + 32], &pair.client),
		.None,
	)
	testing.expect_value(
		t,
		quic.initial_header_protection_remove(packet[:n + 32], &pair.client),
		.None,
	)
	testing.expect(t, packet == before)
	// Coalesced tails are rejected by this single-packet API without mutation.
	testing.expect_value(
		t,
		quic.initial_header_protection_apply(packet[:n + 33], &pair.client),
		.Invalid_Header,
	)
	testing.expect(t, packet == before)
}

@(test)
initial_in_place_zero_length_and_key_erase_without_allocations :: proc(t: ^testing.T) {
	context.allocator = mem.nil_allocator()
	context.temp_allocator = mem.nil_allocator()
	pair := vector_pair()
	// Exact in-place seal/open retain caller storage without heap metadata.
	header_storage: [22]u8
	header := hex(header_storage[:], CLIENT_HEADER)
	data: [1178]u8
	hex(data[:], CLIENT_CRYPTO)
	expected: [1162]u8
	copy(expected[:], data[:1162])
	n, e := quic.initial_payload_seal(data[:], header, data[:1162], &pair.client, 2)
	testing.expect(t, e == .None && n == 1178)
	n, e = quic.initial_payload_open(data[:], header, data[:], &pair.client, 2)
	testing.expect(t, e == .None && n == 1162 && bytes.equal(data[:n], expected[:]))
	// Empty payloads still carry/verify a tag; PN4 allows HP's full sample.
	empty_header: [32]u8
	hn, _, he := quic.long_header_encode_v1(
		empty_header[:],
		{kind = .Initial, packet_number_length = 4, ciphertext_length = 16},
	)
	testing.expect_value(t, he, .None)
	tag: [16]u8
	n, e = quic.initial_payload_seal(tag[:], empty_header[:hn], nil, &pair.client, 0)
	testing.expect(t, e == .None && n == 16)
	n, e = quic.initial_payload_open(nil, empty_header[:hn], tag[:], &pair.client, 0)
	testing.expect(t, e == .None && n == 0)
	_, e = quic.initial_nonce(&pair.client, quic.MAX_VARINT)
	testing.expect_value(t, e, .None)
	quic.initial_keys_clear(&pair.client)
	testing.expect(t, pair.client == quic.Initial_Keys{} && pair.server.initialized)
	_, e = quic.initial_nonce(&pair.client, 0)
	testing.expect_value(t, e, .Invalid_Keys)
	_, e = quic.initial_payload_seal(tag[:], empty_header[:hn], nil, &pair.client, 0)
	testing.expect_value(t, e, .Invalid_Keys)
	quic.initial_key_pair_clear(&pair)
	quic.initial_key_pair_clear(&pair)
	testing.expect(t, pair == quic.Initial_Key_Pair{})
	cid: [21]u8
	_, e = quic.initial_keys_derive_v1(cid[:])
	testing.expect_value(t, e, .Invalid_Connection_ID)
	zero_cid, ze := quic.initial_keys_derive_v1(nil)
	testing.expect(t, ze == .None && zero_cid.client.initialized)
	quic.initial_key_pair_clear(&zero_cid)
}

@(test)
initial_invalid_backend_and_failed_in_place_open_are_safe :: proc(t: ^testing.T) {
	pair := vector_pair()
	defer quic.initial_key_pair_clear(&pair)
	raw: [1200]u8
	packet := hex(raw[:], CLIENT_PACKET)
	before := raw
	testing.expect_value(
		t,
		quic.initial_header_protection_remove(packet, &pair.client, aes.Implementation(9)),
		.Invalid_Implementation,
	)
	testing.expect(t, raw == before)
	testing.expect_value(t, quic.initial_header_protection_remove(packet, &pair.client), .None)
	before = raw
	_, e := quic.initial_payload_open(
		packet[22:],
		packet[:22],
		packet[22:],
		&pair.client,
		2,
		aes.Implementation(9),
	)
	testing.expect(t, e == .Invalid_Implementation && raw == before)
	packet[len(packet) - 1] ~= 1
	n, oe := quic.initial_payload_open(packet[22:], packet[:22], packet[22:], &pair.client, 2)
	testing.expect(t, oe == .Authentication_Failed && n == 0)
	testing.expect(t, bytes.equal(packet[:22], before[:22]))
	for b in packet[22:1184] {testing.expect_value(t, b, u8(0))}
	testing.expect(t, bytes.equal(packet[1184:1199], before[1184:1199]))
	testing.expect_value(t, packet[1199], before[1199] ~ u8(1))
}
