package tests

import "core:bytes"
import "core:crypto"
import "core:crypto/aes"
import "core:crypto/ed25519"
import "core:crypto/sha2"
import "core:crypto/tls"
import "core:crypto/x509"
import "core:encoding/pem"
import "core:net/quic"
import "core:testing"
import "core:time"

protect_put_u16 :: proc(dst: []u8, v: int) {
	dst[0] = u8(v >> 8)
	dst[1] = u8(v)
}

protect_put_u24 :: proc(dst: []u8, v: int) {
	dst[0] = u8(v >> 16)
	dst[1] = u8(v >> 8)
	dst[2] = u8(v)
}

protect_client_hello :: proc(dst: []u8, protocols: []string, params: []u8, include_params: bool, extra: []u8) -> []u8 {
	names := 0
	for protocol in protocols {
		names += 1 + len(protocol)
	}
	ext_len := len(extra)
	if len(protocols) > 0 {
		ext_len += 4 + 2 + names
	}
	if include_params {
		ext_len += 4 + len(params)
	}
	body := 43 + ext_len
	if len(dst) < 4 + body {
		return nil
	}
	dst[0] = 1
	protect_put_u24(dst[1:], body)
	dst[4], dst[5] = 3, 3
	for i in 6 ..< 38 {
		dst[i] = 0x11
	}
	dst[38] = 0
	dst[39], dst[40] = 0, 2
	dst[41], dst[42] = 0x13, 0x01
	dst[43], dst[44] = 1, 0
	protect_put_u16(dst[45:], ext_len)
	at := 47
	if len(protocols) > 0 {
		protect_put_u16(dst[at:], 16)
		protect_put_u16(dst[at + 2:], 2 + names)
		protect_put_u16(dst[at + 4:], names)
		at += 6
		for protocol in protocols {
			dst[at] = u8(len(protocol))
			at += 1
			for b in protocol {
				dst[at] = u8(b)
				at += 1
			}
		}
	}
	if include_params {
		protect_put_u16(dst[at:], 0x0039)
		protect_put_u16(dst[at + 2:], len(params))
		at += 4
		at += copy(dst[at:], params)
	}
	at += copy(dst[at:], extra)
	return dst[:at]
}

protect_server_hello :: proc(dst: []u8) -> []u8 {
	if len(dst) < 90 {
		return nil
	}
	dst[0] = 2
	protect_put_u24(dst[1:], 86)
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

protect_extensions :: proc(dst: []u8, message_type: u8, params, extra: []u8) -> []u8 {
	alpn := [?]u8{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33}
	ext_len := len(alpn) + 4 + len(params) + len(extra)
	body := 2 + ext_len
	if len(dst) < 4 + body {
		return nil
	}
	dst[0] = message_type
	protect_put_u24(dst[1:], body)
	protect_put_u16(dst[4:], ext_len)
	at := 6
	at += copy(dst[at:], alpn[:])
	protect_put_u16(dst[at:], 0x0039)
	protect_put_u16(dst[at + 2:], len(params))
	at += 4
	at += copy(dst[at:], params)
	at += copy(dst[at:], extra)
	return dst[:at]
}

protect_certificate_message :: proc(dst: []u8) -> []u8 {
	block, _, decode_error := pem.decode(#load("../../../../tests/core/crypto/tls/testdata/leaf.pem"))
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
	protect_put_u24(dst[1:], size - 4)
	dst[4] = 0
	protect_put_u24(dst[5:], len(der) + 5)
	protect_put_u24(dst[8:], len(der))
	copy(dst[11:], der)
	dst[size - 2], dst[size - 1] = 0, 0
	return dst[:size]
}

protect_hash :: proc(parts: ..[]u8) -> [32]u8 {
	t: sha2.Context_256
	sha2.init_256(&t)
	for part in parts {
		sha2.update(&t, part)
	}
	out: [32]u8
	sha2.final(&t, out[:])
	return out
}

protect_sign_verify :: proc(dst: []u8, transcript: [32]u8) -> []u8 {
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
	protect_put_u24(dst[1:], 68)
	dst[4], dst[5] = 0x08, 0x07
	dst[6], dst[7] = 0, 64
	ed25519.sign(&key, signed[:], dst[8:8 + ed25519.SIGNATURE_SIZE])
	return dst[:8 + ed25519.SIGNATURE_SIZE]
}

protect_roots :: proc(pool: ^tls.Root_Pool) -> []^x509.Certificate {
	if tls.root_pool_parse(pool, #load("../../../../tests/core/crypto/tls/testdata/root.pem")).kind != .None {
		return nil
	}
	return pool.roots[:pool.count]
}

protect_expect_zero_keys :: proc(t: ^testing.T, h: ^quic.Handshake) {
	testing.expect(t, !h.initial.client.initialized && !h.initial.server.initialized)
	testing.expect(t, crypto.is_zero_constant_time(h.initial.client.key[:]) == 1)
	testing.expect(t, crypto.is_zero_constant_time(h.handshake_secret[:]) == 1)
	testing.expect(t, !h.handshake_read.initialized && !h.handshake_write.initialized)
	testing.expect(t, !h.one_rtt_read.initialized && !h.one_rtt_write.initialized)
	testing.expect(t, h.failed)
}

@(test)
crypto_reassembly_bounds_overlap_and_frames :: proc(t: ^testing.T) {
	storage: [16]u8
	r: quic.Crypto_Reassembly
	testing.expect_value(t, quic.crypto_reassembly_init(&r, storage[:]), .None)
	testing.expect_value(t, quic.crypto_reassembly_write(&r, 3, []u8{4, 5, 6}), .None)
	got, ge := quic.crypto_reassembly_bytes(&r)
	testing.expect(t, ge == .None && len(got) == 0)
	testing.expect_value(t, quic.crypto_reassembly_write(&r, 0, []u8{1, 2, 3}), .None)
	got, ge = quic.crypto_reassembly_bytes(&r)
	testing.expect(t, ge == .None && bytes.equal(got, []u8{1, 2, 3, 4, 5, 6}))
	testing.expect_value(t, quic.crypto_reassembly_write(&r, 2, []u8{3, 4}), .None)
	testing.expect_value(t, quic.crypto_reassembly_write(&r, len(storage), nil), .None)
	testing.expect_value(t, quic.crypto_reassembly_write(&r, u64(len(storage)) + 1, nil), .Cap_Overflow)
	testing.expect(t, r.discarded && crypto.is_zero_constant_time(storage[:]) == 1)
	testing.expect_value(t, quic.crypto_reassembly_write(&r, 0, []u8{1}), .Discarded)

	storage2: [8]u8
	r2: quic.Crypto_Reassembly
	quic.crypto_reassembly_init(&r2, storage2[:])
	testing.expect_value(t, quic.crypto_reassembly_write(&r2, 0, []u8{1, 2, 3, 4}), .None)
	testing.expect_value(t, quic.crypto_reassembly_write(&r2, 1, []u8{9, 9}), .Overlap_Mismatch)
	testing.expect(t, r2.discarded && crypto.is_zero_constant_time(storage2[:]) == 1)

	wide: [128]u8
	r3: quic.Crypto_Reassembly
	quic.crypto_reassembly_init(&r3, wide[:])
	one := [?]u8{0xab}
	for i in 0 ..< quic.CRYPTO_SPAN_CAP {
		testing.expect_value(t, quic.crypto_reassembly_write(&r3, u64(i * 2), one[:]), .None)
	}
	testing.expect_value(t, quic.crypto_reassembly_write(&r3, 80, one[:]), .Span_Exhausted)
	testing.expect(t, r3.discarded)

	frame_storage: [8]u8
	frame := hex(frame_storage[:], "060003010203")
	offset, data, consumed, fe := quic.crypto_frame_decode(frame)
	testing.expect(t, fe == .None && offset == 0 && consumed == 6 && bytes.equal(data, []u8{1, 2, 3}))
	nonminimal := hex(frame_storage[:], "06400001aa")
	offset, data, consumed, fe = quic.crypto_frame_decode(nonminimal)
	testing.expect(t, fe == .None && offset == 0 && consumed == 5 && bytes.equal(data, []u8{0xaa}))
	_, _, _, fe = quic.crypto_frame_decode([]u8{0x01})
	testing.expect_value(t, fe, .Invalid_Input)
	_, _, _, fe = quic.crypto_frame_decode([]u8{0x06, 0x00, 0x05, 0x01})
	testing.expect_value(t, fe, .Truncated)
}

@(test)
rfc9001_retry_and_packet_number_and_a5 :: proc(t: ^testing.T) {
	packet_storage: [36]u8
	packet := hex(packet_storage[:], "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
	odcid_storage: [8]u8
	odcid := hex(odcid_storage[:], "8394c8f03e515708")
	for impl in ([?]aes.Implementation{.Portable, .Hardware}) {
		testing.expect_value(t, quic.retry_integrity_verify(odcid, packet, impl), .None)
		tag: [16]u8
		testing.expect_value(t, quic.retry_integrity_tag(tag[:], odcid, packet[:len(packet) - 16], impl), .None)
		testing.expect(t, bytes.equal(tag[:], packet[len(packet) - 16:]))
	}
	tampered := packet_storage
	tampered[len(packet) - 1] ~= 1
	testing.expect_value(t, quic.retry_integrity_verify(odcid, tampered[:]), .Authentication_Failed)
	long_id: [21]u8
	testing.expect_value(t, quic.retry_integrity_verify(long_id[:], packet), .Invalid_Connection_ID)

	full, pe := quic.packet_number_reconstruct(true, 0xa82f30ea, 0x9b32, 16)
	testing.expect(t, pe == .None && full == 0xa82f9b32)
	cold, ce := quic.packet_number_reconstruct(false, 0, 0xbff4, 24)
	testing.expect(t, ce == .None && cold == 0xbff4)

	secret_storage: [32]u8
	secret := hex(secret_storage[:], "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
	keys: quic.Packet_Keys
	testing.expect_value(t, quic.packet_keys_chacha(&keys, secret), .None)
	defer quic.packet_keys_clear(&keys)
	expect_storage: [32]u8
	testing.expect(t, bytes.equal(keys.key[:], hex(expect_storage[:], "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")))
	testing.expect(t, bytes.equal(keys.iv[:], hex(expect_storage[:], "e0459b3474bdd0e44a41c144")))
	testing.expect(t, bytes.equal(keys.hp[:], hex(expect_storage[:], "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")))
	ku: [32]u8
	testing.expect_value(t, tls.hkdf_expand_label(secret, "quic ku", nil, ku[:]), .None)
	testing.expect(t, bytes.equal(ku[:], hex(expect_storage[:], "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")))
	testing.expect(t, !bytes.equal(keys.key[:], ku[:]))

	published_storage: [21]u8
	published := hex(published_storage[:], "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
	wire_storage := published_storage
	testing.expect_value(t, quic.header_protection_remove(wire_storage[:], &keys, .One_RTT, 0), .None)
	testing.expect(t, bytes.equal(wire_storage[:4], []u8{0x42, 0x00, 0xbf, 0xf4}))
	pn, re := quic.packet_number_reconstruct(true, 654360563, 0xbff4, 24)
	testing.expect(t, re == .None && pn == 654360564)
	plain: [1]u8
	n, oe := quic.payload_open(plain[:], wire_storage[:4], wire_storage[4:], &keys, pn)
	testing.expect(t, oe == .None && n == 1 && plain[0] == 1)

	again := wire_storage
	testing.expect_value(t, quic.header_protection_apply(again[:], &keys, .One_RTT, 0), .None)
	testing.expect(t, bytes.equal(again[:], published))

	sample_bomb: [21]u8
	sample_bomb[0] = 0x42
	for i in 5 ..< 9 {
		sample_bomb[i] = 0xff
	}
	before := sample_bomb
	testing.expect_value(t, quic.header_protection_remove(sample_bomb[:], &keys, .One_RTT, 0), .Header_Protection_Failed)
	testing.expect(t, bytes.equal(sample_bomb[:], before[:]))
}

@(test)
aes_handshake_and_one_rtt_from_tls_labels :: proc(t: ^testing.T) {
	secret_storage: [32]u8
	secret_bytes := hex(secret_storage[:], "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	secret: [32]u8
	copy(secret[:], secret_bytes)
	for level in ([?]tls.Quic_Secret_Level{.Handshake, .Application}) {
		keys: quic.Packet_Keys
		testing.expect_value(t, quic.packet_keys_from_tls(&keys, secret, level), .None)
		expect_storage: [16]u8
		testing.expect(t, bytes.equal(keys.key[:16], hex(expect_storage[:], "1f369613dd76d5467730efcbe3b1a22d")))
		testing.expect(t, bytes.equal(keys.iv[:], hex(expect_storage[:], "fa044b2f42a3fd3b46fb255c")))
		testing.expect(t, bytes.equal(keys.hp[:16], hex(expect_storage[:], "9f50449e04a0e810283a1e9933adedd2")))
		plain := [?]u8{1, 2, 3, 4}
		for impl in ([?]aes.Implementation{.Portable, .Hardware}) {
			packet: [64]u8
			header_len := 0
			kind := quic.Packet_Kind.Handshake
			if level == .Handshake {
				n, _, e := quic.long_header_encode_v1(packet[:], {
					kind = .Handshake,
					packet_number = 7,
					packet_number_length = 1,
					ciphertext_length = 20,
				})
				testing.expect_value(t, e, .None)
				header_len = n
			} else {
				kind = .One_RTT
				n, _, e := quic.short_header_encode_v1(packet[:], {packet_number = 7, packet_number_length = 1})
				testing.expect_value(t, e, .None)
				header_len = n
			}
			sealed, se := quic.payload_seal(packet[header_len:], packet[:header_len], plain[:], &keys, 7, impl)
			testing.expect(t, se == .None && sealed == 20)
			whole := packet[:header_len + sealed]
			saved: [64]u8
			copy(saved[:], whole)
			testing.expect_value(t, quic.header_protection_apply(whole, &keys, kind, 0, impl), .None)
			mask: u8 = 0x0f
			if kind == .One_RTT {
				mask = 0x1f
			}
			testing.expect(t, (whole[0] ~ saved[0]) & ~mask == 0)
			testing.expect_value(t, quic.header_protection_remove(whole, &keys, kind, 0, impl), .None)
			testing.expect(t, bytes.equal(whole[:header_len], saved[:header_len]))
			out: [4]u8
			opened, oe := quic.payload_open(out[:], whole[:header_len], whole[header_len:], &keys, 7, impl)
			testing.expect(t, oe == .None && opened == 4 && bytes.equal(out[:], plain[:]))
		}
		phase: [8]u8
		pn, _, pe := quic.short_header_encode_v1(phase[:], {packet_number = 0, packet_number_length = 1, key_phase = true})
		testing.expect_value(t, pe, .None)
		_, phase_err := quic.payload_seal(phase[pn:], phase[:pn], plain[:], &keys, 0)
		testing.expect_value(t, phase_err, .Key_Update_Disabled)
		reserved := phase
		rn, _, re := quic.short_header_encode_v1(reserved[:], {packet_number = 0, packet_number_length = 1})
		reserved[0] |= 0x08
		_, reserved_err := quic.payload_seal(reserved[rn:], reserved[:rn], plain[:], &keys, 0)
		testing.expect_value(t, reserved_err, .Invalid_Header)

		header := [?]u8{0x44, 0x00}
		boxed: [20]u8
		nonce, ne := quic.packet_nonce(&keys, 0)
		testing.expect_value(t, ne, .None)
		ctx: aes.Context_GCM
		aes.init_gcm(&ctx, keys.key[:16], .Portable)
		aes.seal_gcm(&ctx, boxed[:4], boxed[4:], nonce[:], header[:], plain[:])
		aes.reset_gcm(&ctx)
		opened_phase: [4]u8
		opened_phase[0] = 9
		_, open_phase := quic.payload_open(opened_phase[:], header[:], boxed[:], &keys, 0, .Portable)
		if level == .Handshake {
			testing.expect_value(t, open_phase, .Key_Update_Disabled)
		} else {
			testing.expect_value(t, open_phase, .Authentication_Failed)
		}
		testing.expect(t, crypto.is_zero_constant_time(opened_phase[:]) == 1)
		testing.expect(t, keys.phase == 0 && !keys.update_pending)
		if level == .Application {
			testing.expect(t, bytes.equal(keys.secret[:], secret[:]))
		}
		quic.packet_keys_clear(&keys)
	}
	early, ee := tls.quic_early_packet_keys(secret)
	defer tls.quic_direction_keys_clear(&early)
	testing.expect_value(t, ee.kind, .Early_Data_Disabled)
	testing.expect(t, crypto.is_zero_constant_time(early.key[:]) == 1)

	zero_rtt: [32]u8
	zn, _, ze := quic.long_header_encode_v1(zero_rtt[:], {
		kind = .Zero_RTT,
		packet_number_length = 1,
		ciphertext_length = 20,
	})
	testing.expect_value(t, ze, .None)
	keys: quic.Packet_Keys
	quic.packet_keys_from_tls(&keys, secret, .Handshake)
	defer quic.packet_keys_clear(&keys)
	_, zerr := quic.payload_seal(zero_rtt[zn:], zero_rtt[:zn], []u8{1, 2, 3, 4}, &keys, 0)
	testing.expect_value(t, zerr, .Zero_RTT_Disabled)
}

@(test)
quic_transcript_authentication_discards_keys :: proc(t: ^testing.T) {
	params := [?]u8{1, 2, 3}
	ch_storage, sh_storage: [128]u8
	ch := protect_client_hello(ch_storage[:], []string{"h3"}, params[:], true, nil)
	sh := protect_server_hello(sh_storage[:])
	testing.expect(t, len(ch) == 63 && len(sh) == 90)
	shared: [32]u8
	shared[0] = 0x42
	hs, he := tls.quic_handshake_secrets(shared, ch, sh, params[:])
	defer tls.quic_handshake_keys_clear(&hs)
	testing.expect_value(t, he.kind, .None)
	testing.expect(t, crypto.is_zero_constant_time(hs.handshake_secret[:]) == 0)

	zero: [32]u8
	_, zero_err := tls.quic_handshake_secrets(zero, ch, sh, params[:])
	testing.expect_value(t, zero_err.kind, .Derivation_Failed)
	_, mismatch := tls.quic_handshake_secrets(shared, ch, sh, []u8{1, 2, 4})
	testing.expect_value(t, mismatch.kind, .Transcript_Mismatch)
	alt: [256]u8
	_, missing := tls.quic_handshake_secrets(shared, protect_client_hello(alt[:], []string{"h3"}, nil, false, nil), sh, nil)
	testing.expect_value(t, missing.kind, .Parameters_Missing)
	bad_alpn := protect_client_hello(alt[:], []string{"h2"}, params[:], true, nil)
	_, alpn_err := tls.quic_handshake_secrets(shared, bad_alpn, sh, params[:])
	testing.expect_value(t, alpn_err.kind, .Invalid_ALPN)
	two := protect_client_hello(alt[:], []string{"h3", "h3"}, params[:], true, nil)
	_, two_err := tls.quic_handshake_secrets(shared, two, sh, params[:])
	testing.expect_value(t, two_err.kind, .Invalid_ALPN)
	early_ch := protect_client_hello(alt[:], []string{"h3"}, params[:], true, []u8{0x00, 0x2a, 0x00, 0x00})
	_, early_err := tls.quic_handshake_secrets(shared, early_ch, sh, params[:])
	testing.expect_value(t, early_err.kind, .Early_Data_Disabled)
	big: [1025]u8
	_, big_err := tls.quic_handshake_secrets(shared, ch, sh, big[:])
	testing.expect_value(t, big_err.kind, .Parameters_Oversized)

	ee_storage: [64]u8
	groups := [?]u8{0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d}
	ee := protect_extensions(ee_storage[:], 8, params[:], groups[:])
	cert_storage: [1024]u8
	cert := protect_certificate_message(cert_storage[:])
	testing.expect(t, len(cert) > 13)
	through_cert := protect_hash(ch, sh, ee, cert)
	cv_storage: [80]u8
	cv := protect_sign_verify(cv_storage[:], through_cert)
	through_cv := protect_hash(ch, sh, ee, cert, cv)
	server_finished: [tls.FINISHED_MESSAGE_SIZE]u8
	fn, ferr := tls.finished_encode(server_finished[:], hs.server.secret, through_cv)
	testing.expect(t, ferr == .None && fn == len(server_finished))
	flight_storage: [2048]u8
	at := 0
	at += copy(flight_storage[at:], ee)
	at += copy(flight_storage[at:], cert)
	at += copy(flight_storage[at:], cv)
	at += copy(flight_storage[at:], server_finished[:])
	good_flight: [2048]u8
	flight := good_flight[:copy(good_flight[:], flight_storage[:at])]

	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	roots := protect_roots(pool)
	now := time.unix(1893456000, 0)
	app, client_finished, ae := tls.quic_application_secrets(hs.handshake_secret, ch, sh, flight, "localhost", roots, now, params[:], params[:])
	defer tls.quic_application_keys_clear(&app)
	testing.expect_value(t, ae.kind, .None)
	expect_finished := protect_hash(ch, sh, ee, cert, cv, server_finished[:])
	encoded: [tls.FINISHED_MESSAGE_SIZE]u8
	en, ee2 := tls.finished_encode(encoded[:], hs.client.secret, expect_finished)
	testing.expect(t, ee2 == .None && en == len(encoded) && bytes.equal(encoded[:], client_finished[:]))
	testing.expect(t, crypto.is_zero_constant_time(app.client.key[:]) == 0)

	_, _, wrong_params := tls.quic_application_secrets(hs.handshake_secret, ch, sh, flight, "localhost", roots, now, params[:], []u8{9, 9, 9})
	testing.expect_value(t, wrong_params.kind, .Transcript_Mismatch)
	_, _, wrong_name := tls.quic_application_secrets(hs.handshake_secret, ch, sh, flight, "wrong.example", roots, now, params[:], params[:])
	testing.expect_value(t, wrong_name.kind, .Authentication_Failed)
	testing.expect_value(t, wrong_name.authentication.kind, .Certificate_Chain_Invalid)
	testing.expect_value(t, wrong_name.authentication.x509, .Hostname_Mismatch)
	cv[8] ~= 1
	at = 0
	at += copy(flight_storage[at:], ee)
	at += copy(flight_storage[at:], cert)
	at += copy(flight_storage[at:], cv)
	at += copy(flight_storage[at:], server_finished[:])
	_, _, bad_sig := tls.quic_application_secrets(hs.handshake_secret, ch, sh, flight_storage[:at], "localhost", roots, now, params[:], params[:])
	testing.expect_value(t, bad_sig.kind, .Authentication_Failed)
	testing.expect_value(t, bad_sig.authentication.kind, .Invalid_Signature)
	empty_cert := [?]u8{0x0b, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
	at = 0
	at += copy(flight_storage[at:], ee)
	at += copy(flight_storage[at:], empty_cert[:])
	at += copy(flight_storage[at:], cv)
	at += copy(flight_storage[at:], server_finished[:])
	_, _, empty := tls.quic_application_secrets(hs.handshake_secret, ch, sh, flight_storage[:at], "wrong.example", roots, now, params[:], params[:])
	testing.expect_value(t, empty.kind, .Authentication_Failed)
	testing.expect_value(t, empty.authentication.kind, .Empty_Certificate_List)
	early_ee := protect_extensions(ee_storage[:], 8, params[:], []u8{0x00, 0x2a, 0x00, 0x00})
	at = 0
	at += copy(flight_storage[at:], early_ee)
	at += copy(flight_storage[at:], cert)
	at += copy(flight_storage[at:], cv)
	at += copy(flight_storage[at:], server_finished[:])
	_, _, early_ext := tls.quic_application_secrets(hs.handshake_secret, ch, sh, flight_storage[:at], "localhost", roots, now, params[:], params[:])
	testing.expect_value(t, early_ext.kind, .Early_Data_Disabled)

	initial_buf, handshake_buf, app_buf: [64]u8
	h: quic.Handshake
	defer quic.handshake_fail(&h)
	testing.expect_value(t, quic.handshake_init(&h, .Client, []string{"h3"}, initial_buf[:], handshake_buf[:], app_buf[:]), .None)
	cid_storage: [8]u8
	cid := hex(cid_storage[:], "8394c8f03e515708")
	_, ie := quic.handshake_install_initial(&h, cid)
	testing.expect_value(t, ie, .None)
	initial_packet: [64]u8
	ihl, _, ihe := quic.long_header_encode_v1(initial_packet[:], {
		kind = .Initial,
		destination_id = cid,
		packet_number_length = 1,
		ciphertext_length = 20,
	})
	testing.expect_value(t, ihe, .None)
	initial_plain := [?]u8{9, 8, 7, 6}
	sealed_initial, ise := quic.handshake_payload_seal(&h, initial_packet[ihl:], initial_packet[:ihl], initial_plain[:], .Initial, 0)
	testing.expect(t, ise == .None && sealed_initial == 20)
	initial_out: [4]u8
	opened_initial, ioe := quic.initial_payload_open(initial_out[:], initial_packet[:ihl], initial_packet[ihl:ihl + sealed_initial], &h.initial.client, 0)
	testing.expect(t, ioe == .None && opened_initial == 4 && bytes.equal(initial_out[:], initial_plain[:]))
	testing.expect_value(t, quic.handshake_install_zero_rtt(&h, []u8{1, 2, 3, 4}), .Zero_RTT_Disabled)
	testing.expect(t, !h.have_one_rtt && !h.one_rtt_write.initialized)
	testing.expect_value(t, quic.handshake_accept_client_hello(&h, shared, ch, sh, params[:]).kind, .None)
	testing.expect(t, h.have_handshake && !h.peer_authenticated && !h.initial_discarded)
	testing.expect_value(t, quic.handshake_note_handshake_packet(&h, true), .None)
	testing.expect(t, h.initial_discarded && !h.initial.client.initialized && h.have_handshake)
	testing.expect_value(t, quic.handshake_confirm(&h), .Unauthenticated)
	testing.expect(t, h.have_handshake)
	header: [32]u8
	hn, _, he2 := quic.short_header_encode_v1(header[:], {packet_number_length = 1})
	testing.expect_value(t, he2, .None)
	_, unauth := quic.handshake_payload_seal(&h, header[hn:], header[:hn], []u8{1, 2, 3, 4}, .One_RTT, 0)
	testing.expect_value(t, unauth, .Unauthenticated)
	testing.expect_value(t, quic.handshake_authenticate_server(&h, ch, sh, flight, "localhost", roots, now, params[:]).kind, .None)
	testing.expect(t, h.peer_authenticated && h.have_one_rtt && !h.handshake_complete)
	_, still := quic.handshake_payload_seal(&h, header[hn:], header[:hn], []u8{1, 2, 3, 4}, .One_RTT, 0)
	testing.expect_value(t, still, .Unauthenticated)
	finished_view, fe := quic.handshake_client_finished(&h)
	testing.expect(t, fe == .None && bytes.equal(finished_view, client_finished[:]))
	testing.expect_value(t, quic.handshake_advance_one_rtt(&h), .Unauthenticated)
	testing.expect(t, h.one_rtt_write.phase == 0 && !h.one_rtt_write.update_pending)
	testing.expect_value(t, quic.handshake_note_finished_sent(&h), .None)
	testing.expect(t, h.handshake_complete)
	testing.expect_value(t, quic.handshake_confirm_one_rtt(&h), .Invalid_State)
	one_rtt_plain := [?]u8{1, 2, 3, 4}
	sealed, seal_err := quic.handshake_payload_seal(&h, header[hn:], header[:hn], one_rtt_plain[:], .One_RTT, 0)
	testing.expect(t, seal_err == .None && sealed == 20)
	one_rtt_out: [4]u8
	one_rtt_n, one_rtt_open := quic.payload_open(one_rtt_out[:], header[:hn], header[hn:hn + sealed], &h.one_rtt_write, 0)
	testing.expect(t, one_rtt_open == .None && one_rtt_n == 4 && bytes.equal(one_rtt_out[:], one_rtt_plain[:]))
	testing.expect_value(t, quic.handshake_confirm(&h), .None)
	testing.expect(t, h.handshake_discarded && !h.handshake_read.initialized && h.have_one_rtt)
	testing.expect(t, crypto.is_zero_constant_time(h.handshake_secret[:]) == 1)
	_, after := quic.handshake_payload_seal(&h, header[hn:], header[:hn], one_rtt_plain[:], .Handshake, 0)
	testing.expect_value(t, after, .Invalid_Keys)
	_, still_rtt := quic.handshake_payload_seal(&h, header[hn:], header[:hn], one_rtt_plain[:], .One_RTT, 0)
	testing.expect_value(t, still_rtt, .None)
	read_secret := h.one_rtt_read.secret
	testing.expect_value(t, quic.handshake_advance_one_rtt(&h), .None)
	testing.expect(t, h.one_rtt_write.phase == 1 && h.one_rtt_write.update_pending)
	testing.expect(t, h.one_rtt_read.phase == 0 && !h.one_rtt_read.update_pending && h.one_rtt_read.secret == read_secret)
	testing.expect_value(t, quic.handshake_advance_one_rtt(&h), .Invalid_State)
	testing.expect(t, h.one_rtt_write.phase == 1 && h.one_rtt_write.update_pending)
	testing.expect_value(t, quic.handshake_confirm_one_rtt(&h), .None)
	testing.expect(t, h.one_rtt_write.phase == 1 && !h.one_rtt_write.update_pending)
	phase_header: [32]u8
	ph, _, phe := quic.short_header_encode_v1(phase_header[:], {packet_number = 1, packet_number_length = 1, key_phase = true})
	testing.expect_value(t, phe, .None)
	phase_sealed, phase_se := quic.handshake_payload_seal(&h, phase_header[ph:], phase_header[:ph], one_rtt_plain[:], .One_RTT, 1)
	testing.expect(t, phase_se == .None && phase_sealed == 20)
	phase_out: [4]u8
	phase_n, phase_oe := quic.payload_open(phase_out[:], phase_header[:ph], phase_header[ph:ph + phase_sealed], &h.one_rtt_write, 1)
	testing.expect(t, phase_oe == .None && phase_n == 4 && bytes.equal(phase_out[:], one_rtt_plain[:]))
	testing.expect(t, h.one_rtt_write.phase == 1 && !h.one_rtt_write.update_pending)

	testing.expect_value(t, quic.handshake_ingest_crypto(&h, .One_RTT, 2, []u8{'c'}), .None)
	testing.expect_value(t, quic.handshake_ingest_crypto(&h, .One_RTT, 0, []u8{'a', 'b'}), .None)
	stream, stream_err := quic.handshake_crypto_bytes(&h, .One_RTT)
	testing.expect(t, stream_err == .None && bytes.equal(stream, []u8{'a', 'b', 'c'}))
	testing.expect_value(t, quic.handshake_ingest_crypto(&h, .One_RTT, 0, []u8{'z'}), .Overlap_Mismatch)
	protect_expect_zero_keys(t, &h)
}

@(test)
handshake_discard_directions_and_alpn :: proc(t: ^testing.T) {
	cbufs, sbufs: [3][8]u8
	client, server: quic.Handshake
	defer quic.handshake_fail(&client)
	defer quic.handshake_fail(&server)
	testing.expect_value(t, quic.handshake_init(&client, .Client, []string{"h3"}, cbufs[0][:], cbufs[1][:], cbufs[2][:]), .None)
	testing.expect_value(t, quic.handshake_init(&server, .Server, []string{"h3"}, sbufs[0][:], sbufs[1][:], sbufs[2][:]), .None)
	cid := [?]u8{1, 2, 3, 4}
	_, ce := quic.handshake_install_initial(&client, cid[:])
	_, se := quic.handshake_install_initial(&server, cid[:])
	testing.expect(t, ce == .None && se == .None)
	testing.expect_value(t, quic.handshake_note_handshake_packet(&client, false), .None)
	testing.expect(t, client.have_initial)
	testing.expect_value(t, quic.handshake_note_handshake_packet(&server, true), .None)
	testing.expect(t, server.have_initial)
	testing.expect_value(t, quic.handshake_note_handshake_packet(&server, false), .None)
	testing.expect(t, server.initial_discarded && !server.initial.server.initialized)

	rejected: quic.Handshake
	testing.expect_value(t, quic.handshake_init(&rejected, .Client, []string{"h2"}, cbufs[0][:], cbufs[1][:], cbufs[2][:]), .Invalid_ALPN)
	testing.expect(t, rejected.failed && rejected.crypto[0].buf == nil)
	testing.expect_value(t, quic.handshake_init(&rejected, .Client, []string{"h3", "h3"}, nil, nil, nil), .Invalid_ALPN)
	testing.expect_value(t, quic.handshake_init(&rejected, .Client, nil, nil, nil, nil), .Invalid_ALPN)

	small: [4]u8
	bounded: quic.Handshake
	defer quic.handshake_fail(&bounded)
	testing.expect_value(t, quic.handshake_init(&bounded, .Client, []string{"h3"}, small[:], small[:], small[:]), .None)
	_, be := quic.handshake_install_initial(&bounded, cid[:])
	testing.expect_value(t, be, .None)
	testing.expect_value(t, quic.handshake_ingest_crypto(&bounded, .Initial, 0, []u8{1, 2, 3, 4, 5}), .Cap_Overflow)
	protect_expect_zero_keys(t, &bounded)

	space: quic.Handshake
	level_buf: [32]u8
	defer quic.handshake_fail(&space)
	quic.handshake_init(&space, .Client, []string{"h3"}, level_buf[:], level_buf[:], level_buf[:])
	testing.expect_value(t, quic.handshake_note_authenticated_pn(&space, .One_RTT, 0xa82f30ea), .None)
	got, ge := quic.handshake_reconstruct_pn(&space, .One_RTT, 0x9b32, 16)
	testing.expect(t, ge == .None && got == 0xa82f9b32)
	quic.handshake_fail(&space)
	_, failed := quic.handshake_reconstruct_pn(&space, .One_RTT, 0x9b32, 16)
	testing.expect_value(t, failed, .Invalid_Keys)
}

@(test)
one_rtt_key_update :: proc(t: ^testing.T) {
	plain := [?]u8{1, 2, 3, 4}
	secret_storage: [32]u8
	secret_bytes := hex(secret_storage[:], "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	traffic: [32]u8
	copy(traffic[:], secret_bytes)

	for impl in ([?]aes.Implementation{.Portable, .Hardware}) {
		write, read: quic.Packet_Keys
		defer quic.packet_keys_clear(&write)
		defer quic.packet_keys_clear(&read)
		testing.expect_value(t, quic.packet_keys_from_tls(&write, traffic, .Application), .None)
		read = write
		hp := write.hp
		generation := write.secret
		testing.expect_value(t, quic.packet_keys_advance(&write), .None)
		testing.expect(t, write.phase == 1 && write.update_pending && write.hp == hp && write.secret != generation)
		testing.expect_value(t, quic.packet_keys_advance(&write), .Key_Update_Disabled)
		testing.expect(t, write.phase == 1 && write.update_pending && write.secret != generation && write.hp == hp)

		packet: [64]u8
		hn, _, he := quic.short_header_encode_v1(packet[:], {packet_number = 0, packet_number_length = 1, key_phase = true})
		testing.expect_value(t, he, .None)
		sealed, se := quic.payload_seal(packet[hn:], packet[:hn], plain[:], &write, 0, impl)
		testing.expect(t, se == .None && sealed == 20)
		testing.expect_value(t, quic.header_protection_apply(packet[:hn + sealed], &write, .One_RTT, 0, impl), .None)
		testing.expect_value(t, quic.header_protection_remove(packet[:hn + sealed], &read, .One_RTT, 0, impl), .None)
		out: [4]u8
		n, oe := quic.payload_open(out[:], packet[:hn], packet[hn:hn + sealed], &read, 0, impl)
		testing.expect(t, oe == .None && n == 4 && bytes.equal(out[:], plain[:]))
		testing.expect(t, read.phase == 1 && read.update_pending && read.secret == write.secret && read.hp == hp)
		testing.expect(t, bytes.equal(read.key[:16], write.key[:16]) && read.iv == write.iv)

		skip: [32]u8
		sn, _, ske := quic.short_header_encode_v1(skip[:], {packet_number = 1, packet_number_length = 1})
		testing.expect_value(t, ske, .None)
		bogus: [20]u8
		bogus[0] = 9
		skipped: [4]u8
		skipped[0] = 9
		saved_secret := read.secret
		saved_key := read.key
		saved_iv := read.iv
		_, skip_err := quic.payload_open(skipped[:], skip[:sn], bogus[:], &read, 1, impl)
		testing.expect_value(t, skip_err, .Key_Update_Disabled)
		testing.expect(t, crypto.is_zero_constant_time(skipped[:]) == 1)
		testing.expect(t, read.phase == 1 && read.update_pending && read.secret == saved_secret && read.key == saved_key && read.iv == saved_iv && read.hp == hp)

		testing.expect_value(t, quic.packet_keys_confirm_update(&read), .None)
		testing.expect(t, read.phase == 1 && !read.update_pending && read.secret == saved_secret)
		stale_header := [?]u8{0x40, 0x01}
		stale_box: [20]u8
		stale_nonce, sne := quic.packet_nonce(&write, 1)
		testing.expect_value(t, sne, .None)
		ctx: aes.Context_GCM
		aes.init_gcm(&ctx, write.key[:16], impl)
		aes.seal_gcm(&ctx, stale_box[:4], stale_box[4:], stale_nonce[:], stale_header[:], plain[:])
		aes.reset_gcm(&ctx)
		stale_out: [4]u8
		stale_out[0] = 9
		_, stale_err := quic.payload_open(stale_out[:], stale_header[:], stale_box[:], &read, 1, impl)
		testing.expect_value(t, stale_err, .Authentication_Failed)
		testing.expect(t, crypto.is_zero_constant_time(stale_out[:]) == 1)
		testing.expect(t, read.phase == 1 && !read.update_pending && read.secret == saved_secret && read.key == saved_key && read.iv == saved_iv)

		testing.expect_value(t, quic.packet_keys_confirm_update(&write), .None)
		testing.expect_value(t, quic.packet_keys_advance(&write), .None)
		testing.expect(t, write.phase == 0 && write.update_pending && write.hp == hp && write.secret != saved_secret)
		testing.expect_value(t, quic.packet_keys_confirm_update(&write), .None)
		testing.expect_value(t, quic.packet_keys_confirm_update(&write), .Key_Update_Disabled)
	}

	handshake_keys: quic.Packet_Keys
	defer quic.packet_keys_clear(&handshake_keys)
	testing.expect_value(t, quic.packet_keys_from_tls(&handshake_keys, traffic, .Handshake), .None)
	testing.expect_value(t, quic.packet_keys_advance(&handshake_keys), .Key_Update_Disabled)
	testing.expect(t, handshake_keys.phase == 0 && !handshake_keys.update_pending)
	bare: quic.Packet_Keys
	testing.expect_value(t, quic.packet_keys_advance(&bare), .Key_Update_Disabled)
	testing.expect_value(t, quic.packet_keys_confirm_update(&bare), .Key_Update_Disabled)

	a5_storage: [32]u8
	a5 := hex(a5_storage[:], "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
	chacha: quic.Packet_Keys
	defer quic.packet_keys_clear(&chacha)
	testing.expect_value(t, quic.packet_keys_chacha(&chacha, a5), .None)
	a5_hp := chacha.hp
	a5_key := chacha.key
	testing.expect_value(t, quic.packet_keys_advance(&chacha), .None)
	expect_storage: [32]u8
	ku := hex(expect_storage[:], "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
	testing.expect(t, bytes.equal(chacha.secret[:], ku))
	testing.expect(t, chacha.hp == a5_hp && chacha.phase == 1 && chacha.update_pending)
	testing.expect(t, chacha.key != a5_key)
	ku_key, ku_hp: [32]u8
	ku_iv: [12]u8
	testing.expect_value(t, tls.hkdf_expand_label(chacha.secret[:], "quic key", nil, ku_key[:]), .None)
	testing.expect_value(t, tls.hkdf_expand_label(chacha.secret[:], "quic iv", nil, ku_iv[:]), .None)
	testing.expect_value(t, tls.hkdf_expand_label(chacha.secret[:], "quic hp", nil, ku_hp[:]), .None)
	testing.expect(t, bytes.equal(chacha.key[:], ku_key[:]) && chacha.iv == ku_iv)
	testing.expect(t, !bytes.equal(chacha.hp[:], ku_hp[:]))
	testing.expect_value(t, quic.packet_keys_advance(&chacha), .Key_Update_Disabled)
	testing.expect(t, bytes.equal(chacha.secret[:], ku) && chacha.phase == 1 && chacha.hp == a5_hp)
	testing.expect_value(t, quic.packet_keys_confirm_update(&chacha), .None)
	testing.expect_value(t, quic.packet_keys_advance(&chacha), .None)
	testing.expect(t, chacha.phase == 0 && chacha.update_pending && chacha.hp == a5_hp && !bytes.equal(chacha.secret[:], ku))
}
