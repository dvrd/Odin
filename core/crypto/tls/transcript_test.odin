package tls

import "core:crypto/sha2"
import "core:encoding/hex"
import "core:mem"
import "core:testing"
import "core:fmt"

// RFC 8448 section 3, exact handshake bytes, without record headers.
// https://www.rfc-editor.org/rfc/rfc8448.html#section-3
TRANSCRIPT_TEST_CH :: "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
TRANSCRIPT_TEST_SH :: "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
TRANSCRIPT_TEST_FLIGHT :: "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"

transcript_test_decode :: proc(s: string) -> []u8 {
	bytes, err := hex.decode(transmute([]u8)s)
	assert(err == nil)
	return bytes
}

transcript_test_hash :: proc(s: string) -> (hash: [32]u8) {
	bytes := transcript_test_decode(s)
	assert(len(bytes) == 32)
	copy(hash[:], bytes)
	delete(bytes)
	return
}

@(test)
transcript_rfc8448_and_partitions :: proc(t: ^testing.T) {
	ch := transcript_test_decode(TRANSCRIPT_TEST_CH)
	defer delete(ch)
	sh := transcript_test_decode(TRANSCRIPT_TEST_SH)
	defer delete(sh)
	flight := transcript_test_decode(TRANSCRIPT_TEST_FLIGHT)
	defer delete(flight)
	expected_hello := transcript_test_hash("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
	expected_finished := transcript_test_hash("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
	base: Handshake_Transcript
	transcript_init(&base)
	transcript_update(&base, ch)
	transcript_update(&base, sh)
	testing.expect_value(t, transcript_snapshot(&base), expected_hello)
	// Every two-piece partition crosses all headers, bodies and SHA blocks.
	for split in 0 ..= len(flight) {
		branch := base
		transcript_update(&branch, flight[:split])
		_ = transcript_snapshot(&branch)
		transcript_update(&branch, nil)
		transcript_update(&branch, flight[split:])
		testing.expect_value(t, transcript_snapshot(&branch), expected_finished)
		testing.expect_value(t, transcript_snapshot(&base), expected_hello)
	}
	for width in 1 ..= 67 {
		branch: Handshake_Transcript
		transcript_init(&branch)
		for message in ([2][]u8{ch, sh}) {
			for at := 0; at < len(message); at += width {
				transcript_update(&branch, message[at:min(at + width, len(message))])
			}
		}
		testing.expect_value(t, transcript_snapshot(&branch), expected_hello)
		for at := 0; at < len(flight); at += width {
			transcript_update(&branch, flight[at:min(at + width, len(flight))])
		}
		testing.expect_value(t, transcript_snapshot(&branch), expected_finished)
	}
}

@(test)
transcript_rfc8448_secrets_and_finished :: proc(t: ^testing.T) {
	shared := transcript_test_hash("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
	hello_hash := transcript_test_hash("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
	server_finished_hash := transcript_test_hash("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
	hs, err := handshake_secrets_derive_from_hash(shared, hello_hash)
	testing.expect_value(t, err, .None)
	testing.expect_value(
		t,
		hs.handshake_secret,
		transcript_test_hash("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"),
	)
	testing.expect_value(
		t,
		hs.client_traffic_secret,
		transcript_test_hash("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"),
	)
	testing.expect_value(
		t,
		hs.server_traffic_secret,
		transcript_test_hash("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
	)
	ch := transcript_test_decode(TRANSCRIPT_TEST_CH)
	defer delete(ch)
	sh := transcript_test_decode(TRANSCRIPT_TEST_SH)
	defer delete(sh)
	wrapped, wrapped_error := handshake_secrets_derive(shared, ch, sh)
	testing.expect_value(t, wrapped_error, .None)
	testing.expect_value(t, wrapped, hs)
	app := application_secrets_derive(hs.handshake_secret, server_finished_hash)
	testing.expect_value(
		t,
		app.master_secret,
		transcript_test_hash("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"),
	)
	testing.expect_value(
		t,
		app.client_traffic_secret,
		transcript_test_hash("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"),
	)
	testing.expect_value(
		t,
		app.server_traffic_secret,
		transcript_test_hash("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"),
	)
	flight := transcript_test_decode(TRANSCRIPT_TEST_FLIGHT)
	defer delete(flight)
	tr: Handshake_Transcript
	transcript_init(&tr)
	transcript_update(&tr, ch)
	transcript_update(&tr, sh)
	transcript_update(&tr, flight[:len(flight) - 36])
	testing.expect_value(
		t,
		engine_finished_verify(flight[len(flight) - 36:], hs.server_traffic_secret, transcript_snapshot(&tr)),
		.None,
	)
	testing.expect_value(
		t,
		engine_finished_verify(flight[len(flight) - 36:], hs.client_traffic_secret, transcript_snapshot(&tr)),
		.Verification_Failed,
	)
	testing.expect_value(
		t,
		finished_verify_data(hs.client_traffic_secret, server_finished_hash),
		transcript_test_hash("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"),
	)
	testing.expect(t, application_secrets_derive(hs.handshake_secret, hello_hash) != app)
}

@(test)
transcript_retry_context_and_allocator_independence :: proc(t: ^testing.T) {
	ch := transcript_test_decode(TRANSCRIPT_TEST_CH)
	defer delete(ch)
	sh := transcript_test_decode(TRANSCRIPT_TEST_SH)
	defer delete(sh)
	hrr := transcript_test_decode(
		"020000340303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c00130100000c002b00020304003300020017",
	); defer delete(hrr)
	tr: Handshake_Transcript
	transcript_init(&tr)
	transcript_update(&tr, ch)
	first_hash := transcript_snapshot(&tr)
	message := transcript_message_hash(first_hash)
	testing.expect(t, message[0] == 254 && message[1] == 0 && message[2] == 0 && message[3] == 32)
	transcript_retry(&tr)
	// Independent SHA invocation over the explicit RFC synthetic framing.
	independent: sha2.Context_256
	sha2.init_256(&independent)
	sha2.update(&independent, message[:])
	sha2.update(&independent, hrr)
	sha2.update(&independent, ch)
	sha2.update(&independent, sh)
	expected: [32]u8
	sha2.final(&independent, expected[:])
	transcript_update(&tr, hrr)
	transcript_update(&tr, ch)
	transcript_update(&tr, sh)
	testing.expect_value(t, transcript_snapshot(&tr), expected)
	testing.expect_value(
		t,
		expected,
		transcript_test_hash("eccd5e0a0b1a57121913d6038c1ab437ad7d702c6176219807f6ab670c266a12"),
	)
	prefix: [92]u8
	copy(prefix[:36], message[:])
	copy(prefix[36:], hrr)
	wrapped, wrap_error := handshake_secrets_derive(first_hash, ch, sh, prefix[:])
	from_hash, hash_error := handshake_secrets_derive_from_hash(first_hash, expected)
	testing.expect_value(t, wrap_error, .None)
	testing.expect_value(t, hash_error, .None)
	testing.expect_value(t, wrapped, from_hash)
	server := certificate_verify_input(first_hash, true)
	client := certificate_verify_input(first_hash, false)
	for i in 0 ..< 64 do testing.expect_value(t, server[i], u8(32))
	testing.expect_value(t, string(server[64:97]), SERVER_CERTIFICATE_VERIFY_CONTEXT)
	testing.expect_value(t, server[97], u8(0))
	testing.expect_value(t, string(server[98:]), string(first_hash[:]))
	testing.expect(t, server != client)
	server_digest := certificate_verify_digest(first_hash, true)
	testing.expect_value(
		t,
		server_digest,
		transcript_test_hash("831def041e65ba4b71c1b4307f4cce819d2e774a414812cb83031fefa5b629fb"),
	)
	testing.expect(t, server_digest != certificate_verify_digest(first_hash, false))
	// These helpers cannot depend on an allocation succeeding, including HKDF.
	before := transcript_snapshot(&tr)
	{
		context.allocator = mem.panic_allocator()
		context.temp_allocator = mem.panic_allocator()
		for _ in 0 ..< 1000 {
			branch := tr
			transcript_update(&branch, nil)
			assert(transcript_snapshot(&branch) == before)
			assert(certificate_verify_digest(first_hash, true) == server_digest)
			_, err := handshake_secrets_derive_from_hash(first_hash, before)
			assert(err == .None)
		}
		transcript_init(&tr)
		transcript_update(&tr, ch)
		transcript_retry(&tr)
		transcript_update(&tr, hrr)
		transcript_update(&tr, ch)
		transcript_update(&tr, sh)
		assert(transcript_snapshot(&tr) == before)
		hs, err := handshake_secrets_derive(first_hash, ch, sh)
		assert(err == .None)
		app := application_secrets_derive(hs.handshake_secret, before)
		_ = finished_verify_data(hs.client_traffic_secret, before)
		_ = app
	}
	fmt.printf(
		"TLS transcript size=%d, handshake secrets=%d, application secrets=%d bytes\n",
		size_of(Handshake_Transcript),
		size_of(Handshake_Secrets),
		size_of(Application_Secrets),
	)
}

@(test)
transcript_public_validation_order :: proc(t: ^testing.T) {
	ch := []u8{1, 0, 0, 0}
	sh := []u8{2, 0, 0, 0}
	_, err := handshake_secrets_derive({}, nil, nil)
	testing.expect_value(t, err, .Invalid_Client_Hello)
	_, err = handshake_secrets_derive({}, ch, nil)
	testing.expect_value(t, err, .Invalid_Server_Hello)
	zero, zero_error := handshake_secrets_derive({}, ch, sh)
	testing.expect_value(t, zero_error, .Invalid_Shared_Secret)
	testing.expect_value(t, zero, Handshake_Secrets{})
}
