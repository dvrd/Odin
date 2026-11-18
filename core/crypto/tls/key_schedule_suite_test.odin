package tls

import "core:crypto/aead"
import "core:crypto/hash"
import "core:encoding/hex"
import "core:testing"

// The engine's schedule path (upstream's generic schedule driven the way the
// client engine drives it) for the suites beyond TLS_AES_128_GCM_SHA256.
// RFC 8448 has no SHA-384 or ChaCha20-Poly1305 trace; the expected values come
// from an independent HKDF-Expand-Label implementation (Python hmac/hashlib)
// over this fixed transcript: CH = 01000004 11111111, SH = 02000004 22222222,
// EE = 080000020000, shared secret = 01..20. RFC 8448's own trace is covered
// for TLS_AES_128_GCM_SHA256 in transcript_test.odin.
Schedule_Suite_Vector :: struct {
	suite:                    Cipher_Suite,
	client_handshake:         string,
	server_handshake:         string,
	server_finished:          string,
	client_finished:          string,
	client_application:       string,
	server_application:       string,
	resumption_master:        string,
	client_application_next:  string,
	client_handshake_key:     string,
	client_handshake_iv:      string,
	client_application_key:   string,
	client_application_iv:    string,
}

SCHEDULE_SUITE_VECTORS := [?]Schedule_Suite_Vector {
	{
		suite                   = .TLS_AES_256_GCM_SHA384,
		client_handshake        = "72af2a03aab185c78a6a1b230eb11e67c075b15cd37bd6b29c3c13eff0c1c7e87a51177294062567853ba2f1ca2affdb",
		server_handshake        = "a10ccdc31049ea0ae3ece76205ef251682964d9fc5d901facaa71d1cf06948182b249648c80bc13ed77dd6f0b126cbb9",
		server_finished         = "6f27ce11688da3eef528341aaabf2552a755e9eedf8b75b748f39eff6567cd83470fbe3575b5d006e4573fa04f5341c8",
		client_finished         = "941719ce1d4faedcb183ff9fc34df4874334bcd24c90aaf09313957740446d766e6d770dc136f6711c7f83b1a29fab8a",
		client_application      = "095be6ea206cd307c19ef2276d558c498b37cc44721b54dc6f893e72cda53fe75d0966aeb026d4e82882791a48151c49",
		server_application      = "9e70c3bf1554eef977eecef26377154f4eac297f452d639624ff809d993f4816188c4083612336701045da38d946a2c9",
		resumption_master       = "5d13122a38e15f68332fea5fca369befa9aede7446df8c797563cd7db945dcda00bf7a58f900a12e7156422a967b9c9f",
		client_application_next = "d7e6ca96e01dcf6a028f37d0d3df4af1fdb73b316f6466c749f2797412ed113d2227ee8fcc40f5d0f6321627b107eec2",
		client_handshake_key    = "4cb79662b1008b82942b6bf68d9cb045dea3358ef6eeae446252e4fa3ab64f59",
		client_handshake_iv     = "1cb815ea5def4011274f0eca",
		client_application_key  = "c4e55a8a28c7411cb8bf40877bc6b5ea1bf240ba8b9d36a80d02eb5e91ec15cb",
		client_application_iv   = "7b21d05def23108c73462c8a",
	},
	{
		suite                   = .TLS_CHACHA20_POLY1305_SHA256,
		client_handshake        = "4a0792ebb9779b3cb2f4ede4eadb4f88a7bb84a647a59f38a2cb0e175578d865",
		server_handshake        = "cedeb21f4f0af8cff3e4e10b1a29c686eee8df31ab808cb29ef18bb6e50a0d79",
		server_finished         = "d979655c5d3961606db1cae6e1695639c35a16fd70cc84d1516ea484a38d0e5b",
		client_finished         = "17d65a8434748369e3ef4a2d96be63cdf266061c143808b85eb9b2a35f7d7e8f",
		client_application      = "732b860de590d406e867a4ad625aabf141942cd21bdc64172794bb45ce14f87b",
		server_application      = "29a88ef521267af2d0f821099c47b647067d63d255957ee5c9d70e3968d94367",
		resumption_master       = "f3fa745cdf8a089a76a1c1c400674da9b8c87576ad6a75a7d4f95b96fa246332",
		client_application_next = "d2af0ca3b9529cb277b56bd6e3595af615e2ccb7e13e42c530024a9b8172acf6",
		client_handshake_key    = "491111cf361cdc4ab3dc33fbbb54709ec9b064a57f0fa104e5734d817187730b",
		client_handshake_iv     = "8530ac50b6911c39ef7748af",
		client_application_key  = "6356ef38ae2155b38389d2511fee48e585b0dacc7631a154363bb31cd2e787d3",
		client_application_iv   = "913ed1ebee125ecc21e34a14",
	},
}

schedule_suite_expect :: proc(t: ^testing.T, actual: []u8, expected: string, loc := #caller_location) {
	text := hex.encode(actual)
	defer delete(text)

	testing.expect_value(t, string(text), expected, loc)
}

// A protection keyed directly from an expected key and IV: the peer's view.
schedule_suite_peer :: proc(peer: ^Record_Protection, suite: Cipher_Suite, key_hex, iv_hex: string) {
	key, key_ok := hex.decode(transmute([]u8)key_hex)
	defer delete(key)
	iv, iv_ok := hex.decode(transmute([]u8)iv_hex)
	defer delete(iv)
	assert(key_ok && iv_ok)

	aead.init(&peer.ctx, CIPHER_SUITE_AEAD[suite], key)
	copy(peer.iv[:], iv)
	peer.initialized = true
}

schedule_suite_roundtrip :: proc(t: ^testing.T, sender, peer: ^Record_Protection, loc := #caller_location) {
	body := [?]u8{1, 2, 3, 4, 5}
	wire: [RECORD_HEADER_SIZE + 64]u8
	plain: [64]u8

	written, seal_error := record_seal(sender, wire[:], .Application_Data, body[:])
	testing.expect_value(t, seal_error, Record_Protection_Error.None, loc)

	kind, opened, open_error := record_open(peer, plain[:], wire[:written])
	testing.expect_value(t, open_error, Record_Protection_Error.None, loc)
	testing.expect_value(t, kind, TLS_Content_Type.Application_Data, loc)
	testing.expect_value(t, len(opened), len(body), loc)
}

@(test)
schedule_suites_match_independent_vectors :: proc(t: ^testing.T) {
	client_hello := [?]u8{1, 0, 0, 4, 0x11, 0x11, 0x11, 0x11}
	server_hello := [?]u8{2, 0, 0, 4, 0x22, 0x22, 0x22, 0x22}
	extensions := [?]u8{8, 0, 0, 2, 0, 0}
	shared: [32]u8
	for i in 0 ..< len(shared) {
		shared[i] = u8(i + 1)
	}

	for vector in SCHEDULE_SUITE_VECTORS {
		algorithm := CIPHER_SUITE_HASH[vector.suite]
		size := hash.DIGEST_SIZES[algorithm]

		keys: Handshake_Keys
		defer clear_handshake_keys(&keys)
		schedule_init(&keys, algorithm)
		update_handshake_keys(&keys, shared[:])

		transcript: Handshake_Transcript
		transcript_init(&transcript, algorithm)
		transcript_update(&transcript, client_hello[:])
		transcript_update(&transcript, server_hello[:])

		secrets: Connection_Secrets
		defer clear_connection_secrets(&secrets)
		init_connection_secrets(&secrets, &keys, &transcript, CIPHER_SUITE_AEAD[vector.suite], true, context.allocator, nil)
		schedule_suite_expect(t, secrets.client_secret[:size], vector.client_handshake)
		schedule_suite_expect(t, secrets.server_secret[:size], vector.server_handshake)
		schedule_suite_expect(t, secrets.client_aead.iv[:], vector.client_handshake_iv)

		send, peer: Record_Protection
		record_protection_init(&send, &secrets.client_aead)
		schedule_suite_peer(&peer, vector.suite, vector.client_handshake_key, vector.client_handshake_iv)
		schedule_suite_roundtrip(t, &send, &peer)

		// Server Finished verifies over CH..EE, then joins the transcript.
		transcript_update(&transcript, extensions[:])
		finished_storage: [MAX_FINISHED_MESSAGE_SIZE]u8
		server_finished := finished_storage[:4 + size]
		finished_header_encode(server_finished, size)
		derive_connection_finished(&secrets, &transcript, server_finished[4:], false)
		schedule_suite_expect(t, server_finished[4:], vector.server_finished)
		testing.expect(t, verify_connection_finished(&secrets, &transcript, server_finished[4:], true))
		server_finished[4] ~= 1
		testing.expect(t, !verify_connection_finished(&secrets, &transcript, server_finished[4:], true))
		server_finished[4] ~= 1
		transcript_update(&transcript, server_finished)

		client_storage: [MAX_FINISHED_MESSAGE_SIZE]u8
		client_finished := client_storage[:4 + size]
		finished_header_encode(client_finished, size)
		derive_connection_finished(&secrets, &transcript, client_finished[4:], true)
		schedule_suite_expect(t, client_finished[4:], vector.client_finished)

		through_client := transcript
		transcript_update(&through_client, client_finished)
		digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
		digest := transcript_hash(&through_client, digest_storage[:])

		application := transcript
		finished_connection_secrets(&secrets, &keys, &application)
		schedule_suite_expect(t, secrets.client_secret[:size], vector.client_application)
		schedule_suite_expect(t, secrets.server_secret[:size], vector.server_application)
		schedule_suite_expect(t, secrets.client_aead.iv[:], vector.client_application_iv)

		resumption: [MAX_TRANSCRIPT_HASH_SIZE]u8
		schedule_derive_secret(&keys, "res master", digest, resumption[:size])
		schedule_suite_expect(t, resumption[:size], vector.resumption_master)

		state: Application_State
		defer application_clear(&state)
		application_init(&state, &secrets, resumption[:size])
		testing.expect(t, state.have_resumption)
		testing.expect_value(t, state.resumption_secret_size, size)

		application_peer: Record_Protection
		schedule_suite_peer(&application_peer, vector.suite, vector.client_application_key, vector.client_application_iv)
		schedule_suite_roundtrip(t, &state.send, &application_peer)
		testing.expect_value(t, record_protection_limit(&state.send), AEAD_REKEY_SEQ[CIPHER_SUITE_AEAD[vector.suite]])

		update_connection_secret(&state.secrets, true)
		schedule_suite_expect(t, state.secrets.client_secret[:size], vector.client_application_next)
		record_protection_init(&state.send, &state.secrets.client_aead)
		testing.expect_value(t, state.send.seq, u64(0))

		// By-secret installation derives the same generation.
		next: Record_Protection
		record_protection_init(&next, vector.suite, state.secrets.client_secret[:size])
		schedule_suite_roundtrip(t, &state.send, &next)
	}
}

@(test)
schedule_message_hash_follows_the_suite_hash :: proc(t: ^testing.T) {
	first := [?]u8{1, 0, 0, 1, 0x33}

	for algorithm in ([?]hash.Algorithm{.SHA256, .SHA384}) {
		size := hash.DIGEST_SIZES[algorithm]

		transcript: Handshake_Transcript
		transcript_init(&transcript, algorithm)
		transcript_update(&transcript, first[:])
		expected_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
		expected := transcript_hash(&transcript, expected_storage[:])
		transcript_retry(&transcript)

		message_storage: [MAX_MESSAGE_HASH_SIZE]u8
		message := transcript_message_hash_encode(message_storage[:], expected)
		testing.expect_value(t, len(message), 4 + size)
		testing.expect_value(t, message[0], u8(Handshake_Type.Message_Hash))
		testing.expect_value(t, int(message[3]), size)

		direct: Handshake_Transcript
		transcript_init(&direct, algorithm)
		transcript_update(&direct, message)
		left_storage, right_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
		left := transcript_hash(&transcript, left_storage[:])
		right := transcript_hash(&direct, right_storage[:])
		testing.expect_value(t, string(left), string(right))
	}
}

// A cookie-only HelloRetryRequest naming suite, as hello_retry_request_decode
// accepts it.
schedule_suite_retry :: proc(dst: []u8, suite: Cipher_Suite, cookie: []u8) -> []u8 {
	at := 4
	hello_put_u16(dst, &at, u16(LEGACY_TLS_1_2))
	random := HELLO_RETRY_REQUEST_RANDOM
	at += copy(dst[at:], random[:])
	dst[at] = 0
	at += 1
	hello_put_u16(dst, &at, u16(suite))
	dst[at] = 0
	at += 1
	hello_put_u16(dst, &at, u16(6 + 6 + len(cookie)))
	hello_put_extension(dst, &at, .Supported_Versions, 2)
	hello_put_u16(dst, &at, VERSION_TLS_1_3)
	hello_put_u16(dst, &at, RETRY_COOKIE_EXTENSION)
	hello_put_u16(dst, &at, u16(2 + len(cookie)))
	hello_put_u16(dst, &at, u16(len(cookie)))
	at += copy(dst[at:], cookie)

	dst[0] = u8(Handshake_Type.Server_Hello)
	server_flight_put24(dst[1:4], at - 4)
	return dst[:at]
}

@(test)
schedule_retry_binds_the_transcript_to_the_retry_suite :: proc(t: ^testing.T) {
	cookie := [?]u8{9, 8, 7}
	suites := [?]Cipher_Suite{.TLS_AES_256_GCM_SHA384}
	groups := [?]Named_Group{.X25519}

	conn := new(Conn)
	defer free(conn)
	defer handshake_keys_clear(conn)
	conn.phase = .Handshake_Pending
	conn.config = {server_name = "example.com", offer = .Upstream, cipher_suites = suites[:], groups = groups[:]}
	testing.expect_value(t, client_hello_prepare(conn).kind, Client_Hello_Send_Error_Kind.None)
	conn.phase = .Awaiting_Server_Hello

	// A retry for a suite outside the offer is refused before any state moves.
	storage: [128]u8
	unoffered := schedule_suite_retry(storage[:], .TLS_AES_128_GCM_SHA256, cookie[:])
	_, unoffered_error := hello_retry_request_decode(unoffered, config_cipher_suites(&conn.config))
	testing.expect_value(t, unoffered_error, Server_Hello_Error.Unoffered_Cipher)

	retry := schedule_suite_retry(storage[:], .TLS_AES_256_GCM_SHA384, cookie[:])
	testing.expect_value(t, server_hello_retry_accept(conn, retry).kind, Server_Hello_Read_Error_Kind.None)
	testing.expect_value(t, conn.phase, Conn_Phase.Hello_Retry_Received)
	testing.expect_value(t, conn.retry_message_hash_size, 4 + 48)
	testing.expect_value(t, conn.retry_transcript_size, 4 + 48 + len(retry))
	testing.expect_value(t, conn.retry_client_hello_size, conn.client_hello_size + 6 + len(cookie))

	first: Handshake_Transcript
	transcript_init(&first, .SHA384)
	transcript_update(&first, conn.client_hello[:conn.client_hello_size])
	digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
	digest := transcript_hash(&first, digest_storage[:])
	testing.expect_value(t, conn.retry_transcript[0], u8(Handshake_Type.Message_Hash))
	testing.expect_value(t, string(conn.retry_transcript[4:52]), string(digest))
	testing.expect_value(t, string(conn.retry_transcript[52:conn.retry_transcript_size]), string(retry))
	testing.expect_value(t, client_hello_retry_hash(conn.retry_transcript[52:conn.retry_transcript_size]), hash.Algorithm.SHA384)
}
