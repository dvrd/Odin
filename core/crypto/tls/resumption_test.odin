package tls

import "core:bytes"
import "core:crypto"
import "core:crypto/hkdf"
import "core:testing"
import "core:time"

@(private)
resumption_test_session :: proc(name: string) -> Session {
	session := Session {
		usable = true,
		name_len = len(name),
		ticket_len = 4,
		psk = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		age_add = 0x01020304,
		lifetime_sec = 3600,
		received = time.now(),
		saw_early_data = true,
		early_data_max = 4096,
	}
	copy(session.name[:], name)
	session.ticket[0], session.ticket[1], session.ticket[2], session.ticket[3] = 9, 8, 7, 6
	return session
}

@(private)
resumption_test_binder :: proc(psk: [32]u8, parts: [][]u8) -> [32]u8 {
	secret := psk
	defer crypto.zero_explicit(&secret, size_of(secret))
	early: [32]u8
	defer crypto.zero_explicit(&early, size_of(early))
	salt: [32]u8
	hkdf.extract(.SHA256, salt[:], secret[:], early[:])
	empty := transcript_empty_hash()
	key: [32]u8
	defer crypto.zero_explicit(&key, size_of(key))
	schedule_expand(.SHA256, early[:], "res binder", empty[:], key[:])
	t: Handshake_Transcript
	transcript_init(&t)
	for part in parts {
		transcript_update(&t, part)
	}
	return finished_verify_data(key, transcript_snapshot(&t))
}

@(private)
resumption_test_server_hello :: proc(dst: []u8, psk: bool) -> []u8 {
	ext := 6 + 40
	if psk {
		ext += 6
	}
	body := 38 + 2 + ext
	total := 4 + body
	if len(dst) < total {
		return nil
	}
	dst[0] = 2
	dst[1] = u8(body >> 16)
	dst[2] = u8(body >> 8)
	dst[3] = u8(body)
	dst[4], dst[5] = 3, 3
	for i in 6 ..< 38 {
		dst[i] = 0x11
	}
	dst[38] = 0
	dst[39], dst[40] = 0x13, 0x01
	dst[41] = 0
	dst[42] = u8(ext >> 8)
	dst[43] = u8(ext)
	at := 44
	dst[at], dst[at + 1], dst[at + 2], dst[at + 3] = 0x00, 0x2b, 0x00, 0x02
	dst[at + 4], dst[at + 5] = 0x03, 0x04
	at += 6
	dst[at], dst[at + 1], dst[at + 2], dst[at + 3] = 0x00, 0x33, 0x00, 0x24
	dst[at + 4], dst[at + 5], dst[at + 6], dst[at + 7] = 0x00, 0x1d, 0x00, 0x20
	for i in 0 ..< 32 {
		dst[at + 8 + i] = 0x22
	}
	at += 40
	if psk {
		dst[at], dst[at + 1], dst[at + 2], dst[at + 3] = 0x00, 0x29, 0x00, 0x02
		dst[at + 4], dst[at + 5] = 0x00, 0x00
		at += 6
	}
	return dst[:at]
}

@(test)
resumption_psk_dhe_binder_omits_early_data :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	conn.phase = .Handshake_Pending
	conn.config.server_name = "example.com"
	prepare := engine_client_hello_prepare(conn)
	testing.expect_value(t, prepare.kind, .None)
	testing.expect(t, !conn.psk_offered)
	plain := conn.client_hello_size
	testing.expect(t, resumption_extension_offset(conn.client_hello[:plain], EXTENSION_PRE_SHARED_KEY) < 0)
	testing.expect(t, resumption_extension_offset(conn.client_hello[:plain], EXTENSION_EARLY_DATA) < 0)

	session := resumption_test_session("example.com")
	defer session_clear(&session)
	conn.config.session = &session
	conn.config.remember_tickets = true
	conn.phase = .Handshake_Pending
	prepare = engine_client_hello_prepare(conn)
	testing.expect_value(t, prepare.kind, .None)
	testing.expect(t, conn.psk_offered)
	hello := conn.client_hello[:conn.client_hello_size]
	psk_at := resumption_extension_offset(hello, EXTENSION_PRE_SHARED_KEY)
	modes_at := resumption_extension_offset(hello, EXTENSION_PSK_MODES)
	testing.expect(t, psk_at > modes_at && modes_at > 0)
	testing.expect_value(t, resumption_last_extension_offset(hello), psk_at)
	testing.expect(t, resumption_extension_offset(hello, EXTENSION_EARLY_DATA) < 0)
	testing.expect_value(t, hello[modes_at + 5], PSK_DHE_KE)
	testing.expect_value(t, hello[len(hello) - 33], u8(RESUMPTION_BINDER_LEN))
	expected := resumption_test_binder(session.psk, [][]u8{hello[:len(hello) - RESUMPTION_BINDERS_TAIL]})
	defer crypto.zero_explicit(&expected, size_of(expected))
	testing.expect(t, bytes.equal(hello[len(hello) - 32:], expected[:]))

	early, early_err := session_early_keys(&session)
	defer quic_direction_keys_clear(&early)
	testing.expect_value(t, early_err.kind, .Early_Data_Disabled)
	testing.expect(t, early.secret == [32]u8{} && early.key == [16]u8{} && early.iv == [12]u8{} && early.hp == [16]u8{})
	refused, refused_err := engine_quic_early_packet_keys(session.psk)
	defer quic_direction_keys_clear(&refused)
	testing.expect_value(t, refused_err.kind, .Early_Data_Disabled)

	mismatched := session
	defer session_clear(&mismatched)
	mismatched.name_len = len("other.test")
	copy(mismatched.name[:], "other.test")
	testing.expect(t, !session_offerable(&mismatched, "example.com", time.now()))
	expired := session
	defer session_clear(&expired)
	expired.lifetime_sec = 1
	expired.received = time.time_add(time.now(), -2 * time.Second)
	testing.expect(t, !session_offerable(&expired, "example.com", time.now()))
}

@(test)
resumption_retry_rebinds_without_early_data :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	conn.phase = .Handshake_Pending
	conn.config.server_name = "example.com"
	session := resumption_test_session("example.com")
	defer session_clear(&session)
	conn.config.session = &session
	prepare := engine_client_hello_prepare(conn)
	testing.expect_value(t, prepare.kind, .None)
	ch1 := conn.client_hello[:conn.client_hello_size]
	cookie := []u8{0xaa, 0xbb, 0xcc}
	hrr := []u8{2, 0, 0, 4, 1, 2, 3, 4}
	testing.expect_value(t, client_hello_retry_prepare(conn, hrr, cookie), .None)
	ch2 := conn.retry_client_hello[:conn.retry_client_hello_size]
	testing.expect(t, resumption_extension_offset(ch2, EXTENSION_EARLY_DATA) < 0)
	psk_at := resumption_last_extension_offset(ch2)
	testing.expect(t, psk_at > 0 && hello_u16(ch2, psk_at) == EXTENSION_PRE_SHARED_KEY)
	testing.expect(t, resumption_extension_offset(ch2, RETRY_COOKIE_EXTENSION) > 0)
	testing.expect(t, resumption_extension_offset(ch2, RETRY_COOKIE_EXTENSION) < psk_at)
	expected := resumption_test_binder(session.psk, [][]u8{ch1, hrr, ch2[:len(ch2) - RESUMPTION_BINDERS_TAIL]})
	defer crypto.zero_explicit(&expected, size_of(expected))
	testing.expect(t, bytes.equal(ch2[len(ch2) - 32:], expected[:]))
	keys, err := session_early_keys(&session)
	defer quic_direction_keys_clear(&keys)
	testing.expect_value(t, err.kind, .Early_Data_Disabled)
}

@(test)
resumption_schedule_uses_psk_and_not_early_keys :: proc(t: ^testing.T) {
	shared: [32]u8
	for i in 0 ..< 32 {
		shared[i] = 0x11
	}
	ch := []u8{1, 0, 0, 1, 0}
	sh := []u8{2, 0, 0, 1, 0}
	psk := resumption_test_session("example.com").psk
	defer crypto.zero_explicit(&psk, size_of(psk))
	with_psk, with_err := handshake_secrets_derive(shared, ch, sh, nil, psk[:])
	defer crypto.zero_explicit(&with_psk, size_of(with_psk))
	without, without_err := handshake_secrets_derive(shared, ch, sh, nil, nil)
	defer crypto.zero_explicit(&without, size_of(without))
	testing.expect_value(t, with_err, .None)
	testing.expect_value(t, without_err, .None)
	testing.expect(t, with_psk.handshake_secret != without.handshake_secret)
	testing.expect(t, with_psk.client_traffic_secret != without.client_traffic_secret)
	_, bad := handshake_secrets_derive(shared, ch, sh, nil, []u8{1, 2, 3})
	testing.expect_value(t, bad, .Invalid_Secret_Length)

	storage: [128]u8
	selected := resumption_test_server_hello(storage[:], true)
	hello, err := engine_server_hello_decode(selected)
	testing.expect_value(t, err, .Unsupported_Extension)
	hello, err = engine_server_hello_decode(selected, true)
	testing.expect_value(t, err, .None)
	testing.expect(t, hello.psk_selected)
	plain := resumption_test_server_hello(storage[:], false)
	hello, err = engine_server_hello_decode(plain, true)
	testing.expect_value(t, err, .None)
	testing.expect(t, !hello.psk_selected)
}

@(test)
resumption_flight_keeps_certificate_checks :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	conn.phase = .Handshake_Pending
	conn.config.server_name = "example.com"
	session := resumption_test_session("example.com")
	defer session_clear(&session)
	conn.config.session = &session
	prepare := engine_client_hello_prepare(conn)
	testing.expect_value(t, prepare.kind, .None)
	sh_storage: [128]u8
	sh := resumption_test_server_hello(sh_storage[:], true)
	copy(conn.server_hello[:], sh)
	conn.server_hello_size = len(sh)
	shared: [32]u8
	for i in 0 ..< 32 {
		shared[i] = 0x44
	}
	secrets, derr := handshake_secrets_derive(shared, conn.client_hello[:conn.client_hello_size], sh, nil, session.psk[:])
	defer crypto.zero_explicit(&secrets, size_of(secrets))
	testing.expect_value(t, derr, .None)
	resumption_test_install(conn, shared, session.psk[:])
	ee := []u8{8, 0, 0, 2, 0, 0}
	transcript: Handshake_Transcript
	transcript_init(&transcript)
	transcript_update(&transcript, conn.client_hello[:conn.client_hello_size])
	transcript_update(&transcript, sh)
	transcript_update(&transcript, ee)
	hash := transcript_snapshot(&transcript)
	finished: [FINISHED_MESSAGE_SIZE]u8
	defer crypto.zero_explicit(&finished, size_of(finished))
	n, ferr := finished_encode(finished[:], secrets.server_traffic_secret, hash)
	testing.expect_value(t, ferr, .None)
	testing.expect_value(t, n, FINISHED_MESSAGE_SIZE)
	flight: [6 + FINISHED_MESSAGE_SIZE]u8
	copy(flight[:], ee)
	copy(flight[len(ee):], finished[:])

	conn.psk_selected = false
	full := engine_handshake_server_flight_verify(conn, flight[:])
	testing.expect_value(t, full.kind, .Unexpected_Handshake_Message)

	conn.phase = .Handshake_Pending
	resumption_test_install(conn, shared, session.psk[:])
	conn.psk_selected = true
	early_ee := []u8{8, 0, 0, 6, 0, 4, 0x00, 0x2a, 0x00, 0x00}
	early := engine_handshake_server_flight_verify(conn, early_ee)
	testing.expect_value(t, early.kind, .Early_Data_Disabled)

	conn.phase = .Handshake_Pending
	resumption_test_install(conn, shared, session.psk[:])
	conn.psk_selected = true
	cert_flight: [11]u8
	copy(cert_flight[:], ee)
	cert_flight[6] = 11
	certs := engine_handshake_server_flight_verify(conn, cert_flight[:])
	testing.expect(t, certs.kind != .None)
	testing.expect(t, certs.kind != .Early_Data_Disabled)

	conn.phase = .Handshake_Pending
	resumption_test_install(conn, shared, session.psk[:])
	conn.psk_selected = true
	resumed := engine_handshake_server_flight_verify(conn, flight[:])
	testing.expect_value(t, resumed.kind, .None)
	keys, kerr := session_early_keys(&session)
	defer quic_direction_keys_clear(&keys)
	testing.expect_value(t, kerr.kind, .Early_Data_Disabled)
}

@(test)
resumption_ticket_remember_refuses_early_data :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	session: Session
	defer session_clear(&session)
	conn.config.server_name = "example.com"
	conn.config.session = &session
	conn.config.remember_tickets = true
	master: [32]u8
	for i in 0 ..< 32 {
		master[i] = 0x55
	}
	conn.application.have_resumption = true
	copy(conn.application.resumption_secret[:], master[:])
	conn.application.resumption_secret_size = len(master)
	nonce := []u8{7}
	ticket := []u8{1, 2, 3, 4}
	// lifetime, age_add, nonce, ticket, early_data = 4096.
	body := [?]u8{
		0, 0, 0, 100,
		0, 0, 0, 9,
		1, 7,
		0, 4, 1, 2, 3, 4,
		0, 8,
		0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00,
	}
	message: [4 + len(body)]u8
	message[0] = NEW_SESSION_TICKET_TYPE
	message[3] = u8(len(body))
	copy(message[4:], body[:])
	testing.expect_value(t, application_post_message(conn, message[:], true).kind, .None)
	testing.expect(t, session.usable)
	testing.expect(t, session.saw_early_data)
	testing.expect_value(t, session.early_data_max, u32(0x1000))
	testing.expect_value(t, session.ticket_len, 4)
	testing.expect(t, bytes.equal(session.ticket[:4], ticket))
	expect_psk := session_psk(master, nonce)
	defer crypto.zero_explicit(&expect_psk, size_of(expect_psk))
	testing.expect(t, session.psk == expect_psk)
	keys, err := session_early_keys(&session)
	defer quic_direction_keys_clear(&keys)
	testing.expect_value(t, err.kind, .Early_Data_Disabled)
	testing.expect(t, keys.secret == [32]u8{})

	kept := session.psk
	huge: [4 + 9 + 2 + (SESSION_TICKET_MAX+1) + 2]u8
	huge[0] = NEW_SESSION_TICKET_TYPE
	huge_body := 4 + 4 + 1 + 2 + (SESSION_TICKET_MAX+1) + 2
	huge[1] = u8(huge_body >> 16)
	huge[2] = u8(huge_body >> 8)
	huge[3] = u8(huge_body)
	huge[7] = 100
	huge[12] = 0
	huge[13], huge[14] = u8((SESSION_TICKET_MAX+1)>>8), u8((SESSION_TICKET_MAX+1)&255)
	testing.expect(t, !session_remember(&session, master, huge[:], "example.com", time.now()))
	testing.expect(t, session.usable && session.psk == kept && session.ticket_len == 4)
	crypto.zero_explicit(&kept, size_of(kept))
}

@(private)
resumption_test_allow_get :: proc(method: string) -> bool {
	return method == "GET" || method == "HEAD"
}

@(private)
resumption_test_count :: proc(user: rawptr) {
	if user != nil {
		(^int)(user)^ += 1
	}
}

@(private)
resumption_test_nst :: proc(dst: []u8, lifetime: u32, ticket: []u8, early_max: u32) -> []u8 {
	if len(ticket) < 1 || len(ticket) > 64 {
		return nil
	}
	ext := 0
	if early_max > 0 {
		ext = 8
	}
	body := 4 + 4 + 1 + 1 + 2 + len(ticket) + 2 + ext
	if len(dst) < 4 + body {
		return nil
	}
	dst[0] = NEW_SESSION_TICKET_TYPE
	dst[1] = u8(body >> 16)
	dst[2] = u8(body >> 8)
	dst[3] = u8(body)
	dst[4] = u8(lifetime >> 24)
	dst[5] = u8(lifetime >> 16)
	dst[6] = u8(lifetime >> 8)
	dst[7] = u8(lifetime)
	dst[8], dst[9], dst[10], dst[11] = 0, 0, 0, 3
	dst[12] = 1
	dst[13] = ticket[0]
	at := 14
	dst[at] = u8(len(ticket) >> 8)
	dst[at + 1] = u8(len(ticket))
	at += 2
	copy(dst[at:], ticket)
	at += len(ticket)
	dst[at] = u8(ext >> 8)
	dst[at + 1] = u8(ext)
	at += 2
	if ext == 8 {
		dst[at], dst[at + 1], dst[at + 2], dst[at + 3] = 0x00, 0x2a, 0x00, 0x04
		dst[at + 4] = u8(early_max >> 24)
		dst[at + 5] = u8(early_max >> 16)
		dst[at + 6] = u8(early_max >> 8)
		dst[at + 7] = u8(early_max)
		at += 8
	}
	return dst[:at]
}

@(private)
resumption_test_install :: proc(conn: ^Conn, shared: [32]u8, psk: []u8) {
	local := shared
	defer crypto.zero_explicit(&local, size_of(local))

	conn.server_parameters.cipher_suite = .TLS_AES_128_GCM_SHA256
	schedule_init(&conn.keys, .SHA256, psk)
	update_handshake_keys(&conn.keys, local[:])
	client_handshake_secrets_install(conn)
}

@(private)
resumption_test_arm_flight :: proc(conn: ^Conn, dst: []u8, psk: []u8, accept_early: bool) -> []u8 {
	sh_storage: [128]u8
	sh := resumption_test_server_hello(sh_storage[:], true)
	if sh == nil || len(sh) > len(conn.server_hello) {
		return nil
	}
	copy(conn.server_hello[:], sh)
	conn.server_hello_size = len(sh)
	conn.psk_selected = true
	shared: [32]u8
	shared[0] = 0x44
	hello := handshake_effective_client_hello(conn)
	secrets, derr := handshake_secrets_derive(
		shared,
		hello,
		conn.server_hello[:conn.server_hello_size],
		conn.retry_transcript[:conn.retry_transcript_size],
		psk,
	)
	defer crypto.zero_explicit(&secrets, size_of(secrets))
	if derr != .None {
		return nil
	}
	resumption_test_install(conn, shared, psk)
	ee := []u8{8, 0, 0, 2, 0, 0}
	if accept_early {
		ee = []u8{8, 0, 0, 6, 0, 4, 0x00, 0x2a, 0x00, 0x00}
	}
	transcript: Handshake_Transcript
	transcript_init(&transcript)
	transcript_update(&transcript, conn.retry_transcript[:conn.retry_transcript_size])
	transcript_update(&transcript, hello)
	transcript_update(&transcript, conn.server_hello[:conn.server_hello_size])
	transcript_update(&transcript, ee)
	hash := transcript_snapshot(&transcript)
	finished: [FINISHED_MESSAGE_SIZE]u8
	defer crypto.zero_explicit(&finished, size_of(finished))
	n, ferr := finished_encode(finished[:], secrets.server_traffic_secret, hash)
	if ferr != .None || n != FINISHED_MESSAGE_SIZE || len(dst) < len(ee) + n {
		return nil
	}
	copy(dst, ee)
	copy(dst[len(ee):], finished[:])
	return dst[:len(ee) + n]
}

@(private)
resumption_test_pending :: proc(name: string, cache: ^Session_Cache, session: ^Session) -> ^Conn {
	conn := new(Conn)
	conn.phase = .Handshake_Pending
	conn.config.server_name = name
	conn.config.session_cache = cache
	conn.config.session = session
	return conn
}

@(test)
resumption_cache_resumes_isolates_and_expires :: proc(t: ^testing.T) {
	cache: Session_Cache
	defer session_cache_clear(&cache)
	master: [32]u8
	for i in 0 ..< 32 {
		master[i] = 0x31
	}
	defer crypto.zero_explicit(&master, size_of(master))
	nst_buf: [128]u8
	nst := resumption_test_nst(nst_buf[:], 3600, []u8{9, 8, 7, 6}, 0x1000)
	testing.expect(t, nst != nil)

	stored := new(Conn)
	defer free(stored)
	stored.config.server_name = "example.com"
	stored.config.session_cache = &cache
	stored.config.remember_tickets = true
	stored.application.have_resumption = true
	copy(stored.application.resumption_secret[:], master[:])
	stored.application.resumption_secret_size = len(master)
	testing.expect_value(t, application_post_message(stored, nst, true).kind, .None)
	found := session_cache_lookup(&cache, "example.com", time.now())
	testing.expect(t, found != nil && found.usable && found.saw_early_data)
	testing.expect(t, session_cache_lookup(&cache, "other.example", time.now()) == nil)

	resume := resumption_test_pending("example.com", &cache, nil)
	defer free(resume)
	defer handshake_keys_clear(resume)
	testing.expect_value(t, engine_client_hello_prepare(resume).kind, .None)
	testing.expect(t, resume.psk_offered && resume.offered_session == found)
	hello := resume.client_hello[:resume.client_hello_size]
	testing.expect(t, resumption_extension_offset(hello, EXTENSION_EARLY_DATA) < 0)
	testing.expect(t, resumption_last_extension_offset(hello) == resumption_extension_offset(hello, EXTENSION_PRE_SHARED_KEY))
	refused, refused_err := session_early_keys(found)
	defer quic_direction_keys_clear(&refused)
	testing.expect_value(t, refused_err.kind, .Early_Data_Disabled)
	bare, bare_err := engine_quic_early_packet_keys(found.psk)
	defer quic_direction_keys_clear(&bare)
	testing.expect_value(t, bare_err.kind, .Early_Data_Disabled)

	flight_buf: [80]u8
	flight := resumption_test_arm_flight(resume, flight_buf[:], found.psk[:], false)
	testing.expect(t, flight != nil)
	resumed := engine_handshake_server_flight_verify(resume, flight)
	testing.expect_value(t, resumed.kind, .None)
	testing.expect(t, !resume.early_offered && !resume.early_accepted)

	other := resumption_test_pending("other.example", &cache, nil)
	defer free(other)
	testing.expect_value(t, engine_client_hello_prepare(other).kind, .None)
	testing.expect(t, !other.psk_offered && other.offered_session == nil)

	mismatch := resumption_test_pending("example.com", &cache, nil)
	defer free(mismatch)
	defer handshake_keys_clear(mismatch)
	testing.expect_value(t, engine_client_hello_prepare(mismatch).kind, .None)
	bad_flight := resumption_test_arm_flight(mismatch, flight_buf[:], found.psk[:], false)
	testing.expect(t, bad_flight != nil)
	bad_flight[len(bad_flight) - 1] ~= 0x01
	mismatch_err := engine_handshake_server_flight_verify(mismatch, bad_flight)
	testing.expect_value(t, mismatch_err.kind, .Finished_Failed)

	declined := resumption_test_pending("example.com", &cache, nil)
	defer free(declined)
	defer handshake_keys_clear(declined)
	testing.expect_value(t, engine_client_hello_prepare(declined).kind, .None)
	testing.expect(t, declined.psk_offered)
	declined_flight := resumption_test_arm_flight(declined, flight_buf[:], found.psk[:], false)
	testing.expect(t, declined_flight != nil)
	declined.psk_selected = false
	declined_err := engine_handshake_server_flight_verify(declined, declined_flight)
	testing.expect_value(t, declined_err.kind, .Unexpected_Handshake_Message)

	expired: Session
	defer session_clear(&expired)
	past := time.time_add(time.now(), -2 * 3600 * time.Second)
	testing.expect(t, session_remember(&expired, master, nst, "example.com", past))
	testing.expect(t, !session_offerable(&expired, "example.com", time.now()))
	testing.expect(t, !session_cache_put(&cache, &expired))
	exp := resumption_test_pending("example.com", nil, &expired)
	defer free(exp)
	defer handshake_keys_clear(exp)
	testing.expect_value(t, engine_client_hello_prepare(exp).kind, .None)
	testing.expect(t, !exp.psk_offered)
	exp_flight := resumption_test_arm_flight(exp, flight_buf[:], expired.psk[:], false)
	testing.expect(t, exp_flight != nil)
	exp_err := engine_handshake_server_flight_verify(exp, exp_flight)
	testing.expect_value(t, exp_err.kind, .Unexpected_Handshake_Message)

	later := time.time_add(time.now(), 2 * 3600 * time.Second)
	testing.expect(t, session_cache_lookup(&cache, "example.com", later) == nil)
	testing.expect(t, session_cache_lookup(&cache, "example.com", time.now()) == nil)

	bound: Session_Cache
	defer session_cache_clear(&bound)
	names := [?]string {
		"a0.example", "a1.example", "a2.example", "a3.example",
		"a4.example", "a5.example", "a6.example", "a7.example", "a8.example",
	}
	for i in 0 ..< SESSION_CACHE_CAP + 1 {
		ticket := [?]u8{u8(i + 1), u8(i + 3)}
		message := resumption_test_nst(nst_buf[:], 3600, ticket[:], 0)
		temp: Session
		testing.expect(t, session_remember(&temp, master, message, names[i], time.now()))
		testing.expect(t, session_cache_put(&bound, &temp))
		session_clear(&temp)
		testing.expect(t, !temp.usable)
	}
	testing.expect(t, session_cache_lookup(&bound, names[0], time.now()) == nil)
	kept := session_cache_lookup(&bound, names[SESSION_CACHE_CAP], time.now())
	prior := session_cache_lookup(&bound, names[1], time.now())
	testing.expect(t, kept != nil && prior != nil && kept != prior)
	testing.expect(t, kept.ticket[0] != prior.ticket[0])
	evicted := resumption_test_pending(names[0], &bound, nil)
	defer free(evicted)
	testing.expect_value(t, engine_client_hello_prepare(evicted).kind, .None)
	testing.expect(t, !evicted.psk_offered)
	survivor := resumption_test_pending(names[SESSION_CACHE_CAP], &bound, nil)
	defer free(survivor)
	testing.expect_value(t, engine_client_hello_prepare(survivor).kind, .None)
	testing.expect(t, survivor.psk_offered && survivor.offered_session == kept)
}

@(test)
resumption_rejected_early_data_does_not_apply_twice :: proc(t: ^testing.T) {
	policy := Early_Data_Policy {
		allow = resumption_test_allow_get,
	}
	master: [32]u8
	for i in 0 ..< 32 {
		master[i] = 0x61
	}
	defer crypto.zero_explicit(&master, size_of(master))
	nst_buf: [128]u8
	nst := resumption_test_nst(nst_buf[:], 3600, []u8{4, 5, 6, 7}, 4096)
	session: Session
	defer session_clear(&session)
	testing.expect(t, session_remember(&session, master, nst, "example.com", time.now()))
	testing.expect(t, session.saw_early_data && session.early_data_max == 4096)

	plain := resumption_test_pending("example.com", nil, &session)
	defer free(plain)
	testing.expect_value(t, engine_client_hello_prepare(plain).kind, .None)
	testing.expect(t, plain.psk_offered && !plain.early_offered)
	plain_hello := plain.client_hello[:plain.client_hello_size]
	testing.expect(t, resumption_extension_offset(plain_hello, EXTENSION_EARLY_DATA) < 0)
	disabled, disabled_err := session_early_keys(&session, nil, plain_hello)
	defer quic_direction_keys_clear(&disabled)
	testing.expect_value(t, disabled_err.kind, .Early_Data_Disabled)
	packet_disabled, packet_err := engine_quic_early_packet_keys(session.psk, nil, plain_hello)
	defer quic_direction_keys_clear(&packet_disabled)
	testing.expect_value(t, packet_err.kind, .Early_Data_Disabled)

	rejected := resumption_test_pending("example.com", nil, &session)
	defer free(rejected)
	defer handshake_keys_clear(rejected)
	rejected.config.early_data = &policy
	testing.expect_value(t, engine_client_hello_prepare(rejected).kind, .None)
	testing.expect(t, rejected.early_offered)
	rejected_hello := rejected.client_hello[:rejected.client_hello_size]
	testing.expect(t, resumption_extension_offset(rejected_hello, EXTENSION_EARLY_DATA) > 0)
	testing.expect(t, resumption_last_extension_offset(rejected_hello) == resumption_extension_offset(rejected_hello, EXTENSION_PRE_SHARED_KEY))
	early_keys, early_err := session_early_keys(&session, &policy, rejected_hello)
	defer quic_direction_keys_clear(&early_keys)
	testing.expect_value(t, early_err.kind, .None)
	testing.expect(t, crypto.is_zero_constant_time(early_keys.key[:]) == 0)
	again, again_err := session_early_keys(&session, &policy, rejected_hello)
	defer quic_direction_keys_clear(&again)
	testing.expect_value(t, again_err.kind, .None)
	testing.expect(t, again.key == early_keys.key && again.iv == early_keys.iv)
	other_keys, other_err := session_early_keys(&session, &policy, plain_hello)
	defer quic_direction_keys_clear(&other_keys)
	testing.expect_value(t, other_err.kind, .Early_Data_Disabled)

	flight_buf: [80]u8
	flight := resumption_test_arm_flight(rejected, flight_buf[:], session.psk[:], false)
	testing.expect(t, flight != nil)
	rejected_err := engine_handshake_server_flight_verify(rejected, flight)
	testing.expect_value(t, rejected_err.kind, .None)
	testing.expect(t, rejected.early_rejected && !rejected.early_accepted)
	effects := 0
	testing.expect_value(t, connection_early_data_apply(rejected, "GET", resumption_test_count, &effects), .Deferred)
	testing.expect_value(t, effects, 0)
	testing.expect_value(t, connection_early_data_fallback(rejected, "GET", resumption_test_count, &effects), .Applied)
	testing.expect_value(t, effects, 1)
	testing.expect_value(t, connection_early_data_fallback(rejected, "GET", resumption_test_count, &effects), .None)
	testing.expect_value(t, connection_early_data_apply(rejected, "GET", resumption_test_count, &effects), .None)
	testing.expect_value(t, effects, 1)

	mutated := resumption_test_pending("example.com", nil, &session)
	defer free(mutated)
	defer handshake_keys_clear(mutated)
	mutated.config.early_data = &policy
	testing.expect_value(t, engine_client_hello_prepare(mutated).kind, .None)
	mutated_flight := resumption_test_arm_flight(mutated, flight_buf[:], session.psk[:], false)
	testing.expect(t, mutated_flight != nil)
	mutated_err := engine_handshake_server_flight_verify(mutated, mutated_flight)
	testing.expect_value(t, mutated_err.kind, .None)
	posts := 0
	testing.expect_value(t, connection_early_data_apply(mutated, "POST", resumption_test_count, &posts), .Deferred)
	testing.expect_value(t, posts, 0)
	testing.expect_value(t, connection_early_data_fallback(mutated, "POST", resumption_test_count, &posts), .Applied)
	testing.expect_value(t, posts, 1)
	testing.expect_value(t, connection_early_data_fallback(mutated, "POST", resumption_test_count, &posts), .None)
	testing.expect_value(t, posts, 1)

	accepted := resumption_test_pending("example.com", nil, &session)
	defer free(accepted)
	defer handshake_keys_clear(accepted)
	accepted.config.early_data = &policy
	testing.expect_value(t, engine_client_hello_prepare(accepted).kind, .None)
	second, second_err := session_early_keys(&session, &policy, accepted.client_hello[:accepted.client_hello_size])
	defer quic_direction_keys_clear(&second)
	testing.expect_value(t, second_err.kind, .None)
	testing.expect(t, second.key != early_keys.key)
	accepted_flight := resumption_test_arm_flight(accepted, flight_buf[:], session.psk[:], true)
	testing.expect(t, accepted_flight != nil)
	accepted_err := engine_handshake_server_flight_verify(accepted, accepted_flight)
	testing.expect_value(t, accepted_err.kind, .None)
	testing.expect(t, accepted.early_accepted && !accepted.early_rejected)
	once := 0
	testing.expect_value(t, connection_early_data_apply(accepted, "GET", resumption_test_count, &once), .Applied)
	testing.expect_value(t, once, 1)
	testing.expect_value(t, connection_early_data_fallback(accepted, "GET", resumption_test_count, &once), .None)
	testing.expect_value(t, connection_early_data_apply(accepted, "GET", resumption_test_count, &once), .None)
	testing.expect_value(t, once, 1)

	retried := resumption_test_pending("example.com", nil, &session)
	defer free(retried)
	retried.config.early_data = &policy
	testing.expect_value(t, engine_client_hello_prepare(retried).kind, .None)
	testing.expect(t, retried.early_offered)
	cookie := []u8{0x11, 0x22}
	hrr := []u8{2, 0, 0, 4, 9, 8, 7, 6}
	testing.expect_value(t, client_hello_retry_prepare(retried, hrr, cookie), .None)
	ch2 := retried.retry_client_hello[:retried.retry_client_hello_size]
	testing.expect(t, resumption_extension_offset(ch2, EXTENSION_EARLY_DATA) < 0)
	testing.expect(t, retried.early_rejected && !retried.early_offered)
	retry_effects := 0
	testing.expect_value(t, connection_early_data_apply(retried, "GET", resumption_test_count, &retry_effects), .Deferred)
	testing.expect_value(t, retry_effects, 0)
	testing.expect_value(t, connection_early_data_fallback(retried, "GET", resumption_test_count, &retry_effects), .Applied)
	testing.expect_value(t, retry_effects, 1)
	testing.expect_value(t, connection_early_data_fallback(retried, "GET", resumption_test_count, &retry_effects), .None)
	testing.expect_value(t, retry_effects, 1)
}
