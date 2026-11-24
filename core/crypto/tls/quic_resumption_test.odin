package tls
import "core:crypto"
import "core:crypto/x25519"
import "core:testing"
import "core:time"
import store "credentials/store"

@(private)
early_test_compatible :: proc(previous, current: []u8) -> bool {return string(previous) == string(current)}

@(private)
early_test_allow :: proc(method: string) -> bool {return method == "GET"}

@(private)
early_test_hello :: proc(dst: []u8, session: ^Session, scope: Quic_Session_Scope, early: bool) -> []u8 {
	private: [32]u8
	private[0] = 3
	hello := Client_Hello {
		server_name    = "localhost",
		alpn_protocols = []string{"h3"},
	}
	x25519.scalarmult_basepoint(hello.x25519_public_key[:], private[:])
	crypto.zero_explicit(&private, size_of(private))
	n, e := client_hello_encode(dst, hello)
	assert(e == .None)
	layout, valid := client_hello_layout_decode(dst[:n])
	assert(valid)
	dst[n], dst[n + 1], dst[n + 2], dst[n + 3], dst[n + 4] = 0, 57, 0, 1, 0
	n += 5
	retry_put_u24(dst, 1, n - 4)
	retry_put_u16(dst, layout.extensions_length_offset, u16(layout.extensions_size + 5))
	size, error := quic_client_hello_offer(dst, n, session, scope, time.now(), early)
	assert(error.kind == .None)
	return dst[:size]
}

@(private)
early_test_admit :: proc(
	owner: ^Server_Handshake,
	config: Server_Handshake_Config,
	identity: ^store.Store,
	hello: []u8,
	now: time.Time,
) -> Server_Handshake_Error {
	assert(server_handshake_init(owner, config, context.allocator) == .None)
	_, _, e := server_handshake_feed(owner, .Initial, hello)
	if e != .None {
		return e
	}
	event, _ := server_handshake_peek(owner)
	assert(event.kind == .Peer_Parameters)
	assert(
		server_handshake_select_parameters(
			owner,
			event.id,
			{mode = .QUIC, alpn_protocols = []string{"h3"}, quic_transport_parameters = []u8{0}},
		) ==
		.None,
	)
	return server_handshake_start_flight(owner, identity, now)
}

@(private)
early_test_ticket :: proc(
	identity: ^store.Store,
	config: Server_Handshake_Config,
	scope: Quic_Session_Scope,
) -> Session {
	owner: Server_Handshake
	defer server_handshake_destroy(&owner)
	bytes: [4096]u8
	hello := early_test_hello(bytes[:], nil, scope, false)
	assert(early_test_admit(&owner, config, identity, hello, time.now()) == .None)
	for _ in 0 ..< 100 {
		event, _ := server_handshake_peek(&owner)
		if event.kind == .None {
			break
		}
		assert(event.kind != .Fatal)
		assert(server_handshake_accept(&owner, event.id) == .None)
	}
	master := owner._resumption.master
	defer crypto.zero_explicit(&master, size_of(master))
	finished: [36]u8
	_, e := finished_encode(finished[:], server_test_client_secret(&owner), transcript_snapshot(&owner._transcript))
	assert(e == .None)
	transcript := owner._transcript
	transcript_update(&transcript, finished[:])
	hash := transcript_snapshot(&transcript)
	secret: [32]u8
	schedule_expand(.SHA256, master[:], "res master", hash[:], secret[:])
	defer crypto.zero_explicit(&secret, size_of(secret))
	_, _, fe := server_handshake_feed(&owner, .Handshake, finished[:])
	assert(fe == .None)
	event, _ := server_handshake_peek(&owner)
	assert(event.kind == .Handshake_Bytes && event.level == .Application)
	session: Session
	assert(quic_session_remember(&session, secret, event.bytes, scope, time.now()).kind == .None)
	assert(server_handshake_accept(&owner, event.id) == .None)
	event, _ = server_handshake_peek(&owner)
	assert(event.kind == .Complete)
	assert(server_handshake_accept(&owner, event.id) == .None)
	return session
}

@(test)
quic_early_ticket_real_binder_replay_age_profile_and_capacity :: proc(t: ^testing.T) {
	identity := mtls_store(t, #load("testdata/mtls/server.pem"), #load("testdata/mtls/server-key.pem"))
	defer store.destroy(&identity)
	for mode in 0 ..< 7 {
		keys: Server_Ticket_Keys
		assert(server_ticket_keys_init(&keys) == .None)
		defer server_ticket_keys_close(&keys)
		replay: Anti_Replay
		assert(anti_replay_init(&replay, 1) == .None)
		defer anti_replay_close(&replay)
		profile := [1]u8{1}
		early := Server_Early_Data_Config {
			replay     = &replay,
			profile    = profile[:],
			compatible = early_test_compatible,
			max_age    = time.Minute,
		}
		tickets := Server_Ticket_Config {
			keys         = &keys,
			lifetime     = time.Hour,
			policy_epoch = 1,
			early_data   = &early,
		}
		config := SERVER_HANDSHAKE_DEFAULT_CONFIG
		config.tickets = &tickets
		scope := Quic_Session_Scope {
			server_name = "localhost",
			profile     = profile[:],
		}
		session := early_test_ticket(identity, config, scope)
		defer session_clear(&session)
		testing.expect(t, session.saw_early_data && session.early_data_max == max(u32))
		if mode == 1 {
			profile[0] = 2
		}
		if mode == 3 {
			token: [32]u8
			token[0] = 9
			assert(
				anti_replay_reserve(
					&replay,
					token,
					time.to_unix_seconds(time.now()) + 600,
					time.to_unix_seconds(time.now()),
				) ==
				.None,
			)
		}
		if mode == 4 {
			tickets.early_data = nil
		}
		if mode == 5 {
			assert(server_ticket_keys_rotate(&keys, time.now()) == .None)
			assert(server_ticket_keys_rotate(&keys, time.now()) == .None)
		}
		bytes: [4096]u8
		hello := early_test_hello(bytes[:], &session, scope, true)
		if mode == 6 {
			hello[len(hello) - 1] ~= 1
		}
		now := time.now()
		if mode == 2 {
			now = time.time_add(now, 80 * time.Second)
		}
		owner: Server_Handshake
		error := early_test_admit(&owner, config, identity, hello, now)
		if mode == 6 {
			testing.expect_value(t, error, .Binder_Failed)
		} else {
			testing.expect_value(t, error, .None)
			testing.expect_value(t, owner._resumed, mode != 5)
			testing.expect_value(t, server_handshake_early_accepted(&owner), mode == 0)
			if mode == 0 {
				event, _ := server_handshake_peek(&owner)
				testing.expect_value(t, event.kind, .Early_Traffic_Secret)
				secret, valid := session_early_secret(&session)
				assert(valid)
				policy := Early_Data_Policy {
					allow = early_test_allow,
				}
				expected, ke := quic_early_packet_keys(secret, &policy, hello)
				assert(ke.kind == .None)
				testing.expect_value(t, string(event.secret), string(expected.secret[:]))
				crypto.zero_explicit(&secret, size_of(secret))
				quic_direction_keys_clear(&expected)
				assert(server_handshake_accept(&owner, event.id) == .None)
				testing.expect(t, crypto.is_zero_constant_time(owner._resumption.early_secret[:]) == 1)
			}
		}
		server_handshake_abort(&owner)
		server_handshake_destroy(&owner)
		testing.expect_value(t, owner._stats.live_bytes, 0)
		if mode == 0 || mode == 6 {
			if mode == 6 {
				hello[len(hello) - 1] ~= 1
			}
			next: Server_Handshake
			testing.expect_value(t, early_test_admit(&next, config, identity, hello, time.now()), .None)
			// A failed binder cannot consume a reservation; an admitted connection can.
			testing.expect_value(t, server_handshake_early_accepted(&next), mode == 6)
			server_handshake_destroy(&next)
		}
	}
}
