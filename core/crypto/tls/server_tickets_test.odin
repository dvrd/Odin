package tls
import "core:crypto"
import "core:testing"
import "core:time"
import store "credentials/store"
import credentials "credentials"

@(test)
server_tickets_authenticated_rotation_expiry_and_revocation :: proc(t: ^testing.T) {
	keys: Server_Ticket_Keys
	testing.expect_value(t, server_ticket_keys_init(&keys, time.Hour), .None)
	defer server_ticket_keys_close(&keys)
	config := Server_Ticket_Config {
		keys         = &keys,
		lifetime     = time.Hour,
		policy_epoch = 1,
	}
	now := time.now()
	sec := time.to_unix_seconds(now)
	claims := Server_Ticket_Claims {
		issued        = sec,
		expires       = sec + 3600,
		peer_expires  = sec + 600,
		generation    = 9,
		policy_epoch  = 1,
		authenticated = true,
	}
	claims.psk[0] = 7
	claims.peer[0] = 8
	wire: [TICKET_WIRE_SIZE]u8
	testing.expect(t, server_ticket_crypt(&config, &claims, wire[:], true, now))
	opened: Server_Ticket_Claims
	testing.expect(t, server_ticket_crypt(&config, &opened, wire[:], false, now))
	testing.expect_value(t, opened, claims)
	for offset in ([]int {
			0,
			8,
			20,
			TICKET_WIRE_SIZE - 1,
		}) {
		bad := wire
		bad[offset] ~= 1
		testing.expect(t, !server_ticket_crypt(&config, &opened, bad[:], false, now))
	}
	testing.expect_value(t, server_ticket_keys_rotate(&keys, now), .None)
	testing.expect(t, server_ticket_crypt(&config, &opened, wire[:], false, now))
	testing.expect_value(t, server_ticket_keys_rotate(&keys, now), .None)
	testing.expect(t, !server_ticket_crypt(&config, &opened, wire[:], false, now))
	testing.expect(t, server_ticket_crypt(&config, &claims, wire[:], true, now))
	testing.expect(t, !server_ticket_crypt(&config, &opened, wire[:], false, time.time_add(now, 601 * time.Second)))
	server_ticket_keys_close(&keys)
	testing.expect(
		t,
		crypto.is_zero_constant_time(keys._current.secret[:]) == 1 &&
		crypto.is_zero_constant_time(keys._previous.secret[:]) == 1,
	)
	testing.expect(t, !server_ticket_config_valid(&config))
}

// Drives a real full handshake through ticket issuance; no synthetic success or
// caller-installed PSK can manufacture the ticket used in the next handshake.
@(private)
ticket_test_issue :: proc(t: ^testing.T, identity: ^store.Store, config: Server_Handshake_Config) -> Session {
	owner: Server_Handshake
	assert(server_handshake_init(&owner, config, context.allocator) == .None)
	defer server_handshake_destroy(&owner)
	wire: [1024]u8
	hello, _ := flight_test_hello(wire[:])
	_, _, e := server_handshake_feed(&owner, .Initial, hello)
	assert(e == .None)
	event, _ := server_handshake_peek(&owner)
	assert(server_handshake_accept(&owner, event.id) == .None)
	assert(server_handshake_start_flight(&owner, identity, time.now()) == .None)
	for _ in 0 ..< 100 {
		event, _ = server_handshake_peek(&owner)
		if event.kind == .None {
			break
		}
		assert(event.kind != .Fatal)
		assert(server_handshake_accept(&owner, event.id) == .None)
	}
	master := owner._resumption.master
	defer crypto.zero_explicit(&master, size_of(master))
	finished: [36]u8
	_, fe := finished_encode(finished[:], server_test_client_secret(&owner), transcript_snapshot(&owner._transcript))
	assert(fe == .None)
	transcript := owner._transcript
	transcript_update(&transcript, finished[:])
	hash := transcript_snapshot(&transcript)
	secret: [32]u8
	schedule_expand(.SHA256, master[:], "res master", hash[:], secret[:])
	defer crypto.zero_explicit(&secret, size_of(secret))
	_, _, e = server_handshake_feed(&owner, .Handshake, finished[:])
	assert(e == .None)
	event, _ = server_handshake_peek(&owner)
	testing.expect_value(t, event.kind, .Handshake_Bytes)
	testing.expect_value(t, event.level, .Application)
	session: Session
	assert(session_remember(&session, secret, event.bytes, "localhost", time.now()))
	testing.expect(t, !server_handshake_resumed(&owner))
	assert(server_handshake_accept(&owner, event.id) == .None)
	event, _ = server_handshake_peek(&owner)
	testing.expect_value(t, event.kind, .Complete)
	assert(server_handshake_accept(&owner, event.id) == .None)
	testing.expect_value(t, owner._stats.live_bytes, 0)
	return session
}

@(test)
server_tickets_binder_context_and_fallback :: proc(t: ^testing.T) {
	identity := mtls_store(t, #load("testdata/mtls/server.pem"), #load("testdata/mtls/server-key.pem"))
	defer store.destroy(&identity)
	for mode in 0 ..< 10 {
		keys: Server_Ticket_Keys
		assert(server_ticket_keys_init(&keys, time.Hour) == .None)
		defer server_ticket_keys_close(&keys)
		ticket := Server_Ticket_Config {
			keys         = &keys,
			lifetime     = time.Hour,
			policy_epoch = 1,
		}
		config := SERVER_HANDSHAKE_DEFAULT_CONFIG
		config.tickets = &ticket
		session := ticket_test_issue(t, identity, config)
		defer session_clear(&session)
		if mode == 2 {
			session.ticket[0] ~= 1
		}
		if mode == 3 {
			ticket.policy_epoch = 2
		}
		if mode == 4 {
			assert(server_ticket_keys_rotate(&keys, time.now()) == .None)
			assert(server_ticket_keys_rotate(&keys, time.now()) == .None)
		}
		wire: [4096]u8
		hello, _ := flight_test_hello(wire[:])
		n, offered := resumption_client_hello_offer(wire[:], len(hello), &session, time.now())
		assert(offered)
		if mode == 1 {
			wire[n - 1] ~= 1
		}
		owner: Server_Handshake
		assert(server_handshake_init(&owner, config, context.allocator) == .None)
		_, _, e := server_handshake_feed(&owner, .Initial, wire[:n])
		assert(e == .None)
		event, _ := server_handshake_peek(&owner)
		assert(server_handshake_accept(&owner, event.id) == .None)
		if mode == 5 {
			assert(server_parameters_select(&owner, {}) == .None)
			owner._parameters.value.alpn = transmute([]u8)string("h2")
		}
		if mode == 7 {
			owner._hello.server_name = transmute([]u8)string("other.example")
		}
		if mode == 8 {
			replacement, ce := credentials.create(
				#load("testdata/mtls/server.pem"),
				#load("testdata/mtls/server-key.pem"),
				{},
				context.allocator,
			); assert(ce == .None); assert(store.replace(identity, &replacement).kind == .None)
		}
		roots: Root_Pool
		defer root_pool_destroy(&roots)
		policy: Client_Auth_Config
		if mode == 9 {
			assert(root_pool_parse(&roots, #load("testdata/mtls/root.pem")).kind == .None)
			policy = {
				mode  = .Require,
				roots = roots.roots[:roots.count],
			}
			owner._config.client_auth = &policy
		}
		now := time.now()
		if mode == 6 {
			now = time.time_add(now, 2 * time.Hour)
		}
		e = server_handshake_start_flight(&owner, identity, now)
		if mode == 1 {
			testing.expect_value(t, e, .Binder_Failed)
		} else {
			testing.expect_value(t, e, .None)
			testing.expect_value(t, owner._resumed, mode == 0)
		}
		// Changed authenticated context must choose a complete new handshake.
		server_handshake_abort(&owner)
		server_handshake_destroy(&owner)
		testing.expect_value(t, owner._stats.live_bytes, 0)
	}
}

// The client handshake traffic secret of a TLS_AES_128_GCM_SHA256 flight.
server_test_client_secret :: proc(owner: ^Server_Handshake) -> (secret: [32]u8) {
	copy(secret[:], owner._flight.client_handshake_secret[:32])
	return
}
