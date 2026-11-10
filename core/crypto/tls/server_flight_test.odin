package tls

import "core:crypto/rsa"
import "core:crypto/x25519"
import "core:crypto/x509"
import "core:fmt"
import "core:mem"
import "core:testing"
import "core:time"
import credentials "credentials"
import credential_store "credentials/store"

flight_test_store :: proc(t: ^testing.T, large := false, repeat := 1) -> ^credential_store.Store {
	cert := #load("../../../tests/core/crypto/tls/credentials/testdata/rsa2048-valid.pem")
	key := #load("../../../tests/core/crypto/tls/credentials/testdata/rsa2048.pem")
	if large {
		cert = #load("../../../tests/core/crypto/tls/credentials/testdata/rsa4096-valid.pem")
		key = #load("../../../tests/core/crypto/tls/credentials/testdata/rsa4096.pem")
	}
	chain := make([]u8, len(cert) * repeat); defer delete(chain)
	for i in 0 ..< repeat {copy(chain[i * len(cert):], cert)}
	c, e := credentials.create(chain, key, {}, context.allocator)
	assert(e == .None)
	store, se := credential_store.create({}, context.allocator); assert(se.kind == .None)
	assert(credential_store.replace(store, &c).kind == .None)
	return store
}
flight_test_hello :: proc(
	dst: []u8,
	session: []u8 = nil,
	certificate_offer := true,
) -> (
	[]u8,
	[32]u8,
) {
	private: [32]u8; for &b, i in private[:] {b = u8(i + 1)}
	public: [32]u8; x25519.scalarmult_basepoint(public[:], private[:])
	share := hello_test_share(); copy(share[6:], public[:])
	base := hello_test_extensions(share[:])
	signatures := [4]u8{0, 2, 4, 1}
	extensions: [6]Hello_Test_Extension; copy(extensions[:], base[:])
	extensions[5] = {50, signatures[:]}
	return hello_test_wire(dst, extensions[:6 if certificate_offer else 5], session), private
}
flight_test_start :: proc(
	t: ^testing.T,
	o: ^Server_Handshake,
	a: ^Owner_Test_Audit,
	store: ^credential_store.Store,
	wire: []u8,
) {
	owner_test_ready(t, o, a, wire)
	testing.expect_value(
		t,
		server_handshake_start_flight(o, store, time.from_nanoseconds(1790000000 * 1000000000)),
		.None,
	)
}

@(test)
server_flight_crypto_order_streaming_and_pin :: proc(t: ^testing.T) {
	for large in ([]bool{false, true}) {
		// Repeated DER intentionally exercises a chain cursor; ancestry/trust
		// verification belongs to credential publication policy, not this owner.
		store := flight_test_store(t, large, 3); defer credential_store.destroy(&store)
		a := Owner_Test_Audit {
			backing = context.allocator,
		}; o: Server_Handshake
		storage: [1024]u8; session := []u8{1, 2, 3, 4}
		hello, client_private := flight_test_hello(storage[:], session)
		flight_test_start(t, &o, &a, store, hello)
		reference: Handshake_Transcript; transcript_init(&reference)
		transcript_update(&reference, hello)
		private, random: [32]u8
		for &b, i in private[:] {b = u8(100 + i)}
		for &b, i in random[:] {b = u8(200 + i)}
		testing.expect_value(t, server_flight_prepare_hello(&o, private, random), .None)
		var_private := client_private
		shared: [32]u8
		expected_hs: Handshake_Secrets; expected_app: Application_Secrets
		flight: [dynamic]u8; defer delete(flight)
		secret_index := 0
		started := time.tick_now()
		for events := 0; events < 100; events += 1 {
			event, e := server_handshake_peek(&o); testing.expect_value(t, e, .None)
			if event.kind == .None {
				break
			}
			before := transcript_snapshot(&o._transcript)
			for _ in 0 ..< 3 {
				again, _ := server_handshake_peek(&o)
				testing.expect_value(t, again.id, event.id)
				testing.expect_value(t, transcript_snapshot(&o._transcript), before)
				testing.expect_value(t, server_handshake_accept(&o, event.id + 1), .Invalid_Event)
			}
			testing.expect(t, event.kind != .Complete && event.kind != .Fatal)
			if event.kind == .Handshake_Bytes {
				testing.expect(t, len(event.bytes) <= 2048)
				if event.level == .Initial {
					sh := event.bytes
					testing.expect_value(t, int(sh[38]), len(session))
					testing.expect_value(t, string(sh[39:43]), string(session))
					testing.expect_value(t, string(sh[6:38]), string(random[:]))
					x25519.scalarmult(shared[:], var_private[:], sh[len(sh) - 32:])
					hs, he := handshake_secrets_derive(shared, hello, sh); assert(he == .None)
					expected_hs = hs
					transcript_update(&reference, sh)
					testing.expect_value(t, expected_hs, o._flight.handshake)
				} else {
					append(&flight, ..event.bytes)
					transcript_update(&reference, event.bytes)
				}
			} else if event.kind == .Traffic_Secret {
				expected: [32]u8
				switch secret_index {
				case 0:
					expected = expected_hs.server_traffic_secret
				case 1:
					expected = expected_hs.client_traffic_secret
				case 2:
					expected_app = application_secrets_derive(
						expected_hs.handshake_secret,
						transcript_snapshot(&reference),
					)
					expected = expected_app.server_traffic_secret
				case 3:
					expected = expected_app.client_traffic_secret
				case:
					testing.expect(t, false)
				}
				testing.expect_value(
					t,
					event.direction,
					.Write if secret_index % 2 == 0 else .Read,
				)
				testing.expect_value(
					t,
					event.level,
					.Handshake if secret_index < 2 else .Application,
				)
				testing.expect_value(t, string(event.secret), string(expected[:]))
				secret_index += 1
			}
			testing.expect_value(t, server_handshake_accept(&o, event.id), .None)
			testing.expect_value(
				t,
				transcript_snapshot(&o._transcript),
				transcript_snapshot(&reference),
			)
			// Closing the store retires the generation, but every pending DER
			// chunk/signature still succeeds under the same live lease.
			if events == 0 {
				testing.expect_value(t, credential_store.close(store).kind, .None)
			}
			stats, _ := credential_store.stats(store)
			testing.expect_value(t, stats.active_leases, 1)
		}
		testing.expect_value(t, secret_index, 4)
		testing.expect_value(t, o._phase, .Await_Client_Finished)
		testing.expect(t, mem.check_zero_ptr(&o._flight.handshake, size_of(o._flight.handshake)))
		testing.expect(
			t,
			mem.check_zero_ptr(&o._flight.application, size_of(o._flight.application)),
		)
		ss, _ := credential_store.stats(store); testing.expect_value(t, ss.active_leases, 1)
		testing.expect_value(t, ss.generations, 1)
		// Decode concatenated test output independently of producer stages.
		at := 0; expected_types := []u8{8, 11, 15, 20}
		verify_transcript: Handshake_Transcript; transcript_init(&verify_transcript)
		transcript_update(&verify_transcript, hello)
		public: [32]u8; x25519.scalarmult_basepoint(public[:], private[:])
		sh: [122]u8; shn := server_flight_hello(sh[:], session, public, random)
		transcript_update(&verify_transcript, sh[:shn])
		for kind in expected_types {
			n := 4 + handshake_body_size(flight[at:]); msg := flight[at:at + n]
			testing.expect_value(t, msg[0], kind)
			if kind == 15 {
				leaf: x509.Certificate
				certmsg := flight[6:]
				length := int(certmsg[8]) << 16 | int(certmsg[9]) << 8 | int(certmsg[10])
				parsed, pe := x509.parse(certmsg[11:11 + length], context.allocator)
				assert(pe == .None); leaf = parsed
				pub: rsa.Public_Key; assert(rsa.public_key_set_bytes(&pub, leaf.rsa_n, leaf.rsa_e))
				signed := certificate_verify_input(transcript_snapshot(&verify_transcript), true)
				testing.expect(
					t,
					rsa.verify_pss(&pub, .SHA256, 32, signed[:], msg[8:], mgf1_algo = .SHA256),
				)
				rsa.public_key_clear(&pub); x509.destroy(&leaf)
			}
			if kind == 20 {
				testing.expect_value(
					t,
					finished_verify(
						msg,
						expected_hs.server_traffic_secret,
						transcript_snapshot(&verify_transcript),
					),
					.None,
				)
			}
			transcript_update(&verify_transcript, msg); at += n
		}
		testing.expect_value(t, at, len(flight))
		fmt.printf(
			"flight RSA%d: output=%d owner=%d peak=%d allocations=%d signing+drain=%v\n",
			4096 if large else 2048,
			len(flight),
			size_of(o),
			a.peak,
			a.calls,
			time.tick_since(started),
		)
		server_handshake_destroy(&o); owner_test_clean(t, &a)
		ss,_ = credential_store.stats(store); testing.expect_value(t,ss.active_leases,0); testing.expect_value(t,ss.generations,0)
	}
}

@(test)
server_flight_admission_rejections :: proc(t: ^testing.T) {
	store := flight_test_store(t); defer credential_store.destroy(&store)
	for mode in 0 ..< 5 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}; o: Server_Handshake; storage: [1024]u8
		wire, _ := flight_test_hello(storage[:], nil, mode != 0)
		owner_test_ready(t, &o, &a, wire)
		now := time.from_nanoseconds(1790000000 * 1000000000)
		if mode == 1 {
			now = time.from_nanoseconds(0)
		}
		if mode == 2 {
			now = time.from_nanoseconds(max(i64))
		}
		if mode == 3 {
			o._hello.has_quic_transport_parameters = true
		}
		s := store; if mode == 4 {
			s = nil
		}
		e := server_handshake_start_flight(&o, s, now)
		testing.expect(t, e == .Unsupported || e == .Credential_Failed)
		event, _ := server_handshake_peek(&o); testing.expect_value(t, event.kind, .Fatal)
		stats, _ := credential_store.stats(store); testing.expect_value(t, stats.active_leases, 0)
		server_handshake_destroy(&o); owner_test_clean(t, &a)
	}
	for algorithm in x509.Signature_Algorithm {
		scheme := server_flight_certificate_scheme(algorithm)
		testing.expect_value(
			t,
			scheme != 0,
			algorithm == .RSA_SHA256 || algorithm == .RSA_SHA384 || algorithm == .RSA_SHA512 || algorithm == .ECDSA_SHA256,
		)
	}
}

@(test)
server_flight_abort_each_event_and_allocation_failure :: proc(t: ^testing.T) {
	store := flight_test_store(t); defer credential_store.destroy(&store)
	for stop in 0 ..< 16 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}; o: Server_Handshake; storage: [1024]u8
		wire, _ := flight_test_hello(storage[:]); flight_test_start(t, &o, &a, store, wire)
		for _ in 0 ..< stop {
			event, _ := server_handshake_peek(&o)
			if event.kind == .None {
				break
			}
			testing.expect_value(t, server_handshake_accept(&o, event.id), .None)
		}
		event, _ := server_handshake_peek(&o)
		server_handshake_abort(&o)
		testing.expect_value(t, server_handshake_accept(&o, event.id), .Invalid_Event)
		stats, _ := credential_store.stats(store); testing.expect_value(t, stats.active_leases, 0)
		testing.expect(t, mem.check_zero_ptr(&o._flight, size_of(o._flight)))
		server_handshake_destroy(&o); owner_test_clean(t, &a)
	}
	for mode in 0 ..< 4 {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}; o: Server_Handshake; storage: [1024]u8
		wire, _ := flight_test_hello(storage[:]); flight_test_start(t, &o, &a, store, wire)
		switch mode {
		case 0:
			a.fail_at = 2
		case 1:
			a.delta = 17
		case 2:
			a.error_with_grant = true
		case 3:
			o._next_id = max(u64)
		}
		event, _ := server_handshake_peek(&o)
		testing.expect_value(t, event.kind, .Fatal if mode != 3 else .None)
		stats, _ := credential_store.stats(store); testing.expect_value(t, stats.active_leases, 0)
		server_handshake_destroy(&o); owner_test_clean(t, &a)
	}
}

@(test)
server_flight_rejects_zero_share_and_signing_failure :: proc(t: ^testing.T) {
	store := flight_test_store(t); defer credential_store.destroy(&store)
	for bad_share in ([]bool{true, false}) {
		a := Owner_Test_Audit {
			backing = context.allocator,
		}; o: Server_Handshake; storage: [1024]u8
		wire, _ := flight_test_hello(storage[:]); flight_test_start(t, &o, &a, store, wire)
		if bad_share {
			for &b in o._selection.peer_key_share {b = 0}
		} else {
			for o._flight.stage != .Verify {
				event, _ := server_handshake_peek(&o)
				assert(event.kind != .None && event.kind != .Fatal)
				assert(server_handshake_accept(&o, event.id) == .None)
			}
			// Simulate a lost lease at the signing boundary (internal fault
			// injection only). It must terminate without bytes or success.
			assert(credential_store.release(store, &o._flight.lease).kind == .None)
		}
		event, _ := server_handshake_peek(&o)
		testing.expect_value(t, event.kind, .Fatal)
		testing.expect_value(t, event.error, .Malformed if bad_share else .Signing_Failed)
		stats, _ := credential_store.stats(store); testing.expect_value(t, stats.active_leases, 0)
		server_handshake_destroy(&o); owner_test_clean(t, &a)
	}
}
