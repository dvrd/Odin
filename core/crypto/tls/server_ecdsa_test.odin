package tls

import "core:testing"
import "core:time"
import credentials "credentials"
import credential_store "credentials/store"

@(test)
server_ecdsa_typed_offer_admission_and_finished_lifetime :: proc(t: ^testing.T) {
	for mode in 0 ..< 4 {
		store: ^credential_store.Store
		if mode == 1 {
			store = flight_test_store(t)
		} else {
			c, e := credentials.create(
				#load("../../../tests/core/crypto/tls/credentials/testdata/p256-valid.pem"),
				#load("../../../tests/core/crypto/tls/credentials/testdata/p256.pem"),
				{},
				context.allocator,
			); assert(e == .None)
			var_error: credential_store.Error
			store, var_error = credential_store.create({}, context.allocator)
			assert(var_error.kind == .None)
			assert(credential_store.replace(store, &c).kind == .None)
		}
		defer credential_store.destroy(&store)
		share := hello_test_share()
		base := hello_test_extensions(share[:])
		base[2].data = []u8{0, 2, 4, 3}
		if mode == 2 {
			base[2].data = []u8{0, 2, 8, 4}
		}
		exts: [6]Hello_Test_Extension
		copy(exts[:], base[:])
		exts[5] = {50, []u8{0, 2, 4, 3}}
		if mode == 3 {
			exts[5].data = []u8{0, 2, 4, 1}
		}
		storage: [1024]u8
		hello := hello_test_wire(storage[:], exts[:])
		a := Owner_Test_Audit {
			backing = context.allocator,
		}
		o: Server_Handshake
		owner_test_ready(t, &o, &a, hello)
		e := server_handshake_start_flight(&o, store, time.from_nanoseconds(1790000000 * 1000000000))
		if mode != 0 {
			testing.expect_value(t, e, .Unsupported)
		} else {
			testing.expect_value(t, e, .None)
			saw_verify := false
			for _ in 0 ..< 100 {
				event, ee := server_handshake_peek(&o)
				testing.expect_value(t, ee, .None)
				if event.kind == .None {
					break
				}
				testing.expect(t, event.kind != .Fatal)
				if event.kind == .Handshake_Bytes && len(event.bytes) > 8 && event.bytes[0] == 15 {
					saw_verify = true
					testing.expect_value(t, hello_u16(event.bytes, 4), u16(0x0403))
					testing.expect(t, len(event.bytes) >= 16 && len(event.bytes) <= 80)
				}
				testing.expect_value(t, server_handshake_accept(&o, event.id), .None)
			}
			testing.expect(t, saw_verify)
			testing.expect_value(t, o._phase, .Await_Client_Finished)
			snap, _ := credential_store.stats(store)
			testing.expect_value(t, snap.active_leases, 1)
		}
		server_handshake_destroy(&o)
		owner_test_clean(t, &a)
		snap, _ := credential_store.stats(store)
		testing.expect_value(t, snap.active_leases, 0)
	}
}
