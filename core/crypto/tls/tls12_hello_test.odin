package tls

import "core:mem"
import "core:testing"

@(private)
tls12_test_server_hello :: proc(dst: []u8, extensions: []u8) -> []u8 {
	at := 4
	hello_put_u16(dst, &at, 0x0303)
	for i in 0 ..< 32 {dst[at + i] = u8(i)}
	at += 32
	dst[at] = 0
	at += 1
	hello_put_u16(dst, &at, 0xc02f)
	dst[at] = 0
	at += 1
	hello_put_u16(dst, &at, u16(len(extensions)))
	copy(dst[at:], extensions)
	at += len(extensions)
	dst[0], dst[1], dst[2], dst[3] = 2, 0, u8((at - 4) >> 8), u8(at - 4)
	return dst[:at]
}

@(test)
tls12_server_hello_validation_and_borrowing :: proc(t: ^testing.T) {
	storage: [512]u8
	exts := [?]u8{0, 23, 0, 0, 0xff, 1, 0, 1, 0, 0, 16, 0, 11, 0, 9, 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	wire := tls12_test_server_hello(storage[:], exts[:])
	offer := TLS12_Client_Hello {
		server_name    = "fixture.test",
		alpn_protocols = {"http/1.1"},
	}
	old := context.allocator
	context.allocator = mem.panic_allocator()
	hello, e := tls12_server_hello_decode(wire, offer)
	context.allocator = old
	testing.expect_value(t, e, .None)
	testing.expect(t, hello.extended_master_secret && hello.secure_renegotiation)
	testing.expect_value(t, string(hello.alpn_selected), "http/1.1")
	testing.expect(t, raw_data(hello.alpn_selected) >= raw_data(wire))
	for split in 0 ..< len(wire) {
		_, status := tls12_server_hello_decode(wire[:split], offer)
		testing.expect(t, status != .None)
	}
	for i in 0 ..< len(wire) {
		original := wire[i]
		wire[i] = original ~ 0x80
		_, status := tls12_server_hello_decode(wire, offer)
		// Random is opaque; all other mutated fields must reject.
		if i < 6 || i >= 38 {
			testing.expect(t, status != .None)
		}
		wire[i] = original
	}
	_, unoffered := tls12_server_hello_decode(wire, {server_name = "fixture.test"})
	testing.expect_value(t, unoffered, .Invalid_ALPN)
	copy(wire[30:38], transmute([]u8)string("DOWNGRD\x01"))
	_, downgrade := tls12_server_hello_decode(wire, offer, tls13_offered = true)
	testing.expect_value(t, downgrade, .Downgrade_Detected)
	_, legacy := tls12_server_hello_decode(wire, offer)
	testing.expect_value(t, legacy, .None)
	wire[37] = 0
	_, downgrade_zero := tls12_server_hello_decode(wire, offer, tls13_offered = true)
	testing.expect_value(t, downgrade_zero, .Downgrade_Detected)
}

@(test)
tls12_server_hello_extension_policy :: proc(t: ^testing.T) {
	storage: [512]u8
	offer := TLS12_Client_Hello {
		server_name = "fixture.test",
	}
	cases := []struct {
		data:  []u8,
		error: TLS12_Hello_Error,
	} {
		{{}, .Missing_Extended_Master_Secret},
		{{0, 23, 0, 0}, .Missing_Secure_Renegotiation},
		{{0xff, 1, 0, 1, 0}, .Missing_Extended_Master_Secret},
		{{0, 23, 0, 0, 0, 23, 0, 0}, .Duplicate_Extension},
		{{0, 23, 0, 1, 0}, .Invalid_Extension},
		{{0xff, 1, 0, 1, 1}, .Invalid_Extension},
		{{0, 43, 0, 2, 3, 3}, .Unsupported_Extension},
		{{0, 11, 0, 2, 1, 1}, .Invalid_Extension},
	}
	for c in cases {
		wire := tls12_test_server_hello(storage[:], c.data)
		_, e := tls12_server_hello_decode(wire, offer)
		testing.expect_value(t, e, c.error)
	}
	valid := [?]u8{0, 23, 0, 0, 0xff, 1, 0, 1, 0, 0, 0, 0, 0}
	wire := tls12_test_server_hello(storage[:], valid[:])
	_, dns := tls12_server_hello_decode(wire, offer)
	testing.expect_value(t, dns, .None)
	_, ip := tls12_server_hello_decode(wire, {server_name = "127.0.0.1"})
	testing.expect_value(t, ip, .Invalid_Extension)
	// Old-style server capabilities may include deprecated formats; our
	// selected point encoding remains uncompressed.
	points := [?]u8{0, 23, 0, 0, 0xff, 1, 0, 1, 0, 0, 11, 0, 4, 3, 0, 1, 2}
	_, capabilities := tls12_server_hello_decode(tls12_test_server_hello(storage[:], points[:]), offer)
	testing.expect_value(t, capabilities, .None)
}
