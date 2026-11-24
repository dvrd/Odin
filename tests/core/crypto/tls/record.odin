package test_tls

import "core:bytes"
import "core:crypto/tls"
import "core:encoding/hex"
import "core:testing"

// RFC 8448 section 4: independent HKDF and AES-GCM wire vector. These bytes
// exercise the record machinery only; this client does not implement 0-RTT.
// https://www.rfc-editor.org/rfc/rfc8448#section-4
@(test)
rfc8448_record_vector :: proc(t: ^testing.T) {
	secret, ok := hex.decode(
		transmute([]u8)string("3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62"),
	); assert(ok == nil); defer delete(secret)
	expected, valid := hex.decode(
		transmute([]u8)string("1703030017ab1df420e75c457a7cc5d2844f76d5aee4b4edbf049be0"),
	); assert(valid == nil); defer delete(expected)
	traffic: [32]u8; copy(traffic[:], secret)
	key, iv := tls.traffic_key_iv(traffic)
	writer, reader: tls.Record_Protection
	tls.record_protection_init(&writer, key, iv); tls.record_protection_init(&reader, key, iv)
	wire: [28]u8
	n, err := tls.record_seal(&writer, wire[:], .Application_Data, transmute([]u8)string("ABCDEF"))
	testing.expect_value(t, err, .None)
	testing.expect(t, bytes.equal(wire[:n], expected))
	plaintext: [32]u8
	kind, body, open_error := tls.record_open(&reader, plaintext[:], expected)
	testing.expect_value(t, open_error, .None)
	testing.expect_value(t, kind, .Application_Data)
	testing.expect_value(t, string(body), "ABCDEF")
	tls.record_protection_clear(&reader); tls.record_protection_clear(&writer)
}
