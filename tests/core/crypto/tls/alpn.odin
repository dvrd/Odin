package test_tls

import "core:bytes"
import "core:crypto/tls"
import "core:testing"
import "core:mem"
import "core:crypto/x509"

@(test)
alpn_offers_encode_rfc7301_protocol_name_list :: proc(t: ^testing.T) {
	wire: [2048]u8
	n, error := tls.client_hello_encode(wire[:], {server_name = "localhost", alpn_protocols = {"h2", "http/1.1"}})
	testing.expect_value(t, error, nil)
	// RFC7301 extension16, data-length14, list-length12, two opaque names.
	expected := []u8{0, 16, 0, 14, 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	testing.expect(t, bytes.contains(wire[:n], expected))
}

@(test)
alpn_zero_offers_preserve_original_client_hello_wire :: proc(t: ^testing.T) {
	wire: [tls.MAX_CLIENT_HELLO_SIZE]u8
	n, error := tls.client_hello_encode(wire[:], {server_name = "localhost"})
	testing.expect_value(t, error, nil)
	testing.expect(t, bytes.equal(wire[:n], #load("testdata/hello_without_alpn.wire")))
}

@(test)
alpn_encoding_is_bounded_and_accepts_opaque_names_without_allocation :: proc(t: ^testing.T) {
	context.allocator = mem.nil_allocator()
	context.temp_allocator = mem.nil_allocator()
	wire: [tls.MAX_CLIENT_HELLO_SIZE]u8
	name: [255]u8
	for &b in name {b = 0xff}
	long := string(name[:])
	_, error := tls.client_hello_encode(
		wire[:],
		{server_name = "localhost", alpn_protocols = {long, long, long, long}},
	)
	assert(error == nil) //4*(255-byte name +1 length) exactly1024 list bytes.
	_, error = tls.client_hello_encode(wire[:], {server_name = "localhost", alpn_protocols = {"\x00\xff"}})
	assert(error == nil)
	for &b in wire {b = 0xa5}
	_, error = tls.client_hello_encode(
		wire[:],
		{server_name = "localhost", alpn_protocols = {long, long, long, long, "x"}},
	)
	assert(error == tls.Error(tls.General_Error.Invalid_Config))
	for b in wire {assert(b == 0xa5)}
	_, error = tls.client_hello_encode(wire[:], {server_name = "localhost", alpn_protocols = {""}})
	assert(error == tls.Error(tls.General_Error.Invalid_Config))
	oversized: [256]u8
	_, error = tls.client_hello_encode(wire[:], {server_name = "localhost", alpn_protocols = {string(oversized[:])}})
	assert(error == tls.Error(tls.General_Error.Invalid_Config))
	offers: [17]string
	for &offer in offers {offer = "x"}
	_, error = tls.client_hello_encode(wire[:], {server_name = "localhost", alpn_protocols = offers[:16]})
	assert(error == nil)
	_, error = tls.client_hello_encode(wire[:], {server_name = "localhost", alpn_protocols = offers[:]})
	assert(error == tls.Error(tls.General_Error.Invalid_Config))
	_ = t
}

@(test)
alpn_config_validation_rejects_invalid_offers_before_io :: proc(t: ^testing.T) {
	root: x509.Certificate
	settings := tls.Config {
		server_name    = "localhost",
		root_cas       = {&root},
		alpn_protocols = {""},
	}
	testing.expect_value(t, tls.config_validate(settings), tls.Error(tls.General_Error.Invalid_Config))
}

@(test)
alpn_selection_is_checked_before_authentication_and_not_exposed :: proc(t: ^testing.T) {
	valid := []u8{8, 0, 0, 11, 0, 9, 0, 16, 0, 5, 0, 3, 2, 'h', '2'}
	conn := new(tls.Conn)
	defer free(conn)
	conn.phase = .Server_Finished_Received
	conn.config = {
		server_name    = "localhost",
		alpn_protocols = {"h2"},
	}
	error := tls.handshake_server_flight_verify(conn, valid)
	// A legal ALPN selection reaches the missing Certificate, never success.
	testing.expect_value(t, error, tls.Error(tls.Protocol_Error.Decode_Error))
	testing.expect_value(t, tls.connection_state(conn).negotiated_protocol, "")
	conn.phase = .Server_Finished_Received
	conn.config = {
		server_name    = "localhost",
		alpn_protocols = {"http/1.1"},
	}
	error = tls.handshake_server_flight_verify(conn, valid)
	testing.expect_value(t, error, tls.Error(tls.Protocol_Error.Illegal_Parameter))
	testing.expect_value(t, tls.connection_state(conn).negotiated_protocol, "")
	// An unsolicited response remains an unsupported extension, even if valid.
	testing.expect_value(t, tls.encrypted_extensions_validate(valid, "localhost"), .Unsupported_Extension)
}

@(test)
alpn_rejects_malformed_and_duplicate_server_selections :: proc(t: ^testing.T) {
	messages := []struct {
		wire:     []u8,
		expected: tls.Error,
	} {
		// Empty name; extra zero byte cannot repair its zero length.
		{{8, 0, 0, 10, 0, 8, 0, 16, 0, 4, 0, 2, 0, 0}, tls.Protocol_Error.Decode_Error},
		// Two names are forbidden in a server selection.
		{{8, 0, 0, 14, 0, 12, 0, 16, 0, 8, 0, 6, 2, 'h', '2', 2, 'h', '3'}, tls.Protocol_Error.Decode_Error},
		// Duplicate extension16 is forbidden even for the same chosen name.
		{{8, 0, 0, 20, 0, 18, 0, 16, 0, 5, 0, 3, 2, 'h', '2', 0, 16, 0, 5, 0, 3, 2, 'h', '2'}, tls.Protocol_Error.Decode_Error},
		// A valid selection followed by garbage in its list is not a match.
		{{8, 0, 0, 12, 0, 10, 0, 16, 0, 6, 0, 4, 2, 'h', '2', 0}, tls.Protocol_Error.Decode_Error},
		// Selection list length does not fit its extension.
		{{8, 0, 0, 11, 0, 9, 0, 16, 0, 5, 0, 4, 2, 'h', '2'}, tls.Protocol_Error.Decode_Error},
		{{8, 0, 0, 6, 0, 4, 0, 16, 0, 0}, tls.Protocol_Error.Decode_Error},
		{{8, 0, 0, 10, 0, 8, 0, 16, 0, 4, 0, 2, 1, 'x'}, tls.Protocol_Error.Illegal_Parameter},
	}
	conn := new(tls.Conn)
	defer free(conn)
	for message in messages {
		conn.phase = .Server_Finished_Received
		conn.config = {
			server_name    = "localhost",
			alpn_protocols = {"h2"},
		}
		error := tls.handshake_server_flight_verify(conn, message.wire)
		testing.expect_value(t, error, message.expected)
		testing.expect_value(t, tls.connection_state(conn).negotiated_protocol, "")
	}
}

@(test)
alpn_keeps_existing_exported_procedure_signatures :: proc(t: ^testing.T) {
	validator: proc([]u8, string) -> tls.Error = tls.encrypted_extensions_validate
	encoder: proc([]u8, tls.Client_Hello) -> (int, tls.Error) = tls.client_hello_encode
	testing.expect(t, validator != nil && encoder != nil)
}
