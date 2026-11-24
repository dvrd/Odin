package test_tls

import "core:crypto/tls"
import "core:crypto/x509"
import "core:net"
import "core:testing"
import "core:time"

ALPN_Bind_Probe :: struct {
	writes: int,
}

alpn_bind_read :: proc(data: rawptr, dst: []u8) -> (int, net.Connection_Error) {
	_ = data
	_ = dst
	return 0, {kind = .Peer_Closed}
}

alpn_bind_write :: proc(data: rawptr, src: []u8) -> (int, net.Connection_Error) {
	_ = src
	(cast(^ALPN_Bind_Probe)data).writes += 1
	return 0, {kind = .Peer_Closed}
}

alpn_bind_close :: proc(data: rawptr) -> net.Connection_Error {
	_ = data
	return {}
}

alpn_bind_submit :: proc(
	data: rawptr,
	op: ^net.Async_Operation,
	kind: net.Async_Operation_Kind,
	buffer: []u8,
	deadline: time.Time,
) -> net.Connection_Error {
	_ = op
	_ = kind
	_ = buffer
	_ = deadline
	(cast(^ALPN_Bind_Probe)data).writes += 1
	return {kind = .Invalid_Connection}
}

alpn_bind_cancel :: proc(data: rawptr, op: ^net.Async_Operation) -> net.Connection_Error {
	_ = data
	_ = op
	return {}
}

alpn_bind_schedule :: proc(data: rawptr, callback: proc(rawptr), user_data: rawptr) {
	_ = data
	_ = callback
	_ = user_data
}

@(test)
alpn_transport_tcp_and_quic_offers_do_not_share_a_stack :: proc(t: ^testing.T) {
	testing.expect_value(t, tls.alpn_transport_offers(.TCP, nil), .None)
	for protocols in ([?][]string{{"http/1.1"}, {"h2"}, {"http/1.1", "h2"}, {"h2", "http/1.1"}}) {
		testing.expect_value(t, tls.alpn_transport_offers(.TCP, protocols), .None)
	}
	for protocols in ([?][]string {
			{"h3"},
			{"http/1.1", "h3"},
			{"h2", "h3"},
			{""},
			{"http/2"},
			{"H3"},
			{"private/client"},
		}) {
		testing.expect_value(t, tls.alpn_transport_offers(.TCP, protocols), .Invalid_ALPN)
	}
	h3 := [1]string{tls.ALPN_H3}
	testing.expect_value(t, tls.alpn_transport_offers(.QUIC, h3[:]), .None)
	testing.expect_value(t, tls.alpn_transport_offers(.QUIC, nil), .Invalid_ALPN)
	for protocols in ([?][]string{{"h2"}, {"http/1.1"}, {"h3", "h3"}, {"H3"}, {"h3", "http/1.1"}}) {
		testing.expect_value(t, tls.alpn_transport_offers(.QUIC, protocols), .Invalid_ALPN)
	}
	wire: [tls.MAX_CLIENT_HELLO_SIZE]u8
	n, encode_error := tls.client_hello_encode(wire[:], {server_name = "localhost", alpn_protocols = h3[:]})
	testing.expect_value(t, encode_error, .None)
	testing.expect(t, n > 0)

	root: x509.Certificate
	base := tls.Config {
		server_name = "localhost",
		root_cas    = {&root},
	}
	testing.expect_value(t, tls.config_validate(base), .None)
	h3_config := base
	h3_config.alpn_protocols = h3[:]
	testing.expect_value(t, tls.config_validate(h3_config), .None)

	probe: ALPN_Bind_Probe
	transport := net.Connection {
		data  = &probe,
		read  = alpn_bind_read,
		write = alpn_bind_write,
		close = alpn_bind_close,
	}
	conn := new(tls.Conn)
	defer free(conn)
	testing.expect_value(t, tls.client(conn, transport, h3_config), .Invalid_ALPN)
	testing.expect_value(t, probe.writes, 0)
	testing.expect_value(t, conn.phase, .Uninitialized)

	mixed := [2]string{"http/1.1", "h3"}
	mixed_config := base
	mixed_config.alpn_protocols = mixed[:]
	testing.expect_value(t, tls.client(conn, transport, mixed_config), .Invalid_ALPN)
	testing.expect_value(t, probe.writes, 0)

	h2 := [2]string{"http/1.1", "h2"}
	h2_config := base
	h2_config.alpn_protocols = h2[:]
	testing.expect_value(t, tls.client(conn, transport, h2_config), .None)
	testing.expect_value(t, probe.writes, 0)
	testing.expect_value(t, len(conn.config.alpn_protocols), 2)
	conn^ = {}
	testing.expect_value(t, tls.client(conn, transport, base), .None)
	testing.expect_value(t, len(conn.config.alpn_protocols), 0)
	testing.expect_value(t, probe.writes, 0)

	dial_conn := new(tls.Conn)
	defer free(dial_conn)
	dialed := tls.dial(dial_conn, "127.0.0.1", 1, h3_config)
	testing.expect_value(t, dialed.kind, .Invalid_Config)
	testing.expect_value(t, dialed.config, .Invalid_ALPN)
	testing.expect_value(t, dial_conn.phase, .Uninitialized)

	async_conn := new(tls.Async_Conn)
	defer free(async_conn)
	underlying := net.Async_Connection {
		data   = &probe,
		submit = alpn_bind_submit,
		cancel = alpn_bind_cancel,
	}
	executor := net.Async_Executor {
		schedule = alpn_bind_schedule,
	}
	testing.expect_value(t, tls.async_client(async_conn, underlying, executor, h3_config), .Invalid_ALPN)
	testing.expect_value(t, probe.writes, 0)
	testing.expect(t, !async_conn.initialized)
}
