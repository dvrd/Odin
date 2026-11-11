package tests

import "core:crypto"
import "core:crypto/tls"
import "core:net/quic"
import "core:testing"
import "core:time"

early_allow_get :: proc(method: string) -> bool {
	return method == "GET"
}

@(private)
early_test_nst :: proc(dst: []u8, ticket: []u8) -> []u8 {
	body := 4 + 4 + 1 + 1 + 2 + len(ticket) + 2 + 8
	if len(dst) < 4 + body || len(ticket) != 4 {
		return nil
	}
	for i in 0 ..< 4 + body {
		dst[i] = 0
	}
	dst[0] = 4
	dst[3] = u8(body)
	dst[7] = 100
	dst[11] = 9
	dst[12] = 1
	dst[13] = 7
	dst[14] = 0
	dst[15] = 4
	copy(dst[16:], ticket)
	at := 20
	dst[at], dst[at + 1] = 0, 8
	dst[at + 2], dst[at + 3], dst[at + 4], dst[at + 5] = 0x00, 0x2a, 0x00, 0x04
	dst[at + 6], dst[at + 7], dst[at + 8], dst[at + 9] = 0, 0, 0x10, 0
	return dst[:at + 10]
}

@(test)
zero_rtt_install_requires_policy :: proc(t: ^testing.T) {
	initial, handshake_buf, app: [64]u8
	h: quic.Handshake
	defer quic.handshake_fail(&h)
	testing.expect_value(t, quic.handshake_init(&h, .Client, []string{"h3"}, initial[:], handshake_buf[:], app[:]), .None)

	master: [32]u8
	master[0] = 0x42
	defer crypto.zero_explicit(&master, size_of(master))
	nst_buf: [64]u8
	nst := early_test_nst(nst_buf[:], []u8{1, 2, 3, 4})
	testing.expect(t, nst != nil)
	session: tls.Session
	defer tls.session_clear(&session)
	testing.expect(t, tls.session_remember(&session, master, nst, "example.com", time.now()))

	conn := new(tls.Conn)
	defer free(conn)
	conn.phase = .Handshake_Pending
	conn.config.server_name = "example.com"
	conn.config.session = &session
	testing.expect_value(t, tls.client_hello_prepare(conn).kind, .None)
	testing.expect(t, conn.psk_offered && !conn.early_offered)
	default_buf: [tls.MAX_CLIENT_HELLO_SIZE]u8
	default_n := copy(default_buf[:], conn.client_hello[:conn.client_hello_size])

	secret, ok := tls.session_early_secret(&session)
	defer crypto.zero_explicit(&secret, size_of(secret))
	testing.expect(t, ok)
	testing.expect_value(t, quic.handshake_install_zero_rtt(&h, secret[:]), .Zero_RTT_Disabled)
	testing.expect(t, !h.have_zero_rtt && !h.zero_rtt_write.initialized && !h.have_one_rtt)

	policy := tls.Early_Data_Policy {
		allow = early_allow_get,
	}
	// Default resumption hello has no early_data, so a policy still does not install.
	testing.expect_value(t, quic.handshake_install_zero_rtt(&h, secret[:], &policy, default_buf[:default_n]), .Zero_RTT_Disabled)
	testing.expect(t, !h.have_zero_rtt)

	conn.config.early_data = &policy
	conn.phase = .Handshake_Pending
	testing.expect_value(t, tls.client_hello_prepare(conn).kind, .None)
	testing.expect(t, conn.early_offered)
	early_hello := conn.client_hello[:conn.client_hello_size]
	// Opt-in unset on the install call still refuses, even if the hello offered early data.
	testing.expect_value(t, quic.handshake_install_zero_rtt(&h, secret[:], nil, early_hello), .Zero_RTT_Disabled)

	testing.expect_value(t, quic.handshake_install_zero_rtt(&h, secret[:], &policy, early_hello), .None)
	testing.expect(t, h.have_zero_rtt && h.zero_rtt_write.initialized && !h.have_one_rtt)
	testing.expect(t, crypto.is_zero_constant_time(h.zero_rtt_write.key[:16]) == 0)
	keys, err := tls.session_early_keys(&session, &policy, early_hello)
	defer tls.quic_direction_keys_clear(&keys)
	testing.expect_value(t, err.kind, .None)
	installed_key: [16]u8
	copy(installed_key[:], h.zero_rtt_write.key[:16])
	testing.expect(t, keys.secret == h.zero_rtt_write.secret && keys.key == installed_key)

	quic.handshake_fail(&h)
	testing.expect(t, !h.have_zero_rtt && !h.zero_rtt_write.initialized)
}
