package tests
import "core:net/quic/conn"
import "core:testing"

// Protected native packet exchange with an intentionally dropped Application
// CRYPTO packet. This is a simulator regression, not independent-peer evidence.
@(test)
conn_post_handshake_crypto_loss_ack_and_no_duplicate_delivery :: proc(t: ^testing.T) {
	p := open_pair(t, wide_limits(), false)
	defer close_pair(p)
	settle(t, p)
	ticket := []u8{4, 0, 0, 3, 1, 2, 3}
	testing.expect_value(t, conn.queue_post_handshake(p.server, ticket), .None)
	dropped: [conn.MAX_DATAGRAM]u8
	n, e := conn.pump(p.server, i64(p.link.now), dropped[:])
	testing.expect_value(t, e, .None)
	testing.expect(t, n > 0)
	testing.expect_value(t, len(conn.peek_post_handshake(p.client)), 0)
	timer := conn.timer(p.server, i64(p.link.now))
	testing.expect(t, timer.armed)
	replay: [conn.MAX_DATAGRAM]u8
	rn, re := conn.on_timeout(p.server, timer.at, replay[:])
	testing.expect_value(t, re, .None)
	testing.expect(t, rn > 0)
	testing.expect_value(t, conn.ingest(p.client, timer.at, 2, replay[:rn]), .None)
	testing.expect_value(t, string(conn.peek_post_handshake(p.client)), string(ticket))
	ack: [conn.MAX_DATAGRAM]u8
	an, ae := conn.pump(p.client, timer.at, ack[:])
	testing.expect_value(t, ae, .None)
	testing.expect(t, an > 0)
	testing.expect_value(t, conn.ingest(p.server, timer.at, 1, ack[:an]), .None)
	// Full capacity becomes available only after actual protected ACK retirement.
	full: [conn.POST_HANDSHAKE_CAP]u8
	testing.expect_value(t, conn.queue_post_handshake(p.server, full[:]), .None)
	testing.expect_value(t, conn.consume_post_handshake(p.client, len(ticket)), .None)
	testing.expect_value(t, conn.ingest(p.client, timer.at, 2, dropped[:n]), .None)
	testing.expect_value(t, len(conn.peek_post_handshake(p.client)), 0)
}
