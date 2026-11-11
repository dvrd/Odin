package tests
import "core:crypto/aes"
import "core:net"
import "core:net/quic"
import "core:net/quic/conn"
import "core:testing"

@(private)
reserved_application_packet :: proc(p: ^Pair, bad_tag: bool) -> []u8 {
	packet := make([]u8, 64)
	pn := p.client.model.spaces[2].next_send
	hn, _, he := quic.short_header_encode_v1(
		packet,
		{
			destination_id = p.server.local_cid[:p.server.local_cid_len],
			packet_number = u32(pn),
			packet_number_length = 2,
		},
	)
	assert(he == .None); packet[0] |= 0x08
	keys := &p.client.hs.one_rtt_write; assert(keys.aead == .AES_128_GCM)
	nonce, ne := quic.packet_nonce(keys, pn); assert(ne == .None)
	ctx: aes.Context_GCM; aes.init_gcm(&ctx, keys.key[:16]); defer aes.reset_gcm(&ctx)
	plaintext := [4]u8{1, 0, 0, 0}
	aes.seal_gcm(
		&ctx,
		packet[hn:hn + 4],
		packet[hn + 4:hn + 20],
		nonce[:],
		packet[:hn],
		plaintext[:],
	)
	if bad_tag {
		packet[hn + 19] ~= 1
	}
	assert(
		quic.handshake_header_protection_apply(
			&p.client.hs,
			packet[:hn + 20],
			.One_RTT,
			p.server.local_cid_len,
		) ==
		.None,
	)
	return packet[:hn + 20]
}
@(test)
conn_reserved_bits_only_fail_after_authentication :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	bad := reserved_application_packet(p, true); defer delete(bad)
	e := conn.ingest_from(p.server, i64(p.link.now), {net.IP4_Loopback, 4000}, bad)
	testing.expect(t, e == .None || e == .Discarded); testing.expect(t, conn.established(p.server))
	valid := reserved_application_packet(p, false); defer delete(valid)
	testing.expect_value(
		t,
		conn.ingest_from(p.server, i64(p.link.now), {net.IP4_Loopback, 4000}, valid),
		.Protocol,
	)
	testing.expect_value(t, p.server.phase, .Failed)
}
@(test)
conn_short_malformed_active_cid_packets_preserve_connection :: proc(t: ^testing.T) {
	p := migration_pair(t); defer close_pair(p)
	for size in 1 ..< 21 {
		packet: [32]u8; packet[0] = 0x40
		copy(packet[1:], p.server.local_cid[:p.server.local_cid_len])
		e := conn.ingest_from(p.server, i64(p.link.now), {net.IP4_Loopback, 4000}, packet[:size])
		testing.expect(t, e == .None || e == .Discarded)
	}
	_, we := conn.write(p.client, 0, []u8{1}, true); assert(we == .None)
	migration_exchange(t, p, 4000, 40)
	got: [4]u8; n, fin, re := conn.read(p.server, 0, got[:]); testing.expect_value(t, re, .None)
	testing.expect(t, n == 1 && fin)
}
