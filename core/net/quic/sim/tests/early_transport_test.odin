package tests
import "core:crypto"
import "core:crypto/tls"
import "core:net/quic"
import "core:net/quic/conn"
import "core:testing"

@(test)
conn_early_stream_confirmation_rejection_and_shared_packet_numbers :: proc(t: ^testing.T) {
	for accepted in ([]bool{true, false}) {
		p := open_pair(t, wide_limits(), false)
		settle(t, p)
		client, server := new(conn.Connection), new(conn.Connection)
		client_early := quic.Handshake {
			role          = .Client,
			have_zero_rtt = true,
		}
		server_early := quic.Handshake {
			role          = .Server,
			have_zero_rtt = true,
		}
		secret: [32]u8
		secret[0] = 42
		keys, e := tls.quic_packet_keys_derive(secret, .Application)
		assert(e == nil)
		assert(
			quic.packet_keys_set_aes(
				&client_early.zero_rtt_write,
				keys.key[:],
				keys.iv[:],
				keys.hp[:],
				keys.secret[:],
				false,
			) ==
			.None,
		)
		assert(
			quic.packet_keys_set_aes(
				&server_early.zero_rtt_read,
				keys.key[:],
				keys.iv[:],
				keys.hp[:],
				keys.secret[:],
				false,
			) ==
			.None,
		); client_early.zero_rtt_write.zero_rtt = true; server_early.zero_rtt_read.zero_rtt = true
		tls.quic_direction_keys_clear(&keys)
		crypto.zero_explicit(&secret, size_of(secret))
		limits := wide_limits()
		limits.recv_max_stream_data = conn.STREAM_BYTES
		ccfg := conn.Adopt_Config {
			role         = .Client,
			local_cid    = p.client.local_cid[:p.client.local_cid_len],
			peer_cid     = p.server.local_cid[:p.server.local_cid_len],
			limits       = limits,
			max_datagram = 1200,
		}
		scfg := conn.Adopt_Config {
			role         = .Server,
			local_cid    = p.server.local_cid[:p.server.local_cid_len],
			peer_cid     = p.client.local_cid[:p.client.local_cid_len],
			limits       = limits,
			max_datagram = 1200,
		}
		testing.expect_value(t, conn.adopt_early(client, &client_early, ccfg), .None)
		if accepted {
			testing.expect_value(t, conn.adopt_early(server, &server_early, scfg), .None)
		}
		testing.expect(t, !conn.established(client) && conn.early(client))
		payload := []u8{1, 2, 3, 4}
		written, we := conn.write(client, 0, payload, true)
		testing.expect_value(t, we, .None)
		testing.expect_value(t, written, 4)
		clock := i64(100)
		packet: [conn.MAX_DATAGRAM]u8
		n, pe := conn.pump(client, clock, packet[:])
		testing.expect_value(t, pe, .None)
		testing.expect(t, n > 0)
		view, _, ve := quic.packet_decode_v1(packet[:n], 8)
		testing.expect_value(t, ve, .None)
		testing.expect_value(t, view.kind, .Zero_RTT)
		original := packet
		original_n := n
		if accepted {
			// Application PTO is forbidden until actual handshake confirmation.
			// The external handshake driver owns Initial/Handshake retransmission.
			timer := conn.timer(client, clock)
			testing.expect(t, !timer.armed)
			testing.expect_value(t, conn.ingest(server, clock + 1, 1, packet[:n]), .None)
			output: [16]u8
			rn, fin, re := conn.read(server, 0, output[:])
			testing.expect_value(t, re, .None)
			testing.expect_value(t, rn, 4)
			testing.expect(t, fin && string(output[:rn]) == string(payload))
			sn, se := conn.pump(server, clock + 1, packet[n:])
			testing.expect_value(t, se, .None)
			testing.expect_value(t, sn, 0)
		}
		early_next := client.model.spaces[2].next_send
		ccfg.next_send_pn = max(early_next, p.client.model.spaces[2].next_send)
		scfg.next_send_pn = p.server.model.spaces[2].next_send
		testing.expect_value(t, conn.confirm_early(client, &p.client.hs, ccfg, accepted, clock + 10), .None)
		if accepted {
			testing.expect_value(t, conn.confirm_early(server, &p.server.hs, scfg, true, clock + 10), .None)
		} else {
			testing.expect_value(t, conn.adopt_established(server, &p.server.hs, scfg), .None)
		}
		if accepted {
			testing.expect_value(t, conn.ingest(server, clock + 11, 1, original[:original_n]), .None)
			no_duplicate: [16]u8
			again, _, read_error := conn.read(server, 0, no_duplicate[:])
			testing.expect_value(t, read_error, .None)
			testing.expect_value(t, again, 0)
		}
		testing.expect(t, conn.established(client) && !conn.early(client))
		testing.expect(t, client.model.spaces[2].next_send >= early_next)
		if !accepted {
			n, pe = conn.pump(client, clock + 11, packet[:])
			testing.expect_value(t, pe, .None)
			testing.expect(t, n > 0)
			view, _, ve = quic.packet_decode_v1(packet[:n], 8)
			testing.expect_value(t, ve, .None)
			testing.expect_value(t, view.kind, .One_RTT)
			testing.expect_value(t, conn.ingest(server, clock + 11, 1, packet[:n]), .None)
			output: [16]u8
			rn, fin, re := conn.read(server, 0, output[:])
			testing.expect_value(t, re, .None)
			testing.expect_value(t, rn, 4)
			testing.expect(t, fin && string(output[:rn]) == string(payload))
		}
		conn.destroy(client)
		conn.destroy(server)
		free(client)
		free(server)
		quic.handshake_fail(&client_early)
		quic.handshake_fail(&server_early)
		close_pair(p)
	}
}
