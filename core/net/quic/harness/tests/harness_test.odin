package tests

import "core:mem"
import "core:net/quic"
import "core:net/quic/harness"
import "core:net/quic/sim"
import "core:testing"

Hold :: struct {
	m:          harness.Model,
	ip, hp, ap: [64]harness.Packet,
	st:         [32]harness.Stream,
}

wide :: proc() -> harness.Limits {
	return {
		max_data = 1_000_000,
		max_stream_data = 1_000_000,
		max_streams = 32,
		recv_max_data = 1_000_000,
		recv_max_stream_data = 1_000_000,
		recv_max_streams = 32,
	}
}

boot :: proc(t: ^testing.T, h: ^Hold, role: harness.Role, local, peer: u8) {
	testing.expect_value(
		t,
		harness.init(&h.m, role, []u8{local}, []u8{peer}, h.ip[:], h.hp[:], h.ap[:], h.st[:], 1200),
		.None,
	)
}

active :: proc(m: ^harness.Model, space: harness.Space, pn: u64) -> bool {
	for p in m.packets[int(space)] {
		if p.active && p.number == pn {
			return true
		}
	}
	return false
}

@(test)
published_vectors :: proc(t: ^testing.T) {
	n, trunc, err := harness.pn_wire_length(0xac5c02, true, 0xabe8b3)
	testing.expect(t, err == .None && n == 2 && trunc == 0x5c02)
	n, trunc, err = harness.pn_wire_length(0xace8fe, true, 0xabe8b3)
	testing.expect(t, err == .None && n == 3 && trunc == 0xace8fe)
	full, ok := harness.pn_decode(true, 0xa82f30ea, 0x9b32, 16)
	testing.expect(t, ok && full == 0xa82f9b32)
	full, ok = harness.pn_decode(false, 0, 0x9b32, 16)
	testing.expect(t, ok && full == 0x9b32)
	testing.expect_value(t, harness.initial_window(1200), 12000)
	testing.expect_value(t, harness.initial_window(2000), 14720)
	testing.expect_value(t, harness.initial_window(10000), 20000)
	testing.expect_value(t, harness.minimum_window(1200), 2400)
	// Integer assignment order. The RFC's real-valued 999 ms is not what the pseudocode stores.
	testing.expect_value(t, harness.initial_handshake_pto(), i64(997))
	period, duration, persistent := harness.persistent_congestion_example()
	testing.expect(t, period == 7 && duration == 6 && persistent)
	testing.expect(t, harness.self_check())
	compared, gate_ok := harness.darwin_vs_linux_gate()
	testing.expect(t, !compared && gate_ok && harness.LINUX_PEER_UNSUPPORTED)
}

@(test)
initial_pto_and_anti_deadlock :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	timer := harness.loss_detection_timer(&h.m, 0)
	testing.expect(t, timer.armed && timer.kind == .Anti_Deadlock_Initial && timer.at == 997)
	testing.expect_value(t, harness.arm_handshake(&h.m), .None)
	timer = harness.loss_detection_timer(&h.m, 0)
	testing.expect(t, timer.armed && timer.kind == .Anti_Deadlock_Handshake && timer.space == .Handshake)
	dst: [1200]u8
	n, err := harness.emit(&h.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect(t, err == .None && n == 1200)
	timer = harness.loss_detection_timer(&h.m, 0)
	testing.expect(t, timer.armed && timer.kind == .Probe && timer.space == .Initial && timer.at == 997)
	_, _, early := harness.on_timeout(&h.m, 996, nil)
	testing.expect_value(t, early, .Invalid_Input)
	testing.expect(t, active(&h.m, .Initial, 0) && h.m.pto_count == 0 && h.m.congestion_window == 12000)
	lost_n, kind, te := harness.on_timeout(&h.m, 997, nil)
	testing.expect(t, te == .None && kind == .Probe && lost_n == 0)
	testing.expect(t, active(&h.m, .Initial, 0) && h.m.pto_count == 1 && h.m.congestion_window == 12000)
}

@(test)
application_pto_is_1022 :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	testing.expect_value(t, harness.confirm_handshake(&h.m), .None)
	dst: [128]u8
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Application, ping = true, more_data = true})
	testing.expect_value(t, err, .None)
	timer := harness.loss_detection_timer(&h.m, 0)
	testing.expect(t, timer.armed && timer.kind == .Probe && timer.at == 1022 && timer.space == .Application)
}

@(test)
zero_rtt_does_not_arm_pto :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	testing.expect_value(t, harness.configure(&h.m, wide()), .None)
	dst: [256]u8
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Application, zero_rtt = true, ping = true, more_data = true})
	testing.expect_value(t, err, .None)
	timer := harness.loss_detection_timer(&h.m, 0)
	testing.expect(t, !timer.armed && h.m.bytes_in_flight > 0)
	testing.expect_value(t, harness.reject_zero_rtt(&h.m), .None)
	testing.expect(t, h.m.bytes_in_flight == 0 && h.m.congestion_window == 12000 && !h.m.in_recovery)
}

@(test)
handshake_levels_and_spaces :: proc(t: ^testing.T) {
	client, server: Hold
	boot(t, &client, .Client, 1, 2)
	boot(t, &server, .Server, 2, 1)
	defer harness.destroy(&client.m)
	defer harness.destroy(&server.m)
	dst: [1200]u8
	n, err := harness.emit(&client.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect(t, err == .None && n == 1200)
	initial := dst
	testing.expect_value(t, harness.receive(&server.m, 0, 1, initial[:n]), .None)
	testing.expect_value(t, server.m.path_received, 1200)
	_, serr := harness.emit(&server.m, 1, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect_value(t, serr, .None)
	testing.expect_value(t, harness.arm_handshake(&server.m), .None)
	hn, herr := harness.emit(&server.m, 1, dst[:], {space = .Handshake, ping = true, more_data = true})
	testing.expect_value(t, herr, .None)
	testing.expect(t, !server.m.spaces[int(harness.Space.Initial)].discarded && active(&server.m, .Initial, 0))
	testing.expect(t, server.m.congestion_window == 12000 && !server.m.in_recovery)
	testing.expect_value(t, harness.receive(&client.m, 2, 1, dst[:hn]), .None)
	testing.expect(t, client.m.spaces[int(harness.Space.Initial)].discarded && client.m.handshake_armed)
	testing.expect(t, !client.m.peer_validated_us && client.m.congestion_window == 12000 && !client.m.in_recovery)

	acked: Hold
	boot(t, &acked, .Client, 1, 2)
	defer harness.destroy(&acked.m)
	_, err = harness.emit(&acked.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect_value(t, err, .None)
	_, aerr := harness.acknowledge(&acked.m, 50, .Initial, 0, 0, 0, false, 0, nil)
	testing.expect(t, aerr == .None && !acked.m.peer_validated_us)

	testing.expect_value(t, harness.arm_handshake(&client.m), .None)
	cn, cerr := harness.emit(&client.m, 3, dst[:], {space = .Handshake, ping = true, more_data = true})
	testing.expect(t, cerr == .None && client.m.spaces[int(harness.Space.Initial)].discarded)
	testing.expect(t, client.m.bytes_in_flight == cn && client.m.congestion_window == 12000 && !client.m.in_recovery)
	testing.expect_value(t, harness.receive(&server.m, 4, 1, dst[:cn]), .None)
	testing.expect(t, server.m.spaces[int(harness.Space.Initial)].discarded && server.m.address_validated)
	testing.expect(t, server.m.congestion_window == 12000 && !server.m.in_recovery)
	ack: [256]u8
	an, aerr2 := harness.emit(&server.m, 5, ack[:], {space = .Handshake, attach_ack = true, ack_largest = 0, ack_smallest = 0})
	testing.expect_value(t, aerr2, .None)
	testing.expect_value(t, harness.receive(&client.m, 6, 1, ack[:an]), .None)
	testing.expect(t, client.m.peer_validated_us)
}

@(test)
ack_does_not_cross_spaces :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Server, 2, 1)
	defer harness.destroy(&h.m)
	h.m.address_validated = true
	dst: [1200]u8
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect_value(t, err, .None)
	testing.expect_value(t, harness.arm_handshake(&h.m), .None)
	_, err = harness.emit(&h.m, 0, dst[:], {space = .Handshake, ping = true, more_data = true})
	testing.expect_value(t, err, .None)
	lost: [64]u64
	ln, aerr := harness.acknowledge(&h.m, 10, .Handshake, 0, 0, 0, false, 0, lost[:])
	testing.expect(t, aerr == .None && ln == 0)
	testing.expect(t, active(&h.m, .Initial, 0) && !active(&h.m, .Handshake, 0))
	ln, aerr = harness.acknowledge(&h.m, 10, .Initial, 0, 0, 0, false, 0, lost[:])
	testing.expect(t, aerr == .None && !active(&h.m, .Initial, 0))
}

@(test)
slow_start_app_limited_and_flow_limited :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	dst: [1200]u8
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect_value(t, err, .None)
	ln, aerr := harness.acknowledge(&h.m, 100, .Initial, 0, 0, 0, false, 0, nil)
	testing.expect(t, aerr == .None && ln == 0 && h.m.congestion_window == 13200)

	limited: Hold
	boot(t, &limited, .Client, 1, 2)
	defer harness.destroy(&limited.m)
	_, err = harness.emit(&limited.m, 0, dst[:], {space = .Initial, ping = true, more_data = false})
	testing.expect(t, err == .None && limited.m.app_limited)
	_, aerr = harness.acknowledge(&limited.m, 100, .Initial, 0, 0, 0, false, 0, nil)
	testing.expect(t, aerr == .None && limited.m.congestion_window == 12000)

	flow: Hold
	boot(t, &flow, .Client, 1, 2)
	defer harness.destroy(&flow.m)
	testing.expect_value(t, harness.confirm_handshake(&flow.m), .None)
	limits := wide()
	limits.max_data = 10
	limits.max_stream_data = 10
	testing.expect_value(t, harness.configure(&flow.m, limits), .None)
	_, err = harness.emit(&flow.m, 0, dst[:], {space = .Application, stream = true, stream_len = 11, more_data = true})
	testing.expect(t, err == .Flow_Control && flow.m.flow_limited && flow.m.live_streams == 0)
	_, err = harness.emit(&flow.m, 0, dst[:], {space = .Application, ping = true, more_data = true, bytes = 1200})
	testing.expect_value(t, err, .None)
	_, aerr = harness.acknowledge(&flow.m, 100, .Application, 0, 0, 0, false, 0, nil)
	testing.expect(t, aerr == .None && flow.m.congestion_window == 12000 && flow.m.flow_limited)
	_, err = harness.emit(&flow.m, 200, dst[:], {space = .Application, stream = true, stream_len = 4, more_data = true})
	testing.expect(t, err == .None && !flow.m.flow_limited && flow.m.retained == 4)
}

@(test)
loss_recovery_epochs :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	dst: [1200]u8
	for _ in 0 ..< 4 {
		_, err := harness.emit(&h.m, 1000, dst[:], {space = .Initial, ping = true, more_data = true, bytes = 1200})
		testing.expect_value(t, err, .None)
	}
	ln, err := harness.acknowledge(&h.m, 1100, .Initial, 3, 3, 0, false, 0, nil)
	testing.expect(t, err == .None && ln == 1)
	testing.expect(t, !active(&h.m, .Initial, 0) && active(&h.m, .Initial, 1) && active(&h.m, .Initial, 2))
	testing.expect(t, h.m.congestion_window == 6000 && h.m.ssthresh == 6000 && h.m.in_recovery && h.m.recovery_start == 1100)
	_, err = harness.emit(&h.m, 1200, dst[:], {space = .Initial, ping = true, more_data = true, bytes = 1200})
	testing.expect_value(t, err, .None)
	ln, err = harness.acknowledge(&h.m, 1300, .Initial, 4, 4, 0, false, 0, nil)
	testing.expect(t, err == .None && ln == 2 && !active(&h.m, .Initial, 1) && !active(&h.m, .Initial, 2))
	testing.expect(t, h.m.congestion_window == 6240 && h.m.recovery_start == 1100)
	for _ in 0 ..< 4 {
		_, err = harness.emit(&h.m, 1400, dst[:], {space = .Initial, ping = true, more_data = true, bytes = 1200})
		testing.expect_value(t, err, .None)
	}
	ln, err = harness.acknowledge(&h.m, 1500, .Initial, 8, 8, 0, false, 0, nil)
	testing.expect(t, err == .None && ln == 1 && !active(&h.m, .Initial, 5) && active(&h.m, .Initial, 6))
	testing.expect(t, h.m.congestion_window == 3120 && h.m.ssthresh == 3120 && h.m.recovery_start == 1500 && h.m.in_recovery)
}

@(test)
ecn_and_loss_reduce_once :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	dst: [1200]u8
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect_value(t, err, .None)
	_, err = harness.acknowledge(&h.m, 100, .Initial, 0, 0, 0, true, 1, nil)
	testing.expect(t, err == .None && h.m.congestion_window == 6000 && h.m.in_recovery)
	both: Hold
	boot(t, &both, .Client, 1, 2)
	defer harness.destroy(&both.m)
	for _ in 0 ..< 4 {
		_, err = harness.emit(&both.m, 1000, dst[:], {space = .Initial, ping = true, more_data = true, bytes = 1200})
		testing.expect_value(t, err, .None)
	}
	_, err = harness.acknowledge(&both.m, 1100, .Initial, 3, 3, 0, true, 4, nil)
	testing.expect(t, err == .None && both.m.congestion_window == 6000 && both.m.in_recovery)
}

@(test)
persistent_congestion_scaled_replay :: proc(t: ^testing.T) {
	// RFC 9002 §7.6.3 uses fractional example units where period 7 > duration 6.
	// This replay scales those units by 10 and seeds a sample at tick 0, because
	// tick 0 is a real send time and packets at or before the first sample are excluded.
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	testing.expect_value(t, harness.confirm_handshake(&h.m), .None)
	dst: [1200]u8
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Application, ping = true, more_data = true, bytes = 1200})
	testing.expect_value(t, err, .None)
	_, err = harness.acknowledge(&h.m, 0, .Application, 0, 0, 0, false, 0, nil)
	testing.expect_value(t, err, .None)
	h.m.smoothed_rtt = 2
	h.m.rttvar = 0
	h.m.min_rtt = 2
	h.m.latest_rtt = 2
	h.m.granularity = 10
	h.m.max_ack_delay = 8
	h.m.spaces[int(harness.Space.Application)].next_send = 2
	times := [8]i64{10, 20, 30, 40, 50, 60, 80, 120}
	for at in times {
		_, err = harness.emit(&h.m, at, dst[:], {space = .Application, ping = true, more_data = true, bytes = 1200})
		testing.expect_value(t, err, .None)
	}
	testing.expect(t, !h.m.app_limited)
	ln: int
	ln, err = harness.acknowledge(&h.m, 122, .Application, 9, 9, 0, false, 0, nil)
	testing.expect(t, err == .None && ln == 7)
	// Persistent congestion collapses the window to 2*1200 and ends recovery.
	// The newly acked 1200 bytes are then applied in slow start, so the window is 3600.
	testing.expect_value(t, h.m.ssthresh, i64(6600))
	testing.expect_value(t, h.m.congestion_window, 3600)
	testing.expect_value(t, h.m.bytes_in_flight, 0)
	testing.expect(t, !h.m.in_recovery)
	testing.expect(t, harness.audit(&h.m))
}

@(test)
time_threshold_loss_timer :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	dst: [1200]u8
	for _ in 0 ..< 2 {
		_, err := harness.emit(&h.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
		testing.expect_value(t, err, .None)
	}
	_, err := harness.acknowledge(&h.m, 10, .Initial, 1, 1, 0, false, 0, nil)
	testing.expect_value(t, err, .None)
	timer := harness.loss_detection_timer(&h.m, 10)
	testing.expect(t, timer.armed && timer.kind == .Loss && timer.at == 11 && active(&h.m, .Initial, 0))
	lost_n, kind, te := harness.on_timeout(&h.m, 11, nil)
	testing.expect(t, te == .None && kind == .Loss && lost_n == 1 && h.m.pto_count == 0)
	// The earlier ACK grew the window to 13200. Loss then halves that window.
	testing.expect(t, !active(&h.m, .Initial, 0) && h.m.in_recovery && h.m.congestion_window == 6600)
}

@(test)
flow_reset_close_and_bounds :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	testing.expect_value(t, harness.confirm_handshake(&h.m), .None)
	limits := wide()
	limits.max_data = 100
	limits.max_stream_data = 100
	testing.expect_value(t, harness.configure(&h.m, limits), .None)
	lower := limits
	lower.max_data = 99
	testing.expect_value(t, harness.configure(&h.m, lower), .Protocol)
	testing.expect_value(t, h.m.max_data, u64(100))
	dst: [256]u8
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Application, stream = true, stream_id = 4, stream_len = 1})
	testing.expect_value(t, err, .Protocol)
	_, err = harness.emit(&h.m, 0, dst[:], {space = .Application, stream = true, stream_id = 2, stream_len = 1})
	testing.expect_value(t, err, .Protocol)
	n: int
	n, err = harness.emit(&h.m, 0, dst[:], {space = .Application, stream = true, stream_len = 40, fin = true, more_data = true})
	testing.expect(t, err == .None && h.m.retained == 40 && h.m.data_sent == 40)
	peer: Hold
	boot(t, &peer, .Server, 2, 1)
	defer harness.destroy(&peer.m)
	testing.expect_value(t, harness.confirm_handshake(&peer.m), .None)
	testing.expect_value(t, harness.configure(&peer.m, wide()), .None)
	payload := dst[:n]
	testing.expect_value(t, harness.receive(&peer.m, 1, 9, payload), .None)
	for &b in dst {b = 0xff}
	testing.expect(t, peer.m.retained == 40 && peer.m.recv_data == 40 && harness.audit(&peer.m))
	testing.expect_value(t, harness.consume_recv(&peer.m, 0, 40), .None)
	testing.expect(t, peer.m.retained == 0 && peer.m.live_streams == 0)

	_, err = harness.emit(&h.m, 2, dst[:], {space = .Application, reset = true, reset_final = 40})
	testing.expect(t, err == .None && h.m.retained == 0 && h.m.data_sent == 40)
	testing.expect_value(t, h.m.streams[0].send, harness.Send_State.Reset_Sent)
	_, err = harness.acknowledge(&h.m, 3, .Application, 0, 1, 0, false, 0, nil)
	testing.expect(t, err == .None && h.m.live_streams == 0 && h.m.peak_streams >= 1 && h.m.data_sent == 40)

	_, err = harness.emit(&h.m, 4, dst[:], {space = .Application, stream = true, stream_id = 4, stream_len = 8, more_data = true})
	testing.expect_value(t, err, .None)
	testing.expect(t, h.m.peak_retained >= 8)
	cn, cerr := harness.emit(&h.m, 5, dst[:], {space = .Application, connection_close = true})
	testing.expect(t, cerr == .None && cn > 0 && h.m.closed && h.m.retained == 0 && h.m.live_packets == 0 && h.m.live_streams == 0)
	testing.expect(t, h.m.peak_retained >= 8 && harness.audit(&h.m))
	_, err = harness.emit(&h.m, 6, dst[:], {space = .Application, ping = true})
	testing.expect_value(t, err, .Closed)
}

@(test)
zero_rtt_retains_stream_bytes :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	testing.expect_value(t, harness.configure(&h.m, wide()), .None)
	dst: [256]u8
	_, err := harness.emit(
		&h.m,
		0,
		dst[:],
		{space = .Application, zero_rtt = true, stream = true, stream_len = 8, more_data = true},
	)
	testing.expect(t, err == .None && h.m.retained == 8 && h.m.bytes_in_flight > 0)
	testing.expect_value(t, harness.reject_zero_rtt(&h.m), .None)
	testing.expect(t, h.m.retained == 8 && h.m.bytes_in_flight == 0 && h.m.congestion_window == 12000 && h.m.live_streams == 1)
	testing.expect_value(t, harness.confirm_handshake(&h.m), .None)
	testing.expect_value(t, h.m.retained, 8)
	_, err = harness.emit(&h.m, 1, dst[:], {space = .Application, zero_rtt = true, ping = true})
	testing.expect_value(t, err, .Invalid_Input)
}

@(test)
anti_amplification_and_migration :: proc(t: ^testing.T) {
	client, server: Hold
	boot(t, &client, .Client, 1, 2)
	boot(t, &server, .Server, 2, 1)
	defer harness.destroy(&client.m)
	defer harness.destroy(&server.m)
	fresh := harness.loss_detection_timer(&server.m, 0)
	testing.expect(t, !fresh.armed)
	dst: [1200]u8
	n, err := harness.emit(&client.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect(t, err == .None && n == 1200)
	saved := dst
	testing.expect_value(t, harness.receive(&server.m, 0, 1, saved[:n]), .None)
	for _ in 0 ..< 3 {
		sn, serr := harness.emit(&server.m, 1, dst[:], {space = .Initial, ping = true, more_data = true})
		testing.expect(t, serr == .None && sn == 1200)
	}
	testing.expect_value(t, server.m.path_sent, 3600)
	_, serr := harness.emit(&server.m, 1, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect(t, serr == .Anti_Amplification && server.m.path_sent == 3600 && server.m.live_packets == 3)
	timer := harness.loss_detection_timer(&server.m, 1)
	testing.expect(t, !timer.armed)

	undersized: Hold
	boot(t, &undersized, .Server, 2, 1)
	defer harness.destroy(&undersized.m)
	small: [64]u8
	sn, _, qerr := quic.long_header_encode_v1(small[:], {
		kind = .Initial,
		destination_id = []u8{2},
		source_id = []u8{1},
		packet_number = 9,
		packet_number_length = 1,
		ciphertext_length = 4,
	})
	testing.expect_value(t, qerr, .None)
	for i in sn ..< sn + 4 {small[i] = 0}
	testing.expect_value(t, harness.receive(&undersized.m, 2, 1, small[:sn + 4]), .Datagram_Too_Small)
	testing.expect(t, undersized.m.path_received == sn + 4 && !undersized.m.ack_pending[0])
	garbage := [3]u8{1, 2, 3}
	testing.expect_value(t, harness.receive(&undersized.m, 2, 1, garbage[:]), .Protocol)
	testing.expect_value(t, undersized.m.path_received, sn + 4)
	wn, _, werr := quic.long_header_encode_v1(small[:], {
		kind = .Initial,
		destination_id = []u8{9},
		source_id = []u8{1},
		packet_number = 0,
		packet_number_length = 1,
		ciphertext_length = 4,
	})
	testing.expect_value(t, werr, .None)
	for i in wn ..< wn + 4 {small[i] = 0}
	testing.expect_value(t, harness.receive(&undersized.m, 2, 1, small[:wn + 4]), .Discarded)
	testing.expect_value(t, undersized.m.path_received, sn + 4)

	moved: Hold
	boot(t, &moved, .Server, 2, 1)
	defer harness.destroy(&moved.m)
	testing.expect_value(t, harness.receive(&moved.m, 0, 1, saved[:n]), .None)
	_, err = harness.emit(&moved.m, 1, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect_value(t, err, .None)
	flight := moved.m.bytes_in_flight
	cwnd := moved.m.congestion_window
	again: [1200]u8
	n2, err2 := harness.emit(&client.m, 2, again[:], {space = .Initial, ping = true, more_data = true})
	testing.expect_value(t, err2, .None)
	testing.expect_value(t, harness.receive(&moved.m, 3, 2, again[:n2]), .None)
	testing.expect(t, moved.m.path == 2 && moved.m.path_received == n2 && moved.m.path_sent == 0)
	testing.expect(t, !moved.m.address_validated && moved.m.bytes_in_flight == flight && moved.m.congestion_window == cwnd)
}

@(test)
reorder_duplicate_and_holes :: proc(t: ^testing.T) {
	client, server: Hold
	boot(t, &client, .Client, 1, 2)
	boot(t, &server, .Server, 2, 1)
	defer harness.destroy(&client.m)
	defer harness.destroy(&server.m)
	testing.expect_value(t, harness.confirm_handshake(&client.m), .None)
	testing.expect_value(t, harness.confirm_handshake(&server.m), .None)
	testing.expect_value(t, harness.configure(&client.m, wide()), .None)
	testing.expect_value(t, harness.configure(&server.m, wide()), .None)
	server.m.address_validated = true
	a, b: [256]u8
	an, aerr := harness.emit(&client.m, 0, a[:], {space = .Application, ping = true, more_data = true})
	bn, berr := harness.emit(&client.m, 0, b[:], {space = .Application, ping = true, more_data = true})
	testing.expect(t, aerr == .None && berr == .None)
	testing.expect_value(t, harness.receive(&server.m, 1, 4, b[:bn]), .None)
	testing.expect_value(t, harness.receive(&server.m, 1, 4, a[:an]), .None)
	lo, hi, ok := harness.pending_ack(&server.m, .Application)
	testing.expect(t, ok && lo == 0 && hi == 1)
	testing.expect_value(t, harness.receive(&server.m, 1, 4, b[:bn]), .None)
	testing.expect_value(t, server.m.path_received, an + bn + bn)

	c, d: [256]u8
	cn, cerr := harness.emit(&client.m, 2, c[:], {space = .Application, stream = true, stream_len = 4, more_data = true})
	dn, derr := harness.emit(&client.m, 2, d[:], {space = .Application, stream = true, stream_len = 4, more_data = true})
	testing.expect(t, cerr == .None && derr == .None)
	retained := server.m.retained
	testing.expect_value(t, harness.receive(&server.m, 3, 4, d[:dn]), .Protocol)
	testing.expect(t, server.m.retained == retained && server.m.live_streams == 0)
	testing.expect_value(t, harness.receive(&server.m, 3, 4, c[:cn]), .None)
	testing.expect_value(t, server.m.retained, 4)
	testing.expect_value(t, harness.receive(&server.m, 3, 4, c[:cn]), .None)
	testing.expect_value(t, server.m.retained, 4)
}

@(test)
allocation_failure_and_capacity :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	testing.expect_value(t, harness.confirm_handshake(&h.m), .None)
	dst: [128]u8
	testing.expect_value(t, harness.inject_allocation_failure(&h.m, 1), .None)
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Application, ping = true, more_data = true})
	testing.expect(t, err == .Allocation && h.m.live_packets == 0 && h.m.allocation_failures == 0)
	_, err = harness.emit(&h.m, 0, dst[:], {space = .Application, ping = true, more_data = true})
	testing.expect(t, err == .None && h.m.live_packets == 1)
	for h.m.live_packets < 64 {
		_, err = harness.emit(&h.m, 0, dst[:], {space = .Application, ping = true, more_data = true})
		testing.expect_value(t, err, .None)
	}
	testing.expect_value(t, harness.inject_allocation_failure(&h.m, 1), .None)
	_, err = harness.emit(&h.m, 0, dst[:], {space = .Application, ping = true, more_data = true})
	testing.expect(t, err == .Allocation && h.m.live_packets == 64)
	_, err = harness.emit(&h.m, 0, dst[:], {space = .Application, ping = true, more_data = true})
	testing.expect(t, err == .Capacity && h.m.live_packets == 64 && harness.audit(&h.m))

	streams: Hold
	st: [2]harness.Stream
	ip, hp, ap: [4]harness.Packet
	testing.expect_value(
		t,
		harness.init(&streams.m, .Client, []u8{1}, []u8{2}, ip[:], hp[:], ap[:], st[:], 1200),
		.None,
	)
	defer harness.destroy(&streams.m)
	testing.expect_value(t, harness.confirm_handshake(&streams.m), .None)
	testing.expect_value(t, harness.configure(&streams.m, wide()), .None)
	_, err = harness.emit(&streams.m, 0, dst[:], {space = .Application, stream = true, stream_len = 1, more_data = true})
	testing.expect_value(t, err, .None)
	_, err = harness.emit(&streams.m, 0, dst[:], {space = .Application, stream = true, stream_id = 4, stream_len = 1, more_data = true})
	testing.expect_value(t, err, .None)
	testing.expect_value(t, harness.inject_allocation_failure(&streams.m, 1), .None)
	_, err = harness.emit(&streams.m, 0, dst[:], {space = .Application, stream = true, stream_id = 8, stream_len = 1, more_data = true})
	testing.expect(t, err == .Allocation && streams.m.live_streams == 2 && streams.m.allocation_failures == 0)
	_, err = harness.emit(&streams.m, 0, dst[:], {space = .Application, stream = true, stream_id = 8, stream_len = 1, more_data = true})
	testing.expect_value(t, err, .Capacity)

	recv: Hold
	boot(t, &recv, .Server, 2, 1)
	defer harness.destroy(&recv.m)
	testing.expect_value(t, harness.confirm_handshake(&recv.m), .None)
	testing.expect_value(t, harness.configure(&recv.m, wide()), .None)
	sender: Hold
	boot(t, &sender, .Client, 1, 2)
	defer harness.destroy(&sender.m)
	testing.expect_value(t, harness.confirm_handshake(&sender.m), .None)
	testing.expect_value(t, harness.configure(&sender.m, wide()), .None)
	pn0, e0 := harness.emit(&sender.m, 0, dst[:], {space = .Application, stream = true, stream_len = 3, more_data = true})
	testing.expect_value(t, e0, .None)
	saved: [128]u8
	copy(saved[:pn0], dst[:pn0])
	testing.expect_value(t, harness.inject_allocation_failure(&recv.m, 1), .None)
	testing.expect_value(t, harness.receive(&recv.m, 1, 1, saved[:pn0]), .Allocation)
	testing.expect(t, recv.m.live_streams == 0 && recv.m.retained == 0 && recv.m.allocation_failures == 0)
	pn1, e1 := harness.emit(&sender.m, 1, dst[:], {space = .Application, stream = true, stream_id = 0, stream_len = 3, more_data = true})
	testing.expect_value(t, e1, .None)
	// The failed admission consumed PN 0. A later packet at the same offset is a hole.
	testing.expect_value(t, harness.receive(&recv.m, 2, 1, dst[:pn1]), .Protocol)
	testing.expect_value(t, recv.m.live_streams, 0)
}

@(test)
ack_only_is_not_retained :: proc(t: ^testing.T) {
	h: Hold
	boot(t, &h, .Client, 1, 2)
	defer harness.destroy(&h.m)
	testing.expect_value(t, harness.confirm_handshake(&h.m), .None)
	dst: [128]u8
	before := h.m.live_packets
	_, err := harness.emit(&h.m, 0, dst[:], {space = .Application, attach_ack = true, ack_largest = 1, ack_smallest = 0})
	testing.expect(t, err == .None && h.m.live_packets == before && h.m.bytes_in_flight == 0)
	tiny: [1]u64
	_, err = harness.acknowledge(&h.m, 0, .Application, 0, 0, 0, false, 0, tiny[:])
	testing.expect_value(t, err, .Destination_Undersized)
	testing.expect(t, harness.audit(&h.m))
}

@(test)
nil_allocator_exchange :: proc(t: ^testing.T) {
	context.allocator = mem.nil_allocator()
	context.temp_allocator = mem.nil_allocator()
	client, server: Hold
	boot(t, &client, .Client, 1, 2)
	boot(t, &server, .Server, 2, 1)
	defer harness.destroy(&client.m)
	defer harness.destroy(&server.m)
	testing.expect_value(t, harness.confirm_handshake(&client.m), .None)
	testing.expect_value(t, harness.confirm_handshake(&server.m), .None)
	server.m.address_validated = true
	dst: [128]u8
	ack: [128]u8
	for _ in 0 ..< 1000 {
		n, err := harness.emit(&client.m, 0, dst[:], {space = .Application, ping = true, more_data = true})
		assert(err == .None)
		assert(harness.receive(&server.m, 1, 3, dst[:n]) == .None)
		// The first datagram selects the path and clears validation. This loop
		// is the retention stress test; anti-amplification has its own test.
		server.m.address_validated = true
		lo, hi, ok := harness.pending_ack(&server.m, .Application)
		assert(ok)
		an, aerr := harness.emit(
			&server.m,
			1,
			ack[:],
			{space = .Application, attach_ack = true, ack_smallest = lo, ack_largest = hi, ack_delay = 0},
		)
		assert(aerr == .None)
		assert(harness.receive(&client.m, 2, 3, ack[:an]) == .None)
		assert(client.m.live_packets == 0 && harness.audit(&client.m) && harness.audit(&server.m))
	}
	testing.expect(t, client.m.peak_packets >= 1 && client.m.live_packets == 0)
	_ = t
}

@(test)
sim_hosts_the_model :: proc(t: ^testing.T) {
	context.allocator = mem.nil_allocator()
	context.temp_allocator = mem.nil_allocator()
	packets: [4]sim.Packet_Slot
	timers: [2]sim.Timer_Slot
	storage: [4 * 1200]u8
	link: sim.Link
	testing.expect_value(t, sim.init(&link, packets[:], storage[:], 1200, timers[:]), .None)
	defer sim.destroy(&link)
	client, server: Hold
	boot(t, &client, .Client, 1, 2)
	boot(t, &server, .Server, 2, 1)
	defer harness.destroy(&client.m)
	defer harness.destroy(&server.m)
	from := sim.Address{peer = 1, path = 10}
	to := sim.Address{peer = 2, path = 20}
	dst: [1200]u8
	testing.expect_value(t, sim.inject_allocation_failure(&link, 1), .None)
	testing.expect_value(t, sim.send(&link, from, to, dst[:1], {drop = true}), .None)
	testing.expect_value(t, link.fail_allocations, 1)
	testing.expect_value(t, sim.send(&link, from, to, dst[:1], {delay = -1}), .Invalid_Time)
	testing.expect_value(t, link.fail_allocations, 1)
	n, err := harness.emit(&client.m, 0, dst[:], {space = .Initial, ping = true, more_data = true})
	testing.expect(t, err == .None && n == 1200)
	timer := harness.loss_detection_timer(&client.m, 0)
	testing.expect(t, timer.armed && timer.at == 997 && timer.kind == .Probe)
	testing.expect_value(t, sim.send(&link, from, to, dst[:n]), .Allocation)
	testing.expect_value(t, sim.stats(&link).packets, 0)
	testing.expect_value(t, sim.send(&link, from, to, dst[:n], {drop = true}), .None)
	_, ok, se := sim.step(&link, 0, dst[:])
	testing.expect(t, !ok && se == .None && sim.now(&link) == 0)
	second: [1200]u8
	n2, err2 := harness.emit(&client.m, 0, second[:], {space = .Initial, ping = true, more_data = true})
	testing.expect_value(t, err2, .None)
	testing.expect_value(t, sim.send(&link, from, to, dst[:n], {delay = 5}), .None)
	testing.expect_value(
		t,
		sim.send(&link, {peer = 1, path = 11}, to, second[:n2], {delay = 0, duplicate = true, duplicate_delay = 0}),
		.None,
	)
	out: [1200]u8
	event: sim.Event
	event, ok, se = sim.step(&link, 0, out[:])
	testing.expect(t, ok && se == .None && event.at == 0 && event.source.path == 11)
	testing.expect_value(t, harness.receive(&server.m, i64(event.at), event.source.path, out[:event.size]), .None)
	event, ok, se = sim.step(&link, 0, out[:])
	testing.expect(t, ok && se == .None)
	testing.expect_value(t, harness.receive(&server.m, i64(event.at), event.source.path, out[:event.size]), .None)
	testing.expect_value(t, server.m.path_received, n2 * 2)
	event, ok, se = sim.step(&link, 5, out[:])
	testing.expect(t, ok && se == .None && event.at == 5 && event.source.path == 10)
	testing.expect_value(t, harness.receive(&server.m, i64(event.at), event.source.path, out[:event.size]), .None)
	lo, hi, pending := harness.pending_ack(&server.m, .Initial)
	testing.expect(t, pending && lo == 0 && hi == 1 && server.m.path == 10 && server.m.path_received == n)
	_, ok, se = sim.step(&link, 997, out[:])
	testing.expect(t, !ok && se == .None && sim.now(&link) == 997)
	testing.expect(t, harness.audit(&client.m) && harness.audit(&server.m))
}
