package conn

import "core:net/quic"
import "core:net/quic/harness"

// Shadow datagrams exist only so harness.receive/emit can account for a real
// UDP length. They are not sent and they are not a second recovery model.
structured_size :: proc(req: harness.Emit) -> int {
	n := 6
	if req.attach_ack {
		n += 33
	}
	if req.stream {
		n += 19 + req.stream_len
	}
	if req.reset {
		n += 16
	}
	if req.max_data {
		n += 8
	}
	if req.stop_sending {
		n += 8
	}
	return n
}

long_header_len :: proc(c: ^Connection, space: harness.Space, pn_len, body: int) -> (int, bool) {
	token := 0
	if space == .Initial {
		token = 1
	}
	length := u64(pn_len + body)
	lw, err := quic.varint_size(length)
	if err != .None {
		return 0, false
	}
	return 7 + c.model.peer_cid_len + c.model.local_cid_len + token + lw + pn_len, true
}

// Size harness.emit would accept for req.bytes == 0, including the Initial floor.
harness_natural :: proc(c: ^Connection, req: harness.Emit) -> (int, int, u64, bool) {
	sp := c.model.spaces[int(req.space)]
	pn_len, trunc, err := harness.pn_wire_length(sp.next_send, sp.has_largest_acked, sp.largest_acked)
	if err != .None {
		return 0, 0, 0, false
	}
	structured := structured_size(req)
	eliciting := req.ping || req.stream || req.reset || req.stop_sending || req.max_data || req.handshake_confirmed
	min_size := 0
	if req.space == .Initial && (c.model.role == .Client || eliciting) {
		min_size = harness.K_MIN_INITIAL_DATAGRAM
	}
	if req.space == .Application && (c.model.handshake_confirmed||req.connection_close) {
		header := 1 + c.model.peer_cid_len + pn_len
		natural := header + structured
		if natural < min_size {
			natural = min_size
		}
		return natural, pn_len, trunc, natural <= c.model.max_datagram_size && natural >= header + structured
	}
	// A 2-byte length varint can push the Initial floor from 1200 to 1201.
	// Clamp to max_datagram and solve again. harness.emit accepts 1200.
	body := structured
	for _ in 0 ..< 4 {
		header, ok := long_header_len(c, req.space, pn_len, body)
		if !ok {
			return 0, 0, 0, false
		}
		natural := header + body
		want := natural
		if want < min_size {
			want = min_size
		}
		if want > c.model.max_datagram_size {
			want = c.model.max_datagram_size
		}
		if want < min_size || want < header + structured || want > c.model.max_datagram_size {
			return 0, 0, 0, false
		}
		if natural == want {
			return want, pn_len, trunc, true
		}
		body = want - header
	}
	return 0, 0, 0, false
}

put_u16 :: proc(dst: []u8, v: u16) {
	dst[0] = u8(v >> 8)
	dst[1] = u8(v)
}

put_u32 :: proc(dst: []u8, v: u32) {
	for i in 0 ..< 4 {
		dst[i] = u8((v >> uint((3 - i) * 8)) & 255)
	}
}

put_u64 :: proc(dst: []u8, v: u64) {
	for i in 0 ..< 8 {
		dst[i] = u8((v >> uint((7 - i) * 8)) & 255)
	}
}

write_body :: proc(dst: []u8, req: harness.Emit, stream_off: u64) -> (int, bool) {
	need := structured_size(req)
	if len(dst) < need {
		return 0, false
	}
	for i in 0 ..< need {
		dst[i] = 0
	}
	put_u32(dst, harness.HARNESS_MAGIC)
	dst[4] = harness.HARNESS_VERSION
	flags: u8
	at := 6
	if req.attach_ack {
		flags |= harness.FLAG_ACK
		put_u64(dst[at:], req.ack_largest)
		put_u64(dst[at + 8:], req.ack_smallest)
		put_u64(dst[at + 16:], u64(req.ack_delay))
		dst[at + 24] = 0
		put_u64(dst[at + 25:], 0)
		at += 33
	}
	if req.ping {
		flags |= harness.FLAG_PING
	}
	if req.stream {
		flags |= harness.FLAG_STREAM
		put_u64(dst[at:], req.stream_id)
		put_u64(dst[at + 8:], stream_off)
		put_u16(dst[at + 16:], u16(req.stream_len))
		dst[at + 18] = 1 if req.fin else 0
		at += 19 + req.stream_len
	}
	if req.reset {
		flags |= harness.FLAG_RESET
		put_u64(dst[at:], req.stream_id)
		put_u64(dst[at + 8:], req.reset_final)
		at += 16
	}
	if req.max_data {
		flags |= harness.FLAG_MAX_DATA
		put_u64(dst[at:], req.max_data_value)
		at += 8
	}
	if req.stop_sending {
		flags |= harness.FLAG_STOP
		put_u64(dst[at:], req.stream_id)
		at += 8
	}
	if req.connection_close {
		flags |= harness.FLAG_CLOSE
	}
	if req.handshake_confirmed {
		flags |= harness.FLAG_CONFIRM
	}
	dst[5] = flags
	return need, true
}

// already_received mirrors the harness receive window without mutating it.
already_received :: proc(sp: harness.Space_State, pn: u64) -> bool {
	if !sp.has_recv {
		return false
	}
	if pn < sp.recv_base {
		return sp.recv_base - pn >= u64(harness.K_RECV_WINDOW)
	}
	if pn >= sp.recv_base + u64(harness.K_RECV_WINDOW) {
		return false
	}
	bit := uint(pn - sp.recv_base)
	return sp.recv_bits & (u64(1) << bit) != 0
}

// Unprotected datagram of exactly len(dst) bytes. Destination CID is local.
shadow_packet :: proc(
	c: ^Connection,
	dst: []u8,
	space: harness.Space,
	pn_len: int,
	truncated: u64,
	req: harness.Emit,
	stream_off: u64,
) -> bool {
	if len(dst) == 0 || pn_len < 1 || pn_len > 4 {
		return false
	}
	header := 0
	if space == .Application {
		n, _, err := quic.short_header_encode_v1(dst, {
			destination_id = c.local_cid[:c.local_cid_len],
			packet_number = u32(truncated),
			packet_number_length = pn_len,
		})
		if err != .None || n >= len(dst) {
			return false
		}
		header = n
	} else {
		kind := quic.Packet_Kind.Initial
		if space == .Handshake {
			kind = .Handshake
		}
		solved := 0
		for _ in 0 ..< 4 {
			if solved >= len(dst) {
				return false
			}
			next, ok := long_header_len(c, space, pn_len, len(dst) - solved)
			if !ok {
				return false
			}
			if next == solved && solved != 0 {
				break
			}
			solved = next
		}
		if solved <= 0 || solved >= len(dst) {
			return false
		}
		n, _, err := quic.long_header_encode_v1(dst, {
			kind = kind,
			destination_id = c.local_cid[:c.local_cid_len],
			source_id = c.peer_cid[:c.peer_cid_len],
			packet_number = u32(truncated),
			packet_number_length = pn_len,
			ciphertext_length = u64(len(dst) - solved),
		})
		if err != .None || n != solved {
			return false
		}
		header = n
	}
	written, ok := write_body(dst[header:], req, stream_off)
	if !ok {
		return false
	}
	for i in header + written ..< len(dst) {
		dst[i] = 0
	}
	return true
}
