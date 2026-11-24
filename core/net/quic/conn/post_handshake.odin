package conn

import "core:crypto"
import "../harness"

POST_HANDSHAKE_CAP :: 4096

@(private)
Post_Handshake_Packet :: struct {
	active:     bool,
	pn, offset: u64,
	n:          int,
}

@(private)
Post_Handshake_State :: struct {
	send, receive:           [POST_HANDSHAKE_CAP]u8,
	acked, present:          [POST_HANDSHAKE_CAP]bool,
	send_base, receive_base: u64,
	send_n, send_off:        int,
	packets:                 [PACKETS]Post_Handshake_Packet,
}

// Copies Application-level TLS handshake bytes. Capacity failure is atomic;
// accepted bytes remain owned until their containing packets are acknowledged.
queue_post_handshake :: proc(c: ^Connection, bytes: []u8) -> Error {
	if c == nil || !c.initialized {
		return .Invalid
	}
	if c.cancelled || c.phase == .Closed || c.phase == .Failed {
		return .Closed
	}
	state := &c.post_handshake
	if len(bytes) > POST_HANDSHAKE_CAP - state.send_n ||
	   u64(len(bytes)) > max(u64) - state.send_base - u64(state.send_n) {
		return .Capacity
	}
	copy(state.send[state.send_n:], bytes)
	state.send_n += len(bytes)
	return .None
}

// Borrow until the next connection mutation. Consumption, never this query,
// advances the Application CRYPTO stream; retransmitted bytes are not redelivered.
peek_post_handshake :: proc(c: ^Connection) -> []u8 {
	if c == nil || !c.initialized || c.cancelled {
		return nil
	}
	n := 0
	for n < POST_HANDSHAKE_CAP && c.post_handshake.present[n] {n += 1}; return c.post_handshake.receive[:n]
}

consume_post_handshake :: proc(c: ^Connection, n: int) -> Error {
	if n < 0 || n > len(peek_post_handshake(c)) {
		return .Invalid
	}
	if n == 0 {
		return .None
	}
	state := &c.post_handshake
	copy(state.receive[:], state.receive[n:])
	copy(state.present[:], state.present[n:])
	for i in POST_HANDSHAKE_CAP - n ..< POST_HANDSHAKE_CAP {state.receive[i] = 0; state.present[i] = false}
	state.receive_base += u64(n)
	return .None
}

@(private)
post_handshake_clear :: proc(c: ^Connection) {crypto.zero_explicit(&c.post_handshake, size_of(c.post_handshake))}

@(private)
post_handshake_rewind :: proc(c: ^Connection) {c.post_handshake.send_off = 0}

@(private)
post_handshake_received :: proc(c: ^Connection, p: Parsed) -> Error {
	state := &c.post_handshake
	offset := p.crypto_off
	data := p.crypto_data
	if u64(len(data)) > max(u64) - offset {
		return .Protocol
	}
	if offset < state.receive_base {
		skip := min(u64(len(data)), state.receive_base - offset)
		data = data[int(skip):]
		offset += skip
	}
	if len(data) == 0 {
		return .None
	}
	if offset - state.receive_base > POST_HANDSHAKE_CAP ||
	   u64(len(data)) > POST_HANDSHAKE_CAP - (offset - state.receive_base) {
		return .Capacity
	}
	start := int(offset - state.receive_base)
	// Validate every overlap before changing any bytes.
	for b, i in data {
		at := start + i
		if state.present[at] && state.receive[at] != b {
			return .Protocol
		}
	}
	for b, i in data {at := start + i; state.receive[at] = b; state.present[at] = true}
	return .None
}

@(private)
post_handshake_ack :: proc(c: ^Connection, p: Parsed) {
	if !p.ack {
		return
	}
	state := &c.post_handshake
	for &sent in state.packets {
		if !sent.active {
			continue
		}
		matched := false
		for ri in 0 ..< p.ack_n {
			interval := p.ack_ranges[ri]
			if sent.pn >= interval[0] && sent.pn <= interval[1] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for i in 0 ..< sent.n {
			off := sent.offset + u64(i)
			if off >= state.send_base && off < state.send_base + u64(state.send_n) {
				state.acked[int(off - state.send_base)] = true
			}
		}
		sent = {}
	}
	prefix := 0
	for prefix < state.send_n && state.acked[prefix] {prefix += 1}
	if prefix > 0 {
		copy(state.send[:], state.send[prefix:])
		copy(state.acked[:], state.acked[prefix:])
		for i in state.send_n - prefix ..< state.send_n {state.send[i] = 0; state.acked[i] = false}
		state.send_n -= prefix
		state.send_off = max(0, state.send_off - prefix)
		state.send_base += u64(prefix)
	}
}

@(private)
post_handshake_pump :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error, bool) {
	state := &c.post_handshake
	for state.send_off < state.send_n && state.acked[state.send_off] {state.send_off += 1}
	if state.send_off == state.send_n {
		return 0, .None, false
	}
	// Retire lost journal entries; their bytes remain queued for PTO replay.
	for &sent in state.packets {
		if sent.active {
			live := false
			for packet in c.model.packets[int(harness.Space.Application)] {
				if packet.active && packet.number == sent.pn {
					live = true
					break
				}
			}
			if !live {
				sent = {}
			}
		}
	}
	slot: ^Post_Handshake_Packet
	for &sent in state.packets {
		if !sent.active {
			slot = &sent
			break
		}
	}
	if slot == nil {
		return 0, .Capacity, true
	}
	n := min(state.send_n - state.send_off, c.max_datagram / 2)
	for i in 1 ..< n {
		if state.acked[state.send_off + i] {
			n = i
			break
		}
	}
	request := harness.Emit {
		space     = .Application,
		ping      = true,
		more_data = state.send_off + n < state.send_n,
		probe     = c.force_probe,
	}
	attach_ack(c, &request, .Application)
	frame: [MAX_DATAGRAM]u8
	at, ok := encode_ack_if(c, frame[:], 0, request)
	if !ok {
		return 0, .Protocol, true
	}
	offset := state.send_base + u64(state.send_off)
	at, ok = encode_crypto(frame[:], at, offset, state.send[state.send_off:state.send_off + n])
	if !ok {
		return 0, .Protocol, true
	}
	pn := c.model.spaces[int(harness.Space.Application)].next_send
	written, e := seal_and_emit(c, now, dst, request, frame[:at], 0)
	if e != .None {
		return 0, e, true
	}
	slot^ = {
		active = true,
		pn     = pn,
		offset = offset,
		n      = n,
	}
	state.send_off += n
	c.force_probe = false
	return written, .None, true
}
