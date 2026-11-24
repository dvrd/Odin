package conn

import "core:net/quic"
import ecn "core:net/quic/ecn"

// Real QUIC v1 frames. The harness never sees these bytes. All bounded ACK
// ranges are parsed; ACK emission uses the highest contiguous received range.
Stream_Frame :: struct {
	id, offset: u64,
	data:       []u8,
	fin:        bool,
}

Credit_Frame :: struct {
	id, value: u64,
}

CID_Frame :: struct {
	sequence, retire_prior_to: u64,
	id:                        []u8,
	token:                     [16]u8,
}

Path_Frame :: struct {
	response: bool,
	token:    [8]u8,
}

Parsed :: struct {
	new_token:                                     bool,
	new_ids:                                       [16]CID_Frame,
	new_id_n:                                      int,
	retire_ids:                                    [16]u64,
	retire_id_n:                                   int,
	paths:                                         [16]Path_Frame,
	path_n:                                        int,
	streams:                                       [32]Stream_Frame,
	stream_n:                                      int,
	credits:                                       [32]Credit_Frame,
	credit_n:                                      int,
	control_eliciting:                             bool,
	path_challenge:                                bool,
	path_token:                                    [8]u8,
	ack:                                           bool,
	ack_ecn:                                       bool,
	ecn_counts:                                    ecn.Counts,
	ack_largest, ack_smallest:                     u64,
	ack_ranges:                                    [65][2]u64,
	ack_n:                                         int,
	max_stream_data:                               bool,
	max_stream_id, max_stream_value:               u64,
	max_streams_bidi, max_streams_uni:             bool,
	max_streams_bidi_value, max_streams_uni_value: u64,
	crypto:                                        bool,
	crypto_off:                                    u64,
	crypto_data:                                   []u8,
	stream:                                        bool,
	stream_id, stream_off:                         u64,
	stream_data:                                   []u8,
	fin:                                           bool,
	reset:                                         bool,
	reset_id, reset_final, reset_error:            u64,
	stop:                                          bool,
	stop_id, stop_error:                           u64,
	max_data:                                      bool,
	max_data_v:                                    u64,
	close:                                         bool,
	handshake_done:                                bool,
	ping:                                          bool,
}

take_varint :: proc(src: []u8, at: int) -> (u64, int, bool) {
	if at < 0 || at >= len(src) {
		return 0, at, false
	}
	decoded, n, err := quic.varint_decode(src[at:])
	if err != .None {
		return 0, at, false
	}
	return decoded, at + n, true
}

put_varint :: proc(dst: []u8, at: int, value: u64) -> (int, bool) {
	if at < 0 || at > len(dst) {
		return at, false
	}
	n, err := quic.varint_encode(dst[at:], value)
	if err != .None {
		return at, false
	}
	return at + n, true
}

encode_ack :: proc(dst: []u8, start: int, largest, smallest: u64) -> (int, bool) {
	at := start
	if largest < smallest || at >= len(dst) {
		return at, false
	}
	dst[at] = 0x02
	at += 1
	ok: bool
	at, ok = put_varint(dst, at, largest)
	if !ok {
		return at, false
	}
	at, ok = put_varint(dst, at, 0)
	if !ok {
		return at, false
	}
	at, ok = put_varint(dst, at, 0)
	if !ok {
		return at, false
	}
	return put_varint(dst, at, largest - smallest)
}

encode_crypto :: proc(dst: []u8, start: int, offset: u64, data: []u8) -> (int, bool) {
	at := start
	if at >= len(dst) {
		return at, false
	}
	dst[at] = 0x06
	at += 1
	ok: bool
	at, ok = put_varint(dst, at, offset)
	if !ok {
		return at, false
	}
	at, ok = put_varint(dst, at, u64(len(data)))
	if !ok || at > len(dst) - len(data) {
		return at, false
	}
	copy(dst[at:], data)
	return at + len(data), true
}

encode_stream :: proc(dst: []u8, start: int, id, offset: u64, data: []u8, fin: bool) -> (int, bool) {
	at := start
	if at >= len(dst) {
		return at, false
	}
	kind: u8 = 0x0e
	if fin {
		kind |= 0x01
	}
	dst[at] = kind
	at += 1
	ok: bool
	at, ok = put_varint(dst, at, id)
	if !ok {
		return at, false
	}
	at, ok = put_varint(dst, at, offset)
	if !ok {
		return at, false
	}
	at, ok = put_varint(dst, at, u64(len(data)))
	if !ok || at > len(dst) - len(data) {
		return at, false
	}
	copy(dst[at:], data)
	return at + len(data), true
}

encode_reset :: proc(dst: []u8, start: int, id, final_size: u64, code: u64 = 0) -> (int, bool) {
	at := start
	if at >= len(dst) {
		return at, false
	}
	dst[at] = 0x04
	at += 1
	ok: bool
	at, ok = put_varint(dst, at, id)
	if !ok {
		return at, false
	}
	at, ok = put_varint(dst, at, code)
	if !ok {
		return at, false
	}
	return put_varint(dst, at, final_size)
}

encode_done :: proc(dst: []u8, start: int) -> (int, bool) {
	if start >= len(dst) {
		return start, false
	}
	dst[start] = 0x1e
	return start + 1, true
}

encode_close :: proc(dst: []u8, start: int) -> (int, bool) {
	at := start
	if at >= len(dst) {
		return at, false
	}
	dst[at] = 0x1c
	at += 1
	ok: bool
	at, ok = put_varint(dst, at, 0)
	if !ok {
		return at, false
	}
	at, ok = put_varint(dst, at, 0)
	if !ok {
		return at, false
	}
	return put_varint(dst, at, 0)
}

encode_ping :: proc(dst: []u8, at: int) -> (int, bool) {
	if at >= len(dst) {
		return at, false
	}
	dst[at] = 0x01
	return at + 1, true
}

parse_frames :: proc(src: []u8) -> (parsed: Parsed, ok: bool) {
	at := 0
	for at < len(src) {
		ok = true
		kind := src[at]
		if kind == 0x00 {
			at += 1
			continue
		}
		switch kind {
		case 0x01:
			parsed.ping = true
			at += 1
		case 0x02, 0x03:
			at += 1
			largest, delay, count, first: u64
			largest, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			delay, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			count, at, ok = take_varint(src, at)
			if !ok || count > 64 {
				return {}, false
			}
			first, at, ok = take_varint(src, at)
			if !ok || first > largest {
				return {}, false
			}
			parsed.ack_ranges[0] = {largest - first, largest}
			parsed.ack_n = 1
			low := largest - first
			for _ in 0 ..< count {
				gap, span: u64
				gap, at, ok = take_varint(src, at)
				if !ok || low < 2 || gap > low - 2 {
					return {}, false
				}
				hi := low - gap - 2
				span, at, ok = take_varint(src, at)
				if !ok || span > hi {
					return {}, false
				}
				low = hi - span
				parsed.ack_ranges[parsed.ack_n] = {low, hi}
				parsed.ack_n += 1
			}
			if kind == 0x03 {
				parsed.ack_ecn = true
				parsed.ecn_counts.ect0, at, ok = take_varint(src, at)
				if !ok {
					return {}, false
				}
				parsed.ecn_counts.ect1, at, ok = take_varint(src, at)
				if !ok {
					return {}, false
				}
				parsed.ecn_counts.ce, at, ok = take_varint(src, at)
				if !ok {
					return {}, false
				}
			}
			_ = delay
			if parsed.ack {
				return {}, false
			}
			parsed.ack = true
			parsed.ack_largest = largest
			parsed.ack_smallest = largest - first
		case 0x04:
			at += 1
			id, app, final: u64
			id, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			app, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			final, at, ok = take_varint(src, at)
			if !ok || parsed.reset {
				return {}, false
			}
			_ = app
			parsed.reset = true
			parsed.reset_id = id
			parsed.reset_error = app
			parsed.reset_final = final
		case 0x05:
			at += 1
			id, app: u64
			id, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			app, at, ok = take_varint(src, at)
			if !ok || parsed.stop {
				return {}, false
			}
			_ = app
			parsed.stop = true
			parsed.stop_id = id
			parsed.stop_error = app
		case 0x06:
			at += 1
			off, n: u64
			off, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			n, at, ok = take_varint(src, at)
			if !ok || n > u64(len(src) - at) || parsed.crypto {
				return {}, false
			}
			parsed.crypto = true
			parsed.crypto_off = off
			parsed.crypto_data = src[at:at + int(n)]
			at += int(n)
		case 0x08 ..= 0x0f:
			fin := kind & 0x01 != 0
			has_len := kind & 0x02 != 0
			has_off := kind & 0x04 != 0
			at += 1
			id, off, n: u64
			id, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			if has_off {
				off, at, ok = take_varint(src, at)
				if !ok {
					return {}, false
				}
			}
			data: []u8
			if has_len {
				n, at, ok = take_varint(src, at)
				if !ok || n > u64(len(src) - at) {
					return {}, false
				}
				data = src[at:at + int(n)]
				at += int(n)
			} else {
				data = src[at:]
				at = len(src)
			}
			if parsed.stream_n == len(parsed.streams) {
				return {}, false
			}
			parsed.streams[parsed.stream_n] = {id, off, data, fin}
			parsed.stream_n += 1
			if !parsed.stream {
				parsed.stream_id = id
				parsed.stream_off = off
				parsed.stream_data = data
				parsed.fin = fin
			}
			parsed.stream = true
		case 0x10:
			at += 1
			value: u64
			value, at, ok = take_varint(src, at)
			if !ok || parsed.max_data {
				return {}, false
			}
			parsed.max_data = true
			parsed.max_data_v = value
		case 0x07:
			parsed.new_token = true
			// NEW_TOKEN is opaque and optional for subsequent connections.
			at += 1
			n: u64
			n, at, ok = take_varint(src, at)
			if !ok || n > u64(len(src) - at) {
				return {}, false
			}
			at += int(n)
			parsed.control_eliciting = true
		case 0x14, 0x16, 0x17:
			// advisory BLOCKED / retired locally issued CID
			at += 1
			_, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			parsed.control_eliciting = true
		case 0x15:
			at += 1
			_, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			_, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			parsed.control_eliciting = true
		case 0x18:
			at += 1
			seq, prior: u64
			seq, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			prior, at, ok = take_varint(src, at)
			if !ok || prior > seq || at >= len(src) {
				return {}, false
			}
			n := int(src[at])
			at += 1
			if n == 0 || n > 20 || n + 16 > len(src) - at {
				return {}, false
			}
			if parsed.new_id_n == len(parsed.new_ids) {
				return {}, false
			}
			f := &parsed.new_ids[parsed.new_id_n]
			parsed.new_id_n += 1
			f.sequence = seq
			f.retire_prior_to = prior
			f.id = src[at:at + n]
			copy(f.token[:], src[at + n:at + n + 16])
			at += n + 16
			parsed.control_eliciting = true
		case 0x19:
			at += 1
			seq: u64
			seq, at, ok = take_varint(src, at)
			if !ok || parsed.retire_id_n == len(parsed.retire_ids) {
				return {}, false
			}
			parsed.retire_ids[parsed.retire_id_n] = seq
			parsed.retire_id_n += 1
			parsed.control_eliciting = true
		case 0x1a, 0x1b:
			at += 1
			if len(src) - at < 8 || parsed.path_n == len(parsed.paths) {
				return {}, false
			}
			f := &parsed.paths[parsed.path_n]
			parsed.path_n += 1
			f.response = kind == 0x1b
			copy(f.token[:], src[at:at + 8])
			if !f.response {
				parsed.path_challenge = true
				parsed.path_token = f.token
			}
			at += 8
			parsed.control_eliciting = true
		case 0x11:
			at += 1
			id, value: u64
			id, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			value, at, ok = take_varint(src, at)
			if !ok || parsed.credit_n == len(parsed.credits) {
				return {}, false
			}
			parsed.credits[parsed.credit_n] = {id, value}
			parsed.credit_n += 1
			parsed.max_stream_data = true
			parsed.max_stream_id = id
			parsed.max_stream_value = value
		case 0x12, 0x13:
			at += 1
			value: u64
			value, at, ok = take_varint(src, at)
			if !ok || value > u64(1) << 60 {
				return {}, false
			}
			if kind == 0x12 {
				parsed.max_streams_bidi = true
				parsed.max_streams_bidi_value = value
			} else {
				parsed.max_streams_uni = true
				parsed.max_streams_uni_value = value
			}
		case 0x1c, 0x1d:
			at += 1
			_, at, ok = take_varint(src, at)
			if !ok {
				return {}, false
			}
			if kind == 0x1c {
				_, at, ok = take_varint(src, at)
				if !ok {
					return {}, false
				}
			}
			n: u64
			n, at, ok = take_varint(src, at)
			if !ok || n > u64(len(src) - at) {
				return {}, false
			}
			at += int(n)
			parsed.close = true
		case 0x1e:
			parsed.handshake_done = true
			at += 1
		case:
			return {}, false
		}
		if !ok {
			return {}, false
		}
	}
	return parsed, true
}

encode_credit :: proc(dst: []u8, at: int, id, stream_limit, data_limit: u64) -> (int, bool) {
	p := at
	if p >= len(dst) {
		return p, false
	}
	dst[p] = 0x10
	p += 1
	ok: bool
	p, ok = put_varint(dst, p, data_limit)
	if !ok || p >= len(dst) {
		return p, false
	}
	dst[p] = 0x11
	p += 1
	p, ok = put_varint(dst, p, id)
	if !ok {
		return p, false
	}
	return put_varint(dst, p, stream_limit)
}
