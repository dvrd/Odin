package conn

import "core:net/quic"

// Real QUIC v1 frames. The harness never sees these bytes. ACK handling keeps
// only the first contiguous range; this stack does not emit gap ranges.
Parsed :: struct {
	ack:                         bool,
	ack_largest, ack_smallest:   u64,
	crypto:                      bool,
	crypto_off:                 u64,
	crypto_data:                []u8,
	stream:                      bool,
	stream_id, stream_off:       u64,
	stream_data:                 []u8,
	fin:                         bool,
	reset:                       bool,
	reset_id, reset_final:       u64,
	stop:                        bool,
	stop_id:                     u64,
	max_data:                    bool,
	max_data_v:                  u64,
	close:                       bool,
	handshake_done:              bool,
	ping:                        bool,
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

encode_reset :: proc(dst: []u8, start: int, id, final_size: u64) -> (int, bool) {
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
	at, ok = put_varint(dst, at, 0)
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
			for _ in 0 ..< count {
				_, at, ok = take_varint(src, at)
				if !ok {
					return {}, false
				}
				_, at, ok = take_varint(src, at)
				if !ok {
					return {}, false
				}
			}
			if kind == 0x03 {
				for _ in 0 ..< 3 {
					_, at, ok = take_varint(src, at)
					if !ok {
						return {}, false
					}
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
			if parsed.stream {
				return {}, false
			}
			parsed.stream = true
			parsed.stream_id = id
			parsed.stream_off = off
			parsed.stream_data = data
			parsed.fin = fin
		case 0x10:
			at += 1
			value: u64
			value, at, ok = take_varint(src, at)
			if !ok || parsed.max_data {
				return {}, false
			}
			parsed.max_data = true
			parsed.max_data_v = value
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
