// QUIC v1 wire primitives. All codecs borrow caller storage and allocate nothing.
package quic

MAX_VARINT :: (u64(1) << 62) - 1
Error :: enum {
	None,
	Truncated,
	Invalid_Input,
	Varint_Overflow,
	Destination_Undersized,
	Invalid_Length,
	Invalid_Connection_ID,
	Invalid_Fixed_Bit,
	Unsupported_Version,
	Invalid_Version_List,
	Invalid_Packet_Number,
	Overlapping_Buffers,
}

varint_size :: proc(value: u64, width: int = 0) -> (int, Error) {
	if value > MAX_VARINT {
		return 0, .Varint_Overflow
	}
	if width == 0 {
		if value < 64 {
			return 1, .None
		}
		if value < 16384 {
			return 2, .None
		}
		if value < (u64(1) << 30) {
			return 4, .None
		}
		return 8, .None
	}
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return 0, .Invalid_Input
	}
	if value >= (u64(1) << uint(width * 8 - 2)) {
		return 0, .Varint_Overflow
	}
	return width, .None
}

// Nonminimal encodings are legal for general QUIC integers (RFC 9000 section 16).
varint_decode :: proc(src: []u8) -> (value: u64, consumed: int, err: Error) {
	if len(src) == 0 {
		return 0, 0, .Truncated
	}
	n := 1 << (src[0] >> 6)
	if len(src) < n {
		return 0, 0, .Truncated
	}
	value = u64(src[0] & 0x3f)
	for i in 1 ..< n {value = (value << 8) | u64(src[i])}
	return value, n, .None
}

// Rejected encodes leave dst unchanged. width=0 selects the smallest encoding.
varint_encode :: proc(dst: []u8, value: u64, width: int = 0) -> (int, Error) {
	n, err := varint_size(value, width)
	if err != .None {
		return 0, err
	}
	if len(dst) < n {
		return 0, .Destination_Undersized
	}
	v := value
	for i := n - 1; i >= 0; i -= 1 {
		dst[i] = u8(v & 255)
		v >>= 8
	}
	prefix: u8
	switch n {case 2:
		prefix = 0x40
	case 4:
		prefix = 0x80
	case 8:
		prefix = 0xc0
	}
	dst[0] |= prefix
	return n, .None
}
