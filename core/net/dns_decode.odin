package net

import "core:mem"

// Both readers validate the expanded name; skipping never trusts a truncated
// pointer or an unterminated label sequence just because no text is requested.
skip_hostname :: proc(packet: []u8, start_idx: int) -> (encode_size: int, ok: bool) {
	_, encoded, valid := dns_name_read(packet, start_idx, nil)
	return encoded, valid
}

decode_hostname :: proc(
	packet: []u8,
	start_idx: int,
	allocator := context.allocator,
) -> (
	hostname: string,
	encode_size: int,
	ok: bool,
) {
	buffer: [NAME_MAX]u8
	decoded, encoded, valid := dns_name_read(packet, start_idx, buffer[:])
	if !valid {
		return "", 0, false
	}
	name, allocated := dns_clone_bytes(buffer[:decoded], allocator)
	if !allocated {
		return "", 0, false
	}
	return name, encoded, true
}

@(private)
dns_name_read :: proc(packet: []u8, start: int, output: []u8) -> (decoded, encoded: int, ok: bool) {
	if start < 0 || start >= len(packet) {
		return 0, 0, false
	}
	cursor := start
	jumped := false
	labels, expanded := 0, 0
	for _ in 0 ..< 256 {
		if cursor >= len(packet) {
			return 0, 0, false
		}
		value := packet[cursor]
		if value == 0 {
			if expanded + 1 > NAME_MAX {
				return 0, 0, false
			}
			if !jumped {
				encoded += 1
			}
			return decoded, encoded, true
		}
		if value & 0xc0 == 0xc0 {
			if len(packet) - cursor < 2 {
				return 0, 0, false
			}
			target := (int(value & 0x3f) << 8) | int(packet[cursor + 1])
			// Preserve the existing backwards-only compression policy and bound
			// indirect cycles too, without recursion or allocation.
			if target >= cursor {
				return 0, 0, false
			}
			if !jumped {
				encoded += 2
			}
			jumped = true
			cursor = target
			continue
		}
		if value > LABEL_MAX {
			return 0, 0, false
		}
		size := int(value)
		if size > len(packet) - cursor - 1 {
			return 0, 0, false
		}
		expanded += size + 1
		if expanded >= NAME_MAX {
			return 0, 0, false
		} // Reserve the terminating zero.
		separator := int(labels > 0)
		if decoded > NAME_MAX - size - separator {
			return 0, 0, false
		}
		if len(output) > 0 {
			if decoded + separator + size > len(output) {
				return 0, 0, false
			}
			if separator != 0 {
				output[decoded] = '.'
			}
			copy(output[decoded + separator:], packet[cursor + 1:cursor + 1 + size])
		}
		decoded += separator + size
		if !jumped {
			encoded += size + 1
		}
		cursor += size + 1
		labels += 1
	}
	return 0, 0, false
}

@(private)
dns_clone_bytes :: proc(data: []u8, allocator: mem.Allocator) -> (string, bool) {
	if len(data) == 0 {
		return "", true
	}
	owned, error := make([]u8, len(data), allocator)
	if error != nil || raw_data(owned) == nil || len(owned) != len(data) {
		if raw_data(owned) != nil {
			delete(owned, allocator)
		}
		return "", false
	}
	copy(owned, data)
	return string(owned), true
}

// Validate all extents before making any RDATA slice or advancing a cursor.
@(private)
dns_record_span :: proc(
	packet: []u8,
	start: int,
	owner: []u8 = nil,
) -> (
	header: DNS_Record_Header,
	data_start, finish, owner_size: int,
	ok: bool,
) {
	decoded, encoded, valid := dns_name_read(packet, start, owner)
	if !valid {
		return {}, 0, 0, 0, false
	}
	remaining := len(packet) - start
	if remaining < size_of(DNS_Record_Header) || encoded > remaining - size_of(DNS_Record_Header) {
		return {}, 0, 0, 0, false
	}
	at := start + encoded
	header = (cast(^DNS_Record_Header)raw_data(packet[at:at + size_of(DNS_Record_Header)]))^
	data_start = at + size_of(DNS_Record_Header)
	if int(header.length) > len(packet) - data_start {
		return {}, 0, 0, 0, false
	}
	return header, data_start, data_start + int(header.length), decoded, true
}
