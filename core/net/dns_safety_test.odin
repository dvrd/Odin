package net

import "core:mem"
import "core:testing"

// All fixtures are synthetic wire bytes. No resolver or socket is used here.
@(private)
DNS_Safety_Fixture :: struct {
	bytes:                            [1024]u8,
	length, record_start, data_start: int,
}

@(private)
dns_safety_u16 :: proc(bytes: []u8, at, value: int) {
	bytes[at] = u8(value >> 8)
	bytes[at + 1] = u8(value & 255)
}

@(private)
dns_safety_fixture :: proc(kind: DNS_Record_Type, data: []u8, copies: int = 1) -> DNS_Safety_Fixture {
	f: DNS_Safety_Fixture
	query, error := make_dns_packet(f.bytes[:], 0x1234, "example.test", kind)
	assert(error == nil)
	f.length = len(query)
	f.bytes[2] = 0x81
	f.bytes[3] = 0x80
	dns_safety_u16(f.bytes[:], 6, copies)
	for row in 0 ..< copies {
		if row == 0 {
			f.record_start = f.length
		}
		if kind == .SRV {
			owner := [?]u8{4, '_', 's', 'i', 'p', 4, '_', 't', 'c', 'p', 0xc0, 12}
			copy(f.bytes[f.length:], owner[:])
			f.length += len(owner)
		} else {
			f.bytes[f.length] = 0xc0
			f.bytes[f.length + 1] = 12
			f.length += 2
		}
		dns_safety_u16(f.bytes[:], f.length, int(kind))
		dns_safety_u16(f.bytes[:], f.length + 2, 1)
		f.bytes[f.length + 7] = 42 // TTL
		dns_safety_u16(f.bytes[:], f.length + 8, len(data))
		f.length += size_of(DNS_Record_Header)
		if row == 0 {
			f.data_start = f.length
		}
		copy(f.bytes[f.length:], data)
		f.length += len(data)
	}
	return f
}

@(test)
dns_response_valid_compressed_record_types_keep_values_and_ownership :: proc(t: ^testing.T) {
	for kind in ([?]DNS_Record_Type{.IP4, .IP6, .CNAME, .NS, .MX, .SRV, .TXT}) {
		payload: [32]u8
		data: []u8
		switch kind {
		case .IP4:
			copy(payload[:4], []u8{192, 0, 2, 7})
			data = payload[:4]
		case .IP6:
			payload[0] = 0x20
			payload[1] = 1
			payload[15] = 7
			data = payload[:16]
		case .CNAME, .NS:
			copy(payload[:7], []u8{4, 'n', 'o', 'd', 'e', 0xc0, 12})
			data = payload[:7]
		case .MX:
			copy(payload[:4], []u8{0, 10, 0xc0, 12})
			data = payload[:4]
		case .SRV:
			copy(payload[:8], []u8{0, 1, 0, 2, 1, 187, 0xc0, 12})
			data = payload[:8]
		case .TXT:
			copy(payload[:7], []u8{3, 'a', 0, 'b', 2, 0xff, 0})
			data = payload[:7]
		}
		f := dns_safety_fixture(kind, data)
		records, xid, ok := parse_response(f.bytes[:f.length], kind)
		assert(ok && len(records) == 1)
		testing.expect_value(t, xid, u16be(0x1234))
		switch record in records[0] {
		case DNS_Record_IP4:
			testing.expect_value(t, record.address, IP4_Address{192, 0, 2, 7})
			testing.expect_value(t, record.record_name, "example.test")
			testing.expect_value(t, record.ttl_seconds, u32(42))
		case DNS_Record_IP6:
			testing.expect_value(t, record.address[0], u16be(0x2001))
			testing.expect_value(t, record.address[7], u16be(7))
		case DNS_Record_CNAME:
			testing.expect_value(t, record.host_name, "node.example.test")
		case DNS_Record_NS:
			testing.expect_value(t, record.host_name, "node.example.test")
		case DNS_Record_MX:
			testing.expect_value(t, record.preference, 10)
			testing.expect_value(t, record.host_name, "example.test")
		case DNS_Record_SRV:
			testing.expect_value(t, record.record_name, "_sip._tcp.example.test")
			testing.expect_value(t, record.target, "example.test")
			testing.expect_value(t, record.port, 443)
			testing.expect_value(t, record.priority, 1)
			testing.expect_value(t, record.weight, 2)
		case DNS_Record_TXT:
			testing.expect_value(t, record.value, string(data))
		}
		destroy_dns_records(records)
		// nil has always been a literal type-zero filter, not an ANY request.
		empty, _, empty_ok := parse_response(f.bytes[:f.length])
		testing.expect(t, empty_ok && len(empty) == 0)
		destroy_dns_records(empty)
	}
	f := dns_safety_fixture(.TXT, nil)
	records, _, ok := parse_response(f.bytes[:f.length], .TXT)
	assert(ok && len(records) == 1)
	testing.expect_value(t, records[0].(DNS_Record_TXT).value, "")
	destroy_dns_records(records)
}

@(test)
dns_name_decoders_validate_compression_extents_and_expansion_bounds :: proc(t: ^testing.T) {
	valid := [?]u8{3, 'w', 'w', 'w', 0, 0xc0, 0}
	name, encoded, ok := decode_hostname(valid[:], 5)
	assert(ok)
	testing.expect_value(t, name, "www")
	testing.expect_value(t, encoded, 2)
	delete(name)
	root, root_size, root_ok := decode_hostname(valid[:], 4)
	testing.expect(t, root_ok && root == "" && root_size == 1)
	delete(root)
	invalid := [?][]u8{{}, {0xc0}, {0xc0, 0}, {0xc0, 2, 0}, {64, 0}, {128, 0}, {3, 'a'}, {1, 'a'}, {1, 'a', 0xc0, 0}}
	for packet in invalid {
		_, _, decoded := decode_hostname(packet, 0)
		_, skipped := skip_hostname(packet, 0)
		testing.expect(t, !decoded && !skipped)
	}
	for offset in ([?]int{-1, len(valid), max(int)}) {
		_, _, decoded := decode_hostname(valid[:], offset)
		_, skipped := skip_hostname(valid[:], offset)
		testing.expect(t, !decoded && !skipped)
	}
	long: [256]u8
	for i in 0 ..< 3 {long[i * 64] = 63; for &b in long[i * 64 + 1:i * 64 + 64] {b = 'a'}}
	long[192] = 61
	for &b in long[193:254] {b = 'b'}
	_, length, at_limit := decode_hostname(long[:255], 0, context.temp_allocator)
	testing.expect(t, at_limit && length == 255)
	long[192] = 62
	long[254] = 'b'
	_, too_long := skip_hostname(long[:], 0)
	testing.expect(t, !too_long)
}

@(test)
dns_response_truncation_counts_and_record_spans_are_checked :: proc(t: ^testing.T) {
	base := dns_safety_fixture(.IP4, []u8{192, 0, 2, 1})
	for length in 0 ..< base.length {
		records, _, ok := parse_response(base.bytes[:length], .IP4)
		testing.expect(t, !ok && records == nil)
	}
	for mode in 0 ..< 10 {
		f := base
		switch mode {
		case 0:
			f.bytes[2] &= 0x7f // Not a response.
		case 1:
			dns_safety_u16(f.bytes[:], 4, 0)
		case 2:
			dns_safety_u16(f.bytes[:], 4, 2)
		case 3:
			dns_safety_u16(f.bytes[:], 6, 65535)
		case 4:
			dns_safety_u16(f.bytes[:], 8, 65535)
		case 5:
			dns_safety_u16(f.bytes[:], 10, 65535)
		case 6:
			dns_safety_u16(f.bytes[:], f.data_start - 2, 65535)
		case 7:
			f.bytes[f.record_start + 1] = u8(f.record_start) // Self pointer.
		case 8:
			f.bytes[12] = 0xc0
			f.bytes[13] = 12
		case 9:
			f.bytes[f.record_start] = 64
		}
		records, _, ok := parse_response(f.bytes[:f.length], .IP4)
		testing.expect(t, !ok && records == nil)
	}
	// Original 28-byte root-question/root-owner failure: huge RDLENGTH used to
	// form an unchecked slice. Every byte is local synthetic input.
	malformed: [28]u8
	malformed[2] = 0x80
	malformed[5] = 1
	malformed[7] = 1
	malformed[14] = 1
	malformed[16] = 1
	malformed[19] = 1
	malformed[21] = 1
	malformed[26] = 255
	malformed[27] = 255
	records, _, ok := parse_response(malformed[:], .IP4)
	testing.expect(t, !ok && records == nil)
}

@(test)
dns_selected_record_failure_preserves_cursor_and_exact_rdata_extent :: proc(t: ^testing.T) {
	for kind in ([?]DNS_Record_Type{.IP4, .IP6, .CNAME, .NS, .MX, .SRV}) {
		for data in ([?][]u8{{}, {0xc0}, {0xc0, 12, 0}, {1, 'x'}}) {
			payload: [16]u8
			prefix := 0
			if kind == .MX {
				prefix = 2
			}
			if kind == .SRV {
				prefix = 6
			}
			copy(payload[prefix:], data)
			f := dns_safety_fixture(kind, payload[:prefix + len(data)])
			// Supply bytes beyond declared RDATA: names may not borrow their
			// encoded terminator or pointer byte from the following record.
			f.bytes[f.length] = 0
			cursor := f.record_start
			record, ok := parse_record(f.bytes[:f.length + 1], &cursor, kind)
			testing.expect(t, !ok && record == nil)
			testing.expect_value(t, cursor, f.record_start)
		}
	}
	f := dns_safety_fixture(.IP4, []u8{1, 2, 3, 4})
	for start in ([?]int{-1, f.length, max(int)}) {
		cursor := start
		_, ok := parse_record(f.bytes[:f.length], &cursor, .IP4)
		testing.expect(t, !ok && cursor == start)
	}
	_, nil_cursor := parse_record(f.bytes[:f.length], nil, .IP4)
	testing.expect(t, !nil_cursor)
	cursor := f.record_start
	record, skipped := parse_record(f.bytes[:f.length], &cursor, .TXT)
	testing.expect(t, skipped && record == nil && cursor == f.length)
	// Both the selected and skipped paths validate the enclosing record extent.
	dns_safety_u16(f.bytes[:], f.data_start - 2, 65535)
	for filter in ([?]DNS_Record_Type{.IP4, .TXT}) {
		cursor = f.record_start
		_, ok := parse_record(f.bytes[:f.length], &cursor, filter)
		testing.expect(t, !ok && cursor == f.record_start)
	}
	// Selected unsupported types and SRV owners missing the service/protocol
	// split are semantic failures too, and must not commit the caller's cursor.
	for kind in ([?]DNS_Record_Type{DNS_Record_Type(99), .SRV}) {
		f = dns_safety_fixture(.CNAME, []u8{0, 1, 0, 2, 1, 187, 0xc0, 12})
		dns_safety_u16(f.bytes[:], f.data_start - size_of(DNS_Record_Header), int(kind))
		cursor = f.record_start
		_, ok := parse_record(f.bytes[:f.length], &cursor, kind)
		testing.expect(t, !ok && cursor == f.record_start)
	}
	// Unselected RDATA remains opaque. Its structural owner/header/length must
	// fit, but only the selected type's value gets semantic decoding.
	f = dns_safety_fixture(.CNAME, []u8{0xc0, 255})
	records, _, skipped_response := parse_response(f.bytes[:f.length], .IP4)
	testing.expect(t, skipped_response && len(records) == 0)
	destroy_dns_records(records)
}

@(private)
DNS_Safety_Allocator :: struct {
	backing:              mem.Allocator,
	calls, fail_at, live: int,
	nil_failure:          bool,
}

@(private)
dns_safety_allocate :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	s := cast(^DNS_Safety_Allocator)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
		s.calls += 1
		if s.calls == s.fail_at {
			if s.nil_failure {
				return nil, .None
			}
			return nil, .Out_Of_Memory
		}
		result, error := s.backing.procedure(s.backing.data, mode, size, alignment, old_memory, old_size, location)
		if raw_data(result) != nil {
			s.live += 1
		}
		return result, error
	}
	if mode == .Free && old_memory != nil {
		s.live -= 1
		assert(s.live >= 0)
	}
	return s.backing.procedure(s.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(test)
dns_allocator_failures_clean_table_names_values_and_prior_rows :: proc(t: ^testing.T) {
	f := dns_safety_fixture(.CNAME, []u8{0xc0, 12}, 2)
	// Table, owner and value for each of two rows. Failing row two must also
	// release the fully constructed first row, without exposing partial output.
	for nil_failure in ([?]bool{false, true}) {
		for fail_at in 1 ..= 5 {
			s := DNS_Safety_Allocator {
				backing     = context.allocator,
				fail_at     = fail_at,
				nil_failure = nil_failure,
			}
			a := mem.Allocator {
				procedure = dns_safety_allocate,
				data      = &s,
			}
			records, _, ok := parse_response(f.bytes[:f.length], .CNAME, a)
			testing.expect(t, !ok && records == nil)
			testing.expect_value(t, s.live, 0)
		}
		for fail_at in 1 ..= 2 {
			s := DNS_Safety_Allocator {
				backing     = context.allocator,
				fail_at     = fail_at,
				nil_failure = nil_failure,
			}
			cursor := f.record_start
			_, ok := parse_record(f.bytes[:f.length], &cursor, .CNAME, {procedure = dns_safety_allocate, data = &s})
			testing.expect(t, !ok && cursor == f.record_start)
			testing.expect_value(t, s.live, 0)
		}
	}
	s := DNS_Safety_Allocator {
		backing = context.allocator,
	}
	a := mem.Allocator {
		procedure = dns_safety_allocate,
		data      = &s,
	}
	records, _, ok := parse_response(f.bytes[:f.length], .CNAME, a)
	assert(ok && len(records) == 2)
	testing.expect_value(t, s.calls, 5)
	destroy_dns_records(records, a)
	testing.expect_value(t, s.live, 0)
	// Structural first-pass validation succeeds, but the second selected value
	// has a bad pointer. Cleanup still includes the first successfully parsed row.
	f.bytes[f.length - 1] = 255
	records, _, ok = parse_response(f.bytes[:f.length], .CNAME, a)
	testing.expect(t, !ok && records == nil && s.live == 0)
	records, _, ok = parse_response(f.bytes[:f.length], .CNAME, mem.nil_allocator())
	testing.expect(t, !ok && records == nil)
	name, _, name_ok := decode_hostname(f.bytes[:f.length], 12, mem.nil_allocator())
	testing.expect(t, !name_ok && name == "")
	for nil_failure in ([?]bool{false, true}) {
		failed := DNS_Safety_Allocator {
			backing     = context.allocator,
			fail_at     = 1,
			nil_failure = nil_failure,
		}
		name, _, name_ok = decode_hostname(f.bytes[:f.length], 12, {procedure = dns_safety_allocate, data = &failed})
		testing.expect(t, !name_ok && name == "" && failed.live == 0)
	}
}

@(test)
dns_srv_substrings_borrow_owned_name_after_input_and_temp_reset :: proc(t: ^testing.T) {
	f := dns_safety_fixture(.SRV, []u8{0, 1, 0, 2, 1, 187, 0xc0, 12})
	temporary: [4096]u8
	arena: mem.Arena
	mem.arena_init(&arena, temporary[:])
	context.temp_allocator = mem.arena_allocator(&arena)
	records, _, ok := parse_response(f.bytes[:f.length], .SRV)
	assert(ok && len(records) == 1)
	defer destroy_dns_records(records)
	free_all(context.temp_allocator)
	for &b in temporary {b = 0xdd}
	for &b in f.bytes {b = 0xee}
	r := records[0].(DNS_Record_SRV)
	testing.expect_value(t, r.record_name, "_sip._tcp.example.test")
	testing.expect_value(t, r.service_name, "_sip")
	testing.expect_value(t, r.protocol_name, "_tcp")
	testing.expect_value(t, r.target, "example.test")
	testing.expect(t, raw_data(r.service_name) == raw_data(r.record_name))
	testing.expect(t, uintptr(raw_data(r.protocol_name)) == uintptr(raw_data(r.record_name)) + 5)
}

@(test)
dns_bounded_deterministic_mutations_do_not_escape_tracking_or_bounds :: proc(t: ^testing.T) {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	allocator := mem.tracking_allocator(&tracker)
	seed: u32 = 0x149dec0d
	for iteration in 0 ..< 2048 {
		seed = seed * 1664525 + 1013904223
		kind := DNS_Record_Type.CNAME
		if iteration % 3 == 0 {
			kind = .IP4
		}
		data := []u8{0xc0, 12}
		if kind == .IP4 {
			data = []u8{192, 0, 2, 7}
		}
		f := dns_safety_fixture(kind, data, 2)
		for _ in 0 ..< 1 + iteration % 4 {
			seed = seed * 1664525 + 1013904223
			at := int(seed % u32(f.length))
			f.bytes[at] = u8(seed >> 24)
		}
		length := f.length
		if iteration % 5 == 0 {
			length = int(seed % u32(f.length + 1))
		}
		filter := kind
		if iteration % 7 == 0 {
			filter = nil
		}
		records, _, ok := parse_response(f.bytes[:length], filter, allocator)
		if ok {
			destroy_dns_records(records, allocator)
		} else {
			testing.expect(t, records == nil)
		}
		testing.expect_value(t, tracker.current_memory_allocated, i64(0))
	}
}
