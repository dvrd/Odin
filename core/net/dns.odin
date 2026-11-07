package net

/*
	Package net implements cross-platform Berkeley Sockets, DNS resolution and associated procedures.
	For other protocols and their features, see subdirectories of this package.
*/

/*
	Copyright 2022 Tetralux             <tetraluxonpc@gmail.com>
	Copyright 2022 Colin Davidson       <colrdavidson@gmail.com>
	Copyright 2022 Jeroen van Rijn      <nom@duclavier.com>.
	Copyright 2024 Feoramund            <rune@swevencraft.org>.
	Copyright 2025 Christiano Haesbaert <haesbaert@haesbaert.org>.
	Made available under Odin's license.

	List of contributors:
		Tetralux:        Initial implementation
		Colin Davidson:  Linux platform code, OSX platform code, Odin-native DNS resolver
		Jeroen van Rijn: Cross platform unification, code style, documentation
		Feoramund:       FreeBSD platform code
		Haesbaert:       Security fixes
*/

@(require)
import "base:runtime"
import "core:bufio"
import "core:io"
import "core:mem"
import "core:strings"
import "core:time"

@(require)
import "core:sync"

dns_config_initialized: sync.Once
when ODIN_OS == .Windows {
	dns_configuration := DNS_Configuration{
		resolv_conf = "",
		hosts_file  = "%WINDIR%\\system32\\drivers\\etc\\hosts",
	}
} else when ODIN_OS == .Linux || ODIN_OS == .Darwin || ODIN_OS == .FreeBSD || ODIN_OS == .OpenBSD || ODIN_OS == .NetBSD {
	dns_configuration := DNS_Configuration{
		resolv_conf = "/etc/resolv.conf",
		hosts_file  = "/etc/hosts",
	}
} else {
	DEFAULT_DNS_CONFIGURATION :: DNS_Configuration{}
}

init_dns_configuration :: proc() {
	when ODIN_OS == .Windows {
		_init_dns_configuration()
	}
}

/*
	Resolves a hostname to exactly one IP4 and IP6 endpoint.
	It's then up to you which one you use.
	Note that which address you use to open a socket, determines the type of the socket you get.

	Returns `ok=false` if the host name could not be resolved to any endpoints.

	Returned endpoints have the same port as provided in the string, or 0 if absent.
	If you want to use a specific port, just modify the field after the call to this procedure.

	If the hostname part of the endpoint is actually a string representation of an IP address, DNS resolution will be skipped.
	This allows you to pass both strings like "example.com:9000" and "1.2.3.4:9000" to this function end reliably get
	back an endpoint in both cases.
*/
resolve :: proc(hostname_and_maybe_port: string) -> (ep4, ep6: Endpoint, err: Network_Error) {
	target := parse_hostname_or_endpoint(hostname_and_maybe_port) or_return
	switch t in target {
	case Endpoint:
		// NOTE(tetra): The hostname was actually an IP address; nothing to resolve, so just return it.
		switch _ in t.address {
		case IP4_Address: ep4 = t
		case IP6_Address: ep6 = t
		case:             unreachable()
		}
		return

	case Host:
		err4, err6: Network_Error = ---, ---
		ep4, err4 = resolve_ip4(t.hostname)
		ep6, err6 = resolve_ip6(t.hostname)
		ep4.port  = t.port if err4 == nil else 0
		ep6.port  = t.port if err6 == nil else 0
		if err4 != nil && err6 != nil {
			err = err4
		}
		return
	}
	unreachable()
}

resolve_ip4 :: proc(hostname_and_maybe_port: string) -> (ep4: Endpoint, err: Network_Error) {
	target := parse_hostname_or_endpoint(hostname_and_maybe_port) or_return
	switch t in target {
	case Endpoint:
		// NOTE(tetra): The hostname was actually an IP address; nothing to resolve, so just return it.
		switch _ in t.address {
		case IP4_Address:
			return t, nil
		case IP6_Address:
			err = .Unable_To_Resolve
			return
		}
	case Host:
		recs: []DNS_Record

		if ODIN_OS != .Windows && strings.has_suffix(t.hostname, ".local") {
			recs, _ = get_dns_records_from_nameservers(t.hostname, .IP4, {IP4_mDNS_Broadcast}, nil, context.temp_allocator)
		} else {
			recs, _ = get_dns_records_from_os(t.hostname, .IP4, context.temp_allocator)
		}

		if len(recs) == 0 {
			err = .Unable_To_Resolve
			return
		}
		ep4 = {
			address = recs[0].(DNS_Record_IP4).address,
			port = t.port,
		}
		return
	}
	unreachable()
}

resolve_ip6 :: proc(hostname_and_maybe_port: string) -> (ep6: Endpoint, err: Network_Error) {
	target := parse_hostname_or_endpoint(hostname_and_maybe_port) or_return
	switch t in target {
	case Endpoint:
		// NOTE(tetra): The hostname was actually an IP address; nothing to resolve, so just return it.
		switch _ in t.address {
		case IP4_Address:
			err = .Unable_To_Resolve
			return
		case IP6_Address:
			return t, nil
		}
	case Host:
		recs: []DNS_Record

		if ODIN_OS != .Windows && strings.has_suffix(t.hostname, ".local") {
			recs, _ = get_dns_records_from_nameservers(t.hostname, .IP6, {IP6_mDNS_Broadcast}, nil, context.temp_allocator)
		} else {
			recs, _ = get_dns_records_from_os(t.hostname, .IP6, context.temp_allocator)
		}

		if len(recs) == 0 {
			err = .Unable_To_Resolve
			return
		}
		ep6 = {
			address = recs[0].(DNS_Record_IP6).address,
			port = t.port,
		}
		return
	}
	unreachable()
}

/*
	Performs a recursive DNS query for records of a particular type for the hostname using the OS.

	NOTE: This procedure instructs the DNS resolver to recursively perform CNAME requests on our behalf,
	meaning that DNS queries for a hostname will resolve through CNAME records until an
	IP address is reached.

	IMPORTANT: This procedure allocates memory for each record returned; deleting just the returned slice is not enough!
	See `destroy_records`.
*/
get_dns_records_from_os :: proc(hostname: string, type: DNS_Record_Type, allocator := context.allocator) -> (records: []DNS_Record, err: DNS_Error) {
	init_dns_configuration()
	return _get_dns_records_os(hostname, type, allocator)
}

/*
	A generic DNS client usable on any platform.
	Performs a recursive DNS query for records of a particular type for the hostname.

	NOTE: This procedure instructs the DNS resolver to recursively perform CNAME requests on our behalf,
	meaning that DNS queries for a hostname will resolve through CNAME records until an
	IP address is reached.

	IMPORTANT: This procedure allocates memory for each record returned; deleting just the returned slice is not enough!
	See `destroy_records`.
*/
get_dns_records_from_nameservers :: proc(hostname: string, type: DNS_Record_Type, name_servers: []Endpoint, host_overrides: []DNS_Record, allocator := context.allocator) -> (records: []DNS_Record, err: DNS_Error) {
	return dns_records_from_nameservers_until(hostname, type, name_servers, host_overrides, {}, allocator)
}

// An absolute deadline bounds all socket waits across every nameserver. Zero
// preserves the existing one-second per-server receive policy.
get_dns_records_from_nameservers_until :: proc(hostname: string, type: DNS_Record_Type, name_servers: []Endpoint, host_overrides: []DNS_Record, deadline: time.Time, allocator := context.allocator) -> ([]DNS_Record, DNS_Error) {
	return dns_records_from_nameservers_until(hostname, type, name_servers, host_overrides, deadline, allocator)
}

@(private)
dns_records_from_nameservers_until :: proc(hostname: string, type: DNS_Record_Type, name_servers: []Endpoint, host_overrides: []DNS_Record, deadline: time.Time, allocator := context.allocator) -> (records: []DNS_Record, err: DNS_Error) {
	if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {return nil, .Timeout}
	when ODIN_OS != .Darwin && ODIN_OS != .Linux && ODIN_OS != .FreeBSD && ODIN_OS != .OpenBSD && ODIN_OS != .NetBSD {
		if deadline != (time.Time{}) {return nil, .Unsupported}
	}
	init_dns_configuration()
	context.allocator = allocator

	id: u16be
	rand_ok := runtime.random_generator_read_ptr(context.random_generator, &id, size_of(id))
	assert(rand_ok, "uninitialized gen/context.random_generator")

	dns_packet_buf: [DNS_PACKET_MIN_LEN]byte = ---
	dns_packet := make_dns_packet(dns_packet_buf[:], id, hostname, type) or_return

	dns_response_buf: [4096]u8 = ---
	dns_response: []u8
	for name_server in name_servers {
		if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {return nil, .Timeout}
		conn, sock_err := make_unbound_udp_socket(family_from_endpoint(name_server))
		if sock_err != nil {
			return nil, .Connection_Error
		}
		defer close(conn)

		if deadline != (time.Time{}) {
			remaining := time.diff(time.now(), deadline)
			if remaining <= 0 {return nil, .Timeout}
			if set_option(conn, .Send_Timeout, dns_socket_timeout(remaining)) != nil {return nil, .Unsupported}
		}
		_ = send(conn, dns_packet[:], name_server) or_continue

		receive_deadline := time.tick_add(time.tick_now(), time.Second * 1)
		for {
			timeout := time.tick_diff(time.tick_now(), receive_deadline)
			if timeout < time.Millisecond {
				break
			}
			if deadline != (time.Time{}) {
				remaining := time.diff(time.now(), deadline)
				if remaining <= 0 {
					return nil, .Timeout
				}
				timeout = dns_socket_timeout(min(timeout, remaining))
			}
			if set_option(conn, .Receive_Timeout, timeout) != nil {
				return nil, .Connection_Error
			}

			recv_sz, src := recv_udp(conn, dns_response_buf[:]) or_break
			if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {
				return nil, .Timeout
			}
			if recv_sz < size_of(id) {
				continue
			}
			if src != name_server && !(is_multicast(name_server.address) && src.port == name_server.port) {
				continue
			}

			dns_response = dns_response_buf[:recv_sz]
			xid := transmute(u16be)[2]u8{dns_response[0], dns_response[1]}
			if xid != id {
				continue
			}

			rsp, _, _ok := parse_response(dns_response, type)
			if !_ok {
				return nil, .Server_Error
			}

			if len(rsp) == 0 {
				destroy_dns_records(rsp[:])
				break
			}

			return rsp[:], nil
		}
	}

	if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {return nil, .Timeout}

	return
}

DNS_PACKET_MIN_LEN :: (size_of(u16be) * 6) + NAME_MAX + (size_of(u16be) * 2)

make_dns_packet :: proc(buf: []byte, id: u16be, hostname: string, type: DNS_Record_Type) -> (packet: []byte, err: DNS_Error) {
	assert(len(buf) >= DNS_PACKET_MIN_LEN)

	hdr := DNS_Header{
		id = id,
		is_response = false,
		opcode = 0,
		is_authoritative = false,
		is_truncated = false,
		is_recursion_desired = true,
		is_recursion_available = false,
		response_code = DNS_Response_Code.No_Error,
	}

	_, bits := pack_dns_header(hdr)
	dns_hdr := [6]u16be{}
	dns_hdr[0] = id
	dns_hdr[1] = bits
	dns_hdr[2] = 1

	dns_query := [2]u16be{ u16be(type), 1 }

	b := strings.builder_from_slice(buf[:])

	strings.write_bytes(&b, mem.slice_data_cast([]u8, dns_hdr[:]))
	ok := encode_hostname(&b, hostname)
	if !ok {
		return nil, .Invalid_Hostname_Error
	}
	strings.write_bytes(&b, mem.slice_data_cast([]u8, dns_query[:]))

	return buf[:strings.builder_len(b)], nil
}

// `records` slice is also destroyed.
destroy_dns_records :: proc(records: []DNS_Record, allocator := context.allocator) {
	context.allocator = allocator

	for rec in records {
		switch r in rec {
		case DNS_Record_IP4:
			delete(r.base.record_name)

		case DNS_Record_IP6:
			delete(r.base.record_name)

		case DNS_Record_CNAME:
			delete(r.base.record_name)
			delete(r.host_name)

		case DNS_Record_TXT:
			delete(r.base.record_name)
			delete(r.value)

		case DNS_Record_NS:
			delete(r.base.record_name)
			delete(r.host_name)

		case DNS_Record_MX:
			delete(r.base.record_name)
			delete(r.host_name)

		case DNS_Record_SRV:
			delete(r.record_name)
			delete(r.target)
		}
	}

	delete(records, allocator)
}

/*
	TODO(cloin): Does the DNS Resolver need to recursively hop through CNAMEs to get the IP
	or is that what recursion desired does? Do we need to handle recursion unavailable?
	How do we deal with is_authoritative / is_truncated?
*/

NAME_MAX  :: 255
LABEL_MAX :: 63

pack_dns_header :: proc(hdr: DNS_Header) -> (id: u16be, bits: u16be) {
	id = hdr.id
	bits = hdr.opcode << 1 | u16be(hdr.response_code)
	if hdr.is_response {
		bits |= 1 << 15
	}
	if hdr.is_authoritative {
		bits |= 1 << 10
	}
	if hdr.is_truncated {
		bits |= 1 << 9
	}
	if hdr.is_recursion_desired {
		bits |= 1 << 8
	}
	if hdr.is_recursion_available {
		bits |= 1 << 7
	}

	return id, bits
}

unpack_dns_header :: proc(id: u16be, bits: u16be) -> (hdr: DNS_Header) {
	hdr.id = id
	hdr.is_response            = (bits & (1 << 15)) != 0
	hdr.opcode                 = (bits >> 11) & 0xF
	hdr.is_authoritative       = (bits & (1 << 10)) != 0
	hdr.is_truncated           = (bits & (1 <<  9)) != 0
	hdr.is_recursion_desired   = (bits & (1 <<  8)) != 0
	hdr.is_recursion_available = (bits & (1 <<  7)) != 0
	hdr.response_code          = DNS_Response_Code(bits & 0xF)

	return hdr
}

parse_resolv_conf :: proc(resolv_str: string, allocator := context.allocator) -> (name_servers: []Endpoint) {
	resolv_str := resolv_str
	id_str := "nameserver"
	id_len := len(id_str)

	_name_servers := make([dynamic]Endpoint, 0, allocator)
	for line in strings.split_lines_iterator(&resolv_str) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if len(line) < id_len || strings.compare(line[:id_len], id_str) != 0 {
			continue
		}

		server_ip_str := strings.trim_left_space(line[id_len:])
		if end := strings.index_any(server_ip_str, " \t#;"); end >= 0 {
			server_ip_str = server_ip_str[:end]
		}
		if len(server_ip_str) == 0 {
			continue
		}

		addr := parse_address(server_ip_str)
		if addr == nil {
			continue
		}

		endpoint := Endpoint{
			addr,
			53,
		}
		append(&_name_servers, endpoint)
	}

	return _name_servers[:]
}

parse_hosts :: proc(stream: io.Stream, allocator := context.allocator) -> (hosts: []DNS_Host_Entry, ok: bool) {
	s := bufio.scanner_init(&{}, stream, allocator)
	defer bufio.scanner_destroy(s)

	resize(&s.buf, 256)

	_hosts: [dynamic]DNS_Host_Entry
	_hosts.allocator = allocator
	defer if !ok {
		for host in _hosts {
			delete(host.name, allocator)
		}
		delete(_hosts)
	}

	for bufio.scanner_scan(s) {
		line := bufio.scanner_text(s)

		line, _, _ = strings.partition(line, "#")
		(len(line) > 0) or_continue

		ip_str := strings.fields_iterator(&line) or_continue

		addr := parse_address(ip_str)
		(addr != nil) or_continue

		for hostname in strings.fields_iterator(&line) {
			(len(hostname) > 0) or_continue

			clone, alloc_err := strings.clone(hostname, allocator)
			if alloc_err != nil { return }

			_, alloc_err = append(&_hosts, DNS_Host_Entry{clone, addr})
			if alloc_err != nil { return }
		}
	}

	if bufio.scanner_error(s) != nil { return }

	hosts = _hosts[:]
	ok    = true
	return
}

// www.google.com -> 3www6google3com0
encode_hostname :: proc(b: ^strings.Builder, hostname: string) -> (ok: bool) {
	_hostname := hostname
	for section in strings.split_iterator(&_hostname, ".") {
		if len(section) > LABEL_MAX {
			return
		}

		strings.write_byte(b, u8(len(section)))
		strings.write_string(b, section)
	}
	strings.write_byte(b, 0)

	return true
}

// Uses RFC 952 & RFC 1123
validate_hostname :: proc(hostname: string) -> (ok: bool) {
	if len(hostname) > NAME_MAX || len(hostname) == 0 {
		return
	}

	if hostname[0] == '-' {
		return
	}

	_hostname := hostname
	for label in strings.split_iterator(&_hostname, ".") {
		if len(label) > LABEL_MAX || len(label) == 0 {
			return
		}

		for ch in label {
			switch ch {
			case:
				return
			case 'a'..='z', 'A'..='Z', '0'..='9', '-', '_':
				continue
			}
		}
	}

	return true
}

parse_record :: proc(
	packet: []u8,
	cur_off: ^int,
	filter: DNS_Record_Type = nil,
	allocator := context.allocator,
) -> (
	record: DNS_Record,
	ok: bool,
) {
	if cur_off == nil {
		return nil, false
	}
	owner_buffer: [NAME_MAX]u8
	header, data_start, finish, owner_size, valid := dns_record_span(
		packet,
		cur_off^,
		owner_buffer[:],
	)
	if !valid {
		return nil, false
	}
	if header.type != u16be(filter) {
		cur_off^ = finish; return nil, true
	}
	data := packet[data_start:finish]
	kind := DNS_Record_Type(header.type)
	target_buffer: [NAME_MAX]u8
	value: []u8
	first_dot, second_dot := -1, -1
	prefix := 0
	switch kind {
	case .IP4:
		if len(data) != 4 {
			return nil, false
		}
	case .IP6:
		if len(data) != 16 {
			return nil, false
		}
	case .TXT:
		value = data
	case .CNAME, .NS, .MX, .SRV:
		if kind == .MX {
			prefix = 2
		}
		if kind == .SRV {
			prefix = 6
			owner := string(owner_buffer[:owner_size])
			first_dot = strings.index_byte(owner, '.')
			if first_dot < 0 {
				return nil, false
			}
			rest := strings.index_byte(owner[first_dot + 1:], '.')
			if rest < 0 {
				return nil, false
			}
			second_dot = first_dot + 1 + rest
		}
		if len(data) <= prefix {
			return nil, false
		}
		decoded, encoded, name_ok := dns_name_read(packet, data_start + prefix, target_buffer[:])
		if !name_ok || encoded != len(data) - prefix {
			return nil, false
		}
		value = target_buffer[:decoded]
	case:
		return nil, false
	}
	owned_name, name_ok := dns_clone_bytes(owner_buffer[:owner_size], allocator)
	if !name_ok {
		return nil, false
	}
	owned_value: string
	committed := false
	defer if !committed {
		delete(owned_name, allocator); delete(owned_value, allocator)
	}
	if kind == .TXT || kind == .CNAME || kind == .NS || kind == .MX || kind == .SRV {
		value_ok: bool
		owned_value, value_ok = dns_clone_bytes(value, allocator)
		if !value_ok {
			return nil, false
		}
	}
	base := DNS_Record_Base {
		record_name = owned_name,
		ttl_seconds = u32(header.ttl),
	}
	switch kind {
	case .IP4:
		record = DNS_Record_IP4 {
			base    = base,
			address = (cast(^IP4_Address)raw_data(data))^,
		}
	case .IP6:
		record = DNS_Record_IP6 {
			base    = base,
			address = (cast(^IP6_Address)raw_data(data))^,
		}
	case .TXT:
		record = DNS_Record_TXT {
			base  = base,
			value = owned_value,
		}
	case .CNAME:
		record = DNS_Record_CNAME {
			base      = base,
			host_name = owned_value,
		}
	case .NS:
		record = DNS_Record_NS {
			base      = base,
			host_name = owned_value,
		}
	case .MX:
		record = DNS_Record_MX {
			base       = base,
			host_name  = owned_value,
			preference = (int(data[0]) << 8) | int(data[1]),
		}
	case .SRV:
		record = DNS_Record_SRV {
			base          = base,
			target        = owned_value,
			service_name  = owned_name[:first_dot],
			protocol_name = owned_name[first_dot + 1:second_dot],
			priority      = (int(data[0]) << 8) | int(data[1]),
			weight        = (int(data[2]) << 8) | int(data[3]),
			port          = (int(data[4]) << 8) | int(data[5]),
		}
	}
	cur_off^ = finish; committed = true
	return record, true
}

/*
	DNS Query Response Format:
	- DNS_Header (packed)
	- Query Count
	- Answer Count
	- Authority Count
	- Additional Count
	- Query[]
		- Hostname -- encoded
		- Type
		- Class
	- Answer[]
		- DNS Record Data
	- Authority[]
		- DNS Record Data
	- Additional[]
		- DNS Record Data

	DNS Record Data:
	- DNS_Record_Header
	- Data[]
*/

parse_response :: proc(
	response: []u8,
	filter: DNS_Record_Type = nil,
	allocator := context.allocator,
) -> (
	records: []DNS_Record,
	xid: u16be,
	ok: bool,
) {
	HEADER_SIZE_BYTES :: 12
	if len(response) < HEADER_SIZE_BYTES {
		return nil, 0, false
	}
	chunks := mem.slice_data_cast([]u16be, response[:HEADER_SIZE_BYTES])
	header := unpack_dns_header(chunks[0], chunks[1])
	if !header.is_response || int(chunks[2]) != 1 {
		return nil, 0, false
	}
	_, question_size, question_ok := dns_name_read(response, HEADER_SIZE_BYTES, nil)
	if !question_ok ||
	   len(response) - HEADER_SIZE_BYTES < 4 ||
	   question_size > len(response) - HEADER_SIZE_BYTES - 4 {
		return nil, 0, false
	}
	start := HEADER_SIZE_BYTES + question_size + 4
	total := int(chunks[3]) + int(chunks[4]) + int(chunks[5])
	// An uncompressed root plus the fixed record header is the minimum extent.
	// Bound advertised work by real bytes before any allocation or record loop.
	if total > (len(response) - start) / (1 + size_of(DNS_Record_Header)) {
		return nil, 0, false
	}
	cursor, matching := start, 0
	for _ in 0 ..< total {
		record_header, _, finish, _, valid := dns_record_span(response, cursor)
		if !valid {
			return nil, 0, false
		}
		if record_header.type == u16be(filter) {
			matching += 1
		}
		cursor = finish
	}
	if matching == 0 {
		return nil, header.id, true
	}
	// Allocate the exact returned table once, so its slice owns the whole backing.
	result, error := make([]DNS_Record, matching, allocator)
	if error != nil || raw_data(result) == nil || len(result) != matching {
		if raw_data(result) != nil {
			delete(result, allocator)
		}
		return nil, 0, false
	}
	committed := false
	defer if !committed {
		destroy_dns_records(result, allocator)
	}
	cursor = start
	used := 0
	for _ in 0 ..< total {
		value, valid := parse_record(response, &cursor, filter, allocator)
		if !valid {
			return nil, 0, false
		}
		if value != nil {
			result[used] = value; used += 1
		}
	}
	if used != matching {
		return nil, 0, false
	}
	committed = true
	return result, header.id, true
}

// timeval backends truncate to microseconds: a positive sub-microsecond wait
// must not become {0,0}, which disables SO_RCVTIMEO/SO_SNDTIMEO entirely.
@(private)
dns_socket_timeout :: proc(remaining: time.Duration) -> time.Duration {
	return max(remaining, time.Microsecond)
}
