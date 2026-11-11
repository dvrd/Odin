package net

import "core:time"

// Explicit nameservers are borrowed for this call. Nil uses the platform's
// existing resolver configuration, without changing global resolver settings.
Resolver_Options :: struct {name_servers: []Endpoint}

get_dns_records_from_os_until :: proc(hostname: string, type: DNS_Record_Type, deadline: time.Time, allocator := context.allocator) -> ([]DNS_Record, DNS_Error) {
	if deadline == (time.Time{}) {return get_dns_records_from_os(hostname, type, allocator)}
	if time.diff(time.now(), deadline) <= 0 {return nil, .Timeout}
	when ODIN_OS == .Darwin || ODIN_OS == .Linux || ODIN_OS == .FreeBSD || ODIN_OS == .OpenBSD || ODIN_OS == .NetBSD {
		init_dns_configuration()
		return dns_records_os_until(hostname, type, deadline, allocator)
	} else {
		// OS resolvers without a bounded primitive must not silently block.
		return nil, .Unsupported
	}
}

// Resolves one endpoint, preferring IPv4 without waiting for an unnecessary
// IPv6 query. All queries share one absolute deadline. Local configuration-file
// reads and allocator callbacks are synchronous and must return cooperatively.
resolve_endpoint_until :: proc(hostname: string, port: int, deadline: time.Time, options: Resolver_Options = {}, allocator := context.allocator) -> (endpoint: Endpoint, err: Network_Error) {
	if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {return {}, DNS_Error.Timeout}
	if port <= 0 || port > 65535 {return {}, Dial_Error.Invalid_Argument}
	target := parse_hostname_or_endpoint(hostname) or_return
	switch t in target {
	case Endpoint:
		return {address = t.address, port = port}, nil
	case Host:
		for type in ([?]DNS_Record_Type{.IP4, .IP6}) {
			records: []DNS_Record
			error: DNS_Error
			if options.name_servers != nil {
				records, error = get_dns_records_from_nameservers_until(t.hostname, type, options.name_servers, nil, deadline, allocator)
			} else {
				records, error = get_dns_records_from_os_until(t.hostname, type, deadline, allocator)
			}
			defer destroy_dns_records(records, allocator)
			if error == .Timeout || error == .Unsupported {return {}, error}
			for record in records {
				#partial switch r in record {
				case DNS_Record_IP4: return {address = r.address, port = port}, nil
				case DNS_Record_IP6: return {address = r.address, port = port}, nil
				}
			}
		}
		return {}, Resolve_Error.Unable_To_Resolve
	}
	unreachable()
}

// Enough for the A records a normal reply carries, then the AAAA records.
// Further answers are not dialed; the caller's deadline still applies.
MAX_RESOLVED_ENDPOINTS :: 8
// A later family query must not consume the whole dial budget.
RESOLVE_FOLLOWUP_SLICE :: 250 * time.Millisecond

Resolved_Endpoints :: struct {
	items: [MAX_RESOLVED_ENDPOINTS]Endpoint,
	count: int,
}

// Every A answer, then every AAAA answer, inside one absolute deadline.
// A usable IPv4 result is kept when the IPv6 query itself times out.
resolve_endpoints_until :: proc(
	hostname: string,
	port: int,
	deadline: time.Time,
	options: Resolver_Options = {},
	allocator := context.allocator,
) -> (
	out: Resolved_Endpoints,
	err: Network_Error,
) {
	if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {
		return {}, DNS_Error.Timeout
	}
	if port <= 0 || port > 65535 {
		return {}, Dial_Error.Invalid_Argument
	}
	target := parse_hostname_or_endpoint(hostname) or_return
	switch t in target {
	case Endpoint:
		out.items[0] = {address = t.address, port = port}
		out.count = 1
		return out, nil
	case Host:
		for type in ([?]DNS_Record_Type{.IP4, .IP6}) {
			query_deadline := deadline
			if type == .IP6 && out.count > 0 && deadline != (time.Time{}) {
				remaining := time.diff(time.now(), deadline)
				if remaining <= 0 {
					return out, nil
				}
				if remaining > RESOLVE_FOLLOWUP_SLICE {
					query_deadline = time.time_add(time.now(), RESOLVE_FOLLOWUP_SLICE)
				}
			}
			records: []DNS_Record
			error: DNS_Error
			if options.name_servers != nil {
				records, error = get_dns_records_from_nameservers_until(t.hostname, type, options.name_servers, nil, query_deadline, allocator)
			} else {
				records, error = get_dns_records_from_os_until(t.hostname, type, query_deadline, allocator)
			}
			defer destroy_dns_records(records, allocator)
			if error == .Timeout || error == .Unsupported {
				if out.count > 0 {
					return out, nil
				}
				return {}, error
			}
			for record in records {
				if out.count == MAX_RESOLVED_ENDPOINTS {
					return out, nil
				}
				#partial switch r in record {
				case DNS_Record_IP4:
					out.items[out.count] = {address = r.address, port = port}
					out.count += 1
				case DNS_Record_IP6:
					out.items[out.count] = {address = r.address, port = port}
					out.count += 1
				}
			}
		}
		if out.count == 0 {
			return {}, Resolve_Error.Unable_To_Resolve
		}
		return out, nil
	}
	unreachable()
}
