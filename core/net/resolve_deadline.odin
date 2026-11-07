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
