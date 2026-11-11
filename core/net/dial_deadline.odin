package net

import "core:time"

// Connects to a numeric endpoint within one absolute deadline. Success returns
// a blocking socket, matching dial_tcp. Zero delegates to the unchanged legacy
// endpoint procedure. No resolver, event loop, worker or callback is involved.
// Explicit deadlines are currently implemented on Darwin and Linux only.
dial_tcp_until :: proc(endpoint: Endpoint, deadline: time.Time, options := DEFAULT_TCP_OPTIONS) -> (TCP_Socket, Network_Error) {
	if deadline == (time.Time{}) {return dial_tcp_from_endpoint(endpoint, options)}
	if time.diff(time.now(), deadline) <= 0 {return 0, Dial_Error.Timeout}
	if endpoint.port == 0 {return 0, Dial_Error.Port_Required}
	if endpoint.port < 0 || endpoint.port > 65535 || endpoint.address == nil {return 0, Dial_Error.Invalid_Argument}
	when ODIN_OS == .Darwin || ODIN_OS == .Linux {
		return _dial_tcp_until(endpoint, deadline, options)
	} else {
		return 0, Dial_Error.Unsupported
	}
}

// A blackholed earlier answer must leave time for a later one.
DIAL_CANDIDATE_SLICE :: 250 * time.Millisecond

// Dials resolved addresses in order. Every attempt except the last is capped
// so one dead address cannot spend the caller's whole deadline.
dial_tcp_candidates_until :: proc(
	endpoints: Resolved_Endpoints,
	deadline: time.Time,
	options := DEFAULT_TCP_OPTIONS,
) -> (
	TCP_Socket,
	Network_Error,
) {
	if endpoints.count <= 0 {
		return 0, Resolve_Error.Unable_To_Resolve
	}
	last_error: Network_Error = Resolve_Error.Unable_To_Resolve
	for i in 0 ..< endpoints.count {
		now := time.now()
		if deadline != (time.Time{}) && time.diff(now, deadline) <= 0 {
			return 0, Dial_Error.Timeout
		}
		attempt := deadline
		if i+1 < endpoints.count && deadline != (time.Time{}) {
			remaining := time.diff(now, deadline)
			if remaining > DIAL_CANDIDATE_SLICE {
				attempt = time.time_add(now, DIAL_CANDIDATE_SLICE)
			}
		}
		socket, dial_error := dial_tcp_until(endpoints.items[i], attempt, options)
		if dial_error == nil {
			return socket, nil
		}
		last_error = dial_error
	}
	return 0, last_error
}

// Resolves A and AAAA, then dials later answers inside the same deadline.
dial_tcp_resolved_until :: proc(
	hostname: string,
	port: int,
	deadline: time.Time,
	options: Resolver_Options = {},
	allocator := context.allocator,
) -> (
	TCP_Socket,
	Network_Error,
) {
	endpoints, resolve_error := resolve_endpoints_until(hostname, port, deadline, options, allocator)
	if resolve_error != nil {
		return 0, resolve_error
	}
	return dial_tcp_candidates_until(endpoints, deadline)
}

@(private)
dial_poll_timeout :: proc(deadline: time.Time) -> i32 {
	remaining := time.diff(time.now(), deadline)
	if remaining <= 0 {return 0}
	milliseconds := remaining / time.Millisecond
	if remaining % time.Millisecond != 0 {milliseconds += 1}
	return i32(min(milliseconds, time.Duration(max(i32))))
}
