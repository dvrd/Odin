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

@(private)
dial_poll_timeout :: proc(deadline: time.Time) -> i32 {
	remaining := time.diff(time.now(), deadline)
	if remaining <= 0 {return 0}
	milliseconds := remaining / time.Millisecond
	if remaining % time.Millisecond != 0 {milliseconds += 1}
	return i32(min(milliseconds, time.Duration(max(i32))))
}
