package net

// Numeric nonblocking setup primitives, with zero-time polling and no resolver,
// event loop or callbacks. This capability covers both begin and poll contracts.
TCP_NONBLOCKING_CONNECT_SUPPORTED :: ODIN_OS == .Darwin || ODIN_OS == .Linux

// Success transfers one nonblocking descriptor to the caller whether connected
// is true or false. On failure no descriptor is retained. Never repeats connect.
begin_tcp_connect :: proc(
	endpoint: Endpoint,
	options := DEFAULT_TCP_OPTIONS,
) -> (
	socket: TCP_Socket,
	connected: bool,
	error: Network_Error,
) {
	if endpoint.port == 0 {
		return 0, false, Dial_Error.Port_Required
	}
	if endpoint.address == nil || endpoint.port < 0 || endpoint.port > 65535 {
		return 0, false, Dial_Error.Invalid_Argument
	}
	when ODIN_OS ==
		.Darwin || ODIN_OS == .Linux {return _begin_tcp_connect(endpoint, options)} else {return 0, false, Dial_Error.Unsupported}
}

// Queries a descriptor returned by begin_tcp_connect. Never waits: connected
// false with nil error means still pending. Caller retains descriptor ownership
// on every outcome and MUST close after a terminal error; SO_ERROR is consumed,
// so calling poll again after that error does not repeat a reliable diagnostic.
// On successful completion the descriptor remains nonblocking.
poll_tcp_connect :: proc(socket: TCP_Socket) -> (connected: bool, error: Network_Error) {
	when ODIN_OS ==
		.Darwin || ODIN_OS == .Linux {return _poll_tcp_connect(socket)} else {return false, Dial_Error.Unsupported}
}
