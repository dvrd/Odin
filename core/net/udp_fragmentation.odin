package net

// Configured is returned only after querying the kernel's no-fragment policy.
// Unsupported is distinct from local descriptor/setup failure. No TCP option or
// IPv6-only policy is changed; a dual-stack socket retains both address families.
UDP_Fragmentation_Status :: enum {
	Unsupported,
	Configured,
	Not_Configured,
	Failed,
	Invalid_Family,
	Invalid_Socket,
}

UDP_Fragmentation_Result :: struct {
	status:                 UDP_Fragmentation_Status,
	native_error:           i32,
	ipv4, ipv6, dual_stack: bool,
}

// Disable IP fragmentation on a caller-owned UDP socket. family must describe
// the socket, not an individual peer (which may be IPv4-mapped on dual-stack).
// Failure may leave a partially configured socket; QUIC must not send until a
// later call returns Configured. The socket remains owned by the caller.
udp_disable_fragmentation :: proc(socket: UDP_Socket, family: Address_Family) -> UDP_Fragmentation_Result {
	return _udp_fragmentation_policy(socket, family, true)
}

// Observe policy without changing it. Not_Configured never implies that sending
// QUIC is safe. IPv6 Configured includes IPv4 when dual_stack is true.
udp_fragmentation_policy :: proc(socket: UDP_Socket, family: Address_Family) -> UDP_Fragmentation_Result {
	return _udp_fragmentation_policy(socket, family, false)
}
