#+build !darwin
#+build !linux
package net
@(private)
_udp_fragmentation_policy :: proc(
	socket: UDP_Socket,
	family: Address_Family,
	configure: bool,
) -> UDP_Fragmentation_Result {
	if family != .IP4 && family != .IP6 {
		return {status = .Invalid_Family}
	}
	return {status = .Unsupported}
}
