#+build !darwin
#+build !linux
package net
@(private)
_udp_enable_ecn :: proc(socket: UDP_Socket, family: Address_Family) -> bool {return false}

@(private)
_recv_udp_metadata :: proc(socket: UDP_Socket, dst: []u8) -> (int, Endpoint, UDP_Metadata, UDP_Recv_Error) {
	n, p, e := recv_udp(socket, dst)
	return n, p, {}, e
}

@(private)
_send_udp_ecn :: proc(socket: UDP_Socket, src: []u8, to: Endpoint, ecn: ECN_Codepoint) -> (int, UDP_Send_Error) {
	if ecn != .Not_ECT {
		return 0, .Invalid_Argument
	}
	return send_udp(socket, src, to)
}
