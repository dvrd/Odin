package net

// ECN occupies only the low two bits of the IP traffic-class field.
ECN_Codepoint :: enum u8 {Not_ECT=0, ECT_1=1, ECT_0=2, CE=3}
UDP_Metadata :: struct {ecn:ECN_Codepoint, ecn_valid:bool, control_truncated:bool}

// Enable ancillary ECN reporting. False means unavailable; callers can continue
// unmarked UDP. This does not alter the codepoint used by send_udp.
udp_enable_ecn :: proc(socket:UDP_Socket,family:Address_Family)->bool {return _udp_enable_ecn(socket,family)}
// Receives exactly one datagram. Missing/truncated control data never fabricates
// Not-ECT feedback: ecn_valid is false. Payload truncation retains normal semantics.
recv_udp_metadata :: proc(socket:UDP_Socket,dst:[]u8)->(int,Endpoint,UDP_Metadata,UDP_Recv_Error) {return _recv_udp_metadata(socket,dst)}
// Per-datagram marking avoids socket-wide traffic-class races. DSCP is zero.
send_udp_ecn :: proc(socket:UDP_Socket,src:[]u8,to:Endpoint,ecn:ECN_Codepoint)->(int,UDP_Send_Error) {return _send_udp_ecn(socket,src,to,ecn)}
