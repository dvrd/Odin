package conn

import "core:net"
import "shared:async"

// One call admits at most one datagram and receives at most one. A pending or
// partial send retries udp_hold and does not admit another packet. send_udp
// success is not a peer acknowledgment. Truncation consumes the message and
// does not decode it. Caller owns recv_buf and send_buf for the call.
// A different peer endpoint is a new path and restarts anti-amplification.
// That restart is not connection migration.

exchange_udp :: proc(
	c: ^Connection,
	socket: async.Datagram_Socket,
	peer: net.Endpoint,
	recv_buf, send_buf: []u8,
	now: i64,
	deadline: async.Deadline = {},
) -> (int, int, Error) {
	if c == nil || !c.initialized || now < 0 || peer.address == nil {
		return 0, 0, .Invalid
	}
	if c.cancelled {
		return 0, 0, .Cancelled
	}
	if idle_tick(c,now) {return 0,0,.Closed}
	if _,policy_error:=configure_udp(socket);policy_error!=.None {return 0,0,policy_error}

	sent, blocked, serr := flush_udp(c, socket, peer, send_buf, now, deadline)
	if blocked {
		return sent, 0, serr
	}
	if len(recv_buf) == 0 {
		return sent, 0, serr
	}
	n, from, metadata, rerr := async.receive_udp_metadata(socket, recv_buf, deadline)
	#partial switch rerr.kind {
	case .None:
		if n == 0 {
			return sent, 0, serr
		}
		e:Error
        if c.migration.enabled {e=ingest_from_ecn(c,now,from,recv_buf[:n],metadata.ecn,metadata.ecn_valid&&!metadata.control_truncated)}else{e=ingest(c,now,path_of(from),recv_buf[:n])}
        if e != .None {
			return sent, n, e
		}
		return sent, n, serr
	case .Pending:
		return sent, 0, .Pending
	case .Datagram_Truncated:
		return sent, n, .Truncated
	case .Cancelled:
		return sent, 0, .Cancelled
	case .Timeout:
		return sent, 0, .Not_Ready
	case .Closed, .Peer_Closed:
		return sent, 0, .Closed
	case:
		return sent, 0, .Failed
	}
}

@(private)
flush_udp :: proc(
	c: ^Connection,
	socket: async.Datagram_Socket,
	peer: net.Endpoint,
	send_buf: []u8,
	now: i64,
	deadline: async.Deadline,
) -> (int, bool, Error) {
	if c.udp_hold_len > 0 {
		n, err := send_hold(c, socket, peer, deadline,now)
		return n, err != .None, err
	}
	if len(send_buf) == 0 || c.phase == .Draining || c.phase == .Closed || c.phase == .Failed {
		return 0, false, .None
	}
	target:=peer
 n:int;err:Error
 if c.migration.enabled {n,target,err=pump_to(c,now,send_buf)}else{n,err=pump(c,now,send_buf)}
	if err != .None || n <= 0 {
		soft := err == .None || err == .Congestion || err == .Anti_Amplification || err == .Discarded || err == .Not_Ready
		return 0, !soft, err
	}
	if n > len(c.udp_hold) {
		return 0, true, .Capacity
	}
	copy(c.udp_hold[:n], send_buf[:n])
	c.udp_hold_len = n
 c.udp_hold_peer=target;c.udp_hold_ecn=output_ecn(c);c.udp_hold_eliciting=output_ack_eliciting(c)
	sent, serr := send_hold(c, socket, peer, deadline,now)
	return sent, serr != .None, serr
}

@(private)
send_hold :: proc(
	c: ^Connection,
	socket: async.Datagram_Socket,
	peer: net.Endpoint,
	deadline: async.Deadline,
 now:i64,
) -> (int, Error) {
	target:=peer;if c.udp_hold_peer.address!=nil {target=c.udp_hold_peer}
 n, err := async.send_udp_ecn(socket, target, c.udp_hold[:c.udp_hold_len], c.udp_hold_ecn,deadline)
	#partial switch err.kind {
	case .None:
  output_sent(c,now,c.udp_hold_eliciting)
		c.udp_hold_len = 0
		return n, .None
	case .Pending:
		return 0, .Pending
	case .Partial_Datagram:
		return n, .Partial
	case .Cancelled:
		return 0, .Cancelled
	case .Timeout:
		return 0, .Not_Ready
	case:
		return 0, .Failed
	}
}

@(private)
path_of :: proc(peer: net.Endpoint) -> u32 {
	h: u32 = 2166136261
	switch a in peer.address {
	case net.IP4_Address:
		for b in a {
			h = (h ~ u32(b)) * 16777619
		}
	case net.IP6_Address:
		for w in a {
			h = (h ~ u32(w)) * 16777619
		}
	}
	return h ~ u32(peer.port)
}
