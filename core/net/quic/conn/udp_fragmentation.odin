package conn

import "core:net"
import "shared:async"

// The facade borrows caller-owned UDP sockets; it cannot assume that their
// creation enabled QUIC's no-fragment requirement. Discover the socket family
// (not the peer family) so mapped IPv4 retains an IPv6 dual-stack socket.
configure_udp :: proc(socket:async.Datagram_Socket)->(net.UDP_Fragmentation_Result,Error) {
 endpoint,error:=async.udp_bound_endpoint(socket)
 if error.kind!=.None {
  if error.kind==.Closed {return {status=.Invalid_Socket},.Closed}
  return {status=.Invalid_Socket},.Invalid
 }
 family:=net.family_from_endpoint(endpoint)
 policy,query_error:=async.udp_fragmentation_policy(socket,family)
 if query_error.kind==.None&&policy.status==.Configured {return policy,.None}
 if query_error.kind==.None&&policy.status==.Not_Configured {policy,query_error=async.udp_disable_fragmentation(socket,family)}
 if query_error.kind==.None&&policy.status==.Configured {return policy,.None}
 if policy.status==.Unsupported||query_error.kind==.Unsupported {return policy,.Unsupported}
 if query_error.kind==.Closed {return policy,.Closed}
 if policy.status==.Invalid_Family||policy.status==.Invalid_Socket {return policy,.Invalid}
 return policy,.Failed
}
