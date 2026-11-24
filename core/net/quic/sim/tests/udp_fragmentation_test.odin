#+build darwin, linux
package tests

import "core:net"
import "core:net/quic/conn"
import "core:testing"
import "shared:async"

@(test)
conn_udp_facade_configures_each_borrowed_socket_generation :: proc(t:^testing.T) {
 p:=open_pair(t,wide_limits(),false);defer close_pair(p);settle(t,p)
 r:async.Runtime;assert(async.init(&r,{workers=1,task_capacity=1,io_capacity=1}).kind==.None)
 owner:=async.Task{resume=proc(_:rawptr)->async.Resume_Result{return .Waiting}}
 assert(async.register(&r,&owner).kind==.None)
 for endpoint in ([]net.Endpoint{{net.IP4_Loopback,0},{net.IP6_Loopback,0}}) {
  socket,error:=async.bind_udp(&r,&owner,endpoint);assert(error.kind==.None)
  family:=net.family_from_endpoint(endpoint)
  before,be:=async.udp_fragmentation_policy(socket,family);assert(be.kind==.None)
  testing.expect(t,before.status==.Not_Configured)
  // A zero-buffer exchange performs no UDP read/write, but validates the socket
  // policy before the facade is permitted to emit future protected datagrams.
  sent,received,cause:=conn.exchange_udp(p.client,socket,endpoint,nil,nil,0)
  testing.expect(t,cause==.None&&sent==0&&received==0)
  after,ae:=async.udp_fragmentation_policy(socket,family)
  testing.expect(t,ae.kind==.None&&after.status==.Configured)
  assert(async.close(socket).kind==.None)
  _,_,closed:=conn.exchange_udp(p.client,socket,endpoint,nil,nil,0)
  testing.expect(t,closed==.Closed)
 }
 assert(async.unregister(&r,&owner).kind==.None)
 assert(async.destroy(&r).kind==.None)
}
