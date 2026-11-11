package tests
import "core:net/quic/idle"
import "core:net/quic/conn"
import "core:net/quic/harness"
import "core:testing"
import "core:net"
import "core:fmt"
import "core:time"
import "shared:async"

@(test)
conn_idle_negotiated_timer_uses_peer_ack_delay_without_backoff :: proc(t:^testing.T) {
 p:=open_pair(t,wide_limits(),false);defer close_pair(p);settle(t,p)
 c:=p.server;c.model.smoothed_rtt=20;c.model.rttvar=5
 clock:idle.State;assert(idle.configure(&clock,30000,50,1000))
 assert(conn.configure_timing(c,clock,200)==.None)
 testing.expect(t,harness.base_pto(&c.model,.Initial)==40&&harness.base_pto(&c.model,.Handshake)==40)
 stats:=conn.timing_stats(c,1000)
 testing.expect(t,stats.negotiated_timeout_ms==50&&stats.base_pto_ms==240&&stats.effective_timeout_ms==720&&stats.remaining_ms==720)
 c.model.pto_count=20
 testing.expect(t,conn.timing_stats(c,1000).base_pto_ms==240)
 timer:=conn.timer(c,1000);testing.expect(t,timer.armed&&timer.idle&&timer.at==1720)
 testing.expect(t,conn.configure_timing(c,clock,16384)==.Invalid&&c.model.max_ack_delay==200)
 testing.expect(t,!conn.idle_tick(c,1719)&&conn.idle_tick(c,1720))
 testing.expect(t,c.phase==.Closed&&c.idle_expired&&!c.hs.have_one_rtt&&!c.model.initialized)
 packet:[1200]u8;n,error:=conn.pump(c,1720,packet[:]);testing.expect(t,n==0&&error==.Closed)
 testing.expect(t,conn.timing_stats(c,1720).expired)
}

@(test)
conn_idle_authenticated_receive_ignores_tampered_packet :: proc(t:^testing.T) {
 p:=open_pair(t,wide_limits(),false);defer close_pair(p);settle(t,p)
 c:=p.server;c.model.smoothed_rtt=20;c.model.rttvar=5
 clock:idle.State;assert(idle.configure(&clock,1000,0,1000));assert(conn.configure_timing(c,clock,25)==.None)
 _,e:=conn.write(p.client,0,[]u8{1,2,3},true);assert(e==.None)
 packet:[1200]u8;n,pe:=conn.pump(p.client,1500,packet[:]);assert(pe==.None&&n>0)
 bad:=packet;bad[n-1]~=1
 testing.expect(t,conn.ingest(c,1500,1,bad[:n])==.Discarded&&c.idle.last_activity==1000)
 testing.expect(t,conn.ingest(c,1600,1,packet[:n])==.None&&c.idle.last_activity==1600)
 testing.expect(t,!conn.idle_tick(c,2599)&&conn.idle_tick(c,2600))
}

@(test)
conn_idle_output_preparation_is_not_successful_transmission :: proc(t:^testing.T) {
 p:=open_pair(t,wide_limits(),false);defer close_pair(p);settle(t,p)
 c:=p.client;clock:idle.State;assert(idle.configure(&clock,1000,0,1000));assert(conn.configure_timing(c,clock)==.None)
 _,e:=conn.write(c,0,[]u8{1},false);assert(e==.None)
 packet:[1200]u8;n,pe:=conn.pump(c,1100,packet[:]);assert(pe==.None&&n>0)
 testing.expect(t,c.idle.last_activity==1000&&conn.output_ack_eliciting(c))
 c.seen_done=false;testing.expect(t,conn.timer(c,1100).idle)
 c.seen_done=true;testing.expect(t,!conn.timer(c,1100).idle)
 conn.output_sent(c,1200,true);conn.output_sent(c,1300,true);conn.output_sent(c,1400,false)
 testing.expect(t,c.idle.last_activity==1200)
 idle.received(&c.idle,1500);conn.output_sent(c,1600,false);testing.expect(t,c.idle.last_activity==1500)
 conn.output_sent(c,1700,true);testing.expect(t,c.idle.last_activity==1700)
 conn.output_sent(c,6000,true);testing.expect(t,c.idle_expired&&c.phase==.Closed&&c.idle.last_activity==1700)
}

Idle_UDP_Node :: struct {connection:^conn.Connection,socket:async.Datagram_Socket,peer:net.Endpoint,sent:int,cause:conn.Error}
@(test)
conn_idle_expired_pending_datagram_is_not_emitted_or_revived :: proc(t:^testing.T) {
 p:=open_pair(t,wide_limits(),false);defer close_pair(p);settle(t,p)
 c:=p.client;c.model.smoothed_rtt=20;c.model.rttvar=0
 clock:idle.State;assert(idle.configure(&clock,100,0,1000));assert(conn.configure_timing(c,clock,0)==.None)
 _,we:=conn.write(c,0,[]u8{1,2,3},true);assert(we==.None)
 packet:[1200]u8;n,pe:=conn.pump(c,1050,packet[:]);assert(pe==.None&&n>0)
 receiver,re:=net.make_bound_udp_socket(net.IP4_Loopback,0);assert(re==nil);defer net.close(receiver)
 assert(net.set_option(receiver,.Receive_Timeout,50*time.Millisecond)==nil);target,te:=net.bound_endpoint(receiver);assert(te==.None)
 copy(c.udp_hold[:],packet[:n]);c.udp_hold_len=n;c.udp_hold_peer=target;c.udp_hold_eliciting=conn.output_ack_eliciting(c)
 r:async.Runtime;assert(async.init(&r,{workers=1,task_capacity=1,io_capacity=1}).kind==.None)
 node:=Idle_UDP_Node{connection=c,peer=target}
 owner:=async.Task{data=&node,resume=proc(data:rawptr)->async.Resume_Result {
  node:=cast(^Idle_UDP_Node)data
  node.sent,_,node.cause=conn.exchange_udp(node.connection,node.socket,node.peer,nil,nil,1110)
  return .Done
 }}
 assert(async.register(&r,&owner).kind==.None)
 socket,se:=async.bind_udp(&r,&owner,{net.IP4_Loopback,0});assert(se.kind==.None);node.socket=socket
 assert(async.wake(&r,&owner)&&async.start(&r).kind==.None&&async.wait_idle(&r).kind==.None)
 fmt.printf("IDLE_PENDING sent=%d cause=%v expired=%v hold=%d activity=%d\n",node.sent,node.cause,c.idle_expired,c.udp_hold_len,c.idle.last_activity)
 testing.expect(t,node.sent==0&&node.cause==.Closed&&c.idle_expired&&c.udp_hold_len==0)
 buffer:[1200]u8;got,_,cause:=net.recv_udp(receiver,buffer[:])
 testing.expect(t,got==0&&(cause==.Would_Block||cause==.Timeout),"expired retained output reached the kernel")
 assert(async.destroy(&r).kind==.None)
}
