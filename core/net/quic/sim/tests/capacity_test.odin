package tests
import "core:net/quic/conn"
import "core:testing"

@(test)
conn_reset_ack_reclaims_retained_send_window :: proc(t:^testing.T) {
 p:=migration_pair(t);defer close_pair(p)
 _,e:=conn.write(p.server,1,[]u8{1,2,3},false);assert(e==.None);migration_exchange(t,p,4000,20)
 testing.expect_value(t,conn.stop_sending_with_error(p.client,1,0x10c),.None);migration_exchange(t,p,4000,40)
 found:=false
 for b in p.server.bufs {if b.used&&b.id==1 {found=true;testing.expect(t,b.reset_acked);testing.expect_value(t,b.n,0);testing.expect_value(t,b.send_base,b.reset_final)}}
 testing.expect(t,found)
}
@(test)
conn_capacity_query_does_not_allocate_or_recycle_closed_ids :: proc(t:^testing.T) {
 limits:=wide_limits();limits.max_streams=64
 p:=open_pair(t,limits,false);defer close_pair(p);settle(t,p)
 before:=conn.remaining_stream_records(p.client)
 testing.expect_value(t,conn.stream_admission(p.client,0),.None)
 testing.expect_value(t,conn.remaining_stream_records(p.client),before)
 for id:u64=0;id<128;id+=4 {_,e:=conn.write(p.client,id,nil,false);if e==.Capacity {break};testing.expect_value(t,e,.None)}
 testing.expect_value(t,conn.remaining_stream_records(p.client),0)
 testing.expect_value(t,conn.stream_admission(p.client,128),.Capacity)
}

@(test)
conn_application_close_uses_available_1rtt_keys_before_handshake_done :: proc(t:^testing.T) {
 p:=migration_pair(t);defer close_pair(p)
 p.client.model.handshake_confirmed=false
 testing.expect_value(t,conn.close_with_application_error(p.client,0x100),.None)
 packet:[conn.MAX_DATAGRAM]u8;n,e:=conn.pump(p.client,i64(p.link.now),packet[:]);testing.expect_value(t,e,.None);testing.expect(t,n>0&&packet[0]&0x80==0)
 testing.expect(t,!p.client.model.handshake_confirmed);testing.expect_value(t,p.client.phase,.Draining)
}
