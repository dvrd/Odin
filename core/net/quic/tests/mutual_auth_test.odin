package tests

import "core:bytes"
import "core:crypto/tls"
import credentials "core:crypto/tls/credentials"
import credential_store "core:crypto/tls/credentials/store"
import "core:net/quic"
import "core:net/quic/conn"
import "core:testing"
import "core:time"

@(test)
handshake_mutual_authentication_retains_variable_client_flight :: proc(t:^testing.T) {
 params:=[?]u8{1,2,3}
 ch_storage,sh_storage:[128]u8
 ch:=protect_client_hello(ch_storage[:],[]string{"h3"},params[:],true,nil)
 sh:=protect_server_hello(sh_storage[:])
 shared:[32]u8;shared[0]=0x42
 hs,he:=tls.quic_handshake_secrets(shared,ch,sh,params[:]);assert(he.kind==.None);defer tls.quic_handshake_keys_clear(&hs)
 ee_storage:[64]u8;ee:=protect_extensions(ee_storage[:],8,params[:],nil)
 request:=[?]u8{13,0,0,15,0,0,12,0,13,0,8,0,6,8,4,4,3,8,7}
 cert_storage:[1024]u8;cert:=protect_certificate_message(cert_storage[:])
 cv_storage:[80]u8;cv:=protect_sign_verify(cv_storage[:],protect_hash(ch,sh,ee,request[:],cert))
 finished:[tls.FINISHED_MESSAGE_SIZE]u8
 _,fe:=tls.finished_encode(finished[:],hs.server.secret,protect_hash(ch,sh,ee,request[:],cert,cv));assert(fe==.None)
 server_flight:[2048]u8;at:=0
 for part in ([][]u8{ee,request[:],cert,cv,finished[:]}) {at+=copy(server_flight[at:],part)}
 pool:tls.Root_Pool;roots:=protect_roots(&pool);defer tls.root_pool_destroy(&pool)
 identity,ie:=credentials.create(#load("../../../crypto/tls/testdata/mtls/client.pem"),#load("../../../crypto/tls/testdata/mtls/client-key.pem"),{},context.allocator);assert(ie==.None)
 store,se:=credential_store.create({},context.allocator);assert(se.kind==.None);defer credential_store.destroy(&store);assert(credential_store.replace(store,&identity).kind==.None)
 for empty in ([]bool{false,true}) {
  buffers:[3][2048]u8;h:quic.Handshake
  assert(quic.handshake_init(&h,.Client,[]string{"h3"},buffers[0][:],buffers[1][:],buffers[2][:])==.None)
  assert(quic.handshake_accept_client_hello(&h,shared,ch,sh,params[:]).kind==.None)
  selected:=store;if empty {selected=nil}
  e:=quic.handshake_authenticate_server(&h,ch,sh,server_flight[:at],"localhost",roots,time.unix(1893456000,0),params[:],selected,context.allocator)
  testing.expect_value(t,e.kind,.None)
  flight,re:=quic.handshake_client_finished(&h);assert(re==.None)
  testing.expect(t,len(flight)>tls.FINISHED_MESSAGE_SIZE&&flight[0]==11)
  before_finished:=flight[:len(flight)-tls.FINISHED_MESSAGE_SIZE]
  testing.expect_value(t,tls.finished_verify(flight[len(before_finished):],hs.client.secret,protect_hash(ch,sh,server_flight[:at],before_finished)),.None)
  expected:=make([]u8,len(flight));copy(expected,flight)
  assert(quic.handshake_note_finished_sent(&h)==.None)
  // Authenticated adoption moves every retained certificate/signature byte,
  // including flights larger than the old fixed36-byte Finished array.
  c:conn.Connection
  assert(conn.adopt_established(&c,&h,{role=.Client,local_cid=[]u8{1,2,3,4},peer_cid=[]u8{4,3,2,1},limits={max_data=8192,max_stream_data=256,max_streams=32,recv_max_data=8192,recv_max_stream_data=256,recv_max_streams=32},max_datagram=1200})==.None)
  testing.expect(t,h.client_auth_flight==nil)
  adopted,ae:=quic.handshake_client_finished(&c.hs);assert(ae==.None);testing.expect(t,bytes.equal(adopted,expected))
  packet:[1200]u8
  emitted:=0
  for c.fin_off<len(expected) {n,e:=conn.pump(&c,0,packet[:]);assert(e==.None&&n>0);emitted+=1}
  testing.expect(t,emitted>0&&c.fin_off==len(expected))
  timer:=conn.timer(&c,0);assert(timer.armed)
  n,te:=conn.on_timeout(&c,timer.at,packet[:]);assert(te==.None&&n>0)
  testing.expect(t,c.fin_off>0&&c.fin_off<=len(expected))
  retained,_:=quic.handshake_client_finished(&c.hs);testing.expect(t,bytes.equal(retained,expected))
  // A real protected HANDSHAKE_DONE may arrive during replay. It retires
  // the full owned flight and must let subsequent application output run.
  c.fin_off=0
  done:[64]u8
  hn,_,de:=quic.short_header_encode_v1(done[:],{destination_id=c.local_cid[:c.local_cid_len],packet_number=0,packet_number_length=1});assert(de==.None)
  sn,pe:=quic.payload_seal(done[hn:],done[:hn],[]u8{0x1e,0,0,0},&c.hs.one_rtt_read,0);assert(pe==.None)
  assert(quic.header_protection_apply(done[:hn+sn],&c.hs.one_rtt_read,.One_RTT,c.local_cid_len)==.None)
  testing.expect_value(t,conn.ingest(&c,timer.at+1,0,done[:hn+sn]),.None)
  testing.expect(t,c.seen_done&&c.hs.handshake_discarded&&c.hs.client_auth_flight==nil)
  wrote,we:=conn.write(&c,0,[]u8{'a','f','t','e','r'},true);assert(we==.None&&wrote==5)
  pn,pump_error:=conn.pump(&c,timer.at+1,packet[:]);testing.expect(t,pump_error==.None&&pn>0&&packet[0]&0x80==0)
  conn.destroy(&c);testing.expect(t,c.hs.client_auth_flight==nil)
  delete(expected)
 }
}
