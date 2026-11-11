package tls

import "core:crypto/sha2"
import "core:encoding/pem"
import "core:mem"
import "core:testing"
import "core:time"
import credentials "credentials"
import store "credentials/store"

mtls_store :: proc(t:^testing.T,cert,key:[]u8)->^store.Store {
 credential,e:=credentials.create(cert,key,{},context.allocator);assert(e==.None)
 owner,se:=store.create({},context.allocator);assert(se.kind==.None)
 assert(store.replace(owner,&credential).kind==.None)
 return owner
}
mtls_start :: proc(t:^testing.T,owner:^Server_Handshake,identity:^store.Store,policy:^Client_Auth_Config)->(Handshake_Transcript,[32]u8) {
 config:=SERVER_HANDSHAKE_DEFAULT_CONFIG;config.client_auth=policy
 testing.expect_value(t,server_handshake_init(owner,config,context.allocator),.None)
 wire:[1024]u8;hello,_:=flight_test_hello(wire[:])
 _,_,e:=server_handshake_feed(owner,.Initial,hello);assert(e==.None)
 event,_:=server_handshake_peek(owner);assert(event.kind==.Peer_Parameters);assert(server_handshake_accept(owner,event.id)==.None)
 assert(server_handshake_start_flight(owner,identity,time.now())==.None)
 transcript:Handshake_Transcript;transcript_init(&transcript);transcript_update(&transcript,hello)
 secret:[32]u8;requested:=false
 for _ in 0..<100 {
  event,_=server_handshake_peek(owner);if event.kind==.None {break};assert(event.kind!=.Fatal)
  if event.kind==.Handshake_Bytes {if event.bytes[0]==13&&len(event.bytes)==19 {requested=true};transcript_update(&transcript,event.bytes)}
  if event.kind==.Traffic_Secret&&event.level==.Handshake&&event.direction==.Read {copy(secret[:],event.secret)}
  assert(server_handshake_accept(owner,event.id)==.None)
 }
 testing.expect(t,requested)
 testing.expect_value(t,owner._phase,.Await_Client_Finished)
 return transcript,secret
}
mtls_certificate_wire :: proc(cert_pem:[]u8)->[]u8 {
 p,_,e:=pem.decode(cert_pem);assert(e==nil);defer pem.block_delete(p)
 der:=pem.block_bytes(p);wire:=make([]u8,len(der)+13);wire[0]=11
 server_flight_put24(wire[1:4],len(wire)-4);server_flight_put24(wire[5:8],len(der)+5);server_flight_put24(wire[8:11],len(der));copy(wire[11:],der)
 return wire
}
@(test)
mutual_tls_recordless_authentication_and_rejection :: proc(t:^testing.T) {
 server:=mtls_store(t,#load("testdata/mtls/server.pem"),#load("testdata/mtls/server-key.pem"));defer store.destroy(&server)
 client:=mtls_store(t,#load("testdata/mtls/client.pem"),#load("testdata/mtls/client-key.pem"));defer store.destroy(&client)
 roots:Root_Pool;assert(root_pool_parse(&roots,#load("testdata/mtls/root.pem")).kind==.None);defer root_pool_destroy(&roots)
 for mode in 0..<9 {
  policy:=Client_Auth_Config{mode=.Require,roots=roots.roots[:roots.count]};if mode==1 {policy.mode=.Request}
  owner:Server_Handshake;transcript,secret:=mtls_start(t,&owner,server,&policy)
  selected:=client;if mode==1||mode==2 {selected=nil}
  auth,e:=client_authentication_flight(selected,[]u16{0x0804,0x0403},&transcript,context.allocator);assert(e.kind==.None)
  if mode>=3&&mode<=5 {
   delete(auth)
   cert:=#load("testdata/mtls/wrong-eku.pem") if mode==3 else #load("testdata/mtls/expired.pem") if mode==4 else #load("testdata/mtls/rogue.pem")
   auth=mtls_certificate_wire(cert)
  }
  if mode==6 {auth[len(auth)-1]~=1}
  finished:[36]u8;_,fe:=finished_encode(finished[:],secret,transcript_snapshot(&transcript));assert(fe==.None)
  if mode==7 {finished[35]~=1}
  wire:=make([]u8,len(auth)+36);copy(wire,auth);copy(wire[len(auth):],finished[:]);delete(auth)
  at:=0;cause:Server_Handshake_Error
  for at<len(wire) {
   n,s,e:=server_handshake_feed(&owner,.Handshake,wire[at:at+1]);at+=n;cause=e
   if e!=.None||s==.Terminal {break}
   if mode==8&&at==12 {server_handshake_abort(&owner);break}
  }
  if mode<2 {
   event,_:=server_handshake_peek(&owner);testing.expect_value(t,event.kind,.Complete)
   peer:=server_handshake_peer_identity(&owner);testing.expect_value(t,peer.authenticated,mode==0)
   if mode==0 {testing.expect(t,!mem.check_zero(peer.certificate_sha256[:]))}
   testing.expect_value(t,server_handshake_accept(&owner,event.id),.None)
  } else if mode==8 {testing.expect_value(t,owner._phase,.Aborted)} else {testing.expect(t,cause!=.None);testing.expect(t,!server_handshake_peer_identity(&owner).authenticated)}
  delete(wire);server_handshake_destroy(&owner)
  stats,_:=server_handshake_stats(&owner);testing.expect_value(t,stats.live_bytes,0)
 }
}
@(test)
mutual_tls_request_validation_and_identity_usage :: proc(t:^testing.T) {
 good:Conn
 request:=[?]u8{13,0,0,15,0,0,12,0,13,0,8,0,6,8,4,4,3,8,7}
 testing.expect_value(t,client_auth_request_decode(&good,request[:]).kind,.None)
 testing.expect(t,good.client_auth_requested&&good.client_auth_scheme_count==3)
 for mode in 0..<4 {
  bad:=request
  switch mode {case 0:bad[4]=1;case 1:bad[12]=5;case 2:bad[8]=14;case 3:bad[6]=11}
  c:Conn;testing.expect(t,client_auth_request_decode(&c,bad[:]).kind!=.None)
 }
 policy:=Client_Auth_Config{mode=.Require}
 testing.expect(t,!client_auth_config_valid(&policy))
 owner:=mtls_store(t,#load("testdata/mtls/wrong-eku.pem"),#load("testdata/mtls/wrong-eku-key.pem"));defer store.destroy(&owner)
 tr:Handshake_Transcript;transcript_init(&tr)
 flight,e:=client_authentication_flight(owner,[]u16{0x0804},&tr,context.allocator)
 testing.expect(t,e.kind!=.None&&len(flight)==0)
}

@(test)
mutual_tls_pinned_credential_generation_survives_rotation :: proc(t:^testing.T) {
 owner:=mtls_store(t,#load("testdata/mtls/client.pem"),#load("testdata/mtls/client-key.pem"));defer store.destroy(&owner)
 lease,e:=store.acquire(owner);assert(e.kind==.None);defer _=store.release(owner,&lease)
 expected,fe:=store.fingerprint(owner,lease);assert(fe.kind==.None)
 next,ce:=credentials.create(#load("testdata/mtls/wrong-eku.pem"),#load("testdata/mtls/wrong-eku-key.pem"),{},context.allocator);assert(ce==.None)
 assert(store.replace(owner,&next).kind==.None)
 transcript:Handshake_Transcript;transcript_init(&transcript)
 flight,error:=client_authentication_flight(owner,[]u16{0x0804},&transcript,context.allocator,&lease)
 assert(error.kind==.None);defer delete(flight)
 count:=4+handshake_body_size(flight)
 certs,pe:=server_certificates_parse(flight[:count]);assert(pe.kind==.None);defer server_certificates_destroy(&certs)
 digest:sha2.Context_256;sha2.init_256(&digest);sha2.update(&digest,certs.chain[0].raw);actual:[32]u8;sha2.final(&digest,actual[:])
 testing.expect_value(t,actual,expected)
 transcript_init(&transcript)
 rejected,rejection:=client_authentication_flight(owner,[]u16{0x0804},&transcript,context.allocator)
 testing.expect(t,rejection.kind!=.None&&len(rejected)==0)
}

@(test)
mutual_tls_rejects_cross_store_pins_and_anonymous_resumption_cache :: proc(t:^testing.T) {
 owner:=mtls_store(t,#load("testdata/mtls/client.pem"),#load("testdata/mtls/client-key.pem"));defer store.destroy(&owner)
 other:=mtls_store(t,#load("testdata/mtls/client.pem"),#load("testdata/mtls/client-key.pem"));defer store.destroy(&other)
 lease,e:=store.acquire(owner);assert(e.kind==.None);defer _=store.release(owner,&lease)
 testing.expect_value(t,config_validate({client_credential_lease=&lease}),.Invalid_Client_Credentials)
 testing.expect_value(t,config_validate({client_credentials=other,client_credential_lease=&lease}),.Invalid_Client_Credentials)
 session:=Session{usable=true,name_len=9,ticket_len=1,lifetime_sec=3600,received=time.now()};copy(session.name[:],"localhost");session.ticket[0]=0x44;session.psk[0]=0x55
 defer session_clear(&session)
 cache:Session_Cache;defer session_cache_clear(&cache)
 assert(session_offerable(&session,"localhost",time.now()));assert(session_cache_put(&cache,&session));before:=cache
 conn:=Conn{config={server_name="localhost",client_credentials=owner,session=&session,session_cache=&cache,remember_tickets=true},have_server_finished_transcript=true}
 testing.expect(t,session_resume_candidate(&conn,time.now())==nil)
 conn.config.session=nil
 testing.expect(t,session_resume_candidate(&conn,time.now())==nil)
 master:[32]u8;master[0]=1
 resumption_capture(&conn,master);testing.expect(t,!conn.have_resumption_master)
 // A server-requested certificate must not create a ticket later reusable by
 // an anonymous connection, including when no client identity was available.
 conn.config.client_credentials=nil;conn.client_auth_used=true
 resumption_capture(&conn,master);testing.expect(t,!conn.have_resumption_master)
 testing.expect_value(t,cache,before)
}
