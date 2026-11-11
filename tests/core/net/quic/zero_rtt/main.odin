package main
import "core:crypto/tls"
import "core:crypto"
import "core:crypto/sha2"
import "core:net/quic"
import "core:fmt"
import "core:net"
import credentials "core:crypto/tls/credentials"
import store "core:crypto/tls/credentials/store"
import "core:sync"
import "core:thread"
import saba "shared:saba/core"
import "core:os"
import "core:time"
import http3 "shared:http/v3"
import http "shared:http"
import surf "shared:surf"
State :: struct {control:saba.Server_Control,calls,early_calls,normal_calls:i32,expected:i32,scenario:string,expected_peer:[32]u8}
early_policy :: proc(data:rawptr,request:^saba.Request)->bool {return request.method=="GET"&&request.path=="/allow"}
handler :: proc(data:rawptr,connection:^saba.Connection,request:^saba.Request)->saba.Response {
 s:=cast(^State)data
 if s.scenario=="mtls" {peer:=saba.tls_peer_identity(connection);assert(peer.authenticated&&peer.certificate_sha256==s.expected_peer)}
 if request.early_data {assert(request.path=="/allow");sync.atomic_add(&s.early_calls,1)} else {sync.atomic_add(&s.normal_calls,1)}
 sync.atomic_add(&s.calls,1);return {status=.OK,body=transmute([]u8)string("OK")}
}
server :: proc(directory,scenario:string) {
 cert,e:=os.read_entire_file(fmt.tprintf("%s/server.pem",directory),context.allocator);assert(e==nil);defer delete(cert)
 key,ke:=os.read_entire_file(fmt.tprintf("%s/server-key.pem",directory),context.allocator);assert(ke==nil);defer delete(key)
 credential,ce:=credentials.create(cert,key,{},context.allocator);assert(ce==.None)
 identity,se:=store.create({},context.allocator);assert(se.kind==.None);defer store.destroy(&identity);assert(store.replace(identity,&credential).kind==.None)
 keys:tls.Server_Ticket_Keys;assert(tls.server_ticket_keys_init(&keys)==.None);defer tls.server_ticket_keys_close(&keys)
 replay:tls.Anti_Replay;assert(tls.anti_replay_init(&replay)==.None);defer tls.anti_replay_close(&replay)
 early:=tls.Server_Early_Data_Config{replay=&replay,max_age=time.Minute}
 tickets:=tls.Server_Ticket_Config{keys=&keys,lifetime=time.Hour,policy_epoch=1,early_data=&early}
 state:=State{expected=2,scenario=scenario};if scenario=="replay" {state.expected=3}
 config:=saba.Server{handler=handler,handler_data=&state,control=&state.control,workers=2,port=0,http3={enabled=true,endpoint={net.IP4_Loopback,0},credentials=identity,tickets=&tickets,early_request_policy=early_policy,early_request_data=&state}}
 if scenario=="default" {config.http3.early_request_policy=nil}
 retry:quic.Retry_Tokens;defer quic.retry_tokens_destroy(&retry)
 if (scenario=="retry"||scenario=="large-retry") {secret:[32]u8;crypto.rand_bytes(secret[:]);assert(quic.retry_tokens_init(&retry,secret[:],1,60,time.to_unix_seconds(time.now()))==.None);crypto.zero_explicit(&secret,size_of(secret));config.http3.retry=&retry}
 roots:tls.Root_Pool;defer tls.root_pool_destroy(&roots)
 auth:tls.Client_Auth_Config;tcp_tls:saba.TLS_Config
 if scenario=="mtls" {
  assert(tls.root_pool_load_file(&roots,fmt.tprintf("%s/root.pem",directory)).kind==.None)
  auth={mode=.Require,roots=roots.roots[:roots.count]};tcp_tls={store=identity,client_auth=&auth};config.tls=&tcp_tls
  client_pem,pe:=os.read_entire_file(fmt.tprintf("%s/client.pem",directory),context.allocator);assert(pe==nil);defer delete(client_pem)
  pool:tls.Root_Pool;assert(tls.root_pool_parse(&pool,client_pem).kind==.None);defer tls.root_pool_destroy(&pool)
  state.expected_peer=sha256_leaf(pool.roots[0].raw)
 }
 worker:=thread.create_and_start_with_poly_data(&config,proc(c:^saba.Server){assert(saba.serve(c^))})
 until:=time.tick_add(time.tick_now(),10*time.Second);for !saba.server_ready(&state.control)&&time.tick_diff(time.tick_now(),until)>0 {thread.yield()}
 endpoint,ready:=saba.server_http3_endpoint(&state.control);assert(ready);fmt.printf("READY 127.0.0.1:%d\n",endpoint.port)
 until=time.tick_add(time.tick_now(),20*time.Second);for sync.atomic_load(&state.calls)<state.expected&&time.tick_diff(time.tick_now(),until)>0 {thread.yield()}
 assert(saba.drain_server(&state.control,time.Second));thread.join(worker);thread.destroy(worker)
 fmt.printf("RESULT calls=%d early=%d normal=%d\n",state.calls,state.early_calls,state.normal_calls)
 assert(state.calls==state.expected);if scenario=="accepted"||scenario=="replay"||scenario=="retry"||scenario=="mtls"||scenario=="zero" {assert(state.early_calls==1)} else {assert(state.early_calls==0)}
 stats,stats_error:=store.stats(identity);assert(stats_error.kind==.None&&stats.active_leases==0)
}
sha256_leaf :: proc(bytes:[]u8)->(out:[32]u8) {hash:sha2.Context_256;sha2.init_256(&hash);sha2.update(&hash,bytes);sha2.final(&hash,out[:]);return}
main :: proc() {
 assert(len(os.args)==4)
 directory,endpoint,scenario:=os.args[1],os.args[2],os.args[3]
 if endpoint=="server" {server(directory,scenario);return}
 roots:tls.Root_Pool;assert(tls.root_pool_load_file(&roots,fmt.tprintf("%s/root.pem",directory)).kind==.None);defer tls.root_pool_destroy(&roots)
 address,valid:=net.parse_endpoint(endpoint);assert(valid)
 if scenario=="surf-accepted"||scenario=="surf-reject"||scenario=="surf-default" {
  cache:tls.Session_Cache;defer tls.session_cache_clear(&cache)
  config:=surf.Config{http3=true,http3_early_data=proc(request:^http.Request)->bool{return request.method==.GET},timeout=10*time.Second,tls={root_cas=roots.roots[:roots.count],session_cache=&cache}}
  if scenario=="surf-default" {config.http3_early_data=nil}
  for i in 0..<2 {
   response,error:=surf.execute({method=.GET,url=fmt.tprintf("https://%s/allow",endpoint)},config)
   fmt.printf("RESULT Surf %d error=%v status=%d\n",i,error.kind,response.status)
   assert(error.kind==.None&&response.status==200&&string(response.body)=="OK");surf.response_destroy(&response)
   if i==0 {assert(tls.session_cache_lookup(&cache,"127.0.0.1",time.now())!=nil)}
  };return
 }
 cache:tls.Session_Cache;defer tls.session_cache_clear(&cache)
 for i in 0..<2 {
  pool:http3.Pool
  request:=http3.Client_Request{method="GET",target="/allow",authority="localhost",session_cache=&cache,early_data=i==1}
  result:=http3.pool_exchange_request(&pool,address,"localhost",request,roots.roots[:roots.count],time.time_add(time.now(),8*time.Second))
  fmt.printf("RESULT %d error=%v reason=%s resumed=%v sentearly=%v accepted=%v status=%d\n",i,result.error,string(result.reason[:result.reason_len]),result.resumed,result.early_sent,result.early_accepted,result.status)
  assert(result.error==.None&&result.status==200&&string(result.body[:result.body_len])=="OK")
  if i==0 {
   assert(!result.resumed);saved:=tls.session_cache_lookup(&cache,"localhost",time.now());assert(saved!=nil)
   if scenario=="large"||scenario=="large-retry" {saved.ticket_len=tls.SESSION_TICKET_MAX;for &b in saved.ticket {b=0x55}}
  } else {expected:=scenario!="reject"&&scenario!="large"&&scenario!="large-retry";assert(result.early_sent);assert(result.resumed==expected);assert(result.early_accepted==expected)}
  http3.pool_close(&pool)
 }
}
