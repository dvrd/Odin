package main

import "core:crypto/tls"
import "core:fmt"
import "core:net"
import "core:net/quic/conn"
import "core:os"
import "core:time"
import http3 "shared:http/v3"

main :: proc() {
 assert(len(os.args)==4)
 roots:tls.Root_Pool;assert(tls.root_pool_load_file(&roots,fmt.tprintf("%s/root.pem",os.args[1])).kind==.None);defer tls.root_pool_destroy(&roots)
 original,oe:=net.parse_endpoint(os.args[2]);assert(oe);candidate,ce:=net.parse_endpoint(os.args[3]);assert(ce)
 pool:http3.Pool;defer http3.pool_close(&pool)
 request:=http3.Client_Request{method="GET",target="/cross-path",authority="localhost"}
 first:=http3.pool_exchange_request(&pool,original,"localhost",request,roots.roots[:roots.count],time.time_add(time.now(),8*time.Second))
 assert(first.error==.None&&first.status==200&&string(first.body[:first.body_len])=="OK")
 c:=pool.slots[0].client;assert(c!=nil&&c.transport.seen_done&&c.transport.migration.declined_preferred.used)
 for entry in c.transport.migration.peer {assert(!entry.used||entry.sequence!=1)}
 clock:=i64(time.tick_diff({},time.tick_now()))/i64(time.Millisecond)
 assert(conn.migrate(&c.transport,clock,candidate)==.None)
 second:=http3.pool_exchange_request(&pool,original,"localhost",request,roots.roots[:roots.count],time.time_add(time.now(),8*time.Second))
 if second.error!=.None {fmt.printf("FAIL %v %s\n",second.error,string(second.reason[:second.reason_len]))}
 assert(second.error==.None&&second.status==200&&string(second.body[:second.body_len])=="OK")
 validated:=false;for path in c.transport.migration.paths {if path.used&&path.endpoint==candidate {validated=path.validated&&!path.challenge_pending}}
 assert(validated);assert(c.handshakes==1)
 fmt.println("PASS cross-path authenticatedresponse/candidatevalidation/independentHTTP3")
}
