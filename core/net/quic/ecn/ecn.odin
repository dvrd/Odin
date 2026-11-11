// Caller-serialized ECN accounting shared by QUIC packet owners. Packet owners
// provide exact newly acknowledged marks before retiring their sent history.
package ecn
import "core:net"

Counts :: struct {ect0,ect1,ce:u64}
State :: enum {Disabled,Testing,Capable,Failed}
Space :: struct {sent,peer:Counts, largest:u64, has_largest:bool}
Sender :: struct {state:State, spaces:[3]Space}
Feedback :: struct {accepted,congestion,disabled:bool}
MAX_COUNT :: (u64(1)<<62)-1

init :: proc(s:^Sender,enabled:bool) {s^={};if enabled {s.state=.Testing}}
mark :: proc(s:^Sender)->net.ECN_Codepoint {if s!=nil && (s.state==.Testing || s.state==.Capable) {return .ECT_0};return .Not_ECT}
sent :: proc(s:^Sender,space:int,codepoint:net.ECN_Codepoint) {
 if s==nil || space<0 || space>=3 {return}
 receive(&s.spaces[space].sent,codepoint,true)
}
// Call once per authenticated, nonduplicate QUIC packet, including each packet
// in a coalesced datagram. Unknown/missing ancillary metadata is not Not-ECT.
receive :: proc(counts:^Counts,codepoint:net.ECN_Codepoint,valid:bool) {
 if counts==nil || !valid {return}
 #partial switch codepoint {
 case .ECT_0: counts.ect0=min(MAX_COUNT,counts.ect0+1)
 case .ECT_1: counts.ect1=min(MAX_COUNT,counts.ect1+1)
 case .CE: counts.ce=min(MAX_COUNT,counts.ce+1)
 }
}
@(private)
fail :: proc(s:^Sender)->Feedback {s.state=.Failed;return {disabled=true}}
validate :: proc(s:^Sender,space:int,largest:u64,newly_acked:Counts,present:bool,counts:Counts)->Feedback {
 if s==nil || space<0 || space>=3 || s.state==.Disabled || s.state==.Failed {return {}}
 sp:=&s.spaces[space]
 // RFC9000 13.4.2.1: reordered ACK frames MUST NOT fail ECN validation.
 if sp.has_largest && largest<=sp.largest {return {}}
 sp.largest=largest;sp.has_largest=true
 if !present {
  if newly_acked.ect0>0 || newly_acked.ect1>0 {return fail(s)}
  return {}
 }
 if counts.ect0>MAX_COUNT || counts.ect1>MAX_COUNT || counts.ce>MAX_COUNT ||
  counts.ect0<sp.peer.ect0 || counts.ect1<sp.peer.ect1 || counts.ce<sp.peer.ce ||
  counts.ect0>sp.sent.ect0 || counts.ect1>sp.sent.ect1 ||
  counts.ce>sp.sent.ect0+sp.sent.ect1 || counts.ect0+counts.ect1+counts.ce>sp.sent.ect0+sp.sent.ect1 {return fail(s)}
 d0:=counts.ect0-sp.peer.ect0;d1:=counts.ect1-sp.peer.ect1;dc:=counts.ce-sp.peer.ce
 if d0+dc<newly_acked.ect0 || d1+dc<newly_acked.ect1 || d0+d1+dc<newly_acked.ect0+newly_acked.ect1 {return fail(s)}
 sp.peer=counts
 if newly_acked.ect0>0 || newly_acked.ect1>0 {s.state=.Capable}
 return {accepted=true,congestion=dc>0}
}
// Per-space cumulative feedback survives migration. A new path must prove ECN
// again; owners exclude prior-path ACKs from this path's validation input.
reset_path :: proc(s:^Sender) {if s.state!=.Disabled {s.state=.Testing}}
// Caller arms a three-PTO probe deadline on a fresh path. Lack of validation
// falls back to unmarked traffic rather than abandoning the connection.
timeout :: proc(s:^Sender) {if s.state==.Testing {s.state=.Failed}}
