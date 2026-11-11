package tls

import "core:crypto"
import "core:crypto/sha2"
import "core:mem"
import "core:time"
import credential_store "credentials/store"

@(private)
Server_Resumption :: struct {
 claims:Server_Ticket_Claims,
 master:[32]u8,
 selected:bool,
 selected_index:u16,
 wire:[512]u8,
 wire_size:int,
}
server_handshake_resumed :: proc(owner:^Server_Handshake)->bool {return server_handshake_valid(owner)&&owner._phase==.Complete&&owner._resumed}
@(private)
server_resumption_clear :: proc(owner:^Server_Handshake) {
 if owner._resumption==nil {return};owner._stats.live_bytes-=size_of(Server_Resumption)
 server_handshake_wipe_free(owner,mem.byte_slice(owner._resumption,size_of(Server_Resumption)),align_of(Server_Resumption));owner._resumption=nil
}
@(private)
server_resumption_policy :: proc(owner:^Server_Handshake)->(out:[32]u8) {
 h:sha2.Context_256;sha2.init_256(&h)
 policy:=owner._config.client_auth
 mode:u8;if policy!=nil {mode=u8(policy.mode)};sha2.update(&h,mem.byte_slice(&mode,1))
 if policy!=nil&&policy.mode!=.Disabled {for root in policy.roots {sha2.update(&h,root.raw)}}
 sha2.final(&h,out[:]);return
}
@(private)
server_resumption_prepare :: proc(owner:^Server_Handshake,now:time.Time)->Server_Handshake_Error {
 config:=owner._config.tickets;if config==nil {return .None}
 grant,ok:=server_handshake_allocate(owner,size_of(Server_Resumption),align_of(Server_Resumption));if !ok {return .Allocation_Failed}
 state:=cast(^Server_Resumption)raw_data(grant);owner._resumption=state
 state.claims.sni=ticket_hash(owner._hello.server_name);state.claims.alpn=ticket_hash(owner._parameters.value.alpn)
 state.claims.policy=server_resumption_policy(owner);state.claims.policy_epoch=config.policy_epoch
 fingerprint,fe:=credential_store.fingerprint(owner._flight.store,owner._flight.lease);if fe.kind!=.None {return .Credential_Failed};state.claims.credential=fingerprint
 generation,ge:=credential_store.lease_generation(owner._flight.store,owner._flight.lease);if ge.kind!=.None {return .Credential_Failed};state.claims.generation=generation
 if !owner._hello.has_psk {return .None}
 dhe:=false;for mode in owner._hello.psk_modes {if mode==PSK_DHE_KE {dhe=true}}
 if !dhe {return .None}
 identities:=owner._hello.psk_identities;binders:=owner._hello.psk_binders
 // The codec validated both vectors. Hash the exact CH through identities,
 // omitting the binder vector's length and contents (RFC8446 section4.2.11.2).
 truncated:=owner._hello.wire[:len(owner._hello.wire)-2-len(binders)]
 transcript:=owner._binder_transcript;transcript_update(&transcript,truncated);hash:=transcript_snapshot(&transcript)
 at,binder_at,index:=0,0,0
 for at<len(identities) {
  n:=int(hello_u16(identities,at));at+=2;ticket:=identities[at:at+n];at+=n
  age:=u32(identities[at])<<24|u32(identities[at+1])<<16|u32(identities[at+2])<<8|u32(identities[at+3]);at+=4;_=age
  binder_n:=int(binders[binder_at]);binder_at+=1;binder:=binders[binder_at:binder_at+binder_n];binder_at+=binder_n
  index+=1
  if len(ticket)!=TICKET_WIRE_SIZE||binder_n!=32 {continue}
  opened:Server_Ticket_Claims;defer crypto.zero_explicit(&opened,size_of(opened))
  // Decryption uses a fixed-size copy: caller ClientHello remains immutable.
  copy_ticket:[TICKET_WIRE_SIZE]u8;copy(copy_ticket[:],ticket)
  if !server_ticket_crypt(config,&opened,copy_ticket[:],false,now) {continue}
  if opened.sni!=state.claims.sni||opened.alpn!=state.claims.alpn||opened.credential!=state.claims.credential||opened.generation!=generation||opened.policy!=state.claims.policy||opened.policy_epoch!=state.claims.policy_epoch {continue}
  if owner._config.client_auth!=nil&&owner._config.client_auth.mode==.Require&&!opened.authenticated {continue}
  key:=resumption_binder_key(opened.psk);expected:=finished_verify_data(key,hash);crypto.zero_explicit(&key,size_of(key))
  valid:=crypto.compare_constant_time(binder,expected[:])==1;crypto.zero_explicit(&expected,size_of(expected))
  if !valid {return .Binder_Failed}
  state.claims.psk=opened.psk;state.claims.authenticated=opened.authenticated;state.claims.peer=opened.peer;state.claims.peer_expires=opened.peer_expires
  state.selected=true;state.selected_index=u16(index-1);owner._resumed=true
  return .None
 }
 return .None
}
@(private)
server_resumption_issue :: proc(owner:^Server_Handshake,finished:[]u8)->bool {
 state:=owner._resumption;if state==nil {return false}
 transcript_update(&owner._transcript,finished)
 hash:=transcript_snapshot(&owner._transcript);master:[32]u8
 finished_expand(state.master[:],"res master",hash[:],master[:]);defer crypto.zero_explicit(&master,size_of(master))
 nonce:[16]u8;crypto.rand_bytes(nonce[:]);state.claims.psk=session_psk(master,nonce[:])
 now:=time.now();state.claims.issued=time.to_unix_seconds(now);lifetime:=u32(owner._config.tickets.lifetime/time.Second);state.claims.expires=state.claims.issued+i64(lifetime)
 state.claims.authenticated=owner._peer_identity.authenticated;state.claims.peer=owner._peer_identity.certificate_sha256;state.claims.peer_expires=owner._peer_expires
 // age_add is independent fresh entropy; it need not be recovered to reject0RTT.
 add:[4]u8;crypto.rand_bytes(add[:])
 wire:=state.wire[:];wire[0]=4;server_flight_put24(wire[1:4],4+4+1+len(nonce)+2+TICKET_WIRE_SIZE+2)
 at:=4;wire[at],wire[at+1],wire[at+2],wire[at+3]=u8(lifetime>>24),u8(lifetime>>16),u8(lifetime>>8),u8(lifetime);at+=4
 copy(wire[at:],add[:]);at+=4;wire[at]=u8(len(nonce));at+=1;copy(wire[at:],nonce[:]);at+=len(nonce)
 wire[at],wire[at+1]=u8(TICKET_WIRE_SIZE>>8),u8(TICKET_WIRE_SIZE&255);at+=2
 if !server_ticket_crypt(owner._config.tickets,&state.claims,wire[at:at+TICKET_WIRE_SIZE],true,now) {return false};at+=TICKET_WIRE_SIZE;wire[at],wire[at+1]=0,0;at+=2;state.wire_size=at
 crypto.zero_explicit(&state.master,size_of(state.master));crypto.zero_explicit(&state.claims.psk,size_of(state.claims.psk));return true
}
