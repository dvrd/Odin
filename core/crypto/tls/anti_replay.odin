package tls

import "core:crypto"
import "core:mem"
import "core:sync"
import "core:time"

Anti_Replay_Error :: enum {None,Invalid,Closed,Capacity,Replayed,Expired,Clock,Allocation}
@(private)
Anti_Replay_Entry :: struct {used:bool,identity:[32]u8,expires:i64}
// Stable, bounded owner shared by every worker accepting tickets from a keyring.
// Reservations are never undone on handshake failure: early effects may exist.
Anti_Replay :: struct {_mutex:sync.Mutex,_initialized,_closed:bool,_entries:[]Anti_Replay_Entry,_allocator:mem.Allocator,_last_now:i64}
anti_replay_init :: proc(owner:^Anti_Replay,capacity:int=1024,allocator:mem.Allocator=context.allocator)->Anti_Replay_Error {
 if owner==nil||capacity<1||capacity>65536||allocator.procedure==nil {return .Invalid}
 sync.mutex_lock(&owner._mutex);defer sync.mutex_unlock(&owner._mutex)
 if owner._initialized {return .Invalid}
 entries,e:=make([]Anti_Replay_Entry,capacity,allocator);if e!=nil {return .Allocation}
 owner._entries=entries;owner._allocator=allocator;owner._initialized=true;return .None
}
anti_replay_close :: proc(owner:^Anti_Replay) {
 if owner==nil {return};sync.mutex_lock(&owner._mutex);defer sync.mutex_unlock(&owner._mutex)
 if raw_data(owner._entries)!=nil {crypto.zero_explicit(raw_data(owner._entries),len(owner._entries)*size_of(Anti_Replay_Entry));delete(owner._entries,owner._allocator)}
 owner._entries=nil;owner._closed=true
}
anti_replay_reserve :: proc(owner:^Anti_Replay,identity:[32]u8,expires:i64,now:i64)->Anti_Replay_Error {
 if owner==nil||now<0||expires<=now {return .Expired}
 sync.mutex_lock(&owner._mutex);defer sync.mutex_unlock(&owner._mutex)
 if !owner._initialized||owner._closed {return .Closed}
 if now<owner._last_now {return .Clock};owner._last_now=now
 slot: ^Anti_Replay_Entry
 for &entry in owner._entries {
  if entry.used&&entry.expires<=now {entry={}}
  if entry.used&&entry.identity==identity {return .Replayed}
  if !entry.used&&slot==nil {slot=&entry}
 }
 if slot==nil {return .Capacity};slot^={used=true,identity=identity,expires=expires};return .None
}
// QUIC transport/application context is authenticated inside the ticket. The
// binding checks compatibility; absent policy/context/anti-replay rejects0RTT.
Server_Early_Data_Config :: struct {
 replay:^Anti_Replay,
 profile:[]u8,
 compatible:proc(previous,current:[]u8)->bool,
 max_age:time.Duration,
}
SERVER_EARLY_CONTEXT_MAX :: 192
server_early_data_config_valid :: proc(config:^Server_Early_Data_Config)->bool {
 if config==nil {return true}
 if config.replay==nil||config.compatible==nil||len(config.profile)<1||len(config.profile)>SERVER_EARLY_CONTEXT_MAX||config.max_age<time.Second||config.max_age>time.Hour {return false}
 owner:=config.replay;sync.mutex_lock(&owner._mutex);defer sync.mutex_unlock(&owner._mutex)
 return owner._initialized&&!owner._closed
}
