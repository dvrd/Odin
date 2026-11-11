package store

import "core:sync"

// Identifies the exact pinned credential snapshot, including a retired
// generation. Reading current Store stats is not a substitute: publication may
// rotate between selecting a connection's identity and signing its handshake.
lease_generation :: proc(store:^Store,lease:Lease)->(u64,Error) {
 if store==nil {return 0,{kind=.Invalid_Store}}
 owner:=cast(^Owner)store
 sync.mutex_lock(&owner.mutex);defer sync.mutex_unlock(&owner.mutex)
 index,e:=lookup_lease(owner,lease)
 if e.kind!=.None {return 0,e}
 return owner.generations[index].id,{}
}

// Creates an independent owner of the same generation, never silently the
// current replacement. Copies of Lease are aliases; retain consumes one of the
// Store's bounded lease slots. Failure leaves the borrowed source unchanged.
retain :: proc(store:^Store,source:Lease)->(Lease,Error) {
 if store==nil {return {},{kind=.Invalid_Store}}
 owner:=cast(^Owner)store
 sync.mutex_lock(&owner.mutex);defer sync.mutex_unlock(&owner.mutex)
 index,e:=lookup_lease(owner,source)
 if e.kind!=.None {return {},e}
 if owner.closed {return {},{kind=.Closed}}
 slot:=owner.free_lease
 if slot<0 {return {},{kind=.Capacity}}
 identity,available:=next_local_identity(&owner.next_lease)
 if !available {return {},{kind=.Identity_Exhausted}}
 owner.free_lease=owner.leases[slot].index
 generation:=&owner.generations[index]
 generation.leases+=1;owner.lease_count+=1
 owner.leases[slot]={id=identity,generation=generation.id,index=index,active=true}
 return {_epoch=owner.epoch,_id=identity,_generation=generation.id,_slot=slot},{}
}
