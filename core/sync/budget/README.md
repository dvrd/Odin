# Hierarchical resource accounting

This optional primitive accounts for retained bytes, active streams and retained
blocking jobs without importing a protocol or scheduler. Limits are immutable
and explicit: zero means no allowance. Adapters choose their finite defaults;
a zero Scope is not an unlimited primitive budget.

Create a root, then connection and operation children. At most eight levels are
supported. Each node retains its parent, and each Lease retains its scope. The
root mutex and all ancestor nodes therefore survive their original host owners,
including a released request/connection/runtime while chunks or jobs remain.
Scope copies are aliases unless retain_scope creates an additional owner.
Leases are single owners by convention, like owned memory chunks; copies do not
create additional reservations, and callers must not concurrently mutate aliases.
All scope fields and parent links are internal and must not be changed by hosts.

A successful reserve charges the entire Cost vector to every ancestor atomically.
A rejected reserve changes no usage. replace atomically changes an existing
lease; failure preserves its cost and owner. release clears the owner and
refunds once. Resource overflow is rejected before arithmetic. Rejection counters
saturate instead of wrapping. snapshot reads immutable limits, consistent usage,
peaks, effective closure and rejection count under the hierarchy's one mutex.
The metadata allocator must support thread-safe alloc/free through final scope
retirement; a zero metadata allocator selects the process heap.

Jobs use one combined retained-job ceiling. A positive jobs cost requires Queued,
Running or Held; a zero jobs cost requires None. set_job_phase updates the
breakdown without acquiring new capacity, including after closure. Keep the
lease until the actual retained job/result is released, not merely until its
function returns or its connection is cancelled. Phase transitions cannot make
an accepted job wait for an unrelated running-job quota. replace preserves the
phase, clearing it when jobs becomes zero; increasing zero jobs to positive
requires a fresh phase-bearing reserve.

close prevents new admission through that scope and all descendants. Existing
owners can still retain/release, change job phase or reduce a lease. Increasing
any resource after closure rejects. Scope owner release alone does not close or
reset live charges: independently retained late work still has its bounded scope.

rebind moves a lease between scopes of the same root transactionally. Common
ancestors remain charged exactly once, even when the global limit is already
full; only destination-exclusive ancestors need new admission. Foreign roots,
closed destination or exhausted capacity reject without changing the old lease.
A rebind to the same exact scope is harmless. covers(charged, required) is true
only if required is charged itself or an ancestor of charged. Sharing a root is
insufficient; siblings and new descendants require explicit admission/rebind.
scope_of returns a borrowed Scope valid only while its lease remains alive.

No allocator, free or user callback executes under the hierarchy mutex. Control
nodes allocate before publication and free after unlinking and unlocking.
Snapshot scope_nodes/scope_metadata_bytes count published hierarchy control
nodes separately from charged payload backing. Leases are inline and allocate
no metadata. These control counters have no payload allowance and do not claim
malloc usable size, RSS, connection table capacity or other module metadata.
The companion core:mem/budget allocator charges full requested backing and
retains the metadata needed for allocations that outlive their producer.

Seven focused public tests pass strict ASan and TSan on Darwin arm64: multi-level
atomic rejection/refund/closure, common-ancestor and foreign-root rebind, scope
lifetime after original owners retire, u64/depth boundaries, metadata allocation
failure and reentrant allocator callbacks, 4,000 concurrent job/resource vectors,
and opposite sibling rebinds at a full global limit. Tracking allocators use
actual process heap for payload and tracking metadata; final control allocations
return to zero. This is kernel evidence, not full OKAMI-122 adapter acceptance or
Linux/Windows execution certification.
