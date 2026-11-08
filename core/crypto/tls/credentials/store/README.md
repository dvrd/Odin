# Bounded credential publication and leases

`core:crypto/tls/credentials/store` publishes immutable RSA/P-256 credentials and pins
retired owners while handshakes still borrow them. It is independent of the
parent TLS client, TCP executor, files, environment and background workers.
It adds no implicit clock, certificate policy, trust store or handshake.

```odin
store, error := credential_store.create({}, allocator)
if error.kind != .None { return }
defer credential_store.destroy(&store)

candidate, cause := credentials.create(chain_pem, key_pem, {}, allocator)
if cause != .None { return }
defer credentials.destroy(&candidate)
if credential_store.replace(store, &candidate).kind != .None { return }
// Accepted replacement clears candidate. Any rejection preserves it.

lease, admitted := credential_store.acquire(store)
if admitted.kind != .None { return }
defer credential_store.release(store, &lease)
// Explicit policy: caller chooses the admission clock.
policy := credential_store.check_server_leaf(store, lease, now)
```

## Ownership and access

Keep the Store at its stable address until all API calls are quiescent and
`destroy` succeeds. A Lease is one owning value; copying it does not make another
pin. Transfer it by assignment followed by clearing the source. Do not forge its
fields or concurrently release it against its own borrowers/signers. Distinct
leases may be used concurrently and may refer to the same immutable generation.

`certificate_count`, `certificate_der`, `fingerprint`, `sign_digest_pss_sha256`,
`signature_scheme`, `sign_sha256`
and `check_server_leaf` forward to the immutable credential while validating the
lease. No owning credential pointer is exposed. DER is an immutable borrow by
convention, valid only until that lease is released. Native credential failures
are preserved as `Error{kind=.Credential_Failed, credential=...}`. The store never
chooses a clock or checks policy implicitly during publication/acquisition.

Successful `release(store,&lease)` clears the owning variable before any owner
is destroyed. Releasing an already cleared variable is harmless. An invalid or
foreign-store release preserves the handle so the caller can retry on its actual
store. A copied stale handle cannot release a reused slot/generation. These
identities validate trusted host resource handles; they are not a remote
security capability or protection against arbitrary unsafe pointer misuse.

## Rotation, shutdown and limits

The defaults are four total generations, 1024 simultaneous leases and 16 MiB of
retained credential allocation bytes. Zero fields select defaults; positive
values configure explicit bounds and negative/overflowing values fail. Store
metadata is allocated once up front; it never grows during operation. Lease
admission/release use a preallocated free list. Generation selection scans the
configured bounded generation table.

Replacement requires a free generation record and enough retained-byte headroom
for both old and incoming owners. The old current owner becomes retired; its
last release schedules synchronous destruction outside the metadata mutex.
An owner with zero leases can also be retired by replacement or close. A
`Destroying` record remains unavailable and fully charged until all destruction
and allocator callbacks actually return. Another concurrent replacement cannot
borrow that budget or recycle its record prematurely.

`Capacity`, `Closed` or `Identity_Exhausted` leaves the candidate and current
publication unchanged. Current credentials are never discarded first just to
make a new candidate fit. Accordingly, rotation requires at least two generation
records and simultaneous-byte headroom; a one-generation configuration can hold
one owner but cannot replace it in place.

`stats` separately reports live generation/retired/destroying/lease counts,
retained credential bytes and metadata bytes. Generation count includes
Destroying records; retired count excludes them. Metadata is not charged against
`max_retained_bytes`. Caller-owned candidates and constructor transient peaks are
also outside that retained-store budget. Allocator internal reservations/metadata
are outside these exact requested-byte counters.

`close` rejects new acquisition/replacement and retires the current generation.
Existing leases and their views remain usable until release. Close is idempotent
and may race ordinary operations on distinct leases. It does not wait for leases
or start a cleanup worker. Calls retiring the final pin may perform synchronous
allocator work outside the mutex, so they are not promised to be wait-free.

`destroy(&store)` returns `Busy` without changing open/closed state while leases
or Destroying owners remain. Host quiescence is required before destruction;
this is not a mechanism for racing a freed Store pointer against new API entry.
Once quiescent and unpinned, destroy closes, erases/frees metadata and clears the
owning variable. Repeating it on that variable is safe. Underlying allocators
must remain alive, support exact aligned grants/frees and be safe on any thread
that may retire an owner. The immutable credential's erasure/entropy contracts
remain unchanged. Allocator callbacks may inspect stats while the store is live;
they must not mutate the same store or recursively invoke their own allocator.

The only mutex protects metadata. Parsing, signing, allocation and credential
or metadata destruction do not run under it. Publication never performs an
unsafe load-current-pointer then increment-refcount sequence. Store epochs use
a saturating atomic CAS counter; generation/lease identities saturate under the
mutex. Exhaustion never wraps into an earlier live alias.

## Handshake integration contract

A future recordless handshake acquires one lease at admission and retains it
through verified Finished **and** acceptance of every final output borrowing
certificate storage. Either event alone is insufficient if the other still has
outstanding borrows. Cancellation/failure/close must first end protocol/output
borrows; a record adapter must also quiesce I/O using them before release.
Authenticated idle connections keep no credential lease. Ticket/resumption key
policy is separate. This package implements ownership primitives, not those
future handshake/record-driver transitions.

## Validation and cost

On Darwin arm64, the default store requests 33,104 metadata bytes: a 176-byte
owner, four 40-byte generation records and 1024 32-byte lease records. A Lease
value is 32 bytes. Actual platform sizes are observable through `stats`.
Acquiring/releasing leases performs no allocation; tests hold the allocator-call
count constant through 256 cycles.

Nine tests exercise old/new RSA key sizes and RSA/ECDSA algorithms across rotation, DER lifetime,
typed forwarding errors, capacity preservation, stale/foreign/reused handles,
Busy shutdown, isolated saturating-ID allocation, all three metadata allocation
positions under five failure modes, full erasure and out-of-lock observation,
blocked-free budget accounting, and eight-thread acquisition/rotation/close.
The race fixture pins distinct leases through close, including readers resumed
after close. ASan/allocation tracking and TSan are required; semantic checks on
other targets do not establish runtime portability. No production throughput,
lock contention or full TLS interoperability claim follows from these tests.

```sh
odin test core/crypto/tls/credentials/store -sanitize:address -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true -define:ODIN_TEST_THREADS=1
odin test core/crypto/tls/credentials/store -sanitize:thread -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true -define:ODIN_TEST_THREADS=1
```
