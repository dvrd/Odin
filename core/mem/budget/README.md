# Charged allocation ownership

`core:mem/budget` binds individually releasable allocations to a retained
`core:sync/budget.Scope`. It counts the full requested backing: payload, inline
allocation header and maximum alignment padding. It does not measure allocator
rounding, virtual address reservations, OS buffers, caller stacks or process RSS.
The Binding's fixed control allocation is reported separately as metadata.

Create a Binding with `create(scope, Config{})`; zero backing/metadata allocators
select the process heap. Supply thread-safe metadata/backing allocators whose
lifetime extends through final allocation retirement. Directly nesting another
managed allocator as backing is rejected to prevent duplicate byte charges.
Do not hide managed backing behind arbitrary wrappers and assume it is detected.
The backing must individually free its valid storage. A failed Free must be
non-consuming; transactional resize assumes cleanup of a valid temporary can
succeed. A backend that consumes storage but reports failure is unsupported.

Binding copies are aliases. `retain` creates an additional owner and `release`
clears one. Each allocation independently retains its Binding and a current-scope
Lease. Releasing the caller's Scope or Binding owners does not free outstanding
storage or reset its counters. A dynamic array's allocator remains usable through
its existing allocation, including resize, after caller owners retire. Keep a
Binding owner until the first allocation is made. Do not use an allocator alias
once its last Binding owner and allocation are gone. Nil frees remain harmless.

## Interface

- `allocator(binding)` satisfies `mem.Allocator`: Alloc/Alloc_Non_Zeroed,
  Resize/Resize_Non_Zeroed, Free, Query_Features and Query_Info. Free_All is
  explicitly unsupported. Ordinary array/arena allocation can use this interface.
- `allocate(binding, size, alignment)`, `resize(binding, previous, size, alignment)`
  and `deallocate(binding, whole_base)` provide typed `Error{kind,budget,allocation}`.
  Budget_Rejected preserves the underlying scope error; Allocation_Failed preserves
  backing OOM. Invalid alignment/size, arithmetic overflow and provenance failures
  are distinct. The standard Allocator_Error enum has no budget variant, so both
  budget denial and backing OOM necessarily map to Out_Of_Memory there. Use typed
  helpers for precise attribution; there is no racy per-Binding last_error field.
- `allocation_cost(size, alignment)` reports the exact requested backing cost
  before allocation. A zero-byte allocation has no allocation/header/charge.
- `stats(binding)` reports current/peak requested backing, live allocations,
  budget denials, backing allocation failures and fixed Binding metadata bytes.
- `allocator_scope` borrows the direct allocator Binding's default scope;
  `retain_allocator` creates a Binding owner from that allocator. Hosts can reuse
  a demonstrably covering managed allocator without wrapping/charging it twice.
- `is_managed_allocator`, `allocation_info` and `allocation_scope` recognize only
  this direct allocator and an actual live whole-allocation base. Unknown/interior
  pointers return false without probing memory before the supplied pointer.
  Returned scope/info views borrow their allocation's lifetime.
- `allocation_covers(allocator, base, required)` checks ancestor coverage. Use
  `scopes.same_scope(info.scope, required)` when exact operation identity matters.
  It does not claim that a sibling or descendant scope is already charged.
- `rebind_allocation(allocator, base, destination)` moves the existing allocation
  Lease atomically inside one hierarchy. Common ancestors stay charged once.
  Exhausted, closed, invalid and foreign-root destinations preserve the source.

Every allocation owner serializes operations on that allocation, as with ordinary
free/resize. Independent allocations, Binding retains/releases and snapshots can
run concurrently. Provenance lookup uses a finite intrusive registry of current
allocations; it allocates no lookup metadata. Lookup is linear in that Binding's
live allocation count. No backing allocator, free callback or scope destructor
runs under the Binding mutex or hierarchy mutex. Reference exhaustion is checked
before a CAS changes the count; it returns Overflow without wrapping or mutation.

## Resize, transfer and arenas

Resize reserves the complete new backing while the old allocation remains
charged, then allocates/copies/frees. Its peak therefore includes real temporary
overlap, even when the final result would fit alone. Denial/OOM preserves old
storage, bytes and current scope. Newly grown bytes are zeroed in ordinary Resize;
Resize_Non_Zeroed makes no zeroing promise. Resize follows the allocation's CURRENT
scope after rebind, rather than the Binding's original/default scope.

`core:mem/owned.take_dynamic` already preserves the original allocator and full
capacity. A moved body may outlive its producing response and Scope/Binding owners;
its final owned.destroy returns storage and its charge exactly once. A transport
send, finish signal or producer teardown is not final backing release.

For Dynamic_Arena use a managed allocator for BOTH block_allocator and
array_allocator. Blocks and out-of-band payloads alone do not account for pointer
bookkeeping arrays. Arena suballocations are not direct managed allocations;
provenance helpers deliberately do not infer their arena or custom-release owner.
A host must propagate its managed arena contract explicitly, or make a bounded
copy into an individually free managed allocation when transferring storage.
The Dynamic_Arena allocation-failure prerequisite preserves prior owners and
rolls back a payload when pointer-table admission fails.

## Validation

Thirteen public tests cover typed budget/backing failures and recovery; invalid,
zero, aligned, overflowing and wrong-provenance inputs; real owned dynamic bodies
that resize and transfer after caller owners retire; current-scope resize and
same-root rebind at a full ancestor; failed/foreign/closed rebind; temporary resize
overlap; non-consuming backing free failure; callbacks that query/reenter/release
owners; checked reference exhaustion; eight concurrent allocation/rebind/resize
workers; and charged arena payload/bookkeeping rollback. Tracking allocators use
the real process heap for both payload and tracking internals, and return to zero.

Run against the matching compiler with this source tree selected by ODIN_ROOT:

```sh
ODIN_ROOT=/absolute/matching/source /absolute/matching/odin test \
  /absolute/matching/source/core/mem/budget/tests -sanitize:address -vet \
  -warnings-as-errors -thread-count:1 -define:ODIN_TEST_THREADS=1 \
  -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true -out:/tmp/charged-budget-tests
```

Repeat with `-sanitize:thread`. Library/HTTP/server/offload adapters and the mixed
slow-reader/body/job admission gate remain required for the full OKAMI-122 scope;
this foundation alone is not its completion or a platform/performance claim.
