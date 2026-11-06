# Owned byte chunks

`core:mem/owned` moves byte storage between serialized owners. It has no HTTP,
networking, scheduler or per-buffer heap-metadata dependency. It is suitable as
an ownership primitive for future transport integrations; it is not a QUIC
implementation or an acknowledgment engine.

## Chunk ownership

A `Chunk` contains a borrowed payload view inside its owned full backing storage,
plus either the original allocator or a custom release callback/context.
`allocate` creates storage; `copy_bounded` copies a short-lived source after
checking its byte limit. `take_slice`, `take_dynamic` and `take_custom` adopt
existing allocator/dynamic-array/pool storage and clear their sources only on
success. `take_slice` must receive the entire original allocation, never an
interior slice. `take_dynamic` retains the array's original allocator and full
capacity, including any capacity beyond its payload length.

The allocator, pool and callback context must outlive the final owner. An arena
that is reset when a handler returns cannot back an outstanding chunk. Retaining
one small slice must not accidentally keep a large request arena alive. Custom
release code can return storage to a pool without an individual allocation. The
callback runs in the consumer's current Odin context; required owner state must
come from its explicit long-lived context rather than an assumed producer context.

`move(&destination, &source)` accepts a valid owner only into an empty destination
and clears the source. Rejection leaves both unchanged. `destroy` clears the
exact owner before invoking its release callback and is safe to repeat on that
cleared owner. Callbacks must not mutate their owning queue. They may observe
that their source owner is already empty.

Odin does not enforce move-only values. Copying a `Chunk`, `Queue`, dynamic array
or its backing pointer creates aliases, not another valid owner. After a move,
producers must stop accessing all aliases. `valid` checks ownership metadata and
that payload bytes lie within the charged storage; it cannot prove allocator
provenance, allocation liveness or absence of copied aliases.

## Bounded admission and release

The optional `Queue` is a fixed-capacity FIFO, owned and operated by one serialized
execution context. It is **not thread-safe**. `queue_init` allocates its slots
once and checks capacity multiplication; `queue_submit` performs no payload or
metadata allocation. It accepts the whole chunk or rejects it unchanged:

- `Accepted`: source cleared; the queue is now the only owner.
- `Backpressure`: byte or slot capacity exhausted; the caller retains the chunk.
- `Closed`: no admissions; caller retains the chunk.
- `Invalid`: invalid owner/arguments; caller retains the chunk.

Byte accounting charges full backing length/capacity, not the shorter payload.
These counters measure retained backing bytes, excluding allocator overhead and
the separately allocated fixed queue-slot metadata. Slot capacity is independent:
even zero-byte chunks consume a slot. Checked
subtraction prevents byte-accounting overflow. Producers should wait for their
host's capacity notification before retrying rejected work rather than spin.

`queue_front` borrows the head payload. All producers/consumers must keep pending
bytes unchanged. The view expires on `queue_release_front`, `queue_clear`,
`queue_close` or `queue_destroy`; no alias may be used afterward. A successful
packet send does not call `queue_release_front` automatically.

The transport decides when storage is no longer required. In a retransmitting
transport, a packet send or loss can leave that storage retained for later use;
ACK or a terminal discard policy can permit release. **Memory release does not
prove delivery:** cancellation, reset, failure or shutdown also release storage.
A future QUIC implementation must separately track stream offsets, ACK/loss state
and retransmission-capable representations; this FIFO is not that state machine.

`queue_clear` discards pending owners while preserving slots/admission state,
which can represent cancellation/reset of a body. `queue_close` stops admission
before draining, and can be repeated. `queue_destroy` also releases slot storage
and can be repeated. The same destruction path handles success and terminal
failure without double release. A destroyed queue remains closed until it is
explicitly initialized again.

## Verification

```sh
odin test core/mem/owned/tests -thread-count:1 -warnings-as-errors
odin test core/mem/owned/tests -thread-count:1 -warnings-as-errors -sanitize:address
```

Public-interface tests cover delayed ACK-like retention, full-capacity budget
accounting, zero-byte slot pressure, FIFO wrap, rejection/source preservation,
pool/custom callback release, reentrant destruction, malformed payload views,
dynamic-array moves, allocation failure and repeated teardown.
