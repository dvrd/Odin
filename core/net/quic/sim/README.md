# Deterministic QUIC driver test link

`core:net/quic/sim` is an optional test utility. It imports no QUIC connection,
TLS, socket, thread or wall-clock implementation. It does not implement a peer.

Call `init` with stable, exclusive packet slots, exactly `slots * max_datagram`
bytes of payload storage and timer slots. The link never allocates or frees
storage. Do not copy/mutate initialized links or their storage. `send` copies
input immediately; `step` copies a delivered datagram into caller output, so no
queued packet borrow survives the call. Output/input overlapping internal
storage is rejected before mutation. Full queues return `Capacity`; duplicate
admission is atomic. Oversized datagrams are rejected rather than truncated.

Ticks are nonnegative abstract driver units. They are not nanoseconds or real
time. `step(link, until, output)` delivers the next event at/before `until`,
advancing to its time. With no event it advances to `until`. Insertion sequence
breaks equal-time ties across packets and timers. Invalid time or an undersized
output leaves time and queues unchanged. Check the returned event's `size` to
retry delivery with sufficient output storage. Repeated zero-delay scheduling
is intentionally possible; the test driver must bound its own dispatch loop.

For each delivered packet, the host dispatches `destination.peer`, passes its
source/path and bytes into the real protocol driver, and enqueues its outputs.
For a timer event it dispatches the timer owner and tag. Call `now` to supply
the same explicit clock to every driver. The simulator invokes no callbacks,
so teardown/reentrancy and driver failure handling remain under test control.

Explicit `Plan` inputs provide reproducible loss (`drop`), duplication and
delivery delays. Different delays cause reordering. Changing `Address.path`
models a new source or destination address without inventing migration policy.
There is no hidden randomness; randomized scripts must record their seed/plan.
Drop plus duplicate, unused nonzero duplicate delay and negative/overflowing
delays are rejected. Resource occupancy and peaks are available through `stats`.

Timer handles include the link address, slot and generation. Cancelled/fired
handles cannot cancel a later timer occupying that slot; `clear` retains timer
generations and global event sequence. Generations/sequences never wrap: an
exhausted timer slot is retired, and event sequence exhaustion returns
`Exhausted`. Destroy invalidates every handle; discard them before reinitializing
the same link/storage. `clear` cancels pending work but retains caller storage
and clock; `destroy` also clears the link. Neither securely erases packet bytes.
All calls on one link require external serialization. Only nonnil initialized
links may be passed to the `now`/`stats` inspection functions.

Tests exercise real v1 header datagrams through a loss/retransmission/duplicate
driver, timer ABA/foreign-owner cancellation, replayable reordering and address
changes, capacity/alias/overflow boundaries, and 10,000 iterations with nil
allocators and fixed storage. Fake payloads deliberately carry no authenticated
QUIC meaning. These checks establish the test seam, not handshake/recovery,
flow control, network interoperability or independent-platform correctness.
The broader QUIC interoperability issue remains open until those components
and external-peer gates exist.

```sh
./odin test core/net/quic/sim/tests -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
```
