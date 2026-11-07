# Recordless server owner/event shell

`Server_Handshake` is a transient, serial, single-address owner. Initialize zeroed
storage once with `server_handshake_init`, an explicit bounded config and an
allocator that survives destruction. Do not copy/move it, mutate its underscored
fields, reenter it or call it concurrently. A self-address check rejects ordinary
struct copies; this is a caller ownership contract, not language-enforced linearity.
After destruction, use fresh zeroed storage for a new lifetime. Event IDs are
scoped to that owner lifetime; do not use one owner's IDs with another owner.
No callback, executor, socket, TLS record, clock or credential is stored here.

This is **OKAMI-152's shell**, not a TLS server. Its public path assembles and
negotiates one ClientHello using the restricted codec, publishes tentative offers,
then returns `Await_Flight`. It cannot emit a server flight, install keys,
authenticate a peer, authorize application data or report successful completion.
Missing usable X25519 shares (including retry-required offers) are `Unsupported`;
this shell does not perform HRR. The future flight153 must pin/admit credentials,
check chain-signature compatibility and own the DER pin; Finished154 must gate
completion and release all transient state. ALPN/QUIC binding and interoperability
remain separate gates. Current offers never accept PSK/0-RTT.

## Feed and event ownership

`server_handshake_feed(owner, level, input)` returns a consumed prefix count,
status and error. Input is borrowed only during that call. Consumed bytes are
copied into bounded owner storage; resubmit the unconsumed suffix unchanged.
Empty input may return `Need_Input` with zero consumed. Partial headers use a
four-byte accumulator. Wrong message type fails after its first byte; a declared
oversize or impossible short message fails after its four-byte header, before any
body allocation. Wrong level in the input phase fails with zero consumed.
One complete ClientHello stops exactly at its boundary, even with a coalesced
suffix. No input is retained from the caller.

`Need_Event_Drain` means the pending event must be accepted before further
progress; feed consumes zero while it is pending. `server_handshake_peek` returns
the same immutable payload/ID until acceptance or teardown. Peek does not hash,
allocate, erase, or advance state. `server_handshake_accept(owner, id)` accepts
exactly one current nonzero ID; stale/duplicate/zero IDs are errors without side
effects. Feed after failure, abort or destruction consumes zero and returns
`Terminal`. A pending Fatal can still be peeked/accepted after failure; it never
permits later success. IDs saturate: exhaustion is terminal without a new event.

Event kinds reserve these producer/consumer contracts:

| Kind | Borrow and acceptance contract |
| --- | --- |
| `Handshake_Bytes` | Exact ordered handshake fragments including message headers, Initial/plaintext or Handshake level; no records/CCS. Copy into transport-owned ordered storage before acceptance. Accepted bytes enter the transcript exactly once. |
| `Traffic_Secret` | 32 bytes, AES128GCM/SHA256, explicit level and Read/Write relative to the local server. Derive/copy transport protection before acceptance; owner storage is immediately wiped. Key availability alone never authorizes application delivery. |
| `Peer_Parameters` | Tentative SNI, ALPN **offers** and opaque QUIC parameter presence/bytes from ClientHello. They are neither selected nor authenticated. Copy any needed durable metadata before acceptance. |
| `Complete` | Reserved for Finished154, after authentication and required output acceptance. No public path emits it in this shell. |
| `Fatal` | Stable typed protocol/local error, without sensitive diagnostic payloads or implicit alert/transport handling. |

Every output borrow, including copied event structs, ends at accept/abort/destroy.
The private producer seam copies at most 2,048 bytes into reusable scratch or
borrows an immutable pinned certificate fragment. Shared DER is never wiped by
the shell. Flight153 must keep its credential lease alive until all DER borrows
end and release that lease exactly once on cleanup. The seam has no public
injection API; tests exercise reserved output/secret/completion lifetimes without
pretending to authenticate a handshake. A future producer must enforce protocol
state/order; publishing a Complete test event is not authentication evidence.
Transport acceptance means local storage ownership, not peer acknowledgment.

## Limits and cleanup

Local policy, not TLS wire maxima: ClientHello 45–65,536 bytes including header,
1–128 extensions, fixed 2,048-byte copied-output cap. Input allocates exactly its
declared bounded message after header admission; output scratch allocates lazily
only when a producer needs it. There is no message/event queue or complete-flight
allocation. Both grants coexist until their explicit last-use release or teardown.

Measured Darwin arm64 fixed owner: **720 bytes**; event value: **136 bytes**.
The shell's maximum accepted transient grants total **67,584 bytes** (65,536 +
2,048), two allocations. `server_handshake_stats` reports cumulative requested
bytes/attempts and peak/live **accepted** grants, excluding caller-owned fixed
storage, shared DER, allocator metadata and rejected abnormal grants. The audit
allocator tests separately check complete reported extents of abnormal grants.
No compiled-stack, transitive RSA/crypto stack, platform-independent size,
throughput or production-server memory claim follows from these measurements.

Abort/destroy are idempotent and revoke every borrow. Failure/cancellation clears
header, transcript, secret and output scratch, wipes complete reported grants
before Free and drops all stored input views. Short/oversized/error-bearing grants
are rejected and their full reported extents are wiped/freed. Allocators must
report valid accessible grant extents and honor Free; arbitrary corrupt allocators
are outside this contract. Explicit erasure covers owned storage, not all compiler
registers, stack copies or consumer-owned material. Final success cleanup and
credential release are Finished154/flight153 work.

Run package lifecycle/fault tests with:

```sh
./odin test core/crypto/tls -warnings-as-errors -sanitize:address -out:/tmp/tls-owner-tests
./odin run tests/core/crypto/tls/server_owner -warnings-as-errors -sanitize:address -out:/tmp/tls-owner-consumer
```

Reviewed semantic references: [RFC8446 sections4 and4.4.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-4),
and [Go's serial QUIC TLS events and lifetimes](https://go.dev/src/crypto/tls/quic.go).
This API follows the local native-stack architecture; no Go implementation was copied.
