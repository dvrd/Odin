# Recordless server handshake owner

`Server_Handshake` is a transient, serial, single-address owner. Initialize zeroed
storage once with `server_handshake_init`, an explicit bounded config and an
allocator that survives destruction. Do not copy/move it, mutate its underscored
fields, reenter it or call it concurrently. A self-address check rejects ordinary
struct copies; this is a caller ownership contract, not language-enforced linearity.
After destruction, use fresh zeroed storage for a new lifetime. Event IDs are
scoped to that owner lifetime; do not use one owner's IDs with another owner.
No callback, executor, socket, TLS record or ambient clock is stored here.
Server parameter policy/selection and its binding acceptance hook are documented
in [SERVER_PARAMETERS.md](SERVER_PARAMETERS.md). The P-256/single-retry lifecycle
and its additional transient memory are in [SERVER_RETRY.md](SERVER_RETRY.md).

After assembling the final ClientHello (including a second one if retry was
required), accept its tentative `Peer_Parameters`, then
call `server_handshake_start_flight(owner, store, admission_time)`. The host keeps
the store alive through owner teardown. This acquires one immutable credential
lease and checks leaf validity/KU/EKU/critical extensions at the explicit time.
Publication must establish the host's chain/identity policy; admission does not
verify ancestry, trust or hostname. Rotation/close cannot revoke this lease.

The restricted profile is TLS1.3/AES128GCM-SHA256 with X25519 or P-256 and RSA-PSS-SHA256
CertificateVerify and RSA 2048–4096 credentials. Each transmitted certificate's
parsed signature metadata must match `signature_algorithms_cert`, falling back
to `signature_algorithms` only when absent. This first chain policy supports
RSA PKCS1 SHA256/384/512 signatures only, including roots: other signatures are
`Unsupported`, even when X509 can parse them. It never assumes a compatible
chain from an RSA leaf. No key or PEM is copied/parsed per handshake.

One key-share HRR is supported; PSK/0-RTT is never selected. Retry state, CH2
invariants and zero-cookie policy are in SERVER_RETRY.md.
ALPN and mode-specific opaque QUIC parameters use an explicit pending-event
selection/acceptance API; see SERVER_PARAMETERS.md. Default callers keep optional
TCP/no ALPN. A QUIC binding must validate semantic parameters before selection;
there is no production QUIC transport here.

Drain events through repeated peek/copy/accept until None. The flight is SH
(with session-ID echo), handshake Write/Read secrets, selected-parameter EE, streamed
Certificate, context-separated RSA CertificateVerify, server Finished, then
application Write/Read secrets. Initial SH bytes must enter ordered transport
storage before installing handshake keys. Finished bytes must enter it before
application keys. Certificate headers, DER fragments and per-entry empty
extensions are distinct fragments of one exact message. A peek with no pending
event may produce one event, allocate scratch or synchronously sign; while an
event is pending, repeated peeks never advance or hash it again. Signing uses
OS entropy and is synchronous/non-preemptible; caller owns that latency policy.

Accepting the last application-secret event releases the credential lease and
erases the handshake/application schedules. The owner then enters its
Await_Client_Finished phase, retaining the client handshake secret and transcript
until client Finished authentication. Feed exactly one Finished at Handshake
level; its 32-byte MAC is checked in constant time against the accepted transcript
through server Finished and the client handshake traffic secret. No client
certificate authentication is requested/supplied. Possession of application
secrets or tentative peer offers never authorizes application delivery.

On successful verification and with every flight event accepted, the engine
wipes/frees handshake input/output grants, partial input, secrets and transcript,
then publishes one payload-free `Complete`. Owned selections remain queryable
as authenticated until Complete acceptance wipes/frees their separate grant.
Copy required durable state and accept
that event before the binding delivers application data. Complete is repeatably
peekable until accepted; stale/duplicate acceptance fails. No subsequent Complete
is generated. Engine146, independent matrix157 and
TCP147/QUIC98 remain open.

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

After flight drain, Finished accepts every header/body partition, using at most
36 bytes of the existing unborrowed output scratch; it allocates nothing. A wrong
type consumes its first byte; a wrong length consumes its four-byte header, never
the declared body. Wrong encryption level consumes zero and fails, including
empty input at a wrong level. A bad MAC consumes the complete message and reports
`Finished_Failed`. Correct input with any same-call suffix consumes through
Finished only, fails `Malformed`, and never publishes Complete: the entire call
has one encryption level, so that suffix is old-level data. Bindings must split
input at encryption-level boundaries, retain unconsumed bytes, and handle
Application-level input themselves.

Successful verification is terminal even while Complete awaits acceptance.
Subsequent nonempty feed (duplicate Finished, later old-level data or application
bytes) consumes zero and returns `Terminal/Invalid_State`; it cannot revoke or
repeat success. Empty terminal feed returns `Terminal/None`. Failed/aborted/
destroyed feed retains the existing terminal error. Pending pre-completion events
return zero/Need_Event_Drain; Await_Flight before flight admission returns zero/
Await_Flight. Neither accepts out-of-order input; resubmit only when eligible.

`Need_Event_Drain` means the pending event must be accepted before further
progress; pre-completion feed consumes zero while it is pending. `server_handshake_peek` returns
the same immutable payload/ID until acceptance or teardown. A repeated pending-event peek does not hash, allocate, erase or advance state. `server_handshake_accept(owner, id)` accepts
exactly one current nonzero ID; stale/duplicate/zero IDs are errors without side
effects. Feed after failure, abort or destruction consumes zero and returns
`Terminal`. A pending Fatal can still be peeked/accepted after failure; it never
permits later success. IDs saturate: exhaustion is terminal without a new event.

Event kinds reserve these producer/consumer contracts:

| Kind | Borrow and acceptance contract |
| --- | --- |
| `Handshake_Bytes` | Exact ordered handshake fragments including message headers, Initial/plaintext or Handshake level; no records/CCS. Copy into transport-owned ordered storage before acceptance. Accepted bytes enter the transcript exactly once. |
| `Traffic_Secret` | 32 bytes, AES128GCM/SHA256, explicit level and Read/Write relative to the local server. Derive/copy transport protection before acceptance; owner storage is immediately wiped. Key availability alone never authorizes application delivery. |
| `Peer_Parameters` | Tentative SNI, ALPN **offers** and opaque QUIC parameter presence/bytes from ClientHello. They are neither selected nor authenticated. Validate QUIC semantics before explicit selection/acceptance; copy any needed offer metadata before acceptance. |
| `Complete` | Once after valid client Finished and all required output acceptance; handshake transients are erased; owned selected parameters remain queryable until acceptance wipes/frees them. Copy durable state and accept before application delivery. |
| `Fatal` | Stable typed protocol/local error, without sensitive diagnostic payloads or implicit alert/transport handling. |

Every output borrow, including copied event structs, ends at accept/abort/destroy.
The private producer seam copies at most 2,048 bytes into reusable scratch or
borrows an immutable pinned certificate fragment. Shared DER is never wiped by
the owner. Its credential lease stays live through all DER borrows and is
released exactly once after the flight or during failure/abort/destroy. The seam has no public
injection API and refuses Complete even internally. Only the Finished consumer
can publish success after authentication. The flight producer enforces protocol
state/order.
Transport acceptance means local storage ownership, not peer acknowledgment.

## Limits and cleanup

Local policy, not TLS wire maxima: ClientHello 45–65,536 bytes including header,
1–128 extensions, fixed 2,048-byte copied-output cap. Input allocates exactly its
declared bounded message after header admission; output scratch allocates lazily
only when a producer needs it. There is no message/event queue or complete-flight
allocation. Both grants overlap when publishing SH; ClientHello storage is released once
SH has been copied and its staged handshake schedule derived. Full Certificate
wire overhead is checked against u24 bounds before any flight event. The
credential owner independently caps 16 certificates and 1 MiB summed DER; wire
overhead is additional. No full Certificate message/flight is concatenated.

Measured Darwin arm64 fixed owner: **1,224 bytes**; event value: **136 bytes**.
Without retry, optional TCP/no ALPN retains the two-grant **67,584-byte** maximum.
Selected parameters add one at-most **2,303-byte** grant retained through pending
Complete; the measured maximum overlapping grants without retry is **69,887 bytes**,
three allocations. Retry can retain two complete hellos plus scratch: **133,120
bytes**, three grants; see SERVER_RETRY.md. See SERVER_PARAMETERS.md for exact parameter bounds/lifetimes.
`server_handshake_stats` reports cumulative requested
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
registers, stack copies or consumer-owned material. Successful Finished
verification runs this same full cleanup before publishing
Complete, except for the owned selection grant retained until Complete acceptance;
after acceptance only identity, terminal phase, configuration and cumulative statistics
remain. Destroy also clears allocator/configuration. No resumption/exporter or
post-handshake authentication state is retained.

Run package lifecycle/fault tests with:

```sh
./odin test core/crypto/tls -warnings-as-errors -sanitize:address -out:/tmp/tls-owner-tests
./odin run tests/core/crypto/tls/server_owner -warnings-as-errors -sanitize:address -out:/tmp/tls-owner-consumer
```

Reviewed semantic references: [RFC8446 sections4 and4.4.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-4),
and [Go's serial QUIC TLS events and lifetimes](https://go.dev/src/crypto/tls/quic.go).
This API follows the local native-stack architecture; no Go implementation was copied.

Independent offline client gate (explicit locally installed Go source/toolchain):

```sh
python3 tests/core/crypto/tls/server_flight.py --odin ./odin \
  --go /path/to/go --go-root /path/to/go/root --sanitize address \
  --report /tmp/server-flight.json
```

It encrypts test-only records around public events and drives Go `crypto/tls`
over `net.Pipe`; no listener/production driver is supplied. Both RSA sizes and
16 padded certificates exercise split handshake headers, DER and CV, all four
secret events, and independently authenticated server output. The peer returns
its actual client Finished through a bounded anonymous pipe;
the native owner consumes it one byte at a time and must publish Complete before
the adapter permits bidirectional application exchange. No OpenSSL/non-Darwin
matrix or production
server claim follows; those remain157/147 gates.

The full independent Go/OpenSSL and sanitizer gate is documented in
[SERVER_VERIFICATION.md](SERVER_VERIFICATION.md). It records local capability
limits and does not provide a production record/async binding.
