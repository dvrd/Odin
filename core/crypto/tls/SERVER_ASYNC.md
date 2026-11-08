# Lean asynchronous TLS 1.3 server

`Server_Async_Conn` binds the restricted recordless server to an existing
`net.Async_Connection` and caller-owned `net.Async_Executor`. It uses no thread,
scheduler, blocking network call, second socket owner, client `Conn` or ticket
array. Client APIs remain unchanged. Cryptographic work runs synchronously on
the executor thread and is not preemptible; admission/concurrency policy belongs
to the caller. This is a bounded native implementation, not a throughput or
cross-platform certification.

## Ownership and calls

1. Accept a transport, initialize its async backend (for example
   `nbio.TCP_Async_Connection`), and zero a stable-address `Server_Async_Conn`.
2. Call `server_async_server(&conn, underlying, executor, config, allocator)`.
   Set `config.store` to the credential store. Initialization performs no I/O or
   allocation. Success transfers transport ownership; failure leaves both owner
   and transport untouched. Copies of an initialized owner are invalid.
3. Submit `server_async_handshake(&conn, &operation, deadline)`, using a
   caller-owned `Server_Async_Handshake_Operation` with a callback. Successful
   submission receives exactly one deferred callback. Failure details appear in
   `operation.result` and `server_async_failure`. Rejection receives no callback.
4. After authenticated completion, use `server_async_connection(&conn)` with
   `net.async_read/write/cancel/close`. One read and one write may overlap.
   Additional operations in a direction are rejected. Query authenticated
   borrowed metadata with `server_async_connection_state`; copy it before close.
5. Submit close even after terminal failure and keep running the executor until
   its callback. Only that callback may free the connection owner. Other
   callbacks may submit operations but must keep owner/backend alive.

All calls/callbacks run serially on the executor thread. The executor must defer
scheduled work, and the transport must honor accepted operation deadlines,
cancellation, eventual exactly-once callbacks and close/release semantics from
`core:net`. Keep backend, executor, allocator and store alive through close;
keep operations and application buffers alive through their callbacks. ALPN
preferences borrow through handshake completion. A caller-provided credential
clock is explicit; zero reads the actual host clock at admission.

The driver pins the admitted credential generation through accepted server
output and verified client Finished. Replacement can retire that generation
while it is pinned; success, malformed input, cancellation, deadline and close
release the lease once. Credential parsing/storage has separate caps and
allocator ownership; per-connection stats do not include shared credentials.

## Bounds and records

On the measured Darwin arm64 toolchain the inline owner is2736 bytes, containing
the1224-byte engine. Crypto state is one lazy2112-byte grant, holding only active
read/write protection and two application secrets. Lazy record grants are16645
bytes for received ciphertext,16640 for plaintext, and16645 for transmitted
ciphertext. They are reused and fully erased on reuse/release. Initialization
has zero grants. The engine's assembled hello/scratch/parameters are charged to
the same explicit connection allocator budget. Accepted short, oversized or
error-bearing allocator grants are rejected, erased over their full reported
extent, and returned to the backing allocator.

`max_owned_bytes` defaults to262144 and accepts1024..262144. The measured maximum
65536-byte CH1 plus65536-byte CH2 retry and record buffers peaks at166410 bytes;
a166409 budget rejects that path. The established grants total52042 bytes.
`server_async_stats` reports actual accepted live/peak bytes and allocation
attempts; its nested engine counters are a subset, not additional memory.
Allocator metadata, caller/backend storage, stack/register copies, shared
credentials and RSS are outside this grant count. This is a per-connection
budget, not a process-wide admission limit.

The default total handshake budget is10 seconds; an absolute supplied deadline
can shorten it. It is checked between bounded crypto/actions and forwarded to
I/O. CPU work cannot be interrupted mid-signature. Handshake records default to
4096, configurable1..65536. Engine hello/extension limits retain their own caps.
Each pump consumes at most32 in-memory handshake events before yielding.
Application operations use absolute deadlines; zero disables those deadlines.
Post-handshake control/empty records are capped at1024 between application
payload deliveries. One fixed5-byte accumulator accepts only KeyUpdate.

Partial read cancellation/timeout retains ciphertext/header fragments for the
next read. A complete authenticated record wins a transient cancellation race.
Other transport errors remain visible on the next read. Raw EOF without an
authenticated close_notify is terminal truncation. Partial encrypted writes
are terminal and never retried; reported application counts include only whole
records. Complete wire writes win cancellation/timeout races.

Handshake secrets have role-correct directions. Server write protection changes
to application keys immediately after its Finished is accepted on the wire,
including fatal alerts. Client read protection stays at handshake level through
verified client Finished; application API readiness waits for Complete. KeyUpdate
is sent under old keys before advancing the write epoch. Received updates
advance only read keys; requested replies share the ordered writer. Use
`server_async_key_update(&conn, request_peer)` for a bounded control request;
completion/error belongs to the connection. The last allowed old-key record is
reserved for automatic key update before further application writes.

Close cancels/drains pending I/O. An idle established writer attempts close_notify
under `close_timeout` (default1 second); an interrupted writer aborts without
another record. Close does not await peer close_notify. Protocol failures may
attempt one typed fatal alert under the same finite budget when the writer is
idle; transport failures/partial writes never replay ciphertext. Automatic
failure cleanup closes the transport and erases grants; an explicit close
callback still defines when callers may free the owner. If a backend rejects
close synchronously, that error is returned and the backend retains responsibility
for releasing its resource according to its own contract.

## Profile and verification

TLS1.3, AES128GCM-SHA256, X25519/P256, one stateful key-share retry, RSA-PSS/P-256 ECDSA
credentials and bounded server-preferred ALPN are supported. TCP rejects QUIC
parameter configuration/presence and early_data. No resumption,0RTT, tickets,
client authentication, renegotiation or automatic
connection pooling is supplied. QUIC consumes recordless events separately.

Run the actual async TCP gate from the checkout:

```sh
python3 tests/core/crypto/tls/server_tcp.py --odin ./odin \
  --go /path/to/go --go-root /path/to/matching/go/libexec \
  --openssl /path/to/openssl --sanitize address --report /tmp/server-tcp-asan.json
```

Repeat with `--sanitize thread`. Installed offline Go, OpenSSL development files,
pkg-config, clang and permission for owned ephemeral loopback listeners are
required. No external network endpoint or downloaded dependency is used. The
optional `--case` prefix is for diagnosis; acceptance requires all83 cases with
no filter. Reports retain passed=false on failure and record compiler digest,
client versions, per-session memory/leases and exact peer outcomes.

The51 Go and32 OpenSSL cases cover independent authentication, RSA2048/4096/P-256 credentials,
16 padded certificates, both groups/retries,40KiB in both directions, ALPN,
key updates in both directions, concurrent8 sessions on one executor,
fragmentation/backpressure, credential rotation during outstanding server output,
malformed records, bad encrypted Finished, EOF/deadline/cancel/active close and
exact trust/hostname/time/ALPN rejections. Rotation uses an explicit45-second
fixture handshake budget for eight serial sanitizer-instrumented RSA4096 signs;
the production default remains10 seconds. Every close asserts zero owned bytes
and final store disposal asserts zero leases/generations. The eleven async core
tests additionally audit unusual/failing allocations, partial writes, callback
owner destruction, exact retry budget, control/nonce boundaries and secret
erasure. Run them with the existing [verification gate](SERVER_VERIFICATION.md)
which also preserves native client/Surf and isolated consumer checks.

Evidence is restricted to the recorded local toolchain/platform. Broader HTTP
server adoption, QUIC transport integration and application vendored
copies require their own work and validation.

PSS-SHA256 certificate chains require SHA256/MGF1-SHA256/salt32 and supplied
RSA-encryption issuer keys; certificate and CertificateVerify schemes are
validated separately. The22 PSS additions exercise separate issuer-only trust,
RSA/ECDSA leaves, groups/retry/KU, fragments, wrong salt/hash/MGF/issuer/offers
and tampered signatures. See [SERVER_BASELINE.md](SERVER_BASELINE.md).
