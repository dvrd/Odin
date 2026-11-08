# Native server verification gate

Run the owned independent-peer, lifetime and memory gate from the Odin checkout:

```sh
python3 tests/core/crypto/tls/server_verification.py --odin ./odin \
  --go /path/to/installed/go --go-root /path/to/matching/go/libexec \
  --openssl /path/to/openssl --sanitize address --report /tmp/server-verify-asan.json
```

Repeat with `--sanitize thread` for the thread sanitizer. Both commands require
permission for test-owned loopback listeners. Compilers/Go/OpenSSL development
files and pkg-config must already be installed; no downloads or live endpoints.
Use the matching compiler/standard-library/LLVM pairing in ci/WEBTOOLS_TOOLCHAIN.md.
All binaries, generated public certificates, pipe/file exchanges and reports use
temporary storage. Existing credentials are published fixture keys only.

The gate runs the59-test core server package (including deterministic hello
mutation/transcript, fragmentation/coalescing, allocator failures and complete-
grant erasure),1 private PSS-parameter/44 public X509 tests,11 credential/10 store tests,23 native client tests,22 Surf tests,
the public owner consumer,
27 recordless Go/OpenSSL peers,83 actual async TCP peer cases,192 concurrent
signatures independently verified by both Go and OpenSSL, and empty/isolated Surf
executable consumers. It
records commands, full outputs, return codes, sanitizer, compiler digest/version,
client versions and measured owner/event/retry-grant sizes. A missing memory
measurement or failed subprocess fails the gate; failed gates retain a report
with passed=false. There is no passing skip for a missing client/compiler.

The async server adds eleven core tests; its actual TCP wire gate and measured
connection budget are documented in [SERVER_ASYNC.md](SERVER_ASYNC.md).
The recordless peer fixture remains separate from that driver; the full gate
runs both plus RSA/ECDSA immutable credential checks.

The peer-only command remains available as server_flight.py. Without --openssl
it runs16 Go cases; with an explicit --openssl it also runs11 OpenSSL cases.
The full verification gate requires OpenSSL. Go crypto/tls is driven through
net.Pipe and a bounded record fixture. OpenSSL s_client connects to one owned
127.0.0.1 ephemeral listener per case; one small OpenSSL C client sets an explicit
1,049,088-byte certificate-message cap for the padded16-certificate fixture.
That helper uses OpenSSL's own verification, hostname/time policy, handshake,
record encryption/decryption and shutdown APIs. It implements no cryptography.
The adapter uses native public handshake events and shared fixture record helpers;
it is synchronous test code, not TCP driver147 or an async server API.

Positive cases cover RSA2048/4096,16 padded certificates, X25519/P256, one retry
to either group, ALPN, native verified client Finished/Complete, all four traffic
secret directions through independently encrypted records, and bidirectional
application exchange. Go adds binary opaque ALPN, selected ALPN after retry,
actual altered Finished rejection (with/without retry), and recordless QUIC TLS
handoff with opaque parameters. No QUIC packets or semantic transport-parameter
validation is supplied. TLS1.3 and AES128GCM-SHA256 are forced; no PSK/0RTT.

Both independent clients reject wrong trust, hostname, expired and not-yet-valid
certificates. Go requires matching typed X509 errors; OpenSSL requires nonzero
exit plus exact verification codes18/62/10/9. Rejection aborts the native owner
without Complete/application delivery and asserts zero grants/credential leases.
Only negative fixtures permit OpenSSL4's observed cleartext fatal verification
alerts. Positive fixtures require authenticated encrypted Finished and application
records; this accommodation does not relax a production record adapter.

Handshakes use deterministic record cuts across message headers/DER/CV and
byte-at-a-time native ClientHello/Finished input, with all CH2 splits, coalesced
suffixes and changed transcript/MAC positions in core package tests. Failure and
cancellation audit full reported allocator grants, including unusual grants,
plus stable event identity and credential pins. A finished-lifetime regression
retains one retired credential generation through client authentication, then
requires exact release on success, bad MAC, abort, destroy or wrong level. This is bounded deterministic
coverage rather than exhaustive fuzzing or a complete crypto/security review.

The adapter performs its own close_notify exchange and tears down listener,
connection and child processes. Per-connection I/O/accept deadlines are15 seconds,
OpenSSL/native child contexts20 seconds, and harness subprocesses120 seconds.
Large-chain verification requires a cap above OpenSSL s_client's default; that
initial refusal and the diagnosed OpenSSL4 shutdown wait are recorded in the
implementation report, not hidden by a smaller chain or skipped case.

Measured Darwin arm64: owner1224/event136 bytes; retry133120 maximum accepted
simultaneous grant bytes/three grants. Parameter storage≤2303, copied output≤2048,
per-hello wire≤65536, and DER is pinned/shared under independent credential caps.
Successful Finished erases handshake transients; selected parameter bytes stay
owned only until Complete acceptance. Live bytes and leases then return to zero.
Shared credentials, allocator metadata, record-fixture buffers, compiled/transitive
stack/register copies, RSS and consumer copies are outside engine measurements.

This verifies the restricted RSA-PSS/P-256 ECDSA server engine and async TCP
binding on the recorded local platform. It does not certify non-Darwin execution,
throughput, client certificates, resumption, stateless cookies or QUIC binding.
Engine146's restricted-engine acceptance audit is recorded in
reports/webtools-engine-2026-11-07.md. The async TCP binding also has a standalone gate;
The parent96 acceptance audit is documented in [SERVER_BASELINE.md](SERVER_BASELINE.md).
PSS-SHA256 certificate admission is tested through real RSA/ECDSA leaf chains
with issuer-root-only trust. Both clients reject tampered chain signatures, and
unsupported salt/hash/MGF/issuer/offer profiles fail before application delivery.
QUIC98 still requires transport integration; general TLS compliance requires
its own protocol/policy/platform audit.
