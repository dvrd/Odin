# Recordless server verification gate

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

The gate runs the45-test core server package (including deterministic hello
mutation/transcript, fragmentation/coalescing, allocator failures and complete-
grant erasure),23 native client tests,22 Surf tests, the public owner consumer,
independent Go/OpenSSL peers, and empty/isolated Surf executable consumers. It
records commands, full outputs, return codes, sanitizer, compiler digest/version,
client versions and measured owner/event/retry-grant sizes. A missing memory
measurement or failed subprocess fails the gate; failed gates retain a report
with passed=false. There is no passing skip for a missing client/compiler.

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
plus stable event identity and credential pins. This is bounded deterministic
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

This verifies the current restricted RSA-PSS server engine on the recorded local
platform. It does not certify non-Darwin execution, throughput, ECDSA credentials,
client certificates, resumption, stateless cookies or production TCP/QUIC bindings.
Engine146's rollup requires its own acceptance audit;147/98 and broader96 remain
open until their bindings/integration gates pass. ECDSA158 remains separate before
a general TLS baseline-compliance claim.
