# Immutable RSA credentials

`core:crypto/tls/credentials` owns a leaf-first certificate list and one native
RSA private key. It does not import its parent TLS package, create sockets, read
files, discover trust roots or start workers. X509 currently imports `core:net`
transitively for hostname verification helpers; constructing credentials invokes
no networking. This is a foundation for a server handshake, not a TLS server.

`create(chain_pem,key_pem,limits,allocator)` returns one opaque `^Credential` owner.
The PEM arguments are borrowed during that call; DER, X509 tables and normalized
key storage belong to the returned owner. Inputs may subsequently be changed or
released. Failure returns nil and erases/releases every owned allocation.
Construction checks certificate/key syntax and leaf RSA modulus/exponent matching.
It does not prove chain ancestry, signatures, trust, hostname, current validity,
CA policy or private-key primality. The input order is retained.

Accepted keys are unencrypted two-prime version-0 PKCS#1 (`RSA PRIVATE KEY`) or
PKCS#8 (`PRIVATE KEY`) with a 2048–4096-bit RSA modulus. Exactly one key is allowed;
other blocks, leading/trailing non-whitespace and encrypted keys fail closed.
Certificate blocks must be `CERTIFICATE`, with no intervening unrelated text.
The native X509/key parser profiles and limits also apply.

`certificate_count` and `certificate_der(index)` expose immutable borrows.
Odin's slice type cannot enforce constness: callers must not modify/free them.
`fingerprint` returns the SHA256 digest of the leaf DER by value, independent of
later borrow lifetimes. No mutable private-key pointer is exposed.

`destroy(&owner)` first clears the owning variable, then erases/releases all owned
storage. It is idempotent for that variable. Copied pointers are borrowed aliases,
not additional owners. The handle and allocator must remain alive/stable until
all signers and DER borrowers finish; destruction requires exclusive access.
Rotation/reference leases are deliberately a separate layer (OKAMI-145).

## Bounds and allocator contract

Zero limits select this fixed profile; explicit values may lower it only:

| Limit | Default and maximum |
| --- | ---: |
| Certificates | 16 |
| Sum of certificate DER bytes | 1 MiB |
| Encoded chain PEM bytes | 2 MiB |
| Encoded private-key PEM bytes | 96 KiB |
| Owned allocation bytes, including transient overlap | 4 MiB |

The native private-key DER importer additionally caps input at 64 KiB.
A stable owner contains 128 allocation records; exhausting this metadata also
returns `Storage_Limit`, independently of the byte limit. Allocation/free/resize
accounting is local to the owner, never a global allocator override. Resizes
allocate, copy, erase and release rather than relinquishing a dirty old block.
The peak charge includes the owner, retained DER/tables and temporary PEM blocks.
`storage_usage` reports retained and peak requested allocation bytes.

The backing allocator must provide distinct, correctly aligned, exact-size grants
and support frees for their lifetimes. Unexpected under/overgrants or error returns
with memory are rejected and the entire returned extent is erased/freed before
any typed access. The 4 MiB envelope covers accepted exact-size grants, not a
backing allocator's hidden arena reservations, metadata, internal alignment slack
or arbitrary memory it chooses to return outside its contract. Failed unusual
grants can temporarily exceed a request before rejection; their full extent is
still cleaned. Zero/error/nil-success returns fail without publishing an owner.

Erasure covers source-level owned heap ranges. It does not erase caller PEM,
external aliases, compiler/register copies or unrelated allocator memory.

## Policy and signing

`check_server_leaf(owner,now)` is a separate explicit admission check. It uses
inclusive notBefore/notAfter boundaries, requires DigitalSignature when KU is
present, requires ServerAuth or Any when EKU is present, and rejects unhandled
critical extensions. Absent KU/EKU impose no restriction. No ambient clock is
read. Time comparisons use signed nanosecond values directly to avoid subtraction
overflow at `time.Time` extremes; native X509 date saturation semantics remain.
A future handshake must call this at admission; constructor success is not a
policy verdict.

`sign_digest_pss_sha256` signs a SHA256 digest with RSA-PSS, SHA256 MGF1 and a
32-byte salt. Output is staged locally and copied only on success. Too-small
output or any overlap with owner/backing storage fails unchanged. Native RSA
reads the normalized key and uses per-call scratch, so concurrent calls with
distinct outputs are supported while the owner is immutable. No store lock or
per-connection key copy is added. Compile-time unavailable entropy returns
`Entropy_Unavailable`; catastrophic runtime OS entropy failures retain native
`core:crypto`'s panic policy.

Source-level fixed local arrays are 512 bytes for modulus extraction during
construction and 512+32 bytes for signing staging/digest, separate from the owned
allocation budget. These are not complete compiled/transitive stack bounds;
X509/RSA/PEM routines and compiler/sanitizer frames add their own stack usage.

## Local verification

From an Odin checkout containing this package:

```sh
odin test core/crypto/tls/credentials -sanitize:address -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true -define:ODIN_TEST_THREADS=1
python3 tests/core/crypto/tls/credentials/concurrency.py --odin /path/to/odin --go /path/to/local/go --report /path/to/report.json
python3 tests/core/crypto/tls/credentials/concurrency.py --odin /path/to/odin --go /path/to/local/go --sanitize thread --report /path/to/report-tsan.json
```

Six tests cover ownership, every fixture allocation failure position, unusual
allocator grants/full wiping, exact peak limits, 16/17 certificate bounds, malformed
profiles, explicit leaf policy and output/alias contracts. Independent Go and
OpenSSL verify 8 workers × 8 native signatures for each of 2048/4096 bits under
ASan and TSan. Fixtures are synthetic public test keys, not service identities.
Executable evidence is Darwin arm64; Linux arm64 is semantic checking only.
No performance, complete TLS interoperability or production trust claim follows.
