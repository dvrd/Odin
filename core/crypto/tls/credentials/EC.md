# P-256 ECDSA credential profile

The immutable credential API supports RSA2048–4096 or P-256 ECDSA, one key per
snapshot. `Signature_Scheme` uses typed wire IDs0x0804/0x0403. Call
`signature_scheme(owner)` (or its lease forwarding procedure) to identify the
credential; the engine must also require the matching ClientHello offer. A
scheme selected from client offers alone does not identify a private key.

## Strict key import

SEC1 version1 (`EC PRIVATE KEY`) requires named P-256 parameters. Version0 PKCS8
(`PRIVATE KEY`) requires id-ecPublicKey with named P-256 parameters in its
AlgorithmIdentifier; its inner SEC1 may omit parameters. Any inner parameters
must agree. Private scalar is exactly32 unsigned big-endian bytes and must be
nonzero and strictly less than the order. The existing native
`ecdsa.private_key_set_bytes` performs scalar validation and point derivation.
No curve arithmetic, custom nonce generation or replacement signer is added.

An optional inner public point must exactly equal the native derived65-byte
uncompressed point. The leaf certificate must contain that same point and the
P-256 algorithm. Compressed/infinite/off-curve/mismatched points therefore fail.
The DER cursor enforces canonical lengths/integers and exact consumption at each
level. Attributes, extra fields/duplicates/trailing data, wrong versions,
explicit/absent/wrong curve profiles, other EC curves and encrypted keys are
rejected. Overall key DER retains the64KiB bound; inner SEC1 is at most512 bytes.
PEM/chain/count/storage limits and success-only owner publication remain shared
with RSA. Input PEM is borrowed during construction and is not erased by us.

## Signing and policy

`sign_sha256(owner, scheme, message, out)` hashes message once with SHA256 using
the existing native RSA-PSS or ECDSA signer. This message API deliberately avoids
passing an already-hashed digest to ECDSA's message-hashing primitive. The legacy
`sign_digest_pss_sha256` retains its RSA behavior and rejects EC keys.
ECDSA requires at least72 output bytes, stages the raw64-byte signature and
canonical DER locally, then copies only the successful DER length (at most72).
The encoding is SEQUENCE of minimally encoded positive INTEGER r and s, including
leading sign padding when required. Unused output bytes remain unchanged.
Failure never publishes partial output. Owner/grant aliases are rejected.

Signing reads the immutable native key and uses distinct per-call scratch; no
key copy per connection, owner mutation, allocation, lock across crypto or store
rotation race is introduced. The live lease pins the exact admitted generation
through Finished; scheme identity is queried from that lease again after the
hello/selection storage is erased. RSA/ECDSA publication may alternate while
old leases continue signing. A stale/released lease cannot sign.

Production always requests native hedged RFC6979 ECDSA with OS entropy. There is
no deterministic-mode API or silent fallback. Compile-time unavailable entropy
returns Entropy_Unavailable before signing; catastrophic runtime entropy failure
retains core:crypto's panic policy, as RSA does. Tests exercise malformed input,
all actual allocator failure positions and invalid scheme/output/lease paths;
they do not claim to inject an OS entropy outage. Cryptography is synchronous
and nonpreemptible. Concurrent calls need distinct output and a live owner/lease.

## Representation and evidence

Before selection the RSA-only owner measured11208 bytes, native RSA key2416,
native EC key224. A raw union reuses the prepaid2416-byte key slot; a typed
scheme adds eight bytes including padding, for11216 total. This retains RSA's
one-owner allocation/offset model and bounded metadata while avoiding an extra
key allocation; EC intentionally pays for the unused RSA capacity. Shared
credentials are not per-connection TLS owners. P-256 fixture retained11776/peak
12355 bytes; RSA2048 retained12149/peak14355; RSA4096 retained12661/peak17427.
All accepted heap grants, including rejected abnormal grants, are fully erased
before release. Fixed raw/DER signature arrays are explicitly erased. Native
transitive stack/register copies and caller inputs remain outside that guarantee.

Ten credential tests cover both formats, exact budget boundaries, unusual grants,
zero/order/oversized scalars, malformed points, strict SEC1/PKCS8 profiles,
message/signature mutation and alias/output contracts. Nine store tests include
cross-algorithm rotation and signing after publication close through live leases.
The concurrency fixture runs8 workers x8 signatures for each of RSA2048/RSA4096/
P-256; both independent Go and OpenSSL verify every signature. Actual async TCP
coverage includes26 ECDSA Go/OpenSSL cases (61 total), ECDSA-only OpenSSL offers,
authentication, retries, KU, fragments, concurrent sessions and rotation. The
full [server gate](../SERVER_VERIFICATION.md) records toolchain and sanitizer
receipts. The fixture key scalars1/2 are deliberately public test keys.

Primary encoding/protocol references: [RFC5915](https://www.rfc-editor.org/rfc/rfc5915),
[RFC5480](https://www.rfc-editor.org/rfc/rfc5480),
[RFC8446 section4.4.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3), and
[section9.1](https://www.rfc-editor.org/rfc/rfc8446#section-9.1).
The required P-256/ECDSA capability is added. The conservative server chain
policy still rejects RSA-PSS certificate signatures; full section9.1 admission
and general TLS compliance remain separate audit work. No platform, trust-policy
or production application certification follows from this capability.
