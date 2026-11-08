# Native TLS server acceptance contract

The server backend is native Odin in core:crypto/tls, selected by the shared
native-network-stack architecture. core:crypto/tls/credentials owns immutable
bounded RSA/P-256 snapshots; credentials/store publishes bounded generations
and leases; Server_Handshake owns recordless TLS1.3 handshake state/events;
Server_Async_Conn adapts those events to an existing asynchronous TCP connection
and caller executor. Existing client/blocking APIs are retained. No runtime
OpenSSL/library binding, new I/O owner, thread or per-connection stack is added.

These are separate owning APIs with explicit allocator/lifetime contracts:

- [Credentials](credentials/README.md) and [ECDSA](credentials/EC.md): strict key
  import, matching leaf metadata, explicit time/KU/EKU admission, immutable
  signing, caller-controlled provisioned chain/identity policy and complete
  owned-grant release. Construction does not establish chain trust/hostname.
- [Store](credentials/store/README.md): success-only publication, bounded retired
  generations, independently live leases and safe replacement/close. A retired
  generation remains pinned through accepted server output and verified client
  Finished, or terminal cancellation/failure/destroy.
- [Handshake](SERVER_HANDSHAKE.md): consumed-prefix feed, bounded ClientHello/
  retry/output/parameter grants, one ordered stable event, explicit directional
  traffic secrets and encryption levels, Complete only after Finished. It has
  no TCP record/socket/executor coupling. QUIC reassembly/packets/semantic
  transport parameters remain the transport binding's responsibility.
- [Async TCP](SERVER_ASYNC.md): zero-I/O/zero-allocation constructor, stable-address
  serial owner, caller executor, deferred operations, one read/write overlap,
  bounded lazy record/crypto grants, total handshake deadline/cancellation,
  terminal partial writes/no replay, resumed partial reads, ordered KeyUpdate,
  authenticated close versus truncation and explicit final close callback.

## Algorithms and certificate admission

The implemented profile is TLS1.3/AES128GCM-SHA256, X25519/P-256 key exchange,
one stateful key-share retry, RSA-PSS-RSAE-SHA256 or P-256-ECDSA-SHA256
CertificateVerify, and bounded opaque ALPN. Authentication completes only after
verified client Finished. Resumption/0RTT, tickets and client authentication are
not supplied. No protocol is inferred for HTTP clients/servers by this layer.

CertificateVerify's scheme must be offered and match the pinned private key.
Certificate signatures separately use signature_algorithms_cert, falling back
to signature_algorithms only when absent. The conservative full-chain policy
(including transmitted roots) permits RSA PKCS1 SHA256/384/512, ECDSA-SHA256 with
a supplied P-256 issuer, and RSAE-PSS-SHA256 with a supplied RSA-encryption issuer.
For PSS, immutable parsed metadata must name SHA256, MGF1-SHA256 and salt32;
X509 validates DER framing/trailer before owner publication and requires NULL or
absent parameters on both PSS hash AlgorithmIdentifiers (including the MGF hash). An unknown/other
MGF becomes an unsupported digest. Public metadata is returned by value and
never reparses DER or exposes private-key storage. Other parameter/hash/key
profiles remain Unsupported even when a lower-level X509 verifier supports them.

The final certificate must have a compatible own key algorithm under this
conservative policy; provision the full issuer chain. Issuer ancestry/signatures,
trust and hostname remain the host's provisioning policy and the peer's
verification responsibility, not a claim made by the metadata check. The
independent harness trusts only the final issuer root of a real chain and
requires a verified path to it; a tampered leaf signature must be rejected.
It does not turn the served leaf into a trust anchor. PSS-SPKI/private keys and
additional PSS digests are separate capability increments.

## Evidence and limits

Run the combined [verification gate](SERVER_VERIFICATION.md) with both address
and thread sanitizers. It runs59 core,1 PSS-parameter/44 public X509,11 credential,10 store,23 native-client
and22 Surf tests;27 recordless independent peers;83 actual async TCP cases
(51Go/32OpenSSL);192 concurrent signatures verified by each independent client;
public owner and isolated empty/Surf executable consumers. Reports record actual
compiler digest/version, matching toolchain, peer versions, counts and memory.

PSS cases cover RSA/ECDSA leaves signed by a separate PSS-SHA256 RSA issuer,
root-only trust, P-256/retry/KU/fragmented traffic, exact remote handshake_failure
for unsupported salt/hash/MGF/issuer/offers, and independent rejection of an
altered certificate signature. Go requires typed UnknownAuthorityError for that
signature failure; OpenSSL requires certificate-signature-failure code7. Invalid
PSS parameter DER fails credential construction with complete grant erasure.

Measured local Darwin arm64 owner/grant bounds are unchanged: credential11216,
recordless1224/event136, async2736/key grant2112 bytes; recordless maximum retry
133120 accepted bytes, connection maximum retry plus record buffers166410;
default/hard async budget262144. Shared immutable credential DER/tables have
separate explicit caps and are excluded from per-connection grants. Heap erasure
does not promise caller-input, allocator-metadata, compiled/transitive-stack,
register or RSS erasure. Crypto runs synchronously and cannot be preempted in a
signature; callers own admission/concurrency and that latency.

This completes the native server/credential lifecycle and reusable handshake
milestone. It does not certify general TLS compliance, non-Darwin execution,
formal crypto/security review, exhaustive fuzzing, throughput, HTTP integration,
QUIC packets or application vendored copies. Those retain their separate gates.
Primary signature-policy reference: [RFC8446 section4.2.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3)
and [section9.1](https://www.rfc-editor.org/rfc/rfc8446#section-9.1).
