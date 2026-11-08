# TLS 1.2 compatibility primitives

These additions are prerequisites for native client compatibility. `Conn`, its
TLS 1.3 offer, authentication, async executor and application behavior remain
unchanged. There is no complete TLS 1.2 client or server here. In particular,
Hello negotiation, PRF vectors and record authentication do not establish an
end-to-end authenticated connection. Surf's legacy adapter remains in place.

The separate `TLS12_*` types prevent confusing TLS 1.2 explicit-nonce/AAD records
with TLS 1.3 inner-content records. The bounded pure Hello profile offers fresh
ECDHE_RSA/ECDHE_ECDSA with AES128-GCM/SHA256, X25519/P256, SHA256 signatures,
secure renegotiation signaling, extended master secret (EMS), and optional ALPN.
It offers no tickets, resumption or renegotiation. ServerHello parsing checks
framing, offered cipher/extensions, EMS, initial renegotiation binding and ALPN;
returned session/ALPN slices borrow immutable wire storage. When a future owner
sets `tls13_offered`, either RFC8446 downgrade sentinel is rejected. A failed
TLS 1.3 connection must never cause a reconnect/replay as TLS 1.2.

This deliberately limited profile is not proof of every legacy provider cipher,
certificate or protocol combination. A dual-version driver must additionally
handle TLS 1.3 group/signature capabilities, HRR transcript rules, and coalesced
TLS 1.2 plaintext handshake messages. Existing TLS 1.3 codecs are not relaxed.

SHA256 PRF inputs and output are finite and allocation-free; invalid bounds or
source/output aliases preserve storage. Helpers implement legacy master-secret
vectors, EMS, AES-GCM key expansion and role-specific Finished. The legacy
master-secret helper does not authorize non-EMS negotiation. Owners must erase
returned secret/key material. Independent HMAC/OpenSSL references and a published
Botan SHA256 PRF vector check the schedule.

Record directions own an AES-GCM state, four-byte salt and monotonic sequence.
Sender explicit nonce is the network-order sequence; receiver authenticates with
its local sequence and the actual peer nonce. AAD includes sequence, content type,
TLS1.2 version and plaintext length. Plaintext is bounded to16KiB; a conservative
2^24-record limit prevents key overuse/wrap. A direction cannot be copied/shared
or reinitialized under the same key/salt. Local output-size/alias failures are
retryable; malformed/authentication failures erase and poison the direction.
Tag failure exposes no plaintext. TLS1.2 alert messages may be fragmented or
coalesced; record plaintext is authenticated before a future bounded driver
reassembles two-byte alert messages. No CCS/renegotiation processing is implied.

Tests cover independent Go AES-GCM records (including non-sequence peer nonce),
record/header/ciphertext/tag tampering, replay, zero/max plaintext, sequence/key
limits, failure erasure, alias rejection, short inputs and Hello extensions.
Offline OpenSSL MemoryBIO peers independently exercise RSA/ECDSA and X25519/P256
Hello negotiation; that probe stops before certificate/Finished authentication.
Darwin sanitizer results do not certify Linux runtime or full legacy parity.

References:
- https://www.rfc-editor.org/rfc/rfc5246.html (PRF, records and handshake framing)
- https://www.rfc-editor.org/rfc/rfc5288.html (AES-GCM nonce and key layout)
- https://www.rfc-editor.org/rfc/rfc5289.html (ECDHE AES-GCM cipher suites)
- https://www.rfc-editor.org/rfc/rfc5746.html (secure renegotiation signaling)
- https://www.rfc-editor.org/rfc/rfc7627.html (extended master secret)
- https://www.rfc-editor.org/rfc/rfc8422.html (ECC negotiation)
- https://www.rfc-editor.org/rfc/rfc8446.html (downgrade sentinels)
- https://www.rfc-editor.org/rfc/rfc9325.html (modern TLS usage and key limits)
