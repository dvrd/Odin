# Bounded server P-256 and key-share retry

The recordless server supports X25519 and secp256r1/P-256 with the existing
AES128GCM-SHA256/RSA-PSS-SHA256 credential profile. Server preference is X25519,
then P-256, independent of the order of client groups. A missing share for the
preferred mutually supported group produces exactly one key-share
HelloRetryRequest. An unusable supplied share fails; it never triggers a retry.
Client APIs retain their earlier X25519 profile. ECDSA credential import/signing
is separate158; this capability is not a full TLS baseline-compliance claim.

The pure hello codec returns a borrowed selection with group and no share for
Retry_Required; the recordless owner drives the actual retry. P-256 shares must
have65 bytes and uncompressed prefix4; native ECDH subsequently validates the
point/identity/shared-secret. Production key generation uses existing native
ECDH pointer APIs and system entropy. Private/public curve unions stay transient
on the execution stack and are explicitly cleared; none is copied by value at
the handshake call sites or stored in the owner. No custom curve arithmetic or
large per-connection union was added.

After complete CH1, no Peer_Parameters event is published yet. Instead the owner
replaces CH1's transcript contribution with the synthetic message_hash and emits
one Initial Handshake_Bytes event containing HRR (56–88 bytes, including session
ID echo). Repeated peek is stable. Copy into ordered transport ownership before
acceptance; acceptance hashes HRR once, wipes scratch and opens Initial input for
CH2. Premature CH2 is backpressured; start_flight is invalid until final tentative
peer parameters are accepted. No credential lease is acquired for HRR.

CH1's immutable wire grant remains pinned while CH2 is copied using the usual
bounded header/message accumulator. The unconsumed suffix remains caller-owned.
Every CH2 split is supported; caller input may be overwritten after feed returns.
Wrong levels fail before consuming input; oversized headers fail before allocating
a body. The same per-message45–65536-byte and extension/count limits apply.

CH2 must preserve legacy version, random, session ID, ciphers, compression and
all unchanged extensions/data/order, including unknown extensions, ALPN, SNI,
QUIC parameters and signature offers. Its key_share must contain exactly one
entry for the requested group; missing/wrong/additional shares, another retry,
malformed points/lengths or changed offers fail. Permitted changes are the new
requested key share, removal of early_data, zero padding changes, and PSK binder/
age updates plus removal of incompatible-hash identities. PSK identities retain
order and exact identity bytes; compatible32-byte binders cannot disappear, and
retained binder lengths cannot change. Non32-byte binders may be removed for the
selected SHA256 suite. Binders are never authenticated or selected in this full
certificate-handshake profile. Added/renamed/reordered PSKs fail. Early data is
always rejected and must be absent from CH2.

This is a stateful key-share retry with a **zero cookie budget**: it emits no
cookie and rejects unsolicited cookie extensions on CH1/CH2. Zero padding is
validated by the codec; nonzero padding is malformed. No stateless retry, cookie
provider or reachability/anti-amplification guarantee is supplied. Future protocol
extensions that permit different CH2 changes need their own explicit policy;
unknown extension mutations currently fail. There is no arbitrary CH2 mutation
or second HRR path.

On valid CH2 the owner frees/erases CH1, hashes CH2 once and publishes the sole
tentative Peer_Parameters event. The normal parameter selection, pinned flight,
secret and Finished interfaces then apply. ServerHello uses the same group and
cipher as HRR. HRR/CH2/SH/EE/certificates/CV/Finished all contribute to the accepted
transcript. Native Finished and Complete are still required before application
delivery. A third hello cannot start another handshake in this owner lifetime.

The persistent owner remains **1224 bytes** and events136 on Darwin arm64.
The152-byte application-secret slot is a raw union with the16-byte retained-CH1
slice, with mutually exclusive phases. It is cleared before credential flight
use. Maximum accepted overlapping retry grants measured **133120 bytes**, three
allocations (65536 CH1+65536 CH2+2048 existing scratch). After CH2, the ordinary
input/parameter/output maxima apply; an ALPN selection can add another cumulative
allocation after the first grant is freed, without increasing simultaneous grant
count. Full grants are erased on failure, cancellation, identity exhaustion and
destruction. The shared failure publisher preserves an already published Fatal
and its ID, including the last available ID, rather than cleaning/publishing twice.

Measurements exclude shared credentials, allocator metadata, compiled/transitive
stack/register copies and caller storage. Maximum input/transient storage increased
for retry; fixed owner storage did not. No platform/throughput certification follows.
Independent Go clients verify P-256, both retry groups, selected opaque ALPN after
retry, altered real Finished rejection, all directional secrets and application
exchange. Go1.26 uses a fixed curve preference ordering, so fixture retries use
supported hybrid offers without a share for the requested classical group. The
native server does not negotiate those hybrid groups.

References: [RFC8446 sections4.1.2–4.1.4](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2),
[message_hash section4.4.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.1),
[key shares section4.2.8](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8).
