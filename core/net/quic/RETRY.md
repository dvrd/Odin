# QUIC Retry address-validation tokens

`Retry_Tokens` is a bounded synchronized owner for one current and one previous
32-byte authentication key. Applications provide random secret bytes, a key ID,
maximum token age in Unix seconds and nondecreasing current Unix time to
`retry_tokens_init`. Keep the initialized owner at a stable address; do not copy
it. `retry_tokens_rotate` retains the prior key for one maximum-age interval.
A second rotation evicts the older key, so rotations must be spaced if all issued
tokens must remain valid. `retry_tokens_destroy` erases both keys. Destroy only
after listeners borrowing the owner have stopped.

`retry_token_issue` writes an authenticated versioned token carrying the original
destination CID, Retry source CID, issue time and key ID. HMAC-SHA256 uses a
QUIC/Retry/version domain separator and authenticates the exact peer address
family, address and UDP port as well as the public token metadata. The token is
opaque to clients but is not encrypted; the CIDs and timestamp are public, and
the peer address is authenticated without being encoded into the token.

`retry_token_open` verifies authentication, expected Retry source CID, clock,
expiry and key validity before returning `Retry_Claims`. It rejects rollback and
future timestamps, wrong endpoint/port/family, unknown or evicted keys, malformed
lengths and modified CIDs. No unverified claim is returned. Tokens are at most
91 bytes; original destination CIDs are 8–20 bytes, Retry source CIDs 1–20 bytes.
Lifetime is explicitly bounded to 3600 seconds. A successful return validates an
address for anti-amplification purposes; it does not authenticate an application
or TLS identity. Do not log tokens or secret key bytes.

HTTP/3's listener gate uses this owner before allocating per-peer TLS/QUIC state.
It sends at most a small Retry in response to an eligible Initial datagram of at
least 1200 bytes. Invalid returned tokens are silently dropped. The wire driver
installs new Initial keys from the Retry CID while retaining the original CID
for authenticated transport parameters. The native client verifies Retry
integrity, accepts at most one Retry before a server Initial, copies the opaque
token to subsequent Initials and keeps the original ClientHello/private key.
Packet numbers are never reset across Retry (RFC 9000 §17.2.5.3).

Core tests cover endpoint/CID binding, every-byte token mutation, clock/expiry,
rotation and concurrent issuance/validation during rotation. HTTP/3 tests cover
native and independent curl peers, no-allocation rejection, PN 0 → Retry → PN 1,
source-CID parameter validation, cancellation and lost/repeated Retry packets.

References: [RFC 9000 address validation](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1), [Retry processing](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5), and [RFC 9001 Retry integrity](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8).
