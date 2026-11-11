# QUIC wire foundation

`core:net/quic` provides allocation-free QUIC v1 codecs, Initial/Handshake/1-RTT
packet protection, bounded CRYPTO reassembly and a handshake key owner.
`core:net/quic/conn` is the connection: it owns UDP, packet protection and
stream bytes. ACK, loss, PTO, flow control, congestion and anti-amplification
stay in the harness model. `core:net` does not import this package. There is
no HTTP API. 0-RTT stays off unless `handshake_install_zero_rtt` is called with a
replay-safe policy. The interop server does not opt in. 1-RTT key update
replaces the packet-protection secret, key, and IV for one phase. The header
protection key stays the `quic hp` derived for the connection. The next update
waits for `packet_keys_confirm_update`. A phase skip is refused.

All decoded slices borrow the input. Keep that storage alive and unchanged while
using a view. Encoding writes caller storage, never retains it, rejects overlap
with its written prefix, and leaves the destination unchanged on error. Decoding
errors return an empty view and zero consumed bytes. Buffers and views require
external synchronization if shared between threads.

- `varint_decode` accepts legal nonminimal encodings. `varint_encode` defaults to
  the smallest width; an explicit 1/2/4/8-byte width supports reserved length fields.
- `invariant_decode` reads only version-independent fields, including long CIDs
  through 255 bytes. Short CID length comes from external connection context.
- `packet_decode_v1` enforces v1 CID limits and interprets v1 packet types only
  for version 1. Other nonzero versions return `Unsupported_Version`; use the
  invariant parser to inspect them. Version 0 exposes an opaque version list.
- Initial/0-RTT/Handshake `consumed` follows Length, allowing the caller to advance
  within a coalesced datagram. Short headers, Retry and Version Negotiation have
  no length delimiter and consume the remaining input. Coalescing policy belongs
  to the eventual connection layer.
- `protected_body` begins at `packet_number_offset` and includes the protected PN.
  Its length says nothing about a valid HP sample or AEAD tag. The raw first byte
  exposes protected bits without interpreting them.
- `unprotected_fields_decode` requires an already unmasked packet. It exposes
  truncated PN, reserved bits and short-header key phase. It neither reconstructs
  PN nor authenticates anything. Validate reserved bits only after packet
  authentication as well as HP removal; never change connection state using
  unauthenticated fields.
- Long/short header encoders emit unprotected headers only. `ciphertext_length`
  excludes PN and includes the future AEAD tag. Retry encoding requires an
  externally computed tag; Version Negotiation encoding requires caller versions.

A successful structural decode can deliberately represent a crypto-incomplete
packet, including one byte of protected body. It is not permission to accept that
packet: HP sample bounds, AEAD, Retry integrity, role/token/negotiation checks and
Initial datagram size policy remain separate work. Tests deliberately cover this
boundary. No real network peer interoperability is claimed by this slice.

Wire definitions: [RFC 8999 sections 5–6](https://www.rfc-editor.org/rfc/rfc8999.html#section-5),
[RFC 9000 sections 12.2, 16–17](https://www.rfc-editor.org/rfc/rfc9000.html#section-16),
and [RFC 9001 section 5.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4).
Published integer vectors come from RFC 9000 Appendix A.1; Initial headers and
Retry bytes come from RFC 9001 Appendix A.2–A.4. Codec tests check structure.
Protection tests check those Initial packets, Retry integrity, the Appendix A.5
ChaCha20 packet, and AES Handshake/1-RTT round trips from the TLS secret seam.

Run from an Odin root containing this package:

```sh
./odin test core/net/quic/tests -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
./odin test core/net/quic/tests -sanitize:address -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
```

## Initial packet protection

`initial_keys_derive_v1` derives caller-owned client/server `Initial_Keys` from the
client's original Destination Connection ID (0–20 bytes), using native
SHA-256/HKDF and the v1 salt. It does not decide when a Retry changes that ID.
`initial_nonce` XORs the IV with the caller's full packet number, which must be
less than 2^62. These publicly derivable Initial keys do **not** authenticate a
server or protect against an observer or active attacker.

The explicit send sequence is:

1. Encode the unprotected Initial header with `long_header_encode_v1`. Its
   `ciphertext_length` includes the future 16-byte tag.
2. `initial_payload_seal` writes ciphertext plus tag into caller storage after
   that header. The header's declared Length and truncated PN must agree with
   this payload and the caller's full PN.
3. `initial_header_protection_apply` masks the first byte and PN in a complete
   single packet, sampling at the decoded PN offset plus four. The caller must
   provide enough payload/PADDING for the entire 16-byte sample.

Receive by structurally delimiting one packet, calling
`initial_header_protection_remove`, reconstructing its full PN in the caller,
then `initial_payload_open` with the complete unmasked header through PN.
`packet_number_reconstruct` implements RFC 9000 Appendix A.3 for that caller.
Initial open does not update a replay window, ACK/recovery or connection state.
Only after a successful open may a caller use authenticated
packet contents or validate reserved bits. Successful GCM verification remains
weaker than peer authentication because Initial keys are public.

Crypto operations allocate nothing and retain no buffers or key pointers. Header
protection mutates the caller packet in place; all its sample/structural/alias
checks precede mutation. Payload operations allow exact in-place processing at
the payload start, and reject other destination overlap with input, header, tag
or keys. Rejected preflight operations leave destination storage unchanged. A
failed GCM open returns zero bytes and `Authentication_Failed`, zeroes only its
produced plaintext region, and leaves trailing destination bytes alone. An
in-place open therefore invalidates its ciphertext even on authentication failure.
The separate tag remains caller-owned. Never share mutable keys/buffers across
concurrent calls without synchronization.

Clear every key owner with `initial_keys_clear` or `initial_key_pair_clear` when
finished; these explicitly erase key bytes and the initialization marker. Copies
of the value create additional owners to erase. Temporary derivation secrets (including the local pair after return-value copying),
nonces, masks and AES schedules are explicitly erased internally. Odin does not
provide linear types or guarantees about compiler-created/register copies;
callers must avoid accidental copies and must not reuse a packet number with the
same sending keys. The handshake owner discards Initial keys when a client first
sends Handshake, or a server first accepts Handshake, and discards Handshake keys
on confirm. Other cancellation remains caller policy.

Initial protection is AES-128-GCM plus AES-ECB header protection. Handshake and
1-RTT AES keys come from `core:crypto/tls` traffic secrets (`quic key` / `quic iv`
/ `quic hp`), not from TLS record keys. A 1-RTT update installs
`HKDF-Expand-Label(secret, "quic ku", "", 32)`, then `quic key` and `quic iv`
from that secret. `quic hp` stays in place (RFC 9001 §§5.4 and 6) so header
protection can expose the key-phase bit. The sender calls `packet_keys_advance`
once. The receiver installs that generation only after AEAD success. Failure
drops the trial secret, key, and IV. `packet_keys_confirm_update` is explicit
and is the gate for another update. ChaCha20-Poly1305 is used only to check
the published RFC 9001 A.5 short-header packet and its `quic ku` secret. Retry integrity is checked
against Appendix A.4. Certificate, hostname and Finished checks stay in the TLS
package; a transport-parameter mismatch with the handshake transcript discards
this state. There is no resumption and no network peer in this package.
Tests compare full RFC 9001 client/server Initial packets, derive the published
keys and exercise both AES implementation selections, authentication failures,
truncation, overlap, sample bounds and key erasure. `.Hardware` follows the AES
package's normal portable fallback on machines without acceleration.

Definitions and vectors: [RFC 9001 sections 5.2–5.4 and Appendix A](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2).

## Connection

`core:net/quic/conn` seals real QUIC frames with the handshake owner and asks
the harness to account for the same UDP length. The harness datagram is never
sent. One `send_udp` success is not a peer acknowledgment. A pending send
retries the same datagram. A truncated datagram is not decoded. Caller-owned
buffers are borrowed only for the call.

Anti-amplification stays on until a Handshake packet is accepted. A new peer
endpoint restarts that limit. That restart is not migration.

Not implemented: connection migration, `PATH_CHALLENGE`, preferred address,
version negotiation (unknown versions and Version Negotiation packets are
discarded), Retry, 0-RTT and resumption, `NEW_CONNECTION_ID` and retirement,
ECN, coalesced packets, multipath, stateless reset, address-validation tokens,
and retransmission of a lost stream range. Loss sends a PTO probe. CRYPTO is
resent from offset zero because identical overlap is idempotent. The ACK frame
carries only the first contiguous range. Drain is three times the current PTO
base, not a full idle timeout. A loopback of two connections, or of the
harness, is not an independent peer. Linux is not run here.

```sh
./odin test core/net/quic/sim/tests -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
```

## Harness model

`core:net/quic/harness` is a deterministic test model. It is not the production
connection API, not a UDP socket, and not TLS. Packet protection, header
protection, and Retry integrity stay outside the harness and are not applied to
its datagrams. The model borrows caller packet and stream tables,
keeps no datagram bytes, and advances only when the test passes a tick.

It hosts on `core:net/quic/sim`. The link injects time, loss, duplication,
reordering, address changes, and allocation failure. The model covers v1 header
levels, the three packet-number spaces, ACK/loss/PTO, flow control, congestion,
bounded retention, reset/close, and the server anti-amplification limit.
Published checks are RFC 9000 Appendix A.2–A.3 and RFC 9002's initial window,
PTO constants, and §7.6.3 persistent-congestion arithmetic. The integer Initial
PTO is 997 ms. The RFC's real-valued expression is 999 ms and is described as
one second; the model follows the pseudocode assignment order.

There is no independent Linux peer in this tree. `core/net/quic/harness/peer`
prints that Linux is unsupported, skips the Darwin-vs-Linux comparison, and
exits non-zero only when `self_check` fails. A loopback of this model is not
that peer.

```sh
./odin test core/net/quic/tests -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
./odin test core/net/quic/harness/tests -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
./odin run core/net/quic/harness/peer -warnings-as-errors -sanitize:address
```
