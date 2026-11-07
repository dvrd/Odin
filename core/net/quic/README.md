# QUIC wire foundation

`core:net/quic` currently provides allocation-free QUIC v1 header and integer
codecs. It has no connection, socket, TLS, recovery or HTTP API.

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
Retry bytes come from RFC 9001 Appendix A.2–A.4. Vector tests check codecs only,
not cryptographic verification.

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
then `initial_payload_open` with the complete unmasked header through PN. No
packet-number reconstruction, replay window, ACK/recovery or connection-state
updates occur here. Only after a successful open may a caller use authenticated
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
same sending keys. Key discard timing and connection cancellation remain caller
policy.

This slice covers Initial AES-128-GCM plus AES-ECB header protection only. It does
not implement TLS CRYPTO integration, certificate/server authentication, Retry
integrity, application traffic keys, resumption or network interoperability.
Tests compare full RFC 9001 client/server Initial packets, derive the published
keys and exercise both AES implementation selections, authentication failures,
truncation, overlap, sample bounds and key erasure. `.Hardware` follows the AES
package's normal portable fallback on machines without acceleration.

Definitions and vectors: [RFC 9001 sections 5.2–5.4 and Appendix A](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2).
