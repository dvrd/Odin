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
