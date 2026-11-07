The server-side ClientHello codec inspects one complete, exactly framed TLS
handshake message. `server_client_hello_size` inspects up to the first four bytes
and returns `Need_Input` for an incomplete header; it permits a coalesced suffix.
`server_client_hello_decode` requires exactly the declared message and returns
`Malformed` for any truncated or trailing bytes. Neither routine retains state.
The recordless owner must accumulate/copy split input and submit only the
first declared message, retaining its coalesced suffix for the next state.

`Server_Client_Hello_View` and `Server_Client_Hello_Selection` borrow the caller's
immutable message storage. No allocation, credentials, random generation,
cryptography, clock, transport, or callbacks are involved. On error the returned view/selection is empty, except that Retry_Required
returns the supported version/cipher/group/signature with no peer share. Pass only a successfully decoded view to
`server_client_hello_negotiate`; modifying its fields bypasses decoder validation.

The decoder validates legacy version, session ID (at most 32 bytes), the single
null compression method, zero padding, unsolicited-cookie rejection, recognized
vector framing, extension uniqueness,
key-share/group membership and order, and the required extension relationships.
Unknown/GREASE extension bodies and unknown identifiers remain opaque and do not
prevent a compatible offer from being selected. ALPN values are opaque bytes,
not text. The SNI host_name uses ASCII DNS syntax, excludes IP literals/trailing
dots, and has a local 253-byte limit. QUIC parameter bytes are opaque; the binding
must enforce mode, required presence, semantics and its own byte limit.

Limits are local policy, not RFC wire maxima: default/hard maximum 65,536 bytes
including the four-byte handshake header, at most 128 extensions (configurable
downward), and at most 128 groups, shares, SNI names and ALPN names. Duplicate ALPN
names are rejected; name comparison is byte-exact. Extension duplicate
checks rescan at most 128 prior entries; key-share validation uses a monotonically
advancing group cursor. Other offer vectors are scanned linearly within the wire
cap. `Limit` distinguishes these refusals from malformed wire syntax.

Selection is TLS1.3/AES128GCM-SHA256/rsa_pss_rsae_sha256 with X25519 preferred
before P-256. Missing a share for the preferred mutually supported group returns
Retry_Required and a borrowed group selection. The codec produces no HRR;
the recordless owner drives the single retry documented in SERVER_RETRY.md.
X25519 shares require32 bytes; P-256 requires65 and uncompressed prefix4. Native
ECDH validates points/shared secrets during the flight. Missing compatible offers
return Unsupported. ECDSA credential ownership/signing and other capabilities
remain separate before any full TLS baseline-compliance claim.

PSK identities, binders, modes and early-data offers are strictly framed; PSK must
be last, binder/identity counts must match, PSK requires modes, and early data
requires PSK. Well-formed PSK plus full-handshake offers can select the full
handshake. PSK and 0-RTT are never selected/accepted. Binder authentication is
unnecessary when no PSK is selected and is not performed here.

Certificate compatibility is a separate admission gate in OKAMI-153. It must
check actual chain signature metadata against `signature_algorithms_cert`, or
`signature_algorithms` if the former is absent; an RSA leaf does not establish
the issuer's signing algorithm. Offer selection alone does not admit a chain,
authenticate the peer, select ALPN, bind QUIC, or implement a complete TLS server.

Normative references: [RFC 8446 sections 4.1.2 and 4.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2),
[key-share ordering, section 4.2.8](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8),
[PSK modes and early data, sections 4.2.9–4.2.11](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.9),
[required extension coupling, section 9.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-9.2),
[SNI, RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3),
and [opaque ALPN, RFC 7301 section 3.1](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1).

The two captured public ClientHello fixtures come from independent Go and OpenSSL
clients, using a capture-only connection and memory BIO without network traffic.
Generator sources are in `testdata/generate_server_go_hello.go` and
`testdata/generate_server_openssl_hello.c`; run them from the Odin root to replace
the corresponding fixtures. Captured randomness and key shares are test data.
Decode/negotiation tests include both captured profiles, every assembly boundary,
exact wire/entry caps and 135,168 single-byte mutations with both allocators set
to panic. This corpus is bounded regression coverage, not exhaustive fuzzing.

A repeatable capture gate uses only temporary output and leaves checked-in
fixtures unchanged (requires installed Go, OpenSSL development files and
`pkg-config`):

```sh
python3 tests/core/crypto/tls/client_hello_capture.py --odin ./odin
```

Use `--go /path/to/go --go-root /path/to/libexec` to select a complete installed
toolchain. Downloads are disabled. The gate builds an ASan public-API consumer
and verifies fresh capture parsing/selection; it does not complete a handshake.
