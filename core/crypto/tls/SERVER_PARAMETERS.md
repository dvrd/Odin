# Recordless server ALPN and extension parameters

After feeding ClientHello, inspect the pending `Peer_Parameters` event. Its SNI,
ALPN offer list and QUIC transport-parameter bytes are tentative, borrowed from
owned ClientHello storage until event acceptance/abort/destruction. Validate host
policy before accepting. Call
`server_handshake_select_parameters(owner, event.id, config)` to select parameters
and accept that exact event. Stale IDs and invalid config leave it pending. A
protocol/limit/allocation failure terminates the owner and revokes all borrows.
Use abort to reject a binding's semantic/policy check. There are no callbacks.

`Server_Handshake_Parameters_Config` supplies server ALPN preferences, required
versus optional negotiation, TCP/QUIC mode, and local opaque QUIC parameters. The
config and its strings/bytes need survive only this call; the engine copies the
selection and both peer/local QUIC blobs into one exact-size owned grant. No
configuration slice is retained. Output/query slices must remain immutable while
borrowed. Existing callers may accept Peer_Parameters normally, then start the
flight: this selects the default optional TCP profile with no ALPN support.
Neither h2 nor h3 is implicitly enabled by this engine.

ALPN names use existing validation: 1–255 opaque bytes, at most16 local names and
1,024 encoded list bytes including name prefixes. Duplicate local names are
Invalid_Config. The ClientHello codec rejects malformed/empty/duplicate names,
duplicate extensions, and more than128 peer names; its overall65,536-byte message
cap also bounds offer bytes. Names compare byte-for-byte, including case, embedded
zero and non-UTF8 bytes. Server preference wins, and the response contains exactly
one offered name. Empty/over-limit config fails before any allocation. Required
ALPN requires a nonempty preference list. Optional permits an absent client offer;
when both sides support ALPN but have no overlap, selection fails
`No_Application_Protocol` (RFC7301 section3.2). An explicitly empty optional server
list ignores ALPN. This typed engine error is not itself a transmitted TLS alert;
a future binding maps it to no_application_protocol as appropriate.

QUIC mode always requires ALPN, a present client transport-parameter extension
(empty is distinguishable from missing), and an empty legacy session ID.
Calling select_parameters in this mode is the binding's explicit acceptance hook:
**first validate both peer and local transport-parameter semantics in the QUIC
binding**. The TLS engine only bounds/copies these opaque blobs. Each direction
has a local1,024-byte cap, not a protocol maximum. A QUIC config serializes the
local extension even for an empty blob. TCP mode rejects a peer QUIC extension
and rejects nonempty local QUIC config. No mode inference from extension presence
is performed. Transport parameters are not TLS records or QUIC packet state.

EncryptedExtensions encodes the selected ALPN and, in QUIC mode, local transport
parameters. Its maximum1,296 bytes fit existing2,048-byte output scratch. It is
accepted/hashed exactly once with all other handshake bytes; CV and Finished
cover it. The engine cannot continue without the host's explicit QUIC selection.
No placeholder callback or production QUIC driver is supplied.

`server_handshake_parameters` returns final selected ALPN plus peer/local QUIC
bytes and mode, with `authenticated=false` before valid client Finished. After
verification it reports true while Complete is pending. This is the Finished
completion boundary, not client certificate identity authentication or QUIC
handshake confirmation. Application delivery still requires accepting Complete.
Copy required durable selections **before accepting Complete**; that acceptance
wipes/frees the parameter grant and invalidates the query/borrows. Failed Finished,
cancellation, destruction or any flight error also wipe/free it, with no success
or authenticated query. Other handshake transients/secrets are already erased
before Complete is published. Repeated query/peek never allocates or changes data.

Darwin arm64 measurements: fixed owner1,224 bytes (previously1,136), event136;
parameter storage at most2,303 bytes (255+1,024+1,024). Without retry, maximum accepted overlapping
grants measured69,887 bytes (65,536 ClientHello+2,303 selections+2,048 scratch),
three allocations. Optional no-ALPN TCP retains two grants/67,584-byte maximum.
A prior key-share retry temporarily retains both hellos, separately bounded in
SERVER_RETRY.md (133,120 bytes); CH1 is erased before parameter selection.
The retained selection grant is counted by stats until Complete acceptance;
then live bytes return to zero. Full reported allocator grants are erased before
Free, including rejected short/oversized/error-bearing grants. These exclude
shared credentials, allocator metadata, compiled/transitive stack, registers and
consumer copies, and are not production memory/performance claims.

The independent fixture extends `tests/core/crypto/tls/server_flight.py` with
server-preferred and binary opaque ALPN through Go TLS and a Go `QUICClient`
recordless exchange: fragmented handshake bytes, both opaque parameter blobs,
four matching directional secrets and actual client Finished/native Complete.
The QUIC fixture's deliberately opaque test bytes are not semantic validation of
transport parameters. It implements no packets, recovery, application transport,
TCP driver or HTTP versions. Independent verification is documented in
SERVER_VERIFICATION.md; ECDSA158 and bindings147/98 remain separate open gates.

References: [RFC7301 section3.2](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.2),
[RFC9001 section8](https://www.rfc-editor.org/rfc/rfc9001.html#section-8),
[Go QUIC TLS API](https://pkg.go.dev/crypto/tls#QUICConn).
