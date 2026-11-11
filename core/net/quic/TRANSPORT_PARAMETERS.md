# Transport parameter and connection ID admission

`transport_parameters_validate` validates a complete peer extension before a
binding publishes any parameter side effects. Its context identifies the sender
and the authenticated handshake packet CIDs. It checks duplicate identifiers
(including unknown identifiers and alternate varint widths), complete framing,
numeric varint consumption/ranges, server-only roles, required CIDs, exact CID
binding, Retry presence, and fixed/preferred-address structure. Unknown parameters
remain opaque. The validator allocates nothing and retains no caller slices.

The accepted TLS extension resource profile is1024 bytes, matching
`tls.SERVER_QUIC_PARAMETERS_CAP`. This is a finite resource bound, not a claim
that larger unknown parameters are invalid QUIC syntax. Bindings map `.Limit` to
CRYPTO_BUFFER_EXCEEDED0x0d and `.Invalid_Context` to INTERNAL_ERROR0x01. Other
validation failures are TRANSPORT_PARAMETER_ERROR0x08. Reject before parameter
assignment, transcript policy selection or application effects. The TLS engine
authenticates the raw extension; it does not interpret QUIC parameter semantics.

The connection manager owns four CID slots and four path slots. A local CID is
retirable only after its initial handshake advertisement or a successful actual
NEW_CONNECTION_ID emit. A failed CID allocation does not consume its sequence.
Retirement cannot name the containing packet's destination CID. Retired peer IDs
remain excluded after retirement ACKs through a monotonic floor plus16 bounded
sparse records; capacity pressure preserves ownership instead of forgetting IDs.

`decline_preferred_address` explicitly declines the optional address migration
while admitting and retiring its authenticated sequence1 CID. It owns the CID and
reset token, never selects that CID for active output, and consistently handles
repeated NEW_CONNECTION_ID offers. A conflicting repeated sequence1 offer fails.
Bindings call it after manager initialization and before application pumping.
The parameter validator rejects a preferred CID equal to the initial CID or a
reset token reused between those two IDs, independent of parameter order.

Locally initiated path probes reserve an unused peer CID before their first
packet, including a local-port rebind. That CID is used for the candidate's
protected output while ordinary output retains the active path's CID. Successful
validation selects the challenge origin's reserved CID. Abandoned reservations
are retired; scarce CID credit returns bounded backpressure. Peer rebinding may
continue using the current CID under RFC9000's explicit exception.

If a peer withdraws the current CID while all remaining CIDs are bound to other
destinations, ordinary output returns Not_Ready before packet-number/accounting
changes. ACKs and application bytes remain owned. Reserved-path probes can still
progress, and fresh unbound CID credit restores ordinary output. A CID already
used on another destination is never selected as the fallback.

An authenticated PATH_RESPONSE is matched across the bounded set of actually
sent, unexpired outstanding challenges. It validates only the challenge origin;
the response's arrival endpoint does not gain validation. Unknown, expired,
unsent and consumed/replayed tokens do not validate a path. A response to an
unexpanded challenge validates its origin address but schedules a new expanded
challenge before MTU admission/promotion.

References: [CID negotiation](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.2),
[transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2),
[cross-path responses](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.3),
[CID privacy](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5), and
[retirement](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16).
