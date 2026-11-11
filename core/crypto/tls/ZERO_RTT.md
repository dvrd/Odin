# QUIC resumption and policy-controlled early requests

The QUIC drivers now offer real TLS1.3 PSK-DHE sessions, capture encrypted
NewSessionTicket messages and use separate early packet keys. Client early data
is explicit: HTTP3 Client_Request.early_data, or Surf Config.http3_early_data
method/path predicate. Nil predicates send no early requests. An optional caller
Session_Cache survives pool destruction; otherwise a live HTTP3 Pool owns a
bounded cache. Tickets bind SNI/ALPN, trusted roots, client identity and port.
Live pool lanes also bind the admitted trust digest; changing trusted roots uses
a new authenticated lane while active old tunnels retain their owner. Late ticket
capture uses the digest snapshot and never dereferences a destroyed root pool.
Cached early use additionally requires unchanged local receive settings and the
remembered server transport/HTTP3 settings. Fresh connections use static-only
QPACK until actual SETTINGS arrive; cached settings never reset live tables.

The server needs initialized Server_Ticket_Keys and Anti_Replay owners, a
Server_Ticket_Config with early_data pointing to Server_Early_Data_Config
(replay owner and explicit max_age), and an HTTP3/Saba early-request predicate.
The HTTP3 binding supplies and authenticates its own transport/settings profile;
applications need not serialize protocol details. Without the application policy
no early extension is advertised or accepted. The anti-replay owner must be shared
by all workers using the ticket keyring, kept at a stable address and alive until
configured connections end. Its fixed-capacity table is mutex protected, expires
reservations and fails closed when full or the clock regresses. Reservations are
never released on cancellation: application effects might already exist. Keys
are generated per process by the supported API; unrelated processes safely use
full handshakes rather than sharing an unsynchronized anti-replay domain.

A matching ticket must pass the binder, age/skew, unchanged authentication policy
and compatible remembered profile before an atomic reservation permits early
keys. A repeated ticket may still resume at1RTT, but its early packets are ignored.
QUIC NSTs use the required0xffffffff early-data sentinel; flow control bounds
actual early bytes. Unknown/expired/context-mismatched tickets fall back to full
handshakes. HRR always rejects early data. Method/path policy runs once before
handler effects. Approved Saba requests carry Request.early_data=true and, for
mTLS, the previously validated ticket principal. This is PSK-based early identity,
not a new certificate proof. Denied requests wait for client Finished and expose
early_data=false before the handler runs. Application authorization still applies;
increment ticket policy_epoch when revoking identities or authorization policy.

Application packet numbers are shared across0RTT and1RTT and never reset after
Retry or rejection. A provisional Core connection owns the actual stream buffers,
flow accounting and retransmission journal before Finished. Confirmation moves
new1RTT keys into that owner. Acceptance preserves offsets; rejection retransmits
retained bytes at the same offsets with fresh packet numbers, without rerunning
upload producers. Retry updates the destination and retransmits retained data.
Timer/congestion progress continues during the TLS handshake. Servers never emit
0RTT ACKs. Reordered accepted packets remain readable for a bounded three-PTO
key-retention interval; authenticated duplicates are not redelivered. Early
packets cannot migrate/validate a path. Forbidden ACK/CRYPTO/HANDSHAKE_DONE/
NEW_TOKEN/RETIRE_CONNECTION_ID/PATH_RESPONSE frames fail before application effects.

Owned finite limits remain explicit:192-byte authenticated profile,128-byte H3
profile,4096-byte tickets/eight client cache slots, configured anti-replay slots,
existing per-stream transport retention and8192-byte pre-Finished Application
packet holding. Applications can safely decline early data when these conditions
are not supported. TLS-over-TCP0RTT is not enabled by this QUIC feature.

Reproduction: tests/core/net/quic/zero_rtt.py builds a fresh paired native binary
and runs published aioquic1.3.0 peers with trusted synthetic credentials. The
matrix covers native HTTP3 and public Surf accepted/rejected/default behavior,
normal Saba early policy/replayed ticket/deferred denial/nil default/mTLS identity,
and Retry. Core packet tests additionally drop0RTT, force actual PTO, confirm or
reject and verify duplicate suppression. This is distinct from independent wire
proof. See SERVER_RESUMPTION.md for ticket ownership/rotation and CLIENT_AUTH.md
for initial certificate authentication.

Protocol references: [QUIC remembered parameters](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4.1),
[QUIC0RTT TLS rules](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.6), and
[HTTP3 remembered SETTINGS](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.2).
