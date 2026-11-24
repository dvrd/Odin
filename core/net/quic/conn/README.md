# Bounded QUIC connection

`Connection` owns protected application packets, stream bytes, ACK retention,
loss/PTO replay and bounded receive reassembly. Calls on one connection must be
serialized. Do not copy an initialized connection: its harness borrows embedded
packet and stream tables. `destroy`/`cancel` release retention and key ownership.

A wire TLS driver transfers an authenticated `quic.Handshake` using
`adopt_established`. Success moves the handshake and zeroes the source; failure
leaves it owned by the caller. The handshake's CRYPTO backing buffers and local
parameter slice remain borrowed and must outlive the adopted connection. Pass
the actual next packet numbers in application
and Handshake spaces, local/peer CIDs, and the exact received application bitmap
(bit zero is `largest_recv_pn`). The client's Finished is replayed using the
transferred Handshake keys until HANDSHAKE_DONE. The server sends and retains
HANDSHAKE_DONE until acknowledged. A server drops obsolete Handshake packets.
The legacy `init(Material)` path uses precomputed shared-secret/flight fixtures;
it is not a real TLS negotiation API.

Set `directional_limits` and all peer transport limits explicitly after real TLS.
`peer_bidi_local` is peer TP0x05, `peer_bidi_remote` is TP0x06 and `peer_uni` is
TP0x07. These limit writes on peer-initiated bidi, locally initiated bidi, and
local uni streams respectively. Local receive limits belong in `limits.recv_*`.
A zero grant in an unrelated direction does not suppress another stream kind.

Each stream has a sliding send and a sliding receive window. Both default to
`STREAM_BYTES` (256) and are set per connection by `Stream_Windows` in
`Adopt_Config.windows` (or `Config.windows`). Acknowledged bytes are reclaimed
while absolute offsets persist. Consumed bytes return connection and stream
credit via retained MAX_DATA/MAX_STREAM_DATA frames. A transfer can exceed the
window; `write` takes all of its bytes or returns `Capacity`, and
`stream_send_room` reports what it would take now. A window larger than a
datagram is sent one STREAM frame per packet. Out-of-order fragments and
identical overlaps are accepted within the window. Conflicting retained overlaps
and inconsistent final sizes are protocol errors. A packet exceeding the
retained receive window is discarded without ACK so it can retry after
consumption. Advertised initial per-stream receive credit must fit the receive
window; adoption rejects a larger initial grant.

Stream bytes live in fixed blocks from one pool per connection, each with its
acknowledged/retry or present bitmap, so a stream holds memory for what it has
buffered and an idle stream holds none. The default pool is embedded and covers
a full default window for every record in both directions. A window above
`STREAM_BYTES` needs `Stream_Windows.allocator`: the pool is allocated once at
adoption and freed by `destroy`, and nothing allocates on the packet path.
`send_pool` and `recv_pool` bound the heap bytes all streams share. Zero sizes a
pool so it cannot run out: every record's full send window, and for receive the
connection receive window plus two blocks per record. A smaller send pool makes
`write` return `Capacity` until acknowledgments free blocks; a smaller receive
pool discards the packet it cannot buffer, unacknowledged. `next_readable` enumerates readable bytes, FIN and reset; applications
must track delivered terminal events.

Bounds are 32 streams open at once, 64 outstanding packets, 32 STREAM and 32
MAX_STREAM_DATA frames per packet, 65 ACK ranges, 4096-byte maximum datagrams.
Peer bidi streams permit responses; uni streams reject reverse writes.

A stream's record is released once the stream is closed in both directions:
every sent byte and the FIN or RESET_STREAM acknowledged, and the received end
handed to the application (`read` returned `fin`, or `Protocol` for a reset
stream) or abandoned with `stop_sending_with_error`. A bidi stream the
application never finishes or resets keeps its record.
`remaining_stream_records` counts free records, so it reflects streams open now.
Unread bytes of a released stream return their connection credit in a retained
MAX_DATA frame.

A released ID is recognised by a mark per stream kind (ID & 3): the count of
streams opened so far. Below the mark with no record means closed. Frames for a
closed stream are ignored. Calls about one answer without reopening it: `read`
returns no bytes and no `fin`, `write` returns `Protocol`,
`reset_stream_with_error` and `stop_sending_with_error` return `None`.
Because of the mark, local streams of one kind must be opened lowest ID first,
each four above the last; skipping one returns `Stream_Order` and opens
nothing. A new stream that only waits for flow-control credit counts as opened.
A stream the peer opens also opens every lower stream of its kind, each with a
record, so its frames may arrive in any order.

After authenticated transport parameters, `migration_enable` installs an endpoint
and bounded CID ownership. Advertise an active CID limit of four and pass the
peer's authenticated limit (at least two). Four local and four peer IDs, sixteen
pending retirements and four paths bound memory. New CIDs and retirements are
retained/retried until packet acknowledgment; retired IDs stop routing. CID
sequence conflicts, invalid retirement and peer limit overflow are errors.
`peer_reset_tokens` copies the active peer tokens for stateless-reset detection;
reset generation belongs to the borrowed Reset_Secrets owner.

Use `accepts_destination_id` for listener routing, `ingest_from` for endpoint-aware
input and `pump_to` for output. A candidate endpoint is admitted only after packet
authentication. Challenges and responses bind to that endpoint and an unpredictable
nonce; each path has its own amplification budget. Lost probes retry up to three
times, and candidates expire even if their budget cannot fund a probe. Inactive
validated slots can be reused. Application traffic uses the validated active
path; a port-only NAT change retains network estimates, while a network change
starts a fresh congestion/RTT epoch without resetting packet numbers or losing
retained bytes. Old-path feedback cannot tune the new epoch. Retain the endpoint
with any emitted datagram that has not reached the socket yet.

`migrate` starts validation to a remote endpoint after a caller prepares its local
socket. It respects the peer's disable-active-migration transport parameter.
`active_endpoint` supplies the destination for ordinary timer-generated output.
The UDP helper retains destination and ECN mark with pending datagram bytes.

ECN is opt-in through `ecn_enable`. Pass actual ancillary metadata with
`ingest_from_ecn`; missing metadata is not fabricated as Not-ECT. ACK_ECN counters
include only authenticated nonduplicate packets. Sent marks are retained until
ACK processing, and invalid/bleached feedback disables marking while streams
remain usable. A migration restarts path validation of ECN capability.

Version negotiation, Retry, preferred address and coalesced
datagrams remain outside this connection. Advisory BLOCKED frames are accepted.
Independent wire interoperability belongs to the real TLS driver's loopback and
external-peer tests, not the deterministic Material fixture pair.

`now` and timer deadlines use elapsed milliseconds with the default RFC9002
constants. Drivers must not pass nanoseconds to that millisecond model. A
protected HANDSHAKE_DONE retires retained client authentication CRYPTO, releases
its owned backing and drops Handshake keys before further application output.

Stateless reset detection is protection-first and accepts random short-header CID
prefixes; listener unknown-CID dispatch calls `observe_unrouted_reset`. Routed
failures return `Stateless_Reset` after token verification. `was_stateless_reset`
identifies terminal Core state until destroy. See ../RESET.md for key/CID ownership.

`reset_stream_with_error` and `stop_sending_with_error` retain the application
error code through ACK/loss/retransmission. A received STOP_SENDING produces a
RESET_STREAM with its received code. `receive_reset_error` and `receive_stop_error`
return the retained peer codes; legacy reset_stream keeps its code0 behavior.


Explicit early transport uses `adopt_early` and `confirm_early`: bounded STREAM
state stays provisional until authentication completes, and rejected client data
replays at the same offsets with new Application packet numbers. TLS supplies
distinct early keys and an explicit anti-replay/application policy. The HTTP3
binding owns ticket profiles and actual request execution; early keys alone
provide no permission to run application effects. Server early output waits for
confirmation, and retained early read keys expire after a bounded3PTO window.
