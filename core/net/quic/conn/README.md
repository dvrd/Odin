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

Each stream has a 256-byte sliding send and receive window. Acknowledged bytes
are reclaimed while absolute offsets persist. Consumed bytes return connection
and stream credit via retained MAX_DATA/MAX_STREAM_DATA frames. Incremental
transfers can exceed 256 bytes; callers retry writes after ACK/credit progress.
Out-of-order fragments and identical overlaps are accepted within the window.
Conflicting retained overlaps and inconsistent final sizes are protocol errors.
A packet exceeding the retained receive window is discarded without ACK so it
can retry after consumption. Set advertised initial per-stream receive credit to
at most 256; adoption rejects a larger initial grant. `next_readable` enumerates readable bytes, FIN and reset; applications
must track delivered terminal events.

Bounds are 32 stream IDs for the connection lifetime, 64 outstanding packets,
32 STREAM and 32 MAX_STREAM_DATA frames per packet, 65 ACK ranges, 4096-byte
maximum datagrams. Stream metadata remains until destroy to preserve final sizes
and direction ownership after data storage is reclaimed. Peer bidi streams permit
responses; uni streams reject reverse writes.

After authenticated transport parameters, `migration_enable` installs an endpoint
and bounded CID ownership. Advertise an active CID limit of four and pass the
peer's authenticated limit (at least two). Four local and four peer IDs, sixteen
pending retirements and four paths bound memory. New CIDs and retirements are
retained/retried until packet acknowledgment; retired IDs stop routing. CID
sequence conflicts, invalid retirement and peer limit overflow are errors.
`peer_reset_tokens` copies the active peer tokens for stateless-reset detection;
reset generation/detection is a separate layer.

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

Version negotiation, Retry, 0-RTT, preferred address, stateless reset and coalesced
datagrams remain outside this connection. Advisory BLOCKED frames are accepted.
Independent wire interoperability belongs to the real TLS driver's loopback and
external-peer tests, not the deterministic Material fixture pair.

`now` and timer deadlines use elapsed milliseconds with the default RFC9002
constants. Drivers must not pass nanoseconds to that millisecond model. A
protected HANDSHAKE_DONE retires retained client authentication CRYPTO, releases
its owned backing and drops Handshake keys before further application output.
