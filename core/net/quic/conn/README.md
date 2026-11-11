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

Version negotiation, Retry, 0-RTT, migration/CID rotation and retirement, stateless
reset, ECN and coalesced datagrams remain outside this connection. Offered
NEW_CONNECTION_ID with `retire_prior_to=0` is accepted without switching CID;
nonzero retirement is unsupported. PATH_CHALLENGE is answered on the existing
path; this does not enable migration. Advisory BLOCKED frames are accepted.
Independent wire interoperability belongs to the real TLS driver's loopback and
external-peer tests, not the deterministic Material fixture pair.
