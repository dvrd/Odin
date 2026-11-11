# Stateless reset ownership

`Reset_Secrets` is an explicit, borrowed, synchronized owner. Supply a 32-byte
application secret to `reset_secrets_init`; this library does not install a
production key. Do not copy the initialized owner. Keep it alive until every
listener and connection using it has closed. `destroy` returns Busy while CID
leases remain; successful destruction wipes secret material.

CIDs are sixteen bytes: a public two-byte key ID and fourteen random bytes.
The reset token is the first sixteen bytes of HMAC-SHA256 over the versioned,
domain-separated CID length and complete CID. It is not address-bound, allowing
validated migration. Issued CIDs have 112 random bits. Two key generations and
256 unique live lease records bound memory. Lease records reject copied/double
release and wrong-owner release.

All reset-owner clock arguments are named `now_unix_ms` and use Unix milliseconds.
These are distinct from a transport model's monotonic millisecond timer. Generation
and rotation reject clock rollback; lease release still completes cleanup using
the greatest observed clock. `Reset_Config` zero values select defaults: retention
3600000ms, global burst64/refill32 per second, per-IP burst4/refill2 per second.
Retention must be positive and at most one day. Rate policy cannot disable the
feature silently: pass a nil reset owner to disable generation.

`reset_cid_random` mints an unleased CID for stateless Retry; it extends the key's
retention horizon. `reset_cid_acquire` creates a unique lease and exposes its token.
`reset_cid_issue` combines both operations. Release a lease when its CID retires
or the connection closes. Previous-generation eviction is refused while any
lease remains or its post-mint/release retention horizon has not elapsed. This
keeps tokens reproducible after connection state disappears. Rotation can return
Busy; rotate/retire connection IDs and wait for the retention window rather than
silently invalidating advertised tokens. When Retry and reset are configured
together, reset retention must cover the Retry token maximum age.

`reset_packet` is a last-resort generator for unknown short-header packets carrying
a recognized CID generation. It never answers a long header or a trigger of21
bytes or less. Its random short-form response is21..43 bytes and strictly shorter
than its trigger. Thus reset exchanges cannot amplify and terminate at the minimum
size. A global token bucket plus32 bounded per-IP buckets limit emission; changing
source ports cannot bypass the IP bucket. The listener must suppress generation
for admitted/draining CIDs, even when packet decoding fails. In-place buffers are
supported: the token is derived before output can overwrite the trigger CID.

Core connection detection first attempts ordinary packet protection using copied
read keys. Only failure permits constant-time comparison against all active peer
tokens. Successful authentication, including a reserved-bit violation discovered
after AEAD, never becomes a reset merely because its suffix matches a token.
Minimum21-byte resets can lack a full header-protection sample; sample/protection
failure is sufficient to enter token matching. Unknown CID prefixes are expected.
A detected reset enters terminal state, wipes retained stream/CRYPTO/datagram
bytes and releases local CID leases. The HTTP owner also releases QPACK,
application/producer and credential ownership exactly once.
