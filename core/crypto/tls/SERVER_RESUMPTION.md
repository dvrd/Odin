# TLS1.3 server tickets and PSK-DHE resumption

Create a stable caller-owned `Server_Ticket_Keys` with
`server_ticket_keys_init(&keys)`. The default maximum lifetime is 24 hours; an
explicit limit must be between one second and seven days. Configure
`Server_Ticket_Config{keys=&keys,lifetime=time.Hour,policy_epoch=1}` through
`Server_Handshake_Config.tickets`, `Server_Async_Config.handshake.tickets` or Saba
`TLS_Config.tickets`. Keep config/keyring alive through every connection.
Nil tickets preserves full-handshake behavior and allocates no ticket state.

Keys are generated with OS entropy. Tickets are opaque AES256-GCM messages with
fresh random 96-bit nonces. The keyring retains at most current and previous key;
`server_ticket_keys_rotate(keys,time.now())` generates a fresh current key and
retains the previous key for the configured maximum lifetime. Rotating again
immediately revokes older tickets. `server_ticket_keys_close` erases both secrets
and prevents future issuance/acceptance. Concurrent keyring operations serialize
under a mutex; TLS connections retain only their private key snapshot during
crypto. Time must be nondecreasing. No per-ticket server cache grows with load.

Each ticket binds its PSK to exact SNI, negotiated ALPN, current server leaf
fingerprint and credential-store generation, client-auth mode/trusted roots and
policy_epoch. For mTLS it also binds the previously verified client leaf digest
and earliest presented-chain expiry. Expired identities cannot resume. Changing
trust roots, policy_epoch, server credentials, SNI or ALPN requires a new full
handshake. Increment policy_epoch whenever application authorization/revocation
policy changes; application authorization still applies to the authenticated
resumed identity. A resumed peer proves possession of the resumption PSK; it does
not send or revalidate a new Certificate message. `Peer_Identity` is exposed only
after the resumed client Finished verifies.

The server accepts only psk_dhe_ke with the existing AES128-GCM/SHA256 handshake
profile, verifies the binder over the exact truncated ClientHello (including HRR
transcript state), emits selected_identity and an abbreviated encrypted flight,
and authenticates client Finished. Unknown, expired, revoked or context-mismatched
tickets fall back to the full certificate handshake. A recognized matching ticket
with an invalid binder terminates the connection; it cannot silently downgrade.
No early_data extension is issued or accepted here. QUIC0RTT is a separate policy
and replay-control feature.

After authenticated client Finished the recordless engine emits NewSessionTicket
as `Handshake_Bytes` at Application level before `Complete`. Consumers must send
these bytes under Application keys and retain them through their transport's ACK
or write completion. The TCP async driver does this automatically. QUIC connection
`queue_post_handshake` owns bounded 4096-byte CRYPTO output until ACK; PTO replays
unacknowledged data. `peek_post_handshake`/`consume_post_handshake` expose an owned,
ordered Application CRYPTO receive window without duplicate delivery. This also
supplies the driver foundation for QUIC client ticket capture.

`Connection_State.resumed`, `server_handshake_resumed` and Saba TLS events report
verified resumption. The native client's cache now binds negotiated ALPN, client
identity fingerprint and trusted-root snapshot; incompatible identities/protocols
use a full handshake. It advertises psk_dhe_ke on the initial full handshake when
remember_tickets is enabled, allowing independent servers to issue tickets.
Client opaque tickets are bounded 4096 bytes, eight cache entries; larger peer
tickets are ignored safely. Server-issued tickets are 269 bytes regardless of
certificate-chain size. Fixed bounds remain explicit capacity constraints.

Synthetic fixtures and the independent Go/OpenSSL interoperability runner live
under tests/core/crypto/tls/resumption_wire. Unit tests additionally exercise
binder tampering, unknown/expired/revoked tickets, key rotation, context isolation,
owned ACK/reorder/cancellation cleanup and authenticated resumption metadata.
