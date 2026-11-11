# Native TLS

Import `core:crypto/tls`. This package implements a TLS 1.3 client using
X25519 and AES-128-GCM/SHA-256. It authenticates the server with
`core:crypto/x509` and verifies CertificateVerify and Finished before exposing
application data. Ed25519, ECDSA P-256/SHA-256 and RSA-PSS-RSAE/SHA-256
CertificateVerify signatures are supported.

## Asynchronous connections

The asynchronous interface uses `net.Async_Connection` and an explicit
`net.Async_Executor`. The executor schedules local and buffered completions
without tying TLS to an event-loop implementation. `nbio.async_executor()`
provides the adapter for an application-driven `core:nbio` loop.

1. Connect with `nbio.dial`, then initialize a stable
   `nbio.TCP_Async_Connection` with the connected socket.
2. Call `tls.async_client(&conn, underlying, executor, config, allocator)`.
   This wraps without I/O. Success transfers transport ownership; a validation
   failure leaves it with the caller. Config borrows the hostname and roots.
3. Submit `tls.async_handshake(&conn, &operation, deadline)`. The caller-owned
   `Async_Handshake_Operation` receives one deferred callback containing a
   connection error and detailed handshake result. A zero deadline uses the
   configured handshake timeout (ten seconds by default); an explicit deadline
   can shorten that budget. Application read/write submissions are rejected
   until authentication succeeds.
4. Use `tls.async_connection(&conn)` with `net.async_read`, `net.async_write`,
   `net.async_cancel`, and `net.async_close`. One read and one write can be
   pending simultaneously. Additional operations in a direction are rejected.

All calls and callbacks belong to the executor's owning thread. Workers can
schedule work onto that loop. No blocking network operations or worker threads
are used by the TLS driver. Cryptographic verification runs on the loop thread.
Keep the transport, executor, allocator, configuration, roots, connection,
operation and buffer storage alive for their documented lifetimes. An accepted
operation completes exactly once; rejected operations receive no callback.
Buffered reads still complete later through the executor. Each I/O deadline is
absolute and applies to that operation; zero disables it.

`async_cancel_handshake` is terminal for an unfinished handshake. A read
cancelled or timed out partway through a record retains the ciphertext fragment,
so another read can resume it. A failed partial record write is terminal: the
client never retries a partial encrypted record or reuses its nonce. Completed
wire records win cancellation races. Write counts include complete application
records only. Protocol diagnostics are retained in `async_failure`.

Authenticated close_notify becomes `Peer_Closed`. Raw transport EOF without it
is a terminal truncation error. Post-handshake tickets are validated. They are
stored only when `Config.session` or `Config.session_cache` and `remember_tickets`
are set. That store does not install 0-RTT keys. `session_cache` is a caller-owned
bound of eight tickets, expired on use and isolated by server name. Key updates are processed, and responses share the
ordered writer with application data.

Close rejects new I/O, cancels and drains pending operations, then releases the
transport and clears key material. An idle established writer attempts a
close_notify with a one-second deadline; an interrupted writer aborts without
sending another record. Close does not wait for the peer's close_notify. Keep
running the event loop until close completes; only then free connection state.
Calling raw transport operations after transferring ownership is unsupported.

## Blocking connections

The existing `client`, `handshake`, `dial`, `read`, `write`, `close`, `abort`
and deadline procedures remain available. These operations require serialized
access. `client` wraps without I/O and the first read/write performs a lazy
handshake. Do not mix the blocking and asynchronous interfaces on a connection.
Blocking TCP deadlines currently support Darwin and Linux.

## Trust and protocol scope

Pass trusted roots in `Config.root_cas`. `Root_Pool` loads a PEM bundle with
`root_pool_load_file`; `root_pool_load_system` checks conventional Unix bundle
paths rather than native platform trust APIs. Destroy the pool after all
connections that borrow it have closed.

The client supports cookie-only HelloRetryRequest, fragmented handshake messages,
record buffering, key updates, authenticated shutdown and truncation detection.
Client [ALPN](ALPN.md) offers/selections are bounded and shared by blocking and
asynchronous handshakes. Read authenticated selection through `connection_state`
or `async_connection_state`. Surf's TCP binding allows a missing offer or the
tokens `http/1.1` and `h2`; `h3` is rejected before TCP I/O. That is not HTTP/2
or HTTP/3.
Initial TLS1.3 client certificates and mutual authentication are described in
[CLIENT_AUTH.md](CLIENT_AUTH.md). TLS 1.3 resumption is
`psk_dhe_ke` through `Config.session` or `Config.session_cache`. Early data stays
refused (`Early_Data_Disabled`) unless `Config.early_data` is set to a replay-safe
method policy. Resumption does not install 0-RTT keys on the default path. Rejected
early data falls back without applying the application effect twice. A full handshake, or a
resumption that still sends a certificate, keeps the existing certificate and
hostname checks. Omitting the certificate is accepted only when the PSK is
bound to that same hostname.
The separate restricted server API is described below. Certificate policy and revocation capabilities follow
`core:crypto/x509`.

## Verification

Run `./odin test tests/core/crypto/tls`. Tests cover an independent RFC 8448
record/key vector, fragmented input, deferred buffered completion, cancellation
and resumption, record tampering, partial write failure, key updates, and
close_notify versus truncation. The tests use deterministic test-only keys.
Authentication regressions reject wrong hostnames/roots, expired certificates,
modified CertificateVerify signatures/transcripts, and modified Finished MACs.

Independent Go interoperability is optional and uses only Go's standard library:

```sh
GOCACHE=/tmp/odin-tls-go-cache go run tests/core/crypto/tls/testdata/server.go -dir tests/core/crypto/tls/testdata
# In another terminal, use the printed loopback address:
./odin test tests/core/crypto/tls -define:TLS_TEST_ENDPOINT=127.0.0.1:PORT
```

It checks an authenticated handshake, overlapping read/write with a 40 KB echo,
wrong-hostname rejection and shutdown. Go is not a dependency of the Odin
package or ordinary tests. Regenerate certificates with the fixture's
`-generate` flag. Protocol references: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
and [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448).

## Recordless server foundation

The [bounded recordless owner](SERVER_HANDSHAKE.md) assembles ClientHello,
admits a pinned RSA/P-256 credential, emits the server flight and traffic secrets,
and authenticates client Finished before publishing Complete. It supports the
restricted TLS1.3/X25519-or-P256/AES128GCM/RSA-PSS-or-ECDSA profile with explicit ALPN/
opaque QUIC parameter handoff and one key-share retry (SERVER_RETRY.md); no
resumption or automatic QUIC binding is provided. Initial client authentication
is opt-in through the shared policy in [CLIENT_AUTH.md](CLIENT_AUTH.md).
The [lean async TCP server](SERVER_ASYNC.md) binds these events to the existing
`net.Async_Connection`/caller executor without a second I/O owner.
Existing client APIs and behavior are unchanged. See the contract for explicit
input boundaries, transient erasure and event acceptance requirements.

The [server acceptance contract](SERVER_BASELINE.md) maps native credential,
recordless and async TCP behavior to their validation boundaries, including
PSS-SHA256 certificate-chain admission without weakening authentication.

Server TLS1.3 ticket issuance, key rotation and authenticated PSK-DHE resumption
are documented in [SERVER_RESUMPTION.md](SERVER_RESUMPTION.md).

Policy-controlled QUIC resumption/0RTT integration and replay ownership are
documented in [ZERO_RTT.md](ZERO_RTT.md).
