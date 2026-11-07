# TLS client

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
is a terminal truncation error. Post-handshake tickets are validated and
discarded; key updates are processed, and responses share the ordered writer
with application data.

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
or `async_connection_state`; Surf currently permits only HTTP/1.1 offers.
TLS 1.2, server mode, client certificates, session resumption and 0-RTT
are not implemented. Certificate policy and revocation capabilities follow
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
