# Bounded client ALPN (OKAMI-139)

Set `Config.alpn_protocols` to an ordered `[]string` of opaque protocol names.
The slice and its bytes are borrowed: keep them immutable and alive through the
whole handshake, including the asynchronous completion callback and any retry.
Empty offers retain the previous ClientHello wire bytes and behavior.

The native client profile permits at most 16 names, each 1–255 bytes, and at most
1024 bytes for the complete name list, including each one-byte length prefix.
Empty/oversized names and lists fail configuration validation before transport
ownership transfers or I/O begins. Opaque names can contain zero/non-UTF8 bytes;
this layer does not reinterpret them as text. The pure `Client_Hello` encoder
applies the same limits before writing output.

The client encodes extension 16 in ClientHello and checks the TLS1.3 server
selection in EncryptedExtensions. A selection must contain exactly one offered
name; duplicate, malformed, empty and unsolicited extensions fail the handshake.
No response leaves the selection empty, allowing the application to decide
whether fallback is acceptable. The peer's fatal no-overlap alert remains
available in existing typed handshake diagnostics. These rules follow
[RFC7301 §§3.1–3.2](https://datatracker.ietf.org/doc/html/rfc7301#section-3) and
[RFC8446 §§4.2–4.3.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.2).

Read `connection_state(&conn).negotiated_protocol`, or
`async_connection_state(&conn).negotiated_protocol`. Selection appears only after
certificate/hostname verification, server Finished verification and successful
client Finished completion. It borrows fixed storage in the stable Conn, never
the offer list or transient server-flight allocation. That view expires at
failure, close or connection destruction. Failure/teardown clears stored
selection. Server-flight verification is shared by blocking and async drivers;
a cookie-only HelloRetryRequest retains the original offers and transcript.

No existing exported procedure signature changes. New configuration/state fields
are appended, preserving zero/named aggregates; use named fields when updating
positional aggregates.

## HTTP and transport policy (OKAMI-97)

Core TLS still treats names as opaque bytes. The handshake codec and
certificate path are unchanged. A selection is exposed only after hostname and
certificate verification. No-overlap, malformed, duplicate and unsolicited
selections stay fatal. Empty offers still omit the extension.

`alpn_transport_offers` is the binding. It does no socket I/O and no handshake.

- TCP may offer nothing, `http/1.1`, and `h2`. Nothing means HTTP/1 fallback.
  There is no implicit `h2` or `h3`. Any other name, including `h3`, is
  `Invalid_ALPN`. Surf applies this before DNS, sockets or upload reads,
  including cleartext HTTP. Surf still speaks HTTP/1; an accepted `h2` token
  is not an HTTP/2 driver.
- QUIC may offer only the single opaque name `h3`. An empty list is not an
  implicit HTTP/3 offer. A duplicated `h3` is rejected. This predicate has no
  TCP record entry point and no QUIC packet driver.

`dial` rejects `h3` before `net.dial_tcp`. `client` and `async_client` reject
it before any record write. Other opaque names remain available on that generic
client, including the existing no-overlap fixture. The recordless server
selector (OKAMI-156) stays opaque and is not this binding.

Offering or negotiating `h2` or `h3` does not implement HTTP/2 or HTTP/3.
Those remain OKAMI-102 and OKAMI-98/99. Authentication is not relaxed.

## Storage and verification

ALPN encoding/parsing/selection adds no ALPN-specific dynamic allocation. The
fixed ClientHello/retry buffers and 255-byte owned selection increase each
connection by 2,336 bytes on tested Darwin arm64, even when offers are empty:

| State | Before | With ALPN |
| --- | ---: | ---: |
| Conn | 156,304 B | 158,640 B |
| Async_Conn | 208,384 B | 210,720 B |

MAX_CLIENT_HELLO_SIZE grows from 392 to 1,422 bytes. Caller-owned offers are
additional caller storage.

Matched local handshakes with/without offers had identical tracked peaks:
1,207,496 bytes blocking and 215,184 bytes async, including fixed connection storage
but excluding preloaded roots and event-loop storage. This is a matched-fixture
measurement, not a universal equality guarantee: added server-flight bytes can
cross an existing async receive-buffer growth threshold for another certificate
chain. Generic certificate/receive buffering keeps its existing limits.

```sh
export PATH=/opt/homebrew/opt/llvm@22/bin:$PATH # match the tested compiler's ASan toolchain
./odin test tests/core/crypto/tls -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
./odin test core/crypto/tls -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
./odin test shared/surf/tests -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
python3 tests/core/crypto/tls/alpn_loopback.py --odin ./odin
```

The independent owned Go TLS1.3 peer requires only the local Go toolchain, with
module/toolchain downloads disabled. It exercises blocking/async selection,
server preference, missing/no ALPN, fatal no-overlap, wrong trust/hostname,
authenticated application I/O, offer-storage mutation after completion and
selection after async flight release. Surf negotiates HTTP/1 or falls back when
ALPN is absent. Unit vectors cover the wire layout, unchanged zero-offer bytes,
opaque/boundary names with nil allocators, malformed/duplicate/unoffered server
selections and exported function-value compatibility. This is Darwin arm64
runtime evidence; it does not certify a complete QUIC or HTTP/2/3 implementation.
