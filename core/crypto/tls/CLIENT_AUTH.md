# Initial TLS1.3 client authentication

`Config.client_credentials` supplies an optional immutable RSA/P256 identity
store. Its generation is pinned while Certificate and CertificateVerify are
copied/signed. A connection pool can supply `client_credential_lease` to pin the
exact generation used for its origin identity key; that borrowed lease must
remain alive until handshake completion. Store rotation cannot change the
identity signed by a supplied lease.

`Server_Handshake_Config.client_auth` points to a borrowed `Client_Auth_Config`:

- Disabled/nil never requests a client certificate.
- Request accepts an empty identity; a supplied certificate must fully verify.
- Require rejects an empty identity and requires full verification.

Request/Require require explicit trusted roots. The chain validates time,
critical extensions, clientAuth EKU and digitalSignature usage. CertificateVerify
proves possession with the client context string and complete authenticated
transcript; Finished then authenticates that transcript before application I/O.
The application receives no tentative identity. `Peer_Identity` contains only an
authenticated flag and SHA256 of the leaf's DER, copied by value. Applications
map this identity to their own authorization policy.

The native blocking and asynchronous clients send an empty Certificate when no
matching configured identity is available. Certificate chains are serialized
into bounded owned storage and split into TLS records. Server client-auth
storage is allocated lazily under the host allocator/budget; disabled handshakes
retain their lean fixed owner size. Failure, cancellation and completion dispose
parsed certificates and every owned message. The certificate message bound is
1MiB; server async ownership limits may impose a lower per-connection budget.

`Server_Async_Config.handshake.client_auth` exposes the same recordless policy.
Saba `TLS_Config.client_auth` forwards it through normal serve; the secure handler
calls `tls_peer_identity(connection)`. The convenience facade provides the same
helper and TLS_Client_Auth_Config/Mode/Peer_Identity aliases. Surf already forwards
its ordinary TLS Config, including the identity store. No authentication wrapper
or parallel TLS implementation is introduced.

For QUIC, `quic_application_secrets_mutual` verifies an optional CertificateRequest
in the real server flight and returns application keys plus an allocator-owned
Certificate/CertificateVerify/Finished client flight. Application traffic secrets
derive at server Finished; the client's Finished covers client authentication too.
`quic.handshake_authenticate_server` accepts an optional store, allocator and pinned
identity lease; `handshake_client_finished` returns the entire retained flight.
Its owner moves into Core connection adoption and survives loss/PTO replay until
Handshake-key retirement, failure or destroy. No TCP records are emitted by this
interface. HTTP3 bindings fragment and retain the whole CRYPTO flight. The native
HTTP3 transport bounds retained handshake CRYPTO to 64KiB plus 1024 bytes. Saba
HTTP3 inherits its TCP TLS client-auth policy when no HTTP3 override is supplied;
an explicit Disabled policy can opt out.

Only initial TLS1.3 authentication is introduced here. Post-handshake client auth
and TLS1.2 client certificates remain outside this profile. Existing client tickets
are hostname-bound; configured/client-authenticated handshakes use full handshakes
and do not publish tickets into that anonymous cache. Identity-bound server/client
resumption is tracked separately by OKAMI-382. Anonymous resumption is unchanged.

Verification:

```sh
ODIN_ROOT=/matching/Odin /matching/odin test core/crypto/tls \
  -collection:shared=/matching/shared -sanitize:address
python3 tests/core/crypto/tls/mtls.py --odin /matching/odin \
  --go /matching/go --shared-root /matching/shared \
  --sanitize address --report /tmp/mtls-wire.json
```

The 25 owned cases (21 independent Go/native plus 4 Surf/Saba HTTP3 cases) use actual Saba, Surf and async TLS drivers.
They include required/optional/missing identities, wrong EKU, expired/untrusted
certificates and a 20KB certificate forcing multiple records. Recordless tests
add malformed requests, tampered CertificateVerify/Finished, partial cancellation
and pinned-generation rotation. QUIC tests verify full-flight ownership,
authenticated adoption and retained replay. Native HTTP3 wire verification lives
in shared/http/v3/mtls_transport_test.odin. All identity fixtures are synthetic;
no production certificates or secrets are required.
