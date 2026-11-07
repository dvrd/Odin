# Strict native RSA PKCS8 import (OKAMI-143)

`parse_pkcs8_rsa(dst, der)` imports an unencrypted two-prime RSA key into an
existing `rsa.Private_Key`. Input is borrowed only during the call and is never
mutated or retained. It must not overlap the destination. Nil/empty input,
overlap and input above 64 KiB are rejected before parsing.

This deliberately narrow DER profile accepts PrivateKeyInfo version 0 with
rsaEncryption, absent or DER NULL parameters, and exactly one nested PKCS1
RSAPrivateKey version 0. All eight components must be minimally encoded positive
integers within native modulus/exponent/factor bounds. Trailing fields/bytes,
attributes, encrypted keys, multiprime/version1 and other algorithm identifiers
are rejected. It follows the structures in
[RFC5208 §5](https://datatracker.ietf.org/doc/html/rfc5208#section-5) and
[RFC8017 A.1.2](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2),
without claiming every format those documents permit.

Failures preserve the destination byte-for-byte. A successful import validates a
separate native candidate, erases the complete old destination, installs the
candidate and erases its temporary owner. The parser returns only typed numeric
errors, never key bytes. No input DER view survives the call. The caller must
clear the resulting native key and erase its own input buffers when appropriate.
The existing raw `x509.Private_Key`, PKCS8 marshaling and native RSA APIs remain
unchanged. `parse_pkcs1_rsa` additionally exposes the same strict inner parser for
raw two-prime PKCS1 input, without allocating a PKCS8 envelope. Callers explicitly
choose the format; a failed PKCS8 parse never falls back to another format.

## Validation and ownership limits

Normalization uses existing `rsa.private_key_set_bytes` and its signing self-test;
no RSA arithmetic is added here. That primitive explicitly does not establish
primality of p/q or consistency of the redundant private exponent d. Strict
syntax plus an operational self-test is not a complete mathematical proof of
key validity. Key-strength policy belongs to consumers: Google retains its
existing 256–512-byte modulus range; the generic parser uses the native
128–512-byte modulus limits without adding an application strength policy.

The normalized key and explicit candidate occupy 2,416 bytes each on tested
Darwin arm64; Google also keeps a separate policy candidate of that size. The
parser made zero allocator calls importing independent Go 1024/2048/4096-bit
fixtures, and passed with nil allocators. In a non-ASan default build, the public
PKCS8 parser frame reserves 368 bytes and its shared normalization helper 2,608
bytes including saved registers. These are not the total stack requirements of
Google, ASN.1/RSA callees or another build.
Explicit candidate/old-key/decoded-buffer owners are erased, but source-level
zeroing cannot promise elimination of compiler-created copies, register spills,
external aliases, caller buffers or persistent test fixture files.

## Google integration and PEM prerequisite

Google's `service_key_decode` retains its PEM label/complete-input/64 KiB checks,
imports a temporary native candidate, enforces its existing modulus-size policy,
and only then replaces the prior key. Invalid input, allocator failure or a
smaller core-supported key leaves the prior Google key intact. JSON/file limits
and credential source policy remain unchanged. Its duplicate DER parsing is
replaced by core imports. Both service_key_decode and the deprecated exported
service_rsa_decode retain their exact callable signatures; the latter delegates
to parse_pkcs1_rsa without allocating a PKCS8 envelope.

OKAMI-148 separately makes decoded PEM payload growth erase the full old allocation
before freeing it, and erases final spare capacity in `block_delete`. Allocation
failure (including nil,nil allocators) returns no owning Block and releases
partial storage. This closes decoded-buffer relocation copies; it does not
mutate encoded caller input or establish compiler/register erasure guarantees.

## Offline verification

```sh
export PATH=/opt/homebrew/opt/llvm@22/bin:$PATH # matching ASan linker in this run
./odin test tests/core/crypto/x509 -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
./odin test tests/core/encoding/pem -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
./odin test shared/google/tests -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
python3 tests/core/crypto/x509/private_key_interop.py --odin ./odin
ODIN_ROOT="$PWD" python3 shared/google/tests/standalone.py --odin /path/to/actual/compiler
```

The fixture script disables Go module/toolchain downloads, generates only local
synthetic keys and verifies native PKCS1/PSS signatures with both Go and OpenSSL.
It checks input erasure, replacement from 4096 to 1024 bits, fresh-key byte equality,
Google's smaller-key rejection, explicit clear and real encrypted/multiprime
rejection. Unit tests cover canonical/positive integers, OIDs/parameters,
versions, nested/outer trailing bytes, every truncated prefix, bounds, overlap,
absent NULL, nil allocators, failure preservation and caller ownership.

The PEM allocator audit forces relocation and observes backing bytes before
release, including poisoned spare capacity; every allocation-failure point is
checked for both Out_Of_Memory and nil,nil. Existing certificate PEM tests and
clean vendored consumers also pass. Runtime evidence is Darwin arm64; Linux
arm64 has semantic compilation coverage only. Native TLS server/QUIC work under
OKAMI-96/98 remains separate.
