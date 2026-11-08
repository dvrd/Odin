# Public synthetic fixtures

Every private key in this directory is disposable **public test material**.
Do not use these keys as credentials. Certificates are self-signed and use
`synthetic.invalid`; their fixed validity is 2026-01-01 through 2030-01-01.

`generate.go <directory>` recreates the fixture shapes using only the installed
Go standard library and local randomness. It intentionally generates new key
bytes rather than reproducing the checked-in bytes. KU/EKU/critical-extension
variants isolate leaf policy. No service account, real credential or network
provider is used. `verify.go` checks native RSA-PSS signatures independently with
an exact 32-byte salt.


P-256 fixtures use deliberately public scalar1 (`p256`) and scalar2
(`p256-other`), with SEC1 and PKCS8 encodings and self-signed synthetic.invalid
certificates valid2020–2030. P-384 is an explicit unsupported-profile fixture.
Regenerate only these EC fixtures with `go run generate_ec.go /destination` using
an installed matching Go standard library. These keys must never be used for
service identities. Certificate signatures use the independent Go implementation.
