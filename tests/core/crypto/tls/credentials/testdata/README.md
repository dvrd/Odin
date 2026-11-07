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
