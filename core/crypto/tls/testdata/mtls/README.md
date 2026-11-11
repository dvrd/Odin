Synthetic mutual-TLS test identities, valid2026–2036 (the expired negative is
2021–2022). These keys are public test fixtures and must never serve production.
The CA private key is not retained. All leaves use distinct RSA2048 keys;
server/wrong-eku permit serverAuth, client/expired/rogue permit clientAuth.
The rogue leaf is signed by an unrelated key. The client-large certificate has
an unknown noncritical20KB extension to force multi-record authentication.

Regenerate explicitly with `go run generate.go /path/to/this/directory`.
This replaces every identity; recompile all fixtures together afterward.
