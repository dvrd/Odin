package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	cert, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	p, _ := pem.Decode(cert)
	c, e := x509.ParseCertificate(p.Bytes)
	if e != nil {
		panic(e)
	}
	digest := sha256.Sum256([]byte("credential-concurrency-fixture"))
	for _, path := range os.Args[2:] {
		sig, e := os.ReadFile(path)
		if e != nil {
			panic(e)
		}
		switch key := c.PublicKey.(type) {
		case *rsa.PublicKey:
			if e = rsa.VerifyPSS(key, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}); e != nil {
				panic(e)
			}
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(key, digest[:], sig) {
				panic("invalid ECDSA signature")
			}
		default:
			panic("unsupported key")
		}
	}
	fmt.Printf("Go verified %d signatures with %T\n", len(os.Args)-2, c.PublicKey)
}
