package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	for _, n := range []string{"p256", "p256-other", "p384"} {
		c := elliptic.P256()
		if n == "p384" {
			c = elliptic.P384()
		}
		d := big.NewInt(1)
		if n == "p256-other" {
			d = big.NewInt(2)
		}
		x, y := c.ScalarBaseMult(d.Bytes())
		k := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}
		t := &x509.Certificate{SerialNumber: big.NewInt(158), Subject: pkix.Name{CommonName: "synthetic.invalid"}, DNSNames: []string{"synthetic.invalid"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		der, e := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
		if e != nil {
			panic(e)
		}
		write := func(s, l string, b []byte) {
			if e := os.WriteFile(filepath.Join(os.Args[1], n+s), pem.EncodeToMemory(&pem.Block{Type: l, Bytes: b}), 0600); e != nil {
				panic(e)
			}
		}
		write("-valid.pem", "CERTIFICATE", der)
		a, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			panic(e)
		}
		write("-sec1.pem", "EC PRIVATE KEY", a)
		a, e = x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			panic(e)
		}
		write(".pem", "PRIVATE KEY", a)
	}
}
