package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func write(dir, name string, t string, b []byte) {
	must(os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: t, Bytes: b}), 0600))
}
func main() {
	dir := os.Args[1]
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	rootKey, e := rsa.GenerateKey(rand.Reader, 2048)
	must(e)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Webtools mTLS test CA"}, NotBefore: from, NotAfter: until, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	must(e)
	write(dir, "root.pem", "CERTIFICATE", der)
	for i, name := range []string{"server", "client", "wrong-eku", "expired", "rogue", "client-large"} {
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		must(e)
		c := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: from, NotAfter: until, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if name == "server" || name == "wrong-eku" {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.DNSNames = []string{"localhost"}
			c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		if name == "client-large" {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 383}, Value: make([]byte, 20000)}}
		}
		if name == "expired" {
			c.NotBefore = from.AddDate(-5, 0, 0)
			c.NotAfter = from.AddDate(-4, 0, 0)
		}
		signer := rootKey
		if name == "rogue" {
			signer, e = rsa.GenerateKey(rand.Reader, 2048)
			must(e)
		}
		der, e := x509.CreateCertificate(rand.Reader, c, root, &key.PublicKey, signer)
		must(e)
		write(dir, name+".pem", "CERTIFICATE", der)
		kb, e := x509.MarshalPKCS8PrivateKey(key)
		must(e)
		write(dir, name+"-key.pem", "PRIVATE KEY", kb)
	}
}
