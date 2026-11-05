// Optional independent interoperability fixture; not required by the Odin tests.
// Run with -generate to recreate the deterministic test-only certificate files.
package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := flag.String("dir", ".", "fixture directory")
	generate := flag.Bool("generate", false, "generate test certificates")
	flag.Parse()
	if *generate {
		rootKey := ed25519.NewKeyFromSeed(make([]byte, 32))
		seed := make([]byte, 32)
		seed[0] = 1
		leafKey := ed25519.NewKeyFromSeed(seed)
		root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Odin TLS test root"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		rootDER, err := x509.CreateCertificate(nil, root, root, rootKey.Public(), rootKey)
		must(err)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		leafDER, err := x509.CreateCertificate(nil, leaf, root, leafKey.Public(), rootKey)
		must(err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
		must(err)
		for name, block := range map[string]*pem.Block{"root.pem": {Type: "CERTIFICATE", Bytes: rootDER}, "leaf.pem": {Type: "CERTIFICATE", Bytes: leafDER}, "key.pem": {Type: "PRIVATE KEY", Bytes: keyDER}} {
			must(os.WriteFile(filepath.Join(*dir, name), pem.EncodeToMemory(block), 0600))
		}
		return
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*dir, "leaf.pem"), filepath.Join(*dir, "key.pem"))
	must(err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}})
	must(err)
	fmt.Println(ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
