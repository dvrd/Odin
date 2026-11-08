// Generates published certificate-admission fixtures with independent Go crypto.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	dir := os.Args[1]
	load := func(name string) any {
		b, e := os.ReadFile(filepath.Join(dir, name))
		must(e)
		p, _ := pem.Decode(b)
		k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
		must(e)
		return k
	}
	rootKey := load("rsa4096.pem").(*rsa.PrivateKey)
	rsaKey := load("rsa2048.pem").(*rsa.PrivateKey)
	ecKey := load("p256.pem").(*ecdsa.PrivateKey)
	template := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), BasicConstraintsValid: true, SignatureAlgorithm: x509.SHA256WithRSAPSS, KeyUsage: x509.KeyUsageDigitalSignature}
	}
	root := template(960, "PSS fixture root")
	root.IsCA = true
	root.KeyUsage |= x509.KeyUsageCertSign
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	must(e)
	root, e = x509.ParseCertificate(rootDER)
	must(e)
	encode := func(b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}) }
	rootPEM := encode(rootDER)
	must(os.WriteFile(filepath.Join(dir, "pss-root.pem"), rootPEM, 0600))
	var normal []byte
	for i, profile := range []string{"rsa", "ec", "sha384"} {
		leaf := template(int64(961+i), "synthetic.invalid")
		leaf.DNSNames = []string{"synthetic.invalid"}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		var pub any = &rsaKey.PublicKey
		if profile == "ec" {
			pub = &ecKey.PublicKey
		}
		if profile == "sha384" {
			leaf.SignatureAlgorithm = x509.SHA384WithRSAPSS
		}
		der, e := x509.CreateCertificate(rand.Reader, leaf, root, pub, rootKey)
		must(e)
		if profile == "rsa" {
			normal = der
		}
		chain := append(encode(der), rootPEM...)
		must(os.WriteFile(filepath.Join(dir, "pss-"+profile+"-chain.pem"), chain, 0600))
	}
	tampered := bytes.Clone(normal)
	tampered[len(tampered)-1] ^= 1
	must(os.WriteFile(filepath.Join(dir, "pss-tampered-chain.pem"), append(encode(tampered), rootPEM...), 0600))
	wrongIssuer, e := os.ReadFile(filepath.Join(dir, "p256-valid.pem"))
	must(e)
	must(os.WriteFile(filepath.Join(dir, "pss-wrong-issuer-chain.pem"), append(encode(normal), wrongIssuer...), 0600))
	// Change both signature AlgorithmIdentifiers, and independently re-sign TBS
	// for the valid but unsupported salt20 profile. No production crypto is copied.
	type cert struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	var parsed cert
	rest, e := asn1.Unmarshal(normal, &parsed)
	must(e)
	if len(rest) != 0 {
		panic("trailing DER")
	}
	old := []byte{0xa2, 3, 2, 1, 32}
	replacement := []byte{0xa2, 3, 2, 1, 20}
	if bytes.Count(parsed.TBS.FullBytes, old) != 1 || bytes.Count(parsed.Algorithm.FullBytes, old) != 1 {
		panic("salt fixture framing")
	}
	salt := parsed
	salt.TBS.FullBytes = bytes.Replace(parsed.TBS.FullBytes, old, replacement, 1)
	salt.Algorithm.FullBytes = bytes.Replace(parsed.Algorithm.FullBytes, old, replacement, 1)
	digest := sha256.Sum256(salt.TBS.FullBytes)
	sig, e := rsa.SignPSS(rand.Reader, rootKey, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: 20, Hash: crypto.SHA256})
	must(e)
	salt.Signature = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	der, e := asn1.Marshal(salt)
	must(e)
	must(os.WriteFile(filepath.Join(dir, "pss-salt20-chain.pem"), append(encode(der), rootPEM...), 0600))
	// Preserve the outer SHA256 but give MGF1 a different digest. This is a
	// structurally valid negative profile, rejected before signature use.
	changeMGF := func(data []byte) []byte {
		oid := []byte{6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1}
		at := bytes.Index(data, oid)
		if at < 0 {
			panic("missing hash")
		}
		second := bytes.Index(data[at+len(oid):], oid)
		if second < 0 {
			panic("missing MGF hash")
		}
		result := bytes.Clone(data)
		result[at+len(oid)+second+len(oid)-1] = 2
		return result
	}
	mgf := parsed
	mgf.TBS.FullBytes = changeMGF(parsed.TBS.FullBytes)
	mgf.Algorithm.FullBytes = changeMGF(parsed.Algorithm.FullBytes)
	der, e = asn1.Marshal(mgf)
	must(e)
	must(os.WriteFile(filepath.Join(dir, "pss-mgf384-chain.pem"), append(encode(der), rootPEM...), 0600))
	// A hash AlgorithmIdentifier may have NULL or absent parameters, never
	// an empty OCTET STRING. Change both copies without changing DER lengths.
	changeHashParams := func(data []byte, which int) []byte {
		marker := []byte{6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1, 5, 0}
		at := 0
		for i := 0; i <= which; i++ {
			n := bytes.Index(data[at:], marker)
			if n < 0 {
				panic("hash parameter marker")
			}
			at += n
			if i < which {
				at += len(marker)
			}
		}
		result := bytes.Clone(data)
		result[at+len(marker)-2] = 4
		return result
	}
	for i, name := range []string{"hash-params", "mgf-params"} {
		bad := parsed
		bad.TBS.FullBytes = changeHashParams(parsed.TBS.FullBytes, i)
		bad.Algorithm.FullBytes = changeHashParams(parsed.Algorithm.FullBytes, i)
		der, e = asn1.Marshal(bad)
		must(e)
		must(os.WriteFile(filepath.Join(dir, "pss-"+name+"-chain.pem"), append(encode(der), rootPEM...), 0600))
	}
	malformed := parsed
	bad := []byte{0xa2, 3, 2, 1, 0xff}
	malformed.TBS.FullBytes = bytes.Replace(parsed.TBS.FullBytes, old, bad, 1)
	malformed.Algorithm.FullBytes = bytes.Replace(parsed.Algorithm.FullBytes, old, bad, 1)
	der, e = asn1.Marshal(malformed)
	must(e)
	must(os.WriteFile(filepath.Join(dir, "pss-malformed-chain.pem"), append(encode(der), rootPEM...), 0600))
}
