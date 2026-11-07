// Independent crypto/tls client. The bounded record adapter is test-only;
// it consumes public engine events, never implements production TCP integration.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func readRecord(c net.Conn) (byte, []byte) {
	h := make([]byte, 5)
	_, e := io.ReadFull(c, h)
	must(e)
	n := int(binary.BigEndian.Uint16(h[3:]))
	if n > 18432 {
		panic("oversized record")
	}
	b := make([]byte, n)
	_, e = io.ReadFull(c, b)
	must(e)
	return h[0], b
}
func writeRecord(c net.Conn, kind byte, b []byte) {
	h := []byte{kind, 3, 3, byte(len(b) >> 8), byte(len(b))}
	_, e := c.Write(append(h, b...))
	must(e)
}
func expand(secret []byte, label string, n int) []byte {
	label = "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(label))}
	info = append(info, []byte(label)...)
	info = append(info, 0)
	m := hmac.New(sha256.New, secret)
	m.Write(info)
	m.Write([]byte{1})
	return m.Sum(nil)[:n]
}

type protection struct {
	a   cipher.AEAD
	iv  []byte
	seq uint64
}

func protect(secret []byte) *protection {
	b, e := aes.NewCipher(expand(secret, "key", 16))
	must(e)
	a, e := cipher.NewGCM(b)
	must(e)
	return &protection{a: a, iv: expand(secret, "iv", 12)}
}
func (p *protection) nonce() []byte {
	n := bytes.Clone(p.iv)
	for i := 0; i < 8; i++ {
		n[11-i] ^= byte(p.seq >> uint(i*8))
	}
	p.seq++
	return n
}
func (p *protection) send(c net.Conn, kind byte, b []byte) {
	b = append(bytes.Clone(b), kind)
	n := len(b) + p.a.Overhead()
	h := []byte{23, 3, 3, byte(n >> 8), byte(n)}
	wire := p.a.Seal(nil, p.nonce(), b, h)
	_, e := c.Write(append(h, wire...))
	must(e)
}
func (p *protection) recv(c net.Conn) (byte, []byte) {
	for {
		kind, b := readRecord(c)
		if kind == 20 {
			continue
		}
		if kind != 23 {
			panic("expected ciphertext")
		}
		n := len(b)
		h := []byte{23, 3, 3, byte(n >> 8), byte(n)}
		plain, e := p.a.Open(nil, p.nonce(), b, h)
		must(e)
		i := len(plain) - 1
		for i >= 0 && plain[i] == 0 {
			i--
		}
		if i < 0 {
			panic("empty content")
		}
		return plain[i], plain[:i]
	}
}
func largeCertificate(keyPath, out string) {
	b, e := os.ReadFile(keyPath)
	must(e)
	p, _ := pem.Decode(b)
	k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	must(e)
	key := k.(*rsa.PrivateKey)
	c := &x509.Certificate{SerialNumber: big.NewInt(153), Subject: pkix.Name{CommonName: "synthetic.invalid"}, DNSNames: []string{"synthetic.invalid"}, NotBefore: time.Unix(1767225600, 0), NotAfter: time.Unix(1893456000, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 153}, Value: make([]byte, 8192)}}}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	must(e)
	must(os.WriteFile(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
}
func main() {
	if len(os.Args) == 4 && os.Args[1] == "--large-cert" {
		largeCertificate(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) != 5 {
		panic("peer binary cert key tempdir")
	}
	bad := os.Getenv("WEBTOOLS_BAD_FINISHED") == "1"
	dir := os.Args[4]
	cert, e := os.ReadFile(os.Args[2])
	must(e)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		panic("roots")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	must(a.SetDeadline(time.Now().Add(15 * time.Second)))
	must(b.SetDeadline(time.Now().Add(15 * time.Second)))
	client := tls.Client(a, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, ServerName: "synthetic.invalid", RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}, Time: func() time.Time { return time.Unix(1790000000, 0) }})
	done := make(chan error, 1)
	go func() {
		if e := client.Handshake(); e != nil {
			done <- e
			return
		}
		if client.ConnectionState().NegotiatedProtocol != "" {
			done <- fmt.Errorf("implicit ALPN")
			return
		}
		if bad {
			done <- nil
			return
		}
		buf := make([]byte, 6)
		_, e := io.ReadFull(client, buf)
		if e != nil {
			done <- e
			return
		}
		if string(buf) != "server" {
			done <- fmt.Errorf("server data")
			return
		}
		_, e = client.Write([]byte("client"))
		done <- e
	}()
	kind, ch := readRecord(b)
	if kind != 22 {
		panic("ClientHello")
	}
	in := filepath.Join(dir, "hello.bin")
	out := filepath.Join(dir, "events.bin")
	must(os.WriteFile(in, ch, 0600))
	cmd := exec.Command(os.Args[1], in, os.Args[2], os.Args[3], out)
	if bad {
		cmd.Args = append(cmd.Args, "bad")
	}
	stdin, e := cmd.StdinPipe()
	must(e)
	stdout, e := cmd.StdoutPipe()
	must(e)
	var log bytes.Buffer
	cmd.Stderr = &log
	must(cmd.Start())
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	ready, e := reader.ReadString('\n')
	must(e)
	if ready != "READY\n" {
		panic("engine not ready")
	}
	data, e := os.ReadFile(out)
	must(e)
	var sh, flight []byte
	secrets := make([][]byte, 4)
	si := 0
	for len(data) > 0 {
		if len(data) < 7 {
			panic("event header")
		}
		n := int(binary.BigEndian.Uint32(data[3:7]))
		if n < 1 || n > 2048 || len(data) < 7+n {
			panic("event bound")
		}
		payload := bytes.Clone(data[7 : 7+n])
		switch data[0] {
		case 1:
			if data[1] == 0 {
				sh = append(sh, payload...)
			} else if data[1] == 1 {
				flight = append(flight, payload...)
			} else {
				panic("bytes level")
			}
		case 2:
			if n != 32 || si >= 4 || data[1] != byte(1+si/2) || data[2] != byte(1-si%2) {
				panic("secret order")
			}
			secrets[si] = payload
			si++
		default:
			panic("unexpected event")
		}
		data = data[7+n:]
	}
	if si != 4 {
		panic("missing secrets")
	}
	writeRecord(b, 22, sh)
	hsWrite := protect(secrets[0])
	hsRead := protect(secrets[1])
	// Deliberately split encrypted handshake records inside headers, DER and CV.
	for at := 0; at < len(flight); {
		n := 1 + (at % 127)
		if n > len(flight)-at {
			n = len(flight) - at
		}
		hsWrite.send(b, 22, flight[at:at+n])
		at += n
	}
	kind, finished := hsRead.recv(b)
	if kind != 22 || len(finished) != 36 || finished[0] != 20 {
		panic("client Finished")
	}
	if bad {
		finished[35] ^= 1
	}
	_, e = stdin.Write(finished)
	must(e)
	complete, e := reader.ReadString('\n')
	must(e)
	expected := "COMPLETE\n"
	if bad {
		expected = "REJECTED\n"
	}
	if complete != expected {
		panic("incorrect authentication result")
	}
	must(stdin.Close())
	must(cmd.Wait())
	if bad {
		must(<-done)
		fmt.Printf("independent Go altered Finished rejected without Complete PASS; %s", log.String())
		return
	}
	appWrite := protect(secrets[2])
	appRead := protect(secrets[3])
	appWrite.send(b, 23, []byte("server"))
	kind, body := appRead.recv(b)
	if kind != 23 || string(body) != "client" {
		panic("client application secret")
	}
	must(<-done)
	fmt.Printf("independent Go TLS1.3: certificate/CV/Finished, native client Finished/Complete, both HS/app directions, split records PASS; %s", log.String())
}
