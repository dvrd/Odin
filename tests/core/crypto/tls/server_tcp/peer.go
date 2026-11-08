package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}

// Only the independently supplied final issuer is trusted, never the leaf of a
// real chain. Repeated one-certificate padding fixtures retain their old anchor.
func finalAnchor(data []byte) []byte {
	var last *pem.Block
	for len(bytes.TrimSpace(data)) > 0 {
		var p *pem.Block
		p, data = pem.Decode(data)
		if p == nil || p.Type != "CERTIFICATE" {
			panic("invalid anchor PEM")
		}
		last = p
	}
	if last == nil {
		panic("missing anchor")
	}
	return pem.EncodeToMemory(last)
}

type splitConn struct {
	net.Conn
	fragment int
	delay    time.Duration
	corrupt  bool
}

func (c *splitConn) Read(p []byte) (int, error) {
	if c.delay > 0 {
		time.Sleep(c.delay)
		c.delay = 0
	}
	if c.fragment > 0 && len(p) > c.fragment {
		p = p[:c.fragment]
	}
	return c.Conn.Read(p)
}
func (c *splitConn) Write(p []byte) (int, error) {
	if c.corrupt {
		for at := 0; at+5 <= len(p); {
			n := 5 + int(binary.BigEndian.Uint16(p[at+3:at+5]))
			if n > len(p)-at {
				break
			}
			if p[at] == 23 {
				p = bytes.Clone(p)
				p[at+n-1] ^= 1
				c.corrupt = false
				break
			}
			at += n
		}
	}
	total := 0
	for total < len(p) {
		n := len(p) - total
		if c.fragment > 0 && n > c.fragment {
			n = c.fragment
		}
		used, e := c.Conn.Write(p[total : total+n])
		total += used
		if e != nil {
			return total, e
		}
		if used == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
func largeCertificate(keyPath, out string) {
	b, e := os.ReadFile(keyPath)
	must(e)
	p, _ := pem.Decode(b)
	k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	must(e)
	key := k.(*rsa.PrivateKey)
	cert := &x509.Certificate{SerialNumber: big.NewInt(147), Subject: pkix.Name{CommonName: "synthetic.invalid"}, DNSNames: []string{"synthetic.invalid"}, NotBefore: time.Unix(1767225600, 0), NotAfter: time.Unix(1893456000, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 147}, Value: make([]byte, 8192)}}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	must(e)
	must(os.WriteFile(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
}
func main() {
	if len(os.Args) == 4 && os.Args[1] == "--large-cert" {
		largeCertificate(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) != 6 && len(os.Args) != 8 {
		panic("native cert key count mode [newcert newkey]")
	}
	mode := os.Args[5]
	negative := mode == "trust" || mode == "hostname" || mode == "time" || mode == "before" || mode == "no-alpn" || mode == "no-overlap" || mode == "unsupported-certificate" || mode == "bad-chain"
	count, e := strconv.Atoi(os.Args[4])
	must(e)
	nativeMode := "normal"
	if mode == "key-update" || mode == "rotate" {
		nativeMode = mode
	}
	if strings.HasPrefix(mode, "raw-") {
		nativeMode = "reject"
	}
	if negative || mode == "bad-record" {
		nativeMode = "peer-reject"
	}
	if mode == "timeout" || mode == "cancel" || mode == "close-active" {
		nativeMode = mode
	}
	args := []string{os.Args[2], os.Args[3], os.Args[4], nativeMode}
	if mode == "rotate" {
		args = append(args, os.Args[6], os.Args[7])
	}
	cmd := exec.Command(os.Args[1], args...)
	stdout, e := cmd.StdoutPipe()
	must(e)
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	must(cmd.Start())
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
			fmt.Fprintln(os.Stderr, diagnostics.String())
		}
	}()
	reader := bufio.NewReader(stdout)
	line, e := reader.ReadString('\n')
	must(e)
	if !strings.HasPrefix(line, "READY ") {
		panic("native listener")
	}
	endpoint := strings.TrimSpace(strings.TrimPrefix(line, "READY "))
	root := x509.NewCertPool()
	trustedAnchors := map[string]bool{}
	addAnchor := func(data []byte) bool {
		anchor := finalAnchor(data)
		p, _ := pem.Decode(anchor)
		trustedAnchors[string(p.Bytes)] = true
		return root.AppendCertsFromPEM(anchor)
	}
	cert, e := os.ReadFile(os.Args[2])
	must(e)
	if !addAnchor(cert) {
		panic("roots")
	}
	if mode == "trust" {
		root = x509.NewCertPool()
		trustedAnchors = map[string]bool{}
		b, e := os.ReadFile(filepath.Join(filepath.Dir(os.Args[2]), "rsa4096-valid.pem"))
		must(e)
		if !addAnchor(b) {
			panic("wrong roots")
		}
	}
	if mode == "rotate" {
		b, e := os.ReadFile(os.Args[6])
		must(e)
		if !addAnchor(b) {
			panic("rotation roots")
		}
	}
	payload := make([]byte, 40960)
	for i := range payload {
		payload[i] = byte(i)
	}
	var wg sync.WaitGroup
	results := make(chan error, count)
	bits := make(chan int, count)
	identities := make(chan string, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, e := net.DialTimeout("tcp4", endpoint, 2*time.Second)
			if e != nil {
				results <- e
				return
			}
			defer raw.Close()
			duration := 15 * time.Second
			if mode == "rotate" {
				duration = 60 * time.Second
			}
			raw.SetDeadline(time.Now().Add(duration))
			if nativeMode == "reject" || mode == "timeout" || mode == "cancel" || mode == "close-active" {
				switch mode {
				case "raw-oversize":
					raw.Write([]byte{22, 3, 3, 255, 255})
				case "raw-type":
					raw.Write([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0})
				case "raw-truncate":
					raw.Write([]byte{22, 3})
					raw.Close()
					results <- nil
					return
				}
				if mode == "raw-oversize" || mode == "raw-type" {
					alert := make([]byte, 7)
					_, e := io.ReadFull(raw, alert)
					if e != nil {
						results <- e
						return
					}
					expected := byte(22)
					if mode == "raw-type" {
						expected = 50
					}
					if !bytes.Equal(alert, []byte{21, 3, 3, 0, 2, 2, expected}) {
						results <- fmt.Errorf("wrong fatal alert %x", alert)
					} else {
						results <- nil
					}
					return
				}
				one := make([]byte, 1)
				_, e := raw.Read(one)
				if e == nil {
					results <- fmt.Errorf("raw fixture unexpectedly produced data")
				} else {
					results <- nil
				}
				return
			}
			curves := []tls.CurveID{tls.X25519}
			if mode == "p256" {
				curves = []tls.CurveID{tls.CurveP256}
			}
			if mode == "retry" {
				curves = []tls.CurveID{tls.SecP256r1MLKEM768, tls.X25519, tls.CurveP256}
			}
			if mode == "retry-p256" {
				curves = []tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP256}
			}
			var transport net.Conn = raw
			if mode == "fragment" {
				transport = &splitConn{Conn: raw, fragment: 7}
			}
			if mode == "backpressure" {
				raw.(*net.TCPConn).SetReadBuffer(1024)
				transport = &splitConn{Conn: raw, delay: 200 * time.Millisecond}
			}
			if mode == "bad-record" {
				transport = &splitConn{Conn: raw, corrupt: true}
			}
			names := []string{"h2", "http/1.1"}
			if mode == "no-alpn" {
				names = nil
			}
			if mode == "no-overlap" {
				names = []string{"unregistered"}
			}
			name := "synthetic.invalid"
			if mode == "hostname" {
				name = "wrong.invalid"
			}
			c := tls.Client(transport, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: curves, ServerName: name, RootCAs: root, NextProtos: names, Time: func() time.Time {
				if mode == "time" {
					return time.Unix(2000000000, 0)
				}
				if mode == "before" {
					return time.Unix(0, 0)
				}
				return time.Unix(1790000000, 0)
			}})
			if e := c.Handshake(); e != nil {
				if negative {
					var host x509.HostnameError
					var trust x509.UnknownAuthorityError
					var invalid x509.CertificateInvalidError
					if mode == "hostname" && errors.As(e, &host) || (mode == "trust" || mode == "bad-chain") && errors.As(e, &trust) || (mode == "time" || mode == "before") && errors.As(e, &invalid) && invalid.Reason == x509.Expired || (mode == "no-alpn" || mode == "no-overlap") && strings.Contains(e.Error(), "no application protocol") || mode == "unsupported-certificate" && strings.Contains(e.Error(), "remote error: tls: handshake failure") {
						results <- nil
					} else {
						results <- e
					}
					return
				}
				results <- e
				return
			}
			if negative {
				results <- fmt.Errorf("expected client rejection")
				return
			}
			if mode == "bad-record" {
				if transport.(*splitConn).corrupt {
					results <- fmt.Errorf("fixture did not mutate Finished record")
					return
				}
				one := make([]byte, 1)
				_, e := c.Read(one)
				if e != nil && strings.Contains(e.Error(), "remote error: tls: bad record MAC") {
					results <- nil
				} else {
					results <- fmt.Errorf("expected authenticated fatal bad-record alert: %v", e)
				}
				return
			}
			state := c.ConnectionState()
			if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
				results <- fmt.Errorf("verified chain missing")
				return
			}
			path := state.VerifiedChains[0]
			if !trustedAnchors[string(path[len(path)-1].Raw)] {
				results <- fmt.Errorf("verified path uses an unconfigured anchor")
				return
			}
			if !trustedAnchors[string(state.PeerCertificates[0].Raw)] {
				if len(path) < 2 {
					results <- fmt.Errorf("issuer-only trust path missing")
					return
				}
				fmt.Printf("issuer-only trust verified path depth=%d\n", len(path))
			}

			if c.ConnectionState().NegotiatedProtocol != "http/1.1" {
				results <- fmt.Errorf("ALPN")
				return
			}
			identities <- string(c.ConnectionState().PeerCertificates[0].Raw)
			switch key := c.ConnectionState().PeerCertificates[0].PublicKey.(type) {
			case *rsa.PublicKey:
				bits <- key.N.BitLen()
			case *ecdsa.PublicKey:
				bits <- key.Curve.Params().BitSize
			default:
				panic("unsupported peer key")
			}
			writeDone := make(chan error, 1)
			if mode != "key-update" {
				go func() { _, e := c.Write(payload); writeDone <- e }()
			}
			received := make([]byte, len(payload))
			if _, e := io.ReadFull(c, received); e != nil {
				results <- e
				return
			}
			for i, b := range received {
				if b != byte(255-i) {
					results <- fmt.Errorf("server payload")
					return
				}
			}
			if mode == "key-update" {
				_, e = c.Write(payload)
			} else {
				e = <-writeDone
			}
			if e != nil {
				results <- e
				return
			}
			extra := make([]byte, 1)
			n, e := c.Read(extra)
			if n != 0 || e != io.EOF {
				results <- fmt.Errorf("authenticated shutdown: %d %v", n, e)
				return
			}
			c.Close()
			results <- nil
		}()
	}
	wg.Wait()
	close(results)
	close(bits)
	close(identities)
	for e := range results {
		must(e)
	}
	var rest strings.Builder
	for {
		line, e := reader.ReadString('\n')
		rest.WriteString(line)
		if e == io.EOF {
			break
		}
		must(e)
	}
	must(cmd.Wait())
	if !strings.Contains(rest.String(), fmt.Sprintf("DONE %d", count)) {
		panic("native completion")
	}
	sizes := map[int]int{}
	for b := range bits {
		sizes[b]++
	}
	if mode == "rotate" {
		counts := map[string]int{}
		for id := range identities {
			counts[id]++
		}
		first, _ := pem.Decode(cert)
		secondPEM, e := os.ReadFile(os.Args[6])
		must(e)
		second, _ := pem.Decode(secondPEM)
		if first == nil || second == nil || counts[string(first.Bytes)] != 1 || counts[string(second.Bytes)] != count-1 {
			panic("rotation did not preserve exact old/new certificate generations")
		}
	}

	fmt.Printf("Go native async TLS %s clients=%d key_sizes=%v trust=explicit-anchor-set PASS\n%s%s", mode, count, sizes, rest.String(), diagnostics.String())
}
