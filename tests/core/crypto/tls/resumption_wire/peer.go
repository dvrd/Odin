package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

func main() {
	mode, endpoint, dir := os.Args[1], os.Args[2], os.Args[3]
	roots := x509.NewCertPool()
	b, e := os.ReadFile(dir + "/root.pem")
	if e != nil {
		panic(e)
	}
	if !roots.AppendCertsFromPEM(b) {
		panic("roots")
	}
	cfg := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(4), NextProtos: []string{"http/1.1"}}
	mutual := len(os.Args) > 4 && os.Args[4] == "mtls"
	if mode == "server" {
		cert, e := tls.LoadX509KeyPair(dir+"/server.pem", dir+"/server-key.pem")
		if e != nil {
			panic(e)
		}
		cfg.Certificates = []tls.Certificate{cert}
		if mutual {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
			cfg.ClientCAs = roots
		}
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			panic(e)
		}
		defer l.Close()
		fmt.Println("READY", l.Addr())
		for i := 0; i < 2; i++ {
			raw, e := l.Accept()
			if e != nil {
				panic(e)
			}
			c := tls.Server(raw, cfg)
			if e = c.Handshake(); e != nil {
				panic(e)
			}
			if c.ConnectionState().DidResume != (i == 1) {
				panic("Go server resumed mismatch")
			}
			if mutual && len(c.ConnectionState().VerifiedChains) == 0 {
				panic("missing verified resumed peer")
			}
			if _, e = c.Write([]byte("OK")); e != nil {
				panic(e)
			}
			c.Close()
			fmt.Println("PASS Go-server", i)
		}
		return
	}
	if mutual {
		cert, e := tls.LoadX509KeyPair(dir+"/client.pem", dir+"/client-key.pem")
		if e != nil {
			panic(e)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	for i := 0; i < 2; i++ {
		c, e := tls.Dial("tcp", endpoint, cfg)
		if e != nil {
			panic(e)
		}
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		r, e := http.ReadResponse(bufio.NewReader(c), nil)
		if e != nil {
			panic(e)
		}
		body, e := io.ReadAll(r.Body)
		if e != nil {
			panic(e)
		}
		r.Body.Close()
		wantResume := i == 1 && (len(os.Args) < 6 || os.Args[5] != "full")
		if string(body) != "OK" || c.ConnectionState().DidResume != wantResume {
			panic("Go client response/resumed mismatch")
		}
		c.Close()
		fmt.Println("PASS Go-client", i)
	}
}
