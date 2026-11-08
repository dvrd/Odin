package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Test-owned synchronous record adapter for an independent OpenSSL client. It
// owns one loopback listener/connection/process and has no production API.
func runOpenSSL() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mode := os.Getenv("WEBTOOLS_OPENSSL_CASE")
	negative := mode == "hostname" || mode == "trust" || mode == "time" || mode == "before"
	groups := "X25519"
	if mode == "p256" {
		groups = "P-256"
	}
	if mode == "retry" {
		groups = "P-256:X25519"
	}
	if mode == "retry-p256" {
		groups = "P-384:P-256"
	}
	listener, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(e)
	defer listener.Close()
	must(listener.SetDeadline(time.Now().Add(15 * time.Second)))
	hostname := "synthetic.invalid"
	if mode == "hostname" {
		hostname = "wrong.invalid"
	}
	ca := os.Args[2]
	if mode == "trust" {
		ca = filepath.Join(filepath.Dir(ca), "rsa4096-valid.pem")
	}
	at := "1790000000"
	if mode == "time" {
		at = "2000000000"
	}
	if mode == "before" {
		at = "0"
	}
	args := []string{"s_client", "-connect", listener.Addr().String(), "-servername", "synthetic.invalid", "-verify_hostname", hostname, "-verify_return_error", "-CAfile", ca, "-no-CApath", "-no-CAstore", "-attime", at, "-tls1_3", "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-groups", groups, "-sigalgs", "rsa_pss_rsae_sha256:rsa_pkcs1_sha256", "-quiet", "-no_ign_eof", "-nocommands"}
	if mode == "alpn" {
		args = append(args, "-alpn", "h2,http/1.1")
	}
	client := exec.CommandContext(ctx, os.Getenv("WEBTOOLS_OPENSSL"), args...)
	if mode == "large16" {
		client = exec.CommandContext(ctx, os.Getenv("WEBTOOLS_OPENSSL_LARGE_CLIENT"), listener.Addr().String(), ca)
	}
	ci, e := client.StdinPipe()
	must(e)
	co, e := client.StdoutPipe()
	must(e)
	var diagnostics bytes.Buffer
	client.Stderr = &diagnostics
	must(client.Start())
	defer func() {
		if client.ProcessState == nil {
			client.Process.Kill()
			client.Wait()
			fmt.Fprintln(os.Stderr, "OpenSSL adapter abort diagnostics:", diagnostics.String())
		}
	}()
	conn, e := listener.AcceptTCP()
	must(e)
	defer conn.Close()
	must(conn.SetDeadline(time.Now().Add(15 * time.Second)))
	kind, ch := readRecord(conn)
	if kind != 22 {
		panic("OpenSSL hello")
	}
	dir := os.Args[4]
	in := filepath.Join(dir, "openssl-hello.bin")
	out := filepath.Join(dir, "openssl-events.bin")
	must(os.WriteFile(in, ch, 0600))
	nativeArgs := []string{in, os.Args[2], os.Args[3], out}
	if negative {
		nativeArgs = append(nativeArgs, "reject")
	} else if mode == "alpn" {
		nativeArgs = append(nativeArgs, "alpn")
	}
	native := exec.CommandContext(ctx, os.Args[1], nativeArgs...)
	ni, e := native.StdinPipe()
	must(e)
	no, e := native.StdoutPipe()
	must(e)
	var log bytes.Buffer
	native.Stderr = &log
	must(native.Start())
	defer func() {
		if native.ProcessState == nil {
			native.Process.Kill()
			native.Wait()
		}
	}()
	reader := bufio.NewReader(no)
	ready, e := reader.ReadString('\n')
	must(e)
	expectRetry := mode == "retry" || mode == "retry-p256"
	if ready == "RETRY\n" {
		if !expectRetry {
			panic("unexpected OpenSSL retry")
		}
		event, e := os.ReadFile(out)
		must(e)
		if len(event) < 7 || event[0] != 1 || event[1] != 0 || int(binary.BigEndian.Uint32(event[3:7])) != len(event)-7 {
			panic("retry event")
		}
		writeRecord(conn, 22, event[7:])
		var second []byte
		for {
			kind, second = readRecord(conn)
			if kind != 20 {
				break
			}
		}
		if kind != 22 || len(second) > 65536 {
			panic("OpenSSL CH2")
		}
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(second)))
		_, e = ni.Write(append(header, second...))
		must(e)
		ready, e = reader.ReadString('\n')
		must(e)
	} else if expectRetry {
		panic("missing OpenSSL retry")
	}
	if ready != "READY\n" {
		panic("native ready")
	}
	data, e := os.ReadFile(out)
	must(e)
	var hello, flight []byte
	secrets := make([][]byte, 4)
	si := 0
	for len(data) > 0 {
		if len(data) < 7 {
			panic("event header")
		}
		n := int(binary.BigEndian.Uint32(data[3:7]))
		if n < 1 || n > 2048 || len(data) < 7+n {
			panic("event size")
		}
		body := bytes.Clone(data[7 : 7+n])
		switch data[0] {
		case 1:
			if data[1] == 0 {
				hello = append(hello, body...)
			} else if data[1] == 1 {
				flight = append(flight, body...)
			} else {
				panic("event level")
			}
		case 2:
			if n != 32 || si >= 4 || data[1] != byte(1+si/2) || data[2] != byte(1-si%2) {
				panic("secret order")
			}
			secrets[si] = body
			si++
		default:
			panic("event kind")
		}
		data = data[7+n:]
	}
	if si != 4 {
		panic("missing secrets")
	}
	writeRecord(conn, 22, hello)
	hw := protect(secrets[0])
	hr := protect(secrets[1])
	// Deterministic record cuts cross handshake headers, certificate DER and CV.
	for at := 0; at < len(flight); {
		n := 1 + at%127
		if n > len(flight)-at {
			n = len(flight) - at
		}
		hw.send(conn, 22, flight[at:at+n])
		at += n
	}
	// OpenSSL 4 may send a cleartext fatal verification alert before its
	// handshake finishes. Only negative fixtures allow that input, followed
	// by a required exact independent verification-error code and abort.
	kind, finished := hr.recvWithAlert(conn, negative)
	if negative {
		if kind != 21 || len(finished) != 2 || finished[0] != 2 {
			panic("expected OpenSSL certificate alert")
		}
		must(ci.Close())
		result := client.Wait()
		if result == nil {
			panic("expected OpenSSL verification failure")
		}
		code := "18"
		if mode == "hostname" {
			code = "62"
		}
		if mode == "time" {
			code = "10"
		}
		if mode == "before" {
			code = "9"
		}
		if !strings.Contains(diagnostics.String(), "verify error:num="+code+":") {
			panic("wrong OpenSSL verification failure: " + diagnostics.String())
		}
		_, e = ni.Write([]byte{1})
		must(e)
		state, e := reader.ReadString('\n')
		must(e)
		if state != "REJECTED\n" {
			panic("native reject")
		}
		must(ni.Close())
		must(native.Wait())
		fmt.Printf("independent OpenSSL %s verify-code=%s, native abort/no Complete/zero grants PASS; %s", mode, code, log.String())
		return
	}
	if kind != 22 || len(finished) != 36 || finished[0] != 20 {
		panic("OpenSSL Finished")
	}
	_, e = ni.Write(finished)
	must(e)
	state, e := reader.ReadString('\n')
	must(e)
	if state != "COMPLETE\n" {
		panic("native Complete")
	}
	must(ni.Close())
	must(native.Wait())
	aw := protect(secrets[2])
	ar := protect(secrets[3])
	aw.send(conn, 23, []byte("server"))
	received := make([]byte, 6)
	_, e = io.ReadFull(co, received)
	must(e)
	if string(received) != "server" {
		panic("OpenSSL server data")
	}
	_, e = ci.Write([]byte("client\n"))
	must(e)
	kind, body := ar.recv(conn)
	if kind != 23 || string(body) != "client\n" {
		panic("OpenSSL client data")
	}
	// Complete the fixture's own close_notify exchange before waiting for the
	// independent process; OpenSSL 4's SSL_shutdown can await peer shutdown.
	aw.send(conn, 21, []byte{1, 0})
	must(ci.Close())
	kind, closed := ar.recv(conn)
	if kind != 21 || len(closed) != 2 || closed[1] != 0 {
		panic("OpenSSL close_notify")
	}
	must(client.Wait())
	fmt.Printf("independent OpenSSL %s: CV/server Finished, native client Finished/Complete, split records and bidirectional application exchange PASS; %s", mode, log.String())
	if mode == "large16" {
		fmt.Print(diagnostics.String())
	}
}
