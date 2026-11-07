package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Independent recordless TLS oracle only: no QUIC packets, transport parameter
// semantics, recovery or application delivery are implemented by this fixture.
func runQUIC() {
	cert, e := os.ReadFile(os.Args[2])
	must(e)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		panic("roots")
	}
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, ServerName: "synthetic.invalid", RootCAs: roots, NextProtos: []string{"h3"}, Time: func() time.Time { return time.Unix(1790000000, 0) }}})
	defer q.Close()
	q.SetTransportParameters([]byte{0, 1, 2})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	must(q.Start(ctx))
	var hello []byte
	for {
		event := q.NextEvent()
		if event.Kind == tls.QUICNoEvent {
			break
		}
		if event.Kind != tls.QUICWriteData || event.Level != tls.QUICEncryptionLevelInitial {
			panic("initial event")
		}
		hello = append(hello, event.Data...)
	}
	dir := os.Args[4]
	in := filepath.Join(dir, "quic-hello.bin")
	out := filepath.Join(dir, "quic-events.bin")
	must(os.WriteFile(in, hello, 0600))
	cmd := exec.Command(os.Args[1], in, os.Args[2], os.Args[3], out, "quic")
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
		panic("ready")
	}
	data, e := os.ReadFile(out)
	must(e)
	var initial, handshake []byte
	secrets := map[string][]byte{}
	for len(data) > 0 {
		if len(data) < 7 {
			panic("event header")
		}
		n := int(binary.BigEndian.Uint32(data[3:7]))
		if n < 1 || n > 2048 || len(data) < 7+n {
			panic("event bound")
		}
		body := bytes.Clone(data[7 : 7+n])
		switch data[0] {
		case 1:
			if data[1] == 0 {
				initial = append(initial, body...)
			} else if data[1] == 1 {
				handshake = append(handshake, body...)
			} else {
				panic("level")
			}
		case 2:
			if n != 32 {
				panic("secret size")
			}
			secrets[fmt.Sprintf("%d/%d", data[1], data[2])] = body
		default:
			panic("event kind")
		}
		data = data[7+n:]
	}
	var finished []byte
	done, parameters := false, false
	checked := 0
	drain := func() {
		for {
			event := q.NextEvent()
			switch event.Kind {
			case tls.QUICNoEvent:
				return
			case tls.QUICErrorEvent:
				must(event.Err)
			case tls.QUICSetReadSecret, tls.QUICSetWriteSecret:
				level := 1
				if event.Level == tls.QUICEncryptionLevelApplication {
					level = 2
				} else if event.Level != tls.QUICEncryptionLevelHandshake {
					panic("secret level")
				}
				direction := 1
				if event.Kind == tls.QUICSetWriteSecret {
					direction = 0
				}
				if event.Suite != tls.TLS_AES_128_GCM_SHA256 || !bytes.Equal(event.Data, secrets[fmt.Sprintf("%d/%d", level, direction)]) {
					panic("directional secret mismatch")
				}
				checked++
			case tls.QUICTransportParameters:
				if !bytes.Equal(event.Data, []byte{9, 8, 7}) {
					panic("parameters")
				}
				parameters = true
			case tls.QUICWriteData:
				if event.Level != tls.QUICEncryptionLevelHandshake {
					panic("write level")
				}
				finished = append(finished, event.Data...)
			case tls.QUICHandshakeDone:
				done = true
			default:
				panic(fmt.Sprintf("unexpected QUIC TLS event %v", event.Kind))
			}
		}
	}
	for _, part := range []struct {
		level tls.QUICEncryptionLevel
		data  []byte
	}{{tls.QUICEncryptionLevelInitial, initial}, {tls.QUICEncryptionLevelHandshake, handshake}} {
		for at := 0; at < len(part.data); {
			n := 7
			if n > len(part.data)-at {
				n = len(part.data) - at
			}
			must(q.HandleData(part.level, part.data[at:at+n]))
			at += n
			drain()
		}
	}
	if !done || !parameters || checked != 4 || len(finished) != 36 || q.ConnectionState().NegotiatedProtocol != "h3" {
		panic("QUIC TLS result")
	}
	_, e = stdin.Write(finished)
	must(e)
	complete, e := reader.ReadString('\n')
	must(e)
	if complete != "COMPLETE\n" {
		panic("native authentication")
	}
	must(stdin.Close())
	must(cmd.Wait())
	fmt.Printf("independent Go QUIC TLS: opaque TP/ALPN, fragmented CRYPTO bytes, four matching directional secrets, native Finished/Complete PASS; %s", log.String())
}
