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
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	binary, dir := os.Args[1], os.Args[2]
	root, e := os.ReadFile(filepath.Join(dir, "root.pem"))
	must(e)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		panic("root")
	}
	cases := []struct {
		identity, policy string
		pass             bool
	}{{"client", "require", true},
		{"client-large", "require", true}, {"none", "request", true}, {"none", "require", false}, {"wrong-eku", "require", false}, {"expired", "require", false}, {"rogue", "require", false}}
	for _, c := range cases {
		want := "fail"
		if c.pass {
			want = "pass"
		}
		cmd := exec.Command(binary, "server", dir, "-", c.identity, c.policy, want)
		out, e := cmd.StdoutPipe()
		must(e)
		cmd.Stderr = os.Stderr
		must(cmd.Start())
		r := bufio.NewReader(out)
		line, e := r.ReadString('\n')
		must(e)
		if !strings.HasPrefix(line, "READY ") {
			panic(line)
		}
		endpoint := strings.TrimSpace(strings.TrimPrefix(line, "READY "))
		config := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"http/1.1"}}
		if c.identity != "none" {
			cert, e := tls.LoadX509KeyPair(filepath.Join(dir, c.identity+".pem"), filepath.Join(dir, c.identity+"-key.pem"))
			must(e)
			config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
		}
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", endpoint, config)
		success := false
		if e == nil {
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			_, e = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
			if e == nil {
				response, er := http.ReadResponse(bufio.NewReader(conn), nil)
				if er == nil {
					body, er := io.ReadAll(response.Body)
					success = er == nil && response.StatusCode == 200 && string(body) == "OK"
					response.Body.Close()
				}
			}
			conn.Close()
		}
		if success != c.pass {
			panic(fmt.Sprintf("native Saba case %+v success=%v err=%v", c, success, e))
		}
		tail, _ := io.ReadAll(r)
		must(cmd.Wait())
		fmt.Printf("PASS Go-client/native-Saba %s %s %s %s", c.identity, c.policy, want, tail)
	}
	serverCert, e := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"))
	must(e)
	for _, mode := range []string{"surf", "async"} {
		for _, c := range cases {
			config := &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
			if c.policy == "request" {
				config.ClientAuth = tls.VerifyClientCertIfGiven
			}
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			must(e)
			done := make(chan error, 1)
			go func() {
				raw, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := tls.Server(raw, config)
				e = conn.Handshake()
				if !c.pass {
					if e == nil {
						done <- fmt.Errorf("unexpected peer authentication")
					} else {
						done <- nil
					}
					return
				}
				if e != nil {
					done <- e
					return
				}
				if (len(conn.ConnectionState().VerifiedChains) > 0) != (c.identity != "none") {
					done <- fmt.Errorf("verified identity missing")
					return
				}
				if mode == "surf" {
					_, e = http.ReadRequest(bufio.NewReader(conn))
					if e == nil {
						_, e = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
					}
				} else {
					_, e = io.WriteString(conn, "OK")
				}
				done <- e
			}()
			want := "fail"
			if c.pass {
				want = "pass"
			}
			cmd := exec.Command(binary, mode, dir, listener.Addr().String(), c.identity, c.policy, want)
			output, e := cmd.CombinedOutput()
			listener.Close()
			must(e)
			must(<-done)
			fmt.Printf("PASS Go-server/native-%s %s %s %s %s", mode, c.identity, c.policy, want, output)
		}
	}
	for _, c := range cases[:4] {
		want := "fail"
		if c.pass {
			want = "pass"
		}
		server := exec.Command(binary, "server-h3", dir, "-", c.identity, c.policy, want)
		output, e := server.StdoutPipe()
		must(e)
		server.Stderr = os.Stderr
		must(server.Start())
		reader := bufio.NewReader(output)
		line, e := reader.ReadString('\n')
		must(e)
		if !strings.HasPrefix(line, "READY ") {
			panic(line)
		}
		endpoint := strings.TrimSpace(strings.TrimPrefix(line, "READY "))
		client := exec.Command(binary, "surf-h3", dir, endpoint, c.identity, c.policy, want)
		body, e := client.CombinedOutput()
		if e != nil {
			server.Process.Kill()
			panic(fmt.Sprintf("Surf/SabaH3: %v %s", e, body))
		}
		tail, _ := io.ReadAll(reader)
		must(server.Wait())
		fmt.Printf("PASS native-Surf/native-Saba-HTTP3 %s %s %s %s%s", c.identity, c.policy, want, body, tail)
	}

}
