// Run locally: go run core/crypto/tls/testdata/generate_server_go_hello.go
// No sockets are opened: a capture-only net.Conn stops at the first read.
package main

import (
 "crypto/tls"
 "fmt"
 "io"
 "net"
 "os"
 "time"
)
type capture struct{ wire []byte }
func (c *capture) Read(p []byte) (int,error) {return 0,io.EOF}
func (c *capture) Write(p []byte) (int,error) {c.wire=append(c.wire,p...); return len(p),nil}
func (*capture) Close() error {return nil}
func (*capture) LocalAddr() net.Addr {return nil}
func (*capture) RemoteAddr() net.Addr {return nil}
func (*capture) SetDeadline(time.Time) error {return nil}
func (*capture) SetReadDeadline(time.Time) error {return nil}
func (*capture) SetWriteDeadline(time.Time) error {return nil}
func main(){
 c:=new(capture)
 client:=tls.Client(c,&tls.Config{ServerName:"fixture.invalid",MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,CurvePreferences:[]tls.CurveID{tls.X25519},NextProtos:[]string{"h2","http/1.1"}})
 _=client.Handshake()
 var hello []byte
 for p:=c.wire;len(p)>=5; {n:=int(p[3])<<8|int(p[4]);if len(p)<5+n {panic("truncated capture")};if p[0]==22 {hello=append(hello,p[5:5+n]...)};p=p[5+n:]}
 if len(hello)<4||hello[0]!=1 {panic("no ClientHello")}
 path:="core/crypto/tls/testdata/server_go_client_hello.wire"
 if err:=os.WriteFile(path,hello,0644);err!=nil {panic(err)}
 fmt.Printf("wrote %s: %d bytes; %s\n",path,len(hello),tls.VersionName(tls.VersionTLS13))
}
