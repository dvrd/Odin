// Independent local TLS1.3 peer. The h2 token tests negotiation, not HTTP/2.
package main

import (
 "bufio"
 "crypto/tls"
 "encoding/json"
 "flag"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "strings"
 "time"
)

func main() {
 directory:=flag.String("dir",".","owned fixture certificate directory")
 flag.Parse()
 cert,err:=tls.LoadX509KeyPair(filepath.Join(*directory,"leaf.pem"),filepath.Join(*directory,"key.pem"))
 if err!=nil {panic(err)}
 endpoints:=map[string]string{}
 for name,protocols:=range map[string][]string{"ordered":{"h2","http/1.1"},"none":nil,"incompatible":{"private/server"},"http1":{"http/1.1"}} {
  listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil {panic(err)}
  endpoints[name]=listener.Addr().String()
  config:=&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,CurvePreferences:[]tls.CurveID{tls.X25519},NextProtos:protocols}
  go func(listener net.Listener,config *tls.Config) {
   for {
    raw,err:=listener.Accept();if err!=nil {return}
    go func(raw net.Conn) {
     defer raw.Close()
     raw.SetDeadline(time.Now().Add(3*time.Second))
     connection:=tls.Server(raw,config)
     if connection.Handshake()!=nil {return}
     reader:=bufio.NewReader(connection)
     line,err:=reader.ReadString('\n');if err!=nil {return}
     if strings.HasPrefix(line,"GET ") {
      for {header,err:=reader.ReadString('\n');if err!=nil {return};if header=="\r\n" {break}}
      fmt.Fprint(connection,"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
     } else {fmt.Fprint(connection,line)}
    }(raw)
   }
  }(listener,config)
 }
 if err:=json.NewEncoder(os.Stdout).Encode(endpoints);err!=nil {panic(err)}
 select{}
}
