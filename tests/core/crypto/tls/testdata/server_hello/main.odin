package main
import "core:crypto/tls"
import "core:os"
import "core:fmt"
main :: proc() {
 for path in os.args[1:] {
  data, err := os.read_entire_file(path, context.allocator); assert(err == nil); defer delete(data)
  hello, status := tls.server_client_hello_decode(data); assert(status == .None)
  selection, result := tls.server_client_hello_negotiate(hello); assert(result == .None)
  assert(len(selection.peer_key_share) == 32 && string(hello.server_name) == "fixture.invalid")
  fmt.printf("independent capture accepted: %s (%d bytes)\n", path, len(data))
 }
}
