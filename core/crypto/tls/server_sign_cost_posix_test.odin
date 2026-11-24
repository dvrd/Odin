#+build darwin, linux
package tls

import "core:fmt"
import "core:mem"
import "core:sys/posix"
import "core:testing"
import "core:time"
import credential_store "credentials/store"

@(test)
server_flight_signing_cost :: proc(t: ^testing.T) {
	for large in ([]bool{false, true}) {
		store := flight_test_store(t, large)
		lease, e := credential_store.acquire(store)
		assert(e.kind == .None)
		before, after: posix.rusage
		assert(posix.getrusage(.SELF, &before) == {})
		started := time.tick_now()
		for _ in 0 ..< 3 {
			output: [512]u8
			digest: [32]u8
			digest[0] = 153
			prior := context.allocator
			context.allocator = mem.panic_allocator()
			n, se := credential_store.sign_digest_pss_sha256(store, lease, digest, output[:])
			context.allocator = prior
			testing.expect(t, se.kind == .None && n == (512 if large else 256))
		}
		elapsed := time.tick_since(started)
		assert(posix.getrusage(.SELF, &after) == {})
		user :=
			i64(after.ru_utime.tv_sec - before.ru_utime.tv_sec) * 1000000 +
			i64(after.ru_utime.tv_usec - before.ru_utime.tv_usec)
		system :=
			i64(after.ru_stime.tv_sec - before.ru_stime.tv_sec) * 1000000 +
			i64(after.ru_stime.tv_usec - before.ru_stime.tv_usec)
		fmt.printf(
			"RSA%d 3 signatures: user_cpu_us=%d system_cpu_us=%d wall=%v; context allocator=panic; fixed output=512\n",
			4096 if large else 2048,
			user,
			system,
			elapsed,
		)
		assert(credential_store.release(store, &lease).kind == .None)
		assert(credential_store.destroy(&store).kind == .None)
	}
}
