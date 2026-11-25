#+build darwin, freebsd, openbsd, netbsd
package tests_nbio

import "core:nbio"
import "core:net"
import "core:sys/posix"
import "core:testing"
import "core:time"

@(test)
native_close_and_descriptor_reassociation :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		pair: [2]posix.FD
		assert(posix.socketpair(.UNIX, .STREAM, posix.Protocol(0), &pair) == .OK)
		first_fd := pair[0]
		defer net.close(net.TCP_Socket(first_fd))
		calls := 0
		buffer: [1]byte
		for iteration in 0 ..< 4 {
			if iteration > 0 {
				assert(posix.socketpair(.UNIX, .STREAM, posix.Protocol(0), &pair) == .OK)
				// Atomically close our old socket and reuse its number. Keeping the
				// target occupied prevents another test from acquiring that number.
				assert(posix.dup2(pair[0], first_fd) == first_fd)
				assert(posix.close(pair[0]) == .OK)
				pair[0] = first_fd
			}
			assert(nbio.associate_socket(net.TCP_Socket(pair[0])) == nil)
			op := nbio.recv_poly(net.TCP_Socket(pair[0]), {buffer[:]}, &calls, proc(op: ^nbio.Operation, calls: ^int) {
				if op.recv.err == nil && op.recv.received == 1 do calls^ += 1
			})
			assert(nbio.tick(0) == nil)
			// Reassociating a still-live socket must preserve its waiting operation.
			assert(nbio.associate_socket(net.TCP_Socket(pair[0])) == nil)
			value := byte(iteration + 1)
			assert(posix.write(pair[1], &value, 1) == 1)
			for _ in 0 ..< 100 {
				if calls == iteration + 1 do break
				assert(nbio.tick(time.Millisecond) == nil)
			}
			observed := calls
			if observed != iteration + 1 {
				nbio.cancel(op)
				assert(nbio.run() == nil)
			}
			testing.expect_value(t, observed, iteration + 1)
			testing.expect_value(t, buffer[0], value)
			assert(posix.close(pair[1]) == .OK)
			if observed != iteration + 1 do return
		}
	}
}

// Run with -define:ODIN_NBIO_QUEUE_SIZE=8 as well: twenty distinct knotes
// overflow that changelist and must all reach the kernel before a blocking wait.
@(test)
socket_registrations_survive_changelist_overflow :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		N :: 20
		pairs: [N][2]posix.FD
		buffers: [N][1]byte
		calls := 0
		for &pair, i in pairs {
			assert(posix.socketpair(.UNIX, .STREAM, posix.Protocol(0), &pair) == .OK)
			assert(nbio.associate_socket(net.TCP_Socket(pair[0])) == nil)
			nbio.recv_poly(net.TCP_Socket(pair[0]), {buffers[i][:]}, &calls, proc(op: ^nbio.Operation, calls: ^int) {
				assert(op.recv.err == nil && op.recv.received == 1)
				calls^ += 1
			})
		}
		assert(nbio.tick(0) == nil)
		value := byte(42)
		for pair in pairs do assert(posix.write(pair[1], &value, 1) == 1)
		assert(nbio.run() == nil)
		testing.expect_value(t, calls, N)
		for buffer in buffers do testing.expect_value(t, buffer[0], value)
		for pair in pairs {
			nbio.close(net.TCP_Socket(pair[0]))
			assert(posix.close(pair[1]) == .OK)
		}
		assert(nbio.run() == nil)
	}
}
