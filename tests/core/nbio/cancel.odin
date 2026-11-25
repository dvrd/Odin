package tests_nbio

import "core:nbio"
import "core:net"
import "core:testing"
import "core:time"

@(test)
cancel_pending_and_completed_timeout :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		State :: struct {
			calls:     int,
			cancelled: bool,
		}
		pending, completed: State
		callback :: proc(op: ^nbio.Operation, s: ^State) {
			s.calls += 1
			s.cancelled = op.cancelled
		}
		timer := nbio.timeout_poly(time.Hour, &pending, callback)
		ev(t, nbio.cancel(timer), nil)
		ev(t, nbio.cancel(timer), nil)
		ev(t, pending.calls, 0) // Never inline.
		ready := nbio.next_tick_poly(&completed, callback)
		ev(t, nbio.cancel(ready), nil)
		ev(t, nbio.run(), nil)
		ev(t, pending.calls, 1)
		e(t, pending.cancelled)
		ev(t, completed.calls, 1)
		e(t, !completed.cancelled) // Already-completed work wins.
	}
}

@(test)
cancel_accept_delivers_completion :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		server, listen_err := nbio.listen_tcp({net.IP4_Loopback, 0})
		ev(t, listen_err, nil)
		if listen_err != nil do return
		defer nbio.close(server)
		calls := 0
		accept := nbio.accept_poly(server, &calls, proc(op: ^nbio.Operation, calls: ^int) {
			calls^ += 1
			assert(op.cancelled)
		})
		ev(t, nbio.cancel(accept), nil)
		ev(t, nbio.run(), nil)
		ev(t, calls, 1)
	}
}

@(test)
cancel_partial_receive_preserves_count :: proc(t: ^testing.T) {
	if event_loop_guard(t) {
		testing.set_fail_timeout(t, 5 * time.Second)
		server, listen_err := net.listen_tcp({net.IP4_Loopback, 0})
		ev(t, listen_err, nil)
		if listen_err != nil do return
		defer net.close(server)
		ep, endpoint_err := net.bound_endpoint(server)
		ev(t, endpoint_err, nil)
		client, dial_err := net.dial_tcp(ep)
		ev(t, dial_err, nil)
		if dial_err != nil do return
		defer net.close(client)
		peer, _, accept_err := net.accept_tcp(server)
		ev(t, accept_err, nil)
		if accept_err != nil do return
		defer nbio.close(peer)
		ev(t, nbio.associate_socket(peer), nil)
		_, send_err := net.send_tcp(client, []u8{7, 8})
		ev(t, send_err, nil)
		State :: struct {
			buffer: [4]u8,
			calls:  int,
		}
		state: State
		op := nbio.recv_poly(peer, {state.buffer[:]}, &state, proc(op: ^nbio.Operation, s: ^State) {
				s.calls += 1
				assert(op.cancelled)
				assert(op.recv.received == 2)
				assert(s.buffer[0] == 7 && s.buffer[1] == 8)
			}, all = true)
		// Tick until the first fragment has been consumed, then cancel the remainder.
		for op.recv.received < 2 {ev(t, nbio.tick(0), nil)}
		ev(t, nbio.cancel(op), nil)
		ev(t, nbio.run(), nil)
		ev(t, state.calls, 1)
	}
}
