package tls
import "core:testing"
import "core:thread"

Replay_Attempt :: struct {
	owner:    ^Anti_Replay,
	identity: [32]u8,
	result:   Anti_Replay_Error,
}

@(test)
anti_replay_atomic_reservation_expiry_and_capacity :: proc(t: ^testing.T) {
	owner: Anti_Replay
	testing.expect_value(t, anti_replay_init(&owner, 1), .None)
	defer anti_replay_close(&owner)
	attempts: [16]Replay_Attempt
	workers: [16]^thread.Thread
	for &attempt, i in attempts {
		attempt.owner = &owner
		attempt.identity[0] = 7
		workers[i] = thread.create_and_start_with_poly_data(
			&attempt,
			proc(a: ^Replay_Attempt) {a.result = anti_replay_reserve(a.owner, a.identity, 200, 100)},
		)
	}
	success := 0
	for worker in workers {thread.join(worker); thread.destroy(worker)}
	for attempt in attempts {
		if attempt.result == .None {
			success += 1
		}
		else {
			testing.expect_value(t, attempt.result, .Replayed)
		}
	}
	testing.expect_value(t, success, 1)
	other: [32]u8
	other[0] = 8
	testing.expect_value(t, anti_replay_reserve(&owner, other, 300, 101), .Capacity)
	testing.expect_value(t, anti_replay_reserve(&owner, other, 300, 200), .None)
	testing.expect_value(t, anti_replay_reserve(&owner, other, 301, 199), .Clock)
	anti_replay_close(&owner)
	testing.expect_value(t, anti_replay_reserve(&owner, other, 300, 200), .Closed)
}
