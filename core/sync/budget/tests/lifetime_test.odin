package budget_test

import budget ".."
import "base:intrinsics"
import rt "base:runtime"
import "core:mem"
import "core:testing"
import "core:thread"
import "core:time"

Metadata :: struct {
	backing:                    mem.Allocator,
	query:                      ^budget.Scope,
	attempts, fail_at, queries: int,
}

metadata_allocator :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	state := cast(^Metadata)data
	if state.query != nil {
		_, error := budget.snapshot(state.query^)
		assert(error == .None)
		state.queries += 1
	}
	if size > 0 && (mode == .Alloc || mode == .Alloc_Non_Zeroed) {
		state.attempts += 1
		if state.attempts == state.fail_at do return nil, .Out_Of_Memory
	}
	return state.backing.procedure(state.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(test)
metadata_failure_rolls_back_and_backing_callbacks_can_query_the_hierarchy :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 3 * time.Second)
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	state := Metadata {
		backing = mem.tracking_allocator(&track),
		fail_at = 1,
	}
	allocator := mem.Allocator{metadata_allocator, &state}
	_, failed := budget.create_root({10, 1, 1}, allocator)
	testing.expect_value(t, failed, .Allocation_Failed)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	state.fail_at = 0
	root, error := budget.create_root({10, 1, 1}, allocator)
	assert(error == .None)
	state.query = &root
	state.fail_at = state.attempts + 1
	_, child_failed := budget.create_child(root, {10, 1, 1})
	testing.expect_value(t, child_failed, .Allocation_Failed)
	testing.expect_value(t, view(root).scope_nodes, u64(1))
	state.fail_at = 0
	child, created := budget.create_child(root, {10, 1, 1})
	assert(created == .None)
	testing.expect_value(t, view(root).scope_nodes, u64(2))
	budget.release_scope(&child)
	assert(budget.close(root) == .None)
	_, closed := budget.create_child(root, {})
	testing.expect_value(t, closed, .Closed)
	testing.expect_value(t, view(root).scope_nodes, u64(1))
	testing.expect(t, state.queries >= 4)
	state.query = nil
	budget.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

Concurrent :: struct {
	scope: budget.Scope,
	done:  ^int,
}

concurrent_charges :: proc(state: ^Concurrent) {
	for _ in 0 ..< 1000 {
		lease, error := budget.reserve(state.scope, {4, 1, 1}, .Queued)
		assert(error == .None)
		assert(budget.set_job_phase(&lease, .Running) == .None)
		thread.yield()
		assert(budget.set_job_phase(&lease, .Held) == .None)
		budget.release(&lease)
	}
	intrinsics.atomic_add(state.done, 1)
}

@(test)
concurrent_resource_vectors_and_job_phases_remain_consistent :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	root, error := budget.create_root({16, 4, 4}, mem.tracking_allocator(&track))
	assert(error == .None)
	states: [4]Concurrent
	workers: [4]^thread.Thread
	done: int
	for &state, i in states {
		child, created := budget.create_child(root, {4, 1, 1})
		assert(created == .None)
		state.scope, state.done = child, &done
		workers[i] = thread.create_and_start_with_poly_data(&states[i], concurrent_charges)
		assert(workers[i] != nil)
	}
	for intrinsics.atomic_load(&done) != len(workers) {
		s := view(root)
		testing.expect(t, s.used.jobs <= 4 && s.used.streams == s.used.jobs)
		testing.expect_value(t, s.used.bytes, 4 * s.used.jobs)
		testing.expect_value(t, s.used.queued + s.used.running + s.used.held, s.used.jobs)
		thread.yield()
	}
	for worker in workers {thread.join(worker); thread.destroy(worker)}
	testing.expect_value(t, view(root).used, budget.Usage{})
	testing.expect(t, view(root).peak.bytes <= 16 && view(root).peak.jobs <= 4)
	for &state in states do budget.release_scope(&state.scope)
	budget.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

Rebinding :: struct {
	first, second: budget.Scope,
	lease:         budget.Lease,
	done:          ^int,
}

rebind_between_siblings :: proc(state: ^Rebinding) {
	assert(budget.set_job_phase(&state.lease, .Running) == .None)
	for _ in 0 ..< 1000 {
		destination := state.first
		if budget.same_scope(budget.scope_of(state.lease), state.first) do destination = state.second
		assert(budget.rebind(&state.lease, destination) == .None)
		thread.yield()
	}
	assert(budget.set_job_phase(&state.lease, .Held) == .None)
	budget.release(&state.lease)
	intrinsics.atomic_add(state.done, 1)
}

@(test)
opposite_sibling_rebinds_keep_common_ancestor_charges_exact :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	root, e := budget.create_root({8, 2, 2})
	assert(e == .None)
	first, e1 := budget.create_child(root, {8, 2, 2})
	assert(e1 == .None)
	second, e2 := budget.create_child(root, {8, 2, 2})
	assert(e2 == .None)
	states: [2]Rebinding
	workers: [2]^thread.Thread
	done: int
	for &state, i in states {
		state.first, state.second, state.done = first, second, &done
		initial := first if i == 0 else second
		lease, accepted := budget.reserve(initial, {4, 1, 1}, .Queued)
		assert(accepted == .None)
		state.lease = lease
		lease = {}
	}
	for i in 0 ..< len(states) {
		workers[i] = thread.create_and_start_with_poly_data(&states[i], rebind_between_siblings)
		assert(workers[i] != nil)
	}
	for intrinsics.atomic_load(&done) != len(workers) {
		current := view(root).used
		testing.expect_value(t, current.bytes, 4 * current.jobs)
		testing.expect_value(t, current.queued + current.running + current.held, current.jobs)
		testing.expect(t, current.bytes <= 8 && current.jobs <= 2)
		thread.yield()
	}
	for worker in workers {thread.join(worker); thread.destroy(worker)}
	testing.expect_value(t, view(root).used, budget.Usage{})
	testing.expect_value(t, view(root).peak.bytes, u64(8))
	budget.release_scope(&first)
	budget.release_scope(&second)
	budget.release_scope(&root)
}
