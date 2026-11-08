package mem_budget_test

import charged ".."
import rt "base:runtime"
import "core:mem"
import "core:sync"
import scopes "core:sync/budget"
import "core:testing"
import "core:thread"
import "core:time"

Worker :: struct {
	binding:     charged.Binding,
	destination: scopes.Scope,
	start:       ^sync.Sema,
}
worker :: proc(state: ^Worker) {
	assert(sync.sema_wait_with_timeout(state.start, 3 * time.Second))
	defer charged.release(&state.binding)
	for _ in 0 ..< 500 {
		bytes, allocated := charged.allocate(state.binding, 32, 64)
		assert(allocated.kind == .None)
		for &byte in bytes do byte = 19
		managed := charged.allocator(state.binding)
		assert(
			charged.rebind_allocation(managed, raw_data(bytes), state.destination).kind == .None,
		)
		resized, grown := charged.resize(state.binding, bytes, 128, 128)
		assert(grown.kind == .None)
		for byte in resized[:32] do assert(byte == 19)
		info, known := charged.allocation_info(managed, raw_data(resized)); assert(known)
		assert(scopes.same_scope(info.scope, state.destination))
		assert(charged.deallocate(state.binding, raw_data(resized)).kind == .None)
	}
}

@(test)
concurrent_allocations_rebind_resize_and_reference_retirement_release_all_heap :: proc(
	t: ^testing.T,
) {
	testing.set_fail_timeout(t, 10 * time.Second)
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 1024 * 1024}, allocator); assert(re == .None)
	a, ae := scopes.create_child(root, {bytes = 1024 * 1024}); assert(ae == .None)
	b, be := scopes.create_child(root, {bytes = 1024 * 1024}); assert(be == .None)
	binding, error := charged.create(a, {backing = allocator, metadata_allocator = allocator})
	assert(error.kind == .None)
	start: sync.Sema
	states: [8]Worker; threads: [8]^thread.Thread
	for &state, i in states {
		retained, valid := charged.retain(binding); assert(valid.kind == .None)
		state = {retained, b, &start}
		threads[i] = thread.create_and_start_with_poly_data(&state, worker)
		assert(threads[i] != nil)
	}
	charged.release(&binding) // Only worker owners and allocation headers remain.
	for _ in 0 ..< len(threads) do sync.post(&start)
	for handle in threads {thread.join(handle); thread.destroy(handle)}
	testing.expect_value(t, usage(root).used.bytes, u64(0))
	testing.expect_value(t, usage(a).used.bytes, u64(0))
	testing.expect_value(t, usage(b).used.bytes, u64(0))
	scopes.release_scope(&a); scopes.release_scope(&b); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}
