package mem_budget_test

import charged ".."
import "base:intrinsics"
import rt "base:runtime"
import "core:mem"
import scopes "core:sync/budget"
import "core:testing"

Fail_Backend :: struct {
	backing:         mem.Allocator,
	fail, fail_free: bool,
}
fail_backend :: proc(
	p: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	state := cast(^Fail_Backend)p
	if mode == .Free && state.fail_free {
		state.fail_free = false; return nil, .Invalid_Argument
	}
	if state.fail && (mode == .Alloc || mode == .Alloc_Non_Zeroed) {
		return nil, .Out_Of_Memory
	}
	return state.backing.procedure(
		state.backing.data,
		mode,
		size,
		alignment,
		old_memory,
		old_size,
		location,
	)
}

@(test)
resize_backing_oom_preserves_old_backing_scope_and_bytes :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 8192}, allocator); assert(re == .None)
	backend := Fail_Backend {
		backing = allocator,
	}
	binding, be := charged.create(
		root,
		{backing = {fail_backend, &backend}, metadata_allocator = allocator},
	); assert(be.kind == .None)
	bytes, allocated := charged.allocate(binding, 32); assert(allocated.kind == .None)
	for &byte in bytes do byte = 31
	before := usage(root).used.bytes
	backend.fail = true
	_, failed := charged.resize(binding, bytes, 64)
	testing.expect_value(t, failed.kind, .Allocation_Failed)
	testing.expect_value(t, failed.allocation, .Out_Of_Memory)
	testing.expect_value(t, usage(root).used.bytes, before)
	for byte in bytes do testing.expect_value(t, byte, u8(31))
	info, known := charged.allocation_info(charged.allocator(binding), raw_data(bytes))
	assert(known)
	testing.expect(t, scopes.same_scope(info.scope, root))
	assert(charged.deallocate(binding, raw_data(bytes)).kind == .None)
	charged.release(&binding); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

@(test)
rebind_full_root_succeeds_and_failed_destination_admission_is_atomic :: proc(t: ^testing.T) {
	cost, _ := charged.allocation_cost(32, 64)
	root, re := scopes.create_root({bytes = cost}); assert(re == .None)
	defer scopes.release_scope(&root)
	a, ae := scopes.create_child(root, {bytes = cost}); assert(ae == .None)
	defer scopes.release_scope(&a)
	b, be := scopes.create_child(root, {bytes = cost}); assert(be == .None)
	defer scopes.release_scope(&b)
	small, se := scopes.create_child(root, {bytes = cost - 1}); assert(se == .None)
	defer scopes.release_scope(&small)
	binding, error := charged.create(a); assert(error.kind == .None)
	defer charged.release(&binding)
	bytes, allocated := charged.allocate(binding, 32, 64); assert(allocated.kind == .None)
	managed := charged.allocator(binding)
	assert(charged.rebind_allocation(managed, raw_data(bytes), b).kind == .None)
	testing.expect_value(t, usage(root).used.bytes, cost)
	testing.expect_value(t, usage(root).peak.bytes, cost)
	failed := charged.rebind_allocation(managed, raw_data(bytes), small)
	testing.expect_value(t, failed.budget, .Limit_Exceeded)
	testing.expect_value(t, usage(b).used.bytes, cost)
	testing.expect_value(t, usage(small).used.bytes, u64(0))
	assert(scopes.close(a) == .None)
	closed := charged.rebind_allocation(managed, raw_data(bytes), a)
	testing.expect_value(t, closed.budget, .Closed)
	current, valid := charged.allocation_scope(managed, raw_data(bytes)); assert(valid)
	testing.expect(t, scopes.same_scope(current, b))
	assert(charged.deallocate(binding, raw_data(bytes)).kind == .None)
}

Reentrant_Backend :: struct {
	backing:            mem.Allocator,
	binding:            charged.Binding,
	owner:              ^charged.Binding,
	scope:              scopes.Scope,
	pointer:            rawptr,
	allocations, frees: int,
}
reentrant_backend :: proc(
	p: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	state := cast(^Reentrant_Backend)p
	if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Free {
		assert(charged.stats(state.binding).metadata_bytes > 0)
		snapshot, error := scopes.snapshot(state.scope); assert(error == .None)
		assert(snapshot.used.bytes > 0) // Lease covers callbacks through actual free.
		if mode == .Free {
			_, valid := charged.allocation_info(charged.allocator(state.binding), state.pointer)
			assert(!valid)
			assert(charged.deallocate(state.binding, state.pointer).kind == .Invalid_Pointer)
			charged.release(state.owner); state.frees += 1
		} else {
			state.allocations += 1
		}
	}
	return state.backing.procedure(
		state.backing.data,
		mode,
		size,
		alignment,
		old_memory,
		old_size,
		location,
	)
}

@(test)
backing_callbacks_query_reenter_and_release_binding_without_lock_or_lifetime_failure :: proc(
	t: ^testing.T,
) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 8192}, allocator); assert(re == .None)
	backend := Reentrant_Backend {
		backing = allocator,
		scope   = root,
	}
	binding, be := charged.create(
		root,
		{backing = {reentrant_backend, &backend}, metadata_allocator = allocator},
	); assert(be.kind == .None)
	backend.binding, backend.owner = binding, &binding
	bytes, allocated := charged.allocate(binding, 32); assert(allocated.kind == .None)
	backend.pointer = raw_data(bytes)
	assert(charged.deallocate(binding, raw_data(bytes)).kind == .None)
	testing.expect_value(t, backend.allocations, 1); testing.expect_value(t, backend.frees, 1)
	testing.expect_value(t, usage(root).used.bytes, u64(0))
	scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

@(test)
reference_exhaustion_is_nonwrapping_and_preserves_existing_binding :: proc(t: ^testing.T) {
	root, re := scopes.create_root({bytes = 8192}); assert(re == .None)
	defer scopes.release_scope(&root)
	binding, be := charged.create(root); assert(be.kind == .None)
	defer charged.release(&binding)
	// Test-only private boundary injection avoids performing 2^63 real retains.
	intrinsics.atomic_store(&binding._state.references, max(i64))
	_, retained := charged.retain(binding)
	testing.expect_value(t, retained.kind, .Overflow)
	_, allocated := charged.allocate(binding, 32)
	testing.expect_value(t, allocated.kind, .Overflow)
	testing.expect_value(t, intrinsics.atomic_load(&binding._state.references), max(i64))
	testing.expect_value(t, usage(root).used.bytes, u64(0))
	intrinsics.atomic_store(&binding._state.references, i64(1))
	bytes, accepted := charged.allocate(binding, 1); assert(accepted.kind == .None)
	assert(charged.deallocate(binding, raw_data(bytes)).kind == .None)
}

@(test)
non_consuming_free_failure_rolls_back_temporary_resize_and_keeps_source :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 8192}, allocator); assert(re == .None)
	backend := Fail_Backend {
		backing = allocator,
	}
	binding, be := charged.create(
		root,
		{backing = {fail_backend, &backend}, metadata_allocator = allocator},
	); assert(be.kind == .None)
	bytes, allocated := charged.allocate(binding, 32); assert(allocated.kind == .None)
	for &byte in bytes do byte = 71
	before := usage(root).used.bytes
	backend.fail_free = true
	_, failed := charged.resize(binding, bytes, 64)
	testing.expect_value(t, failed.kind, .Backing_Failed)
	testing.expect_value(t, usage(root).used.bytes, before)
	testing.expect_value(t, charged.stats(binding).allocations, u64(1))
	for byte in bytes do testing.expect_value(t, byte, u8(71))
	_, valid := charged.allocation_info(charged.allocator(binding), raw_data(bytes))
	testing.expect(t, valid)
	assert(charged.deallocate(binding, raw_data(bytes)).kind == .None)
	charged.release(&binding); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}
