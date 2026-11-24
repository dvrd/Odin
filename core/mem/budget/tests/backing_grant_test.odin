package mem_budget_test

import charged "core:mem/budget"
import rt "base:runtime"
import "core:mem"
import scopes "core:sync/budget"
import "core:testing"

Grant_Fault :: struct {
	backing:           mem.Allocator,
	armed:             bool,
	variant:           int,
	storage, reported: []u8,
	frees:             int,
}

grant_fault :: proc(
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
	state := cast(^Grant_Fault)p
	if (mode == .Alloc || mode == .Alloc_Non_Zeroed) && state.armed {
		if state.variant == 7 {
			return nil, nil
		}
		storage, error := state.backing.procedure(state.backing.data, mode, size + 32, alignment, nil, 0, location)
		assert(error == nil)
		state.storage = storage
		grant := storage[:size]
		switch state.variant {
		case 1, 4:
			grant = storage[:size - 1]
		case 2, 5:
			grant = storage[:size + 1]
		case 6:
			grant = storage[1:size + 1]
		case 8:
			grant = storage[:0]
		case:
		}
		state.reported = grant
		if state.variant < 3 {
			return grant, .Out_Of_Memory
		}
		return grant, nil
	}
	if mode == .Free && raw_data(state.storage) != nil && old_memory == raw_data(state.reported) {
		assert(old_size == len(state.reported))
		state.frees += 1
		storage := state.storage
		state.storage = nil
		state.reported = nil
		return state.backing.procedure(
			state.backing.data,
			.Free,
			0,
			alignment,
			raw_data(storage),
			len(storage),
			location,
		)
	}
	return state.backing.procedure(state.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(test)
rejected_backing_grants_release_full_reported_extent :: proc(t: ^testing.T) {
	for variant in ([8]int{0, 1, 2, 4, 5, 6, 7, 8}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		allocator := mem.tracking_allocator(&track)
		state := Grant_Fault {
			backing = allocator,
			armed   = true,
			variant = variant,
		}
		root, re := scopes.create_root({bytes = 10000})
		assert(re == .None)
		binding, be := charged.create(root, {backing = {grant_fault, &state}})
		assert(be.kind == .None)
		bytes, error := charged.allocate(binding, 64, 64)
		testing.expect_value(t, error.kind, .Allocation_Failed)
		testing.expect(t, raw_data(bytes) == nil)
		testing.expect_value(t, track.current_memory_allocated, i64(0))
		if variant != 7 {
			testing.expect_value(t, state.frees, 1)
		}
		view, _ := scopes.snapshot(root)
		testing.expect_value(t, view.used.bytes, u64(0))
		testing.expect_value(t, charged.stats(binding).allocations, u64(0))
		if raw_data(state.storage) != nil {
			delete(state.storage, allocator)
		}
		charged.release(&binding)
		scopes.release_scope(&root)
		mem.tracking_allocator_destroy(&track)
	}
}
