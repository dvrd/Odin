package mem_budget_test

import charged ".."
import rt "base:runtime"
import "core:mem"
import owned "core:mem/owned"
import scopes "core:sync/budget"
import "core:testing"

usage :: proc(scope: scopes.Scope) -> scopes.Snapshot {
	snapshot, error := scopes.snapshot(scope); assert(error == .None)
	return snapshot
}

@(test)
budget_denial_and_backing_failure_have_distinct_typed_errors_and_rollback :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	cost, valid := charged.allocation_cost(32, 64); assert(valid.kind == .None)
	root, se := scopes.create_root({bytes = cost}, allocator); assert(se == .None)
	binding, be := charged.create(root, {backing = allocator, metadata_allocator = allocator})
	assert(be.kind == .None)
	first, e1 := charged.allocate(binding, 32, 64); assert(e1.kind == .None)
	_, denied := charged.allocate(binding, 32, 64)
	testing.expect_value(t, denied.kind, .Budget_Rejected)
	testing.expect_value(t, denied.budget, .Limit_Exceeded)
	testing.expect_value(t, usage(root).used.bytes, cost)
	testing.expect_value(t, usage(root).rejected, u64(1))
	assert(charged.deallocate(binding, raw_data(first)).kind == .None)
	second, e2 := charged.allocate(binding, 32, 64); assert(e2.kind == .None)
	assert(charged.deallocate(binding, raw_data(second)).kind == .None)
	missing, me := charged.create(root, {metadata_allocator = mem.nil_allocator()})
	testing.expect_value(t, me.kind, .Allocation_Failed); charged.release(&missing)
	failed, fe := charged.create(
		root,
		{backing = mem.nil_allocator(), metadata_allocator = allocator},
	)
	assert(fe.kind == .None)
	_, failure := charged.allocate(failed, 32, 64)
	testing.expect_value(t, failure.kind, .Allocation_Failed)
	testing.expect_value(t, failure.allocation, .Out_Of_Memory)
	testing.expect_value(t, failure.budget, .None)
	testing.expect_value(t, usage(root).used.bytes, u64(0))
	testing.expect_value(t, charged.stats(binding).rejected, u64(1))
	testing.expect_value(t, charged.stats(failed).allocation_failures, u64(1))
	charged.release(&binding); charged.release(&failed); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

@(test)
zero_alignment_overflow_and_wrong_provenance_never_change_owners :: proc(t: ^testing.T) {
	root, re := scopes.create_root({bytes = 8192}); assert(re == .None)
	defer scopes.release_scope(&root)
	binding, error := charged.create(root); assert(error.kind == .None)
	defer charged.release(&binding)
	other, oe := charged.create(root); assert(oe.kind == .None)
	defer charged.release(&other)
	zero, ze := charged.allocate(binding, 0); assert(ze.kind == .None && zero == nil)
	testing.expect_value(t, usage(root).used.bytes, u64(0))
	_, invalid := charged.allocate(binding, -1)
	testing.expect_value(t, invalid.kind, .Invalid_Argument)
	_, invalid = charged.allocate(binding, 1, 3)
	testing.expect_value(t, invalid.kind, .Invalid_Argument)
	_, overflow := charged.allocate(binding, max(int), 64)
	testing.expect_value(t, overflow.kind, .Overflow)
	bytes, accepted := charged.allocate(binding, 17, 256); assert(accepted.kind == .None)
	testing.expect_value(t, uintptr(raw_data(bytes)) % 256, uintptr(0))
	allocator := charged.allocator(binding)
	borrowed, managed := charged.allocator_scope(allocator); assert(managed)
	testing.expect(t, scopes.same_scope(borrowed, root))
	retained, held := charged.retain_allocator(allocator); assert(held.kind == .None)
	charged.release(&retained)
	info, known := charged.allocation_info(allocator, raw_data(bytes)); assert(known)
	testing.expect_value(t, info.size, 17)
	testing.expect_value(t, info.alignment, 256)
	_, interior := charged.allocation_info(allocator, rawptr(uintptr(raw_data(bytes)) + 1))
	testing.expect(t, !interior)
	unrelated: u8
	_, unknown := charged.allocation_info(allocator, &unrelated); testing.expect(t, !unknown)
	testing.expect_value(t, charged.deallocate(other, raw_data(bytes)).kind, .Invalid_Pointer)
	query := mem.query_info(raw_data(bytes), allocator)
	queried, ok := query.size.(int); testing.expect(t, ok); testing.expect_value(t, queried, 17)
	features := mem.query_features(allocator); testing.expect(t, .Free_All not_in features)
	_, unsupported := allocator.procedure(allocator.data, .Free_All, 0, 0, nil, 0)
	testing.expect_value(t, unsupported, .Mode_Not_Implemented)
	testing.expect_value(t, usage(root).used.bytes, info.backing_bytes)
	assert(charged.deallocate(binding, raw_data(bytes)).kind == .None)
	testing.expect_value(t, usage(root).used.bytes, u64(0))
}

@(test)
owned_dynamic_body_outlives_binding_scope_owners_and_frees_real_heap :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 8192}, allocator); assert(re == .None)
	child, ce := scopes.create_child(root, {bytes = 8192}); assert(ce == .None)
	binding, be := charged.create(child, {backing = allocator, metadata_allocator = allocator})
	assert(be.kind == .None)
	managed := charged.allocator(binding)
	body, ae := make([dynamic]u8, 4, 64, managed); assert(ae == nil)
	empty, ee := make([dynamic]u8, 0, 0, managed); assert(ee == nil)
	empty_chunk, et := owned.take_dynamic(&empty); assert(et.kind == .None)
	copy(body[:], "body")
	charged.release(&binding); scopes.release_scope(&root); scopes.release_scope(&child)
	extra: [80]u8
	_, grown := append(&body, ..extra[:]); assert(grown == nil)
	chunk, taken := owned.take_dynamic(&body); assert(taken.kind == .None)
	info, valid := charged.allocation_info(managed, raw_data(chunk.storage)); assert(valid)
	testing.expect_value(t, info.size, len(chunk.storage))
	testing.expect(t, info.backing_bytes > u64(len(chunk.data)))
	delete(body)
	testing.expect_value(t, string(chunk.data[:4]), "body")
	testing.expect_value(t, usage(info.scope).used.bytes, info.backing_bytes)
	testing.expect(t, track.current_memory_allocated > 0)
	owned.destroy(&chunk); owned.destroy(&chunk)
	// State is truly freed now; nil-owner cleanup must not read allocator.data.
	_, empty_info := charged.allocation_info(managed, nil); testing.expect(t, !empty_info)
	_, empty_free := managed.procedure(managed.data, .Free, 0, 0, nil, 0)
	testing.expect_value(t, empty_free, nil)
	owned.destroy(&empty_chunk); owned.destroy(&empty_chunk)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

@(test)
rebind_keeps_common_ancestor_charge_once_and_resize_uses_current_scope :: proc(t: ^testing.T) {
	old_cost, _ := charged.allocation_cost(32, 64)
	new_cost, _ := charged.allocation_cost(64, 128)
	limit := old_cost + new_cost
	root, re := scopes.create_root({bytes = limit}); assert(re == .None)
	defer scopes.release_scope(&root)
	a, ae := scopes.create_child(root, {bytes = limit}); assert(ae == .None)
	defer scopes.release_scope(&a)
	b, be := scopes.create_child(root, {bytes = limit}); assert(be == .None)
	defer scopes.release_scope(&b)
	binding, error := charged.create(a); assert(error.kind == .None)
	defer charged.release(&binding)
	bytes, allocated := charged.allocate(binding, 32, 64); assert(allocated.kind == .None)
	for &byte in bytes do byte = 42
	managed := charged.allocator(binding)
	assert(charged.rebind_allocation(managed, raw_data(bytes), b).kind == .None)
	testing.expect_value(t, usage(a).used.bytes, u64(0))
	testing.expect_value(t, usage(b).used.bytes, old_cost)
	testing.expect_value(t, usage(root).used.bytes, old_cost)
	testing.expect(t, charged.allocation_covers(managed, raw_data(bytes), root))
	testing.expect(t, !charged.allocation_covers(managed, raw_data(bytes), a))
	assert(scopes.close(a) == .None)
	resized, grown := charged.resize(binding, bytes, 64, 128); assert(grown.kind == .None)
	for byte in resized[:32] do testing.expect_value(t, byte, u8(42))
	for byte in resized[32:] do testing.expect_value(t, byte, u8(0))
	current, valid := charged.allocation_scope(managed, raw_data(resized)); assert(valid)
	testing.expect(t, scopes.same_scope(current, b))
	testing.expect_value(t, usage(root).used.bytes, new_cost)
	testing.expect_value(t, usage(root).peak.bytes, limit)
	other_root, fe := scopes.create_root({bytes = limit}); assert(fe == .None)
	defer scopes.release_scope(&other_root)
	rejected := charged.rebind_allocation(managed, raw_data(resized), other_root)
	testing.expect_value(t, rejected.budget, .Foreign_Root)
	testing.expect_value(t, usage(root).used.bytes, new_cost)
	assert(charged.deallocate(binding, raw_data(resized)).kind == .None)
}

@(test)
resize_overlap_budget_failure_preserves_original_bytes_and_identity :: proc(t: ^testing.T) {
	cost, _ := charged.allocation_cost(32, 64)
	root, re := scopes.create_root({bytes = cost}); assert(re == .None)
	defer scopes.release_scope(&root)
	binding, error := charged.create(root); assert(error.kind == .None)
	defer charged.release(&binding)
	bytes, allocated := charged.allocate(binding, 32, 64); assert(allocated.kind == .None)
	for &byte in bytes do byte = 23
	_, rejected := charged.resize(binding, bytes, 32, 64)
	testing.expect_value(t, rejected.kind, .Budget_Rejected)
	testing.expect_value(t, usage(root).used.bytes, cost)
	info, valid := charged.allocation_info(charged.allocator(binding), raw_data(bytes))
	assert(valid)
	testing.expect_value(t, info.size, 32)
	for byte in bytes do testing.expect_value(t, byte, u8(23))
	assert(charged.deallocate(binding, raw_data(bytes)).kind == .None)
}

@(test)
dynamic_arena_block_cycle_failure_preserves_previous_owner_and_managed_recovery :: proc(
	t: ^testing.T,
) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 65536}, allocator); assert(re == .None)
	payload, pe := scopes.create_child(root, {bytes = 65536}); assert(pe == .None)
	tables, te := scopes.create_child(root, {}); assert(te == .None)
	blocks, be := charged.create(payload, {backing = allocator, metadata_allocator = allocator})
	assert(be.kind == .None)
	denied, de := charged.create(tables, {backing = allocator, metadata_allocator = allocator})
	assert(de.kind == .None)
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = charged.allocator(blocks),
		array_allocator = charged.allocator(denied),
		block_size = 1024,
		out_band_size = 2048,
	)
	view := mem.dynamic_arena_allocator(&arena)
	previous, accepted := mem.alloc_bytes(1024, allocator = view); assert(accepted == nil)
	for &byte in previous do byte = 39
	before := usage(root).used.bytes
	bytes, error := mem.alloc_bytes(64, allocator = view)
	testing.expect_value(t, error, .Out_Of_Memory); testing.expect_value(t, len(bytes), 0)
	testing.expect_value(t, usage(root).used.bytes, before)
	for byte in previous do testing.expect_value(t, byte, u8(39))
	mem.dynamic_arena_destroy(&arena)
	testing.expect_value(t, usage(root).used.bytes, u64(0))
	managed := charged.allocator(blocks)
	mem.dynamic_arena_init(
		&arena,
		block_allocator = managed,
		array_allocator = managed,
		block_size = 1024,
		out_band_size = 2048,
	)
	for size in ([?]int{64, 4096}) {
		allocated_chunk, allocation_error := mem.alloc_bytes(
			size,
			allocator = mem.dynamic_arena_allocator(&arena),
		)
		assert(allocation_error == nil && len(allocated_chunk) == size)
	}
	testing.expect(t, usage(root).used.bytes > u64(64 + 4096))
	mem.dynamic_arena_destroy(&arena)
	testing.expect_value(t, usage(root).used.bytes, u64(0))
	charged.release(&blocks); charged.release(&denied)
	scopes.release_scope(&payload); scopes.release_scope(&tables); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

@(test)
dynamic_arena_out_of_band_table_denial_releases_already_allocated_payload :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	cost, _ := charged.allocation_cost(4096, mem.DEFAULT_ALIGNMENT)
	root, re := scopes.create_root({bytes = cost}, allocator); assert(re == .None)
	binding, be := charged.create(root, {backing = allocator, metadata_allocator = allocator})
	assert(be.kind == .None)
	managed := charged.allocator(binding)
	baseline := track.current_memory_allocated
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = managed,
		array_allocator = managed,
		block_size = 1024,
		out_band_size = 2048,
	)
	bytes, error := mem.alloc_bytes(4096, allocator = mem.dynamic_arena_allocator(&arena))
	testing.expect_value(t, error, .Out_Of_Memory); testing.expect_value(t, len(bytes), 0)
	testing.expect_value(t, usage(root).peak.bytes, cost)
	testing.expect_value(t, usage(root).used.bytes, u64(0))
	testing.expect_value(t, track.current_memory_allocated, baseline)
	mem.dynamic_arena_destroy(&arena)
	charged.release(&binding); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}
