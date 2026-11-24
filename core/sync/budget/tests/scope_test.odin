package budget_test

import budget ".."
import rt "base:runtime"
import "core:mem"
import "core:testing"

view :: proc(scope: budget.Scope) -> budget.Snapshot {
	snapshot, error := budget.snapshot(scope)
	assert(error == .None)
	return snapshot
}

@(test)
ancestor_admission_is_atomic_and_closed_scopes_allow_phase_and_refund :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	root, e := budget.create_root({100, 2, 2}, mem.tracking_allocator(&track))
	assert(e == .None)
	conn, e2 := budget.create_child(root, {80, 2, 2})
	assert(e2 == .None)
	op, e3 := budget.create_child(conn, {60, 2, 2})
	assert(e3 == .None)
	first, accepted := budget.reserve(op, {50, 1, 1}, .Queued)
	assert(accepted == .None)
	_, rejected := budget.reserve(op, {11, 0, 0})
	testing.expect_value(t, rejected, .Limit_Exceeded)
	testing.expect_value(t, view(root).used, budget.Usage{50, 1, 1, 1, 0, 0})
	second, more := budget.reserve(conn, {30, 1, 1}, .Running)
	assert(more == .None)
	testing.expect_value(t, budget.replace(&first, {55, 1, 1}), .Limit_Exceeded)
	testing.expect_value(t, budget.cost_of(first).bytes, u64(50))
	testing.expect_value(t, view(root).used.bytes, u64(80))
	budget.release(&second)
	assert(budget.replace(&first, {60, 1, 1}) == .None)
	assert(budget.close(conn) == .None)
	assert(budget.set_job_phase(&first, .Running) == .None)
	assert(budget.set_job_phase(&first, .Held) == .None)
	_, closed := budget.reserve(op, {1, 0, 0})
	testing.expect_value(t, closed, .Closed)
	assert(budget.replace(&first, {59, 1, 1}) == .None)
	testing.expect_value(t, budget.replace(&first, {60, 1, 1}), .Closed)
	testing.expect_value(t, view(root).used, budget.Usage{59, 1, 1, 0, 0, 1})
	testing.expect_value(t, view(root).peak.bytes, u64(80))
	testing.expect_value(t, view(root).rejected, u64(4))
	budget.release(&first)
	budget.release(&first)
	testing.expect_value(t, view(root).used, budget.Usage{})
	budget.release_scope(&op)
	budget.release_scope(&conn)
	budget.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

@(test)
rebind_moves_exclusive_ancestors_without_double_charging_the_global_limit :: proc(t: ^testing.T) {
	root, e := budget.create_root({80, 2, 2})
	assert(e == .None)
	a, e2 := budget.create_child(root, {80, 2, 2})
	assert(e2 == .None)
	b, e3 := budget.create_child(root, {80, 2, 2})
	assert(e3 == .None)
	op_a, e4 := budget.create_child(a, {80, 2, 2})
	assert(e4 == .None)
	op_b, e5 := budget.create_child(b, {80, 2, 2})
	assert(e5 == .None)
	small, e6 := budget.create_child(b, {20, 2, 2})
	assert(e6 == .None)
	other_root, e7 := budget.create_root({80, 2, 2})
	assert(e7 == .None)
	lease, accepted := budget.reserve(op_a, {80, 1, 1}, .Running)
	assert(accepted == .None)
	assert(budget.rebind(&lease, op_b) == .None)
	testing.expect_value(t, view(root).used.bytes, u64(80))
	testing.expect_value(t, view(a).used.bytes, u64(0))
	testing.expect_value(t, view(b).used.bytes, u64(80))
	testing.expect_value(t, budget.rebind(&lease, small), .Limit_Exceeded)
	testing.expect_value(t, budget.rebind(&lease, other_root), .Foreign_Root)
	testing.expect(t, budget.same_scope(budget.scope_of(lease), op_b))
	testing.expect(t, budget.covers(op_b, b) && !budget.covers(b, op_b))
	testing.expect(t, !budget.covers(op_a, op_b) && !budget.same_root(root, other_root))
	assert(budget.rebind(&lease, b) == .None)
	testing.expect_value(t, view(op_b).used.bytes, u64(0))
	testing.expect_value(t, view(root).peak.bytes, u64(80))
	budget.release(&lease)
	owners := []^budget.Scope{&small, &op_a, &op_b, &a, &b, &other_root, &root}
	for owner in owners {
		budget.release_scope(owner)
	}
}

@(test)
late_lease_and_retained_scope_outlive_all_original_hierarchy_owners :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	root, e := budget.create_root({64, 1, 1}, mem.tracking_allocator(&track))
	assert(e == .None)
	conn, e2 := budget.create_child(root, {64, 1, 1})
	assert(e2 == .None)
	op, e3 := budget.create_child(conn, {64, 1, 1})
	assert(e3 == .None)
	lease, accepted := budget.reserve(op, {64, 1, 1}, .Running)
	assert(accepted == .None)
	budget.release_scope(&op)
	budget.release_scope(&conn)
	budget.release_scope(&root)
	borrowed := budget.scope_of(lease)
	testing.expect_value(t, view(borrowed).scope_nodes, u64(3))
	testing.expect_value(t, view(borrowed).used.bytes, u64(64))
	retained, valid := budget.retain_scope(borrowed)
	assert(valid == .None)
	budget.release(&lease)
	testing.expect_value(t, view(retained).used, budget.Usage{})
	testing.expect(t, track.current_memory_allocated > 0)
	budget.release_scope(&retained)
	budget.release_scope(&retained)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

@(test)
zero_limits_overflow_and_depth_bound_reject_without_wrapping :: proc(t: ^testing.T) {
	root, e := budget.create_root({max(u64), max(u64), max(u64)})
	assert(e == .None)
	lease, accepted := budget.reserve(root, {max(u64), 0, max(u64)}, .Queued)
	assert(accepted == .None)
	_, overflow := budget.reserve(root, {1, 0, 0})
	testing.expect_value(t, overflow, .Overflow)
	assert(budget.set_job_phase(&lease, .Running) == .None)
	assert(budget.set_job_phase(&lease, .Held) == .None)
	testing.expect_value(t, view(root).used.held, max(u64))
	assert(budget.replace(&lease, {}) == .None)
	testing.expect_value(t, budget.replace(&lease, {0, 0, 1}), .Invalid_Config)
	budget.release(&lease)
	chain: [budget.MAX_DEPTH]budget.Scope
	chain[0] = root
	for i in 1 ..< len(chain) {
		child, error := budget.create_child(chain[i - 1], {})
		assert(error == .None)
		chain[i] = child
	}
	_, too_deep := budget.create_child(chain[len(chain) - 1], {})
	testing.expect_value(t, too_deep, .Depth_Exceeded)
	_, exhausted := budget.reserve(chain[len(chain) - 1], {1, 0, 0})
	testing.expect_value(t, exhausted, .Limit_Exceeded)
	_, invalid := budget.reserve({}, {})
	testing.expect_value(t, invalid, .Invalid_Handle)
	for i := len(chain) - 1; i >= 0; i -= 1 do budget.release_scope(&chain[i])
}
