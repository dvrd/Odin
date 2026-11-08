package budget

import "core:sync"

reserve :: proc(scope: Scope, cost: Cost, phase: Job_Phase = .None) -> (Lease, Error) {
	node := scope._node
	if node == nil do return {}, .Invalid_Handle
	if !phase_valid(cost, phase) do return {}, .Invalid_Config
	root := node.root
	sync.lock(&root.mu); defer sync.unlock(&root.mu)
	error: Error
	if path_closed(node) do error = .Closed
	else if node.references == max(u64) do error = .Overflow
	if error == .None {
		for ancestor := node; ancestor != nil; ancestor = ancestor.parent {
			error = admit(ancestor, {}, cost)
			if error != .None do break
		}
	}
	if error != .None {
		reject(node); return {}, error
	}
	for ancestor := node; ancestor != nil; ancestor = ancestor.parent {
		change_usage(ancestor, {}, cost, .None, phase)
	}
	node.references += 1
	return {node, cost, phase}, .None
}

// Atomically replace all three resource counts. Increasing costs after close
// rejects; reducing/refunding remains possible. The existing job phase persists.
replace :: proc(owner: ^Lease, cost: Cost) -> Error {
	if owner == nil || owner._node == nil do return .Invalid_Handle
	node := owner._node; old := owner._cost
	phase := owner._phase
	if cost.jobs == 0 do phase = .None
	if !phase_valid(cost, phase) do return .Invalid_Config
	sync.lock(&node.root.mu); defer sync.unlock(&node.root.mu)
	error: Error
	if (cost.bytes > old.bytes || cost.streams > old.streams || cost.jobs > old.jobs) &&
	   path_closed(node) {
		error = .Closed
	}
	if error == .None {
		for ancestor := node; ancestor != nil; ancestor = ancestor.parent {
			error = admit(ancestor, old, cost)
			if error != .None do break
		}
	}
	if error != .None {
		reject(node); return error
	}
	for ancestor := node; ancestor != nil; ancestor = ancestor.parent {
		change_usage(ancestor, old, cost, owner._phase, phase)
	}
	owner._cost, owner._phase = cost, phase
	return .None
}

// Combined jobs were admitted once; phase changes never acquire capacity, even
// after closure. The same lease persists through queue, execution and held result.
set_job_phase :: proc(owner: ^Lease, phase: Job_Phase) -> Error {
	if owner == nil || owner._node == nil do return .Invalid_Handle
	if !phase_valid(owner._cost, phase) do return .Invalid_Config
	node := owner._node
	sync.lock(&node.root.mu); defer sync.unlock(&node.root.mu)
	for ancestor := node; ancestor != nil; ancestor = ancestor.parent {
		change_usage(ancestor, owner._cost, owner._cost, owner._phase, phase)
	}
	owner._phase = phase
	return .None
}

// Destination admission excludes common ancestors, which already hold this
// charge. Failure, including a foreign root, preserves the original lease.
rebind :: proc(owner: ^Lease, destination: Scope) -> Error {
	if owner == nil || owner._node == nil || destination._node == nil do return .Invalid_Handle
	old, target := owner._node, destination._node
	if old.root != target.root do return .Foreign_Root
	if old == target do return .None
	root := old.root
	sync.lock(&root.mu)
	common := old
	for !in_path(common, target) do common = common.parent
	error: Error
	if path_closed(target) do error = .Closed
	else if target.references == max(u64) do error = .Overflow
	if error == .None {
		for ancestor := target; ancestor != common; ancestor = ancestor.parent {
			error = admit(ancestor, {}, owner._cost)
			if error != .None do break
		}
	}
	if error != .None {
		reject(target); sync.unlock(&root.mu); return error
	}
	for ancestor := old; ancestor != common; ancestor = ancestor.parent {
		change_usage(ancestor, owner._cost, {}, owner._phase, .None)
	}
	for ancestor := target; ancestor != common; ancestor = ancestor.parent {
		change_usage(ancestor, {}, owner._cost, .None, owner._phase)
	}
	target.references += 1; owner._node = target
	sync.unlock(&root.mu)
	previous := Scope{old}; release_scope(&previous)
	return .None
}

release :: proc(owner: ^Lease) {
	if owner == nil do return
	old := owner^; owner^ = {}
	if old._node == nil do return
	node := old._node
	sync.lock(&node.root.mu)
	for ancestor := node; ancestor != nil; ancestor = ancestor.parent {
		change_usage(ancestor, old._cost, {}, old._phase, .None)
	}
	sync.unlock(&node.root.mu)
	scope := Scope{node}; release_scope(&scope)
}

// These return borrowed views; retaining scope_of explicitly creates an owner.
scope_of :: proc(source: Lease) -> Scope {return {source._node}}
cost_of :: proc(source: Lease) -> Cost {return source._cost}
phase_of :: proc(source: Lease) -> Job_Phase {return source._phase}
