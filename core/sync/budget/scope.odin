package budget

import rt "base:runtime"
import "core:mem"
import "core:sync"

// Explicit zero limits permit no resource usage. The metadata allocator must
// support thread-safe allocation/free and outlive every child, lease and owner.
create_root :: proc(limits: Limits, allocator: mem.Allocator = {}) -> (Scope, Error) {
	backing := allocator
	if backing.procedure == nil do backing = rt.heap_allocator()
	node, error := new(Node, backing)
	if error != nil || node == nil do return {}, .Allocation_Failed
	node.root, node.references, node.limits, node.depth = node, 1, limits, 1
	node.allocator = backing
	node.scope_nodes, node.scope_metadata_bytes = 1, size_of(Node)
	return {node}, .None
}

create_child :: proc(parent: Scope, limits: Limits) -> (Scope, Error) {
	source := parent._node
	if source == nil do return {}, .Invalid_Handle
	if source.depth >= MAX_DEPTH do return {}, .Depth_Exceeded
	root := source.root
	node, error := new(Node, root.allocator)
	if error != nil || node == nil do return {}, .Allocation_Failed
	node.root, node.parent, node.references = root, source, 1
	node.limits, node.depth, node.allocator = limits, source.depth + 1, root.allocator
	sync.lock(&root.mu)
	result: Error
	identities_full := source.references == max(u64) || root.scope_nodes == max(u64)
	metadata_full := root.scope_metadata_bytes > max(u64) - size_of(Node)
	if path_closed(source) do result = .Closed
	else if identities_full || metadata_full {
		result = .Overflow
	}
	if result != .None {
		sync.unlock(&root.mu); free(node, root.allocator); return {}, result
	}
	source.references += 1
	root.scope_nodes += 1; root.scope_metadata_bytes += size_of(Node)
	sync.unlock(&root.mu)
	return {node}, .None
}

retain_scope :: proc(source: Scope) -> (Scope, Error) {
	node := source._node
	if node == nil do return {}, .Invalid_Handle
	root := node.root
	sync.lock(&root.mu); defer sync.unlock(&root.mu)
	if node.references == max(u64) do return {}, .Overflow
	node.references += 1
	return source, .None
}

// Clears before releasing. Final frees occur after unlocking; no allocator or
// destructor executes under the hierarchy lock, including cascading parents.
release_scope :: proc(owner: ^Scope) {
	if owner == nil do return
	node := owner._node; owner^ = {}
	if node == nil do return
	root := node.root
	retired: [MAX_DEPTH]^Node; count := 0
	sync.lock(&root.mu)
	for node != nil {
		assert(node.references > 0)
		node.references -= 1
		if node.references != 0 do break
		assert(node.used == (Usage{}))
		retired[count] = node; count += 1
		root.scope_nodes -= 1; root.scope_metadata_bytes -= size_of(Node)
		node = node.parent
	}
	sync.unlock(&root.mu)
	for dead in retired[:count] do free(dead, dead.allocator)
}

close :: proc(scope: Scope) -> Error {
	node := scope._node
	if node == nil do return .Invalid_Handle
	sync.lock(&node.root.mu); node.closed = true; sync.unlock(&node.root.mu)
	return .None
}

snapshot :: proc(scope: Scope) -> (Snapshot, Error) {
	node := scope._node
	if node == nil do return {}, .Invalid_Handle
	root := node.root
	sync.lock(&root.mu); defer sync.unlock(&root.mu)
	return {
			limits = node.limits,
			used = node.used,
			peak = node.peak,
			rejected = node.rejected,
			closed = path_closed(node),
			depth = node.depth,
			scope_nodes = root.scope_nodes,
			scope_metadata_bytes = root.scope_metadata_bytes,
		},
		.None
}

same_scope :: proc(a, b: Scope) -> bool {return a._node != nil && a._node == b._node}
same_root :: proc(a, b: Scope) -> bool {
	return a._node != nil && b._node != nil && a._node.root == b._node.root
}
// True only when required is charged itself or an ancestor of charged. Merely
// sharing a root is insufficient: sibling/descendant admission requires rebind.
covers :: proc(charged, required: Scope) -> bool {
	return same_root(charged, required) && in_path(required._node, charged._node)
}

@(private)
in_path :: proc(needle, start: ^Node) -> bool {
	node := start
	for node != nil {
		if node == needle do return true
		node = node.parent
	}
	return false
}
@(private)
path_closed :: proc(start: ^Node) -> bool {
	node := start
	for node != nil {
		if node.closed do return true
		node = node.parent
	}
	return false
}
