package budget

import "core:mem"
import "core:sync"

MAX_DEPTH :: 8
Limits :: struct {
	bytes, streams, jobs: u64,
}
Cost :: struct {
	bytes, streams, jobs: u64,
}
Usage :: struct {
	bytes, streams, jobs, queued, running, held: u64,
}
Job_Phase :: enum {
	None,
	Queued,
	Running,
	Held,
}
Error :: enum {
	None,
	Invalid_Config,
	Invalid_Handle,
	Limit_Exceeded,
	Closed,
	Depth_Exceeded,
	Allocation_Failed,
	Foreign_Root,
	Overflow,
}

// Scope copies are aliases; retain_scope creates another owner. A child and
// every lease retain their nodes independently of request/runtime storage.
Scope :: struct {
	_node: ^Node,
}
// Move-only by convention. Copies do not own another reservation. Mutating or
// releasing aliases concurrently is unsupported, as with owned memory chunks.
Lease :: struct {
	_node:  ^Node,
	_cost:  Cost,
	_phase: Job_Phase,
}
Snapshot :: struct {
	limits:                            Limits,
	used, peak:                        Usage,
	rejected:                          u64,
	closed:                            bool,
	depth:                             int,
	// Whole-hierarchy control metadata, separate from charged payload bytes.
	scope_nodes, scope_metadata_bytes: u64,
}

@(private)
Node :: struct {
	root, parent:                      ^Node,
	mu:                                sync.Mutex,
	references:                        u64,
	limits:                            Limits,
	used, peak:                        Usage,
	rejected:                          u64,
	closed:                            bool,
	depth:                             int,
	allocator:                         mem.Allocator,
	// Only the root stores hierarchy-wide control-node accounting.
	scope_nodes, scope_metadata_bytes: u64,
}
