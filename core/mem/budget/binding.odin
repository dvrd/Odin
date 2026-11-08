package mem_budget

import "base:intrinsics"
import rt "base:runtime"
import "core:mem"
import "core:sync"
import scopes "core:sync/budget"

Error_Kind :: enum {
	None,
	Invalid_Config,
	Invalid_Handle,
	Invalid_Pointer,
	Invalid_Argument,
	Overflow,
	Budget_Rejected,
	Allocation_Failed,
	Backing_Failed,
	Unsupported_Mode,
}
Error :: struct {
	kind:       Error_Kind,
	budget:     scopes.Error,
	allocation: mem.Allocator_Error,
}
Config :: struct {
	// Zero selects the process heap. backing must provide thread-safe alloc/free
	// and individually release valid storage. Metadata survives every allocation.
	backing, metadata_allocator: mem.Allocator,
}
// Copies are aliases. Retain a separate owner before publishing a Binding to
// another thread. Each allocation also retains it until actual backing release.
Binding :: struct {
	_state: ^State,
}
Stats :: struct {
	allocations, backing_bytes, peak_backing_bytes: u64,
	rejected, allocation_failures, metadata_bytes:  u64,
}
// scope is borrowed until this allocation is freed/rebound/resized. Independent
// operations on one allocation must be externally serialized, like ordinary free.
Allocation_Info :: struct {
	scope:           scopes.Scope,
	size, alignment: int,
	backing_bytes:   u64,
}
@(private)
State :: struct {
	references:                  i64,
	mu:                          sync.Mutex,
	backing, metadata_allocator: mem.Allocator,
	default_scope:               scopes.Scope,
	first:                       ^Header,
	registered:                  int,
	stats:                       Stats,
}
@(private)
Header :: struct {
	previous, next:  ^Header,
	binding:         ^State,
	storage:         []u8,
	data:            rawptr,
	size, alignment: int,
	lease:           scopes.Lease,
}

create :: proc(scope: scopes.Scope, config: Config = {}) -> (Binding, Error) {
	retained, error := scopes.retain_scope(scope)
	if error != .None do return {}, {kind = .Invalid_Config, budget = error}
	backing, metadata := config.backing, config.metadata_allocator
	if backing.procedure == nil do backing = rt.heap_allocator()
	if metadata.procedure == nil do metadata = rt.heap_allocator()
	if backing.procedure == allocator_proc {
		scopes.release_scope(&retained); return {}, {kind = .Invalid_Config}
	}
	state, ae := new(State, metadata)
	if ae != nil || state == nil {
		scopes.release_scope(&retained)
		if ae == nil do ae = .Out_Of_Memory
		return {}, {kind = .Allocation_Failed, allocation = ae}
	}
	state.references, state.backing, state.metadata_allocator = 1, backing, metadata
	state.default_scope = retained
	state.stats.metadata_bytes = u64(size_of(State))
	return {state}, {}
}

retain :: proc(source: Binding) -> (Binding, Error) {
	if source._state == nil do return {}, {kind = .Invalid_Handle}
	if !retain_state(source._state) do return {}, {kind = .Overflow}
	return source, {}
}
release :: proc(owner: ^Binding) {
	if owner == nil do return
	state := owner._state; owner^ = {}
	if state != nil do release_state(state)
}
allocator :: proc(source: Binding) -> mem.Allocator {
	if source._state == nil do return {}
	return {allocator_proc, source._state}
}
is_managed_allocator :: proc(source: mem.Allocator) -> bool {
	return source.procedure == allocator_proc && source.data != nil
}
default_scope :: proc(source: Binding) -> scopes.Scope {
	if source._state == nil do return {}
	return source._state.default_scope
}
stats :: proc(source: Binding) -> Stats {
	if source._state == nil do return {}
	state := source._state
	sync.lock(&state.mu); defer sync.unlock(&state.mu)
	return state.stats
}

@(private)
retain_state :: proc(state: ^State) -> bool {
	sync.lock(&state.mu); defer sync.unlock(&state.mu)
	previous := intrinsics.atomic_load(&state.references)
	assert(previous > 0)
	if previous == max(i64) do return false
	_, changed := intrinsics.atomic_compare_exchange_strong(
		&state.references,
		previous,
		previous + 1,
	)
	assert(changed) // All reference mutations use this mutex; no retry loop.
	return true
}
@(private)
release_state :: proc(state: ^State) {
	sync.lock(&state.mu)
	previous := intrinsics.atomic_load(&state.references)
	assert(previous > 0)
	_, changed := intrinsics.atomic_compare_exchange_strong(
		&state.references,
		previous,
		previous - 1,
	)
	assert(changed)
	sync.unlock(&state.mu)
	if previous != 1 do return
	assert(state.registered == 0 && state.stats.allocations == 0)
	assert(state.stats.backing_bytes == 0)
	scope, metadata := state.default_scope, state.metadata_allocator
	state.default_scope = {}
	scopes.release_scope(&scope)
	free(state, metadata)
}

// Registry lookup never probes memory before an arbitrary/interior input pointer.
// The allocation owner serializes free/rebind/resize and preserves its lifetime.
@(private)
find_header :: proc(state: ^State, pointer: rawptr) -> ^Header {
	sync.lock(&state.mu); defer sync.unlock(&state.mu)
	header := state.first
	for _ in 0 ..< state.registered {
		assert(header != nil)
		if header.data == pointer do return header
		header = header.next
	}
	assert(header == nil)
	return nil
}

allocation_info :: proc(source: mem.Allocator, whole_base: rawptr) -> (Allocation_Info, bool) {
	if !is_managed_allocator(source) || whole_base == nil do return {}, false
	header := find_header(cast(^State)source.data, whole_base)
	if header == nil do return {}, false
	return {
			scopes.scope_of(header.lease),
			header.size,
			header.alignment,
			scopes.cost_of(header.lease).bytes,
		},
		true
}
allocation_scope :: proc(source: mem.Allocator, whole_base: rawptr) -> (scopes.Scope, bool) {
	info, valid := allocation_info(source, whole_base)
	return info.scope, valid
}
allocation_covers :: proc(
	source: mem.Allocator,
	whole_base: rawptr,
	required: scopes.Scope,
) -> bool {
	scope, valid := allocation_scope(source, whole_base)
	return valid && scopes.covers(scope, required)
}
rebind_allocation :: proc(
	source: mem.Allocator,
	whole_base: rawptr,
	destination: scopes.Scope,
) -> Error {
	if !is_managed_allocator(source) do return {kind = .Invalid_Handle}
	header := find_header(cast(^State)source.data, whole_base)
	if header == nil do return {kind = .Invalid_Pointer}
	error := scopes.rebind(&header.lease, destination)
	if error != .None do return {kind = .Budget_Rejected, budget = error}
	return {}
}

// Recognizes a direct managed allocator only. The returned default scope is
// borrowed; keep an allocator owner/allocation alive or retain_allocator first.
allocator_scope :: proc(source: mem.Allocator) -> (scopes.Scope, bool) {
	if !is_managed_allocator(source) do return {}, false
	return (cast(^State)source.data).default_scope, true
}
retain_allocator :: proc(source: mem.Allocator) -> (Binding, Error) {
	if !is_managed_allocator(source) do return {}, {kind = .Invalid_Handle}
	state := cast(^State)source.data
	if !retain_state(state) do return {}, {kind = .Overflow}
	return {state}, {}
}
