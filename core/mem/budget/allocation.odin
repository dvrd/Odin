package mem_budget

import "core:mem"
import "core:sync"
import scopes "core:sync/budget"

// A zero-byte request returns nil without charge. Backing cost includes the full
// requested payload, inline header and maximum alignment padding, not RSS.
allocation_cost :: proc(size, alignment: int) -> (u64, Error) {
	if size < 0 || alignment < 1 || !mem.is_power_of_two(uintptr(alignment)) {
		return 0, {kind = .Invalid_Argument}
	}
	if size == 0 do return 0, {}
	if alignment - 1 > max(int) - size_of(Header) do return 0, {kind = .Overflow}
	overhead := size_of(Header) + alignment - 1
	if size > max(int) - overhead {
		return 0, {kind = .Overflow}
	}
	return u64(size + overhead), {}
}

allocate :: proc(source: Binding, size: int, alignment: int = mem.DEFAULT_ALIGNMENT) -> ([]u8, Error) {
	if source._state == nil do return nil, {kind = .Invalid_Handle}
	return allocate_in_scope(source._state, source._state.default_scope, size, alignment, true)
}

@(private)
allocate_in_scope :: proc(state: ^State, scope: scopes.Scope, size, alignment: int, zeroed: bool) -> ([]u8, Error) {
	cost, validation := allocation_cost(size, alignment)
	if validation.kind != .None || cost == 0 do return nil, validation
	if !retain_state(state) do return nil, {kind = .Overflow}
	lease, admission := scopes.reserve(scope, {bytes = cost})
	if admission != .None {
		record_failure(state, false)
		release_state(state)
		return nil, {kind = .Budget_Rejected, budget = admission}
	}
	storage, ae := mem.alloc_bytes_non_zeroed(int(cost), max(alignment, align_of(Header)), state.backing)
	if ae != nil ||
	   len(storage) != int(cost) ||
	   raw_data(storage) == nil ||
	   uintptr(raw_data(storage)) % uintptr(max(alignment, align_of(Header))) != 0 {
		// An error does not transfer disposal responsibility back to the
		// allocator. Release every reported grant before dropping its charge.
		if raw_data(storage) != nil do delete(storage, state.backing)
		if ae == nil do ae = .Out_Of_Memory
		scopes.release(&lease)
		record_failure(state, true)
		release_state(state)
		return nil, {kind = .Allocation_Failed, allocation = ae}
	}
	header := cast(^Header)raw_data(storage)
	data := mem.align_forward(rawptr(uintptr(raw_data(storage)) + size_of(Header)), uintptr(alignment))
	header^ = {
		binding   = state,
		storage   = storage,
		data      = data,
		size      = size,
		alignment = alignment,
		lease     = lease,
	}
	register_header(state, header, cost)
	result := (cast([^]u8)data)[:size]
	if zeroed do mem.zero_slice(result)
	return result, {}
}

@(private)
register_header :: proc(state: ^State, header: ^Header, cost: u64) {
	sync.lock(&state.mu)
	defer sync.unlock(&state.mu)
	assert(state.registered < max(int))
	header.next = state.first
	if state.first != nil do state.first.previous = header
	state.first = header
	state.registered += 1
	state.stats.allocations += 1
	state.stats.backing_bytes += cost
	state.stats.peak_backing_bytes = max(state.stats.peak_backing_bytes, state.stats.backing_bytes)
}

@(private)
record_failure :: proc(state: ^State, allocation: bool) {
	sync.lock(&state.mu)
	defer sync.unlock(&state.mu)
	if allocation {
		if state.stats.allocation_failures < max(u64) do state.stats.allocation_failures += 1
	} else if state.stats.rejected < max(u64) {
		state.stats.rejected += 1
	}
}

// Successful free removes provenance before calling the backing allocator, then
// releases its lease after the backing has actually been returned. A valid
// backing Free must succeed; non-consuming operational errors preserve ownership.
deallocate :: proc(source: Binding, whole_base: rawptr) -> Error {
	if whole_base == nil do return {}
	if source._state == nil do return {kind = .Invalid_Handle}
	state := source._state
	header := find_header(state, whole_base)
	if header == nil do return {kind = .Invalid_Pointer}
	return free_header(state, header)
}

@(private)
free_header :: proc(state: ^State, header: ^Header) -> Error {
	storage, lease := header.storage, header.lease
	cost := scopes.cost_of(lease).bytes
	unregister_header(state, header)
	error := delete(storage, state.backing)
	if error != nil {
		// Standard backing failure is non-consuming. Keep header/lease/ref alive.
		reregister_header(state, header)
		return {kind = .Backing_Failed, allocation = error}
	}
	sync.lock(&state.mu)
	state.stats.allocations -= 1
	state.stats.backing_bytes -= cost
	sync.unlock(&state.mu)
	scopes.release(&lease)
	release_state(state)
	return {}
}

@(private)
unregister_header :: proc(state: ^State, header: ^Header) {
	sync.lock(&state.mu)
	defer sync.unlock(&state.mu)
	if header.previous != nil do header.previous.next = header.next
	else do state.first = header.next
	if header.next != nil do header.next.previous = header.previous
	header.previous, header.next = nil, nil
	state.registered -= 1
}

@(private)
reregister_header :: proc(state: ^State, header: ^Header) {
	sync.lock(&state.mu)
	defer sync.unlock(&state.mu)
	header.next = state.first
	if state.first != nil do state.first.previous = header
	state.first = header
	state.registered += 1
}

// Resizing uses allocate/copy/free, charging the complete temporary overlap.
// Failed admission/allocation preserves the original bytes, owner and scope.
resize :: proc(source: Binding, previous: []u8, size: int, alignment: int = mem.DEFAULT_ALIGNMENT) -> ([]u8, Error) {
	if source._state == nil do return nil, {kind = .Invalid_Handle}
	if raw_data(previous) == nil {
		if len(previous) != 0 do return nil, {kind = .Invalid_Argument}
		return allocate(source, size, alignment)
	}
	header := find_header(source._state, raw_data(previous))
	if header == nil do return nil, {kind = .Invalid_Pointer}
	if len(previous) != header.size do return nil, {kind = .Invalid_Argument}
	return resize_header(source._state, header, size, alignment, true)
}

@(private)
resize_header :: proc(state: ^State, header: ^Header, size, alignment: int, zeroed: bool) -> ([]u8, Error) {
	_, validation := allocation_cost(size, alignment)
	if validation.kind != .None do return nil, validation
	if size == 0 do return nil, free_header(state, header)
	result, error := allocate_in_scope(state, scopes.scope_of(header.lease), size, alignment, zeroed)
	if error.kind != .None do return nil, error
	copy(result, (cast([^]u8)header.data)[:header.size])
	freed := free_header(state, header)
	if freed.kind != .None {
		// A backing allocator that cannot release valid storage is unsuitable
		// for transactional resize. Failure to discard this temporary is fatal.
		temporary := find_header(state, raw_data(result))
		assert(free_header(state, temporary).kind == .None)
		return nil, freed
	}
	return result, {}
}
