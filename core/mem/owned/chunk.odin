package owned

import "core:mem"

// A release callback returns the entire backing storage to its owner. Its
// user_data (for example, a pool) must survive until release, independently of
// the producing request's arena. The callback must not mutate the owning queue.
Release_Proc :: proc(storage: []u8, user_data: rawptr)

// Move-only by convention: copying this value or retaining aliases to data does
// not create another owner. Use move/take helpers, then destroy the last owner.
// data may be shorter than storage; byte admission charges the entire backing.
Chunk :: struct {
	data: []u8,
	storage: []u8,
	allocator: mem.Allocator,
	release: Release_Proc,
	user_data: rawptr,
}

Error_Kind :: enum {None, Invalid_Input, Limit_Exceeded, Allocation_Failed}
Error :: struct {kind: Error_Kind, allocation: mem.Allocator_Error}

// Checks release ownership and that payload bytes lie within charged backing.
// The caller still must supply an actual live allocation; raw slices cannot
// prove allocator provenance or protect against separately copied aliases.
valid :: proc(chunk: ^Chunk) -> bool {
	if chunk == nil {return false}
	custom := chunk.release != nil
	allocated := chunk.allocator.procedure != nil
	if custom == allocated {return false}
	if len(chunk.storage) > 0 && raw_data(chunk.storage) == nil {return false}
	if len(chunk.data) == 0 {return true}
	storage := uintptr(raw_data(chunk.storage))
	data := uintptr(raw_data(chunk.data))
	if data < storage {return false}
	offset := data - storage
	if offset > uintptr(len(chunk.storage)) {return false}
	return uintptr(len(chunk.data)) <= uintptr(len(chunk.storage)) - offset
}

allocate :: proc(size: int, allocator := context.allocator) -> (chunk: Chunk, error: Error) {
	if size < 0 || allocator.procedure == nil {return {}, {kind=.Invalid_Input}}
	data, allocation_error := make([]u8, size, allocator)
	if allocation_error != nil {return {}, {kind=.Allocation_Failed, allocation=allocation_error}}
	if size > 0 && raw_data(data) == nil {return {}, {kind=.Allocation_Failed, allocation=.Out_Of_Memory}}
	return {data=data, storage=data, allocator=allocator}, {}
}

// Convenience path for callers whose source cannot outlive the operation.
// The limit is checked before allocation. Queue admission is still explicit.
copy_bounded :: proc(data: []u8, limit: int, allocator := context.allocator) -> (chunk: Chunk, error: Error) {
	if limit < 0 {return {}, {kind=.Invalid_Input}}
	if len(data) > limit {return {}, {kind=.Limit_Exceeded}}
	chunk, error = allocate(len(data), allocator)
	if error.kind != .None {return}
	copy(chunk.data, data)
	return
}

// Adopts an entire allocation, not an interior subslice. It must have been
// allocated with allocator and must be individually releasable by that owner.
take_slice :: proc(source: ^[]u8, allocator := context.allocator) -> (chunk: Chunk, error: Error) {
	if source == nil || allocator.procedure == nil {return {}, {kind=.Invalid_Input}}
	if len(source^) > 0 && raw_data(source^) == nil {return {}, {kind=.Invalid_Input}}
	chunk = {data=source^, storage=source^, allocator=allocator}
	source^ = nil
	return
}

// Moves an array's full capacity and its original allocator without allocating
// per-chunk metadata. Only successful adoption clears the source array.
take_dynamic :: proc(source: ^[dynamic]u8) -> (chunk: Chunk, error: Error) {
	if source == nil {return {}, {kind=.Invalid_Input}}
	if source.allocator.procedure == nil || len(source^) < 0 || cap(source^) < 0 || len(source^) > cap(source^) ||
	   (cap(source^) > 0 && raw_data(source^) == nil) {
		return {}, {kind=.Invalid_Input}
	}
	chunk = {
		data=source^[:],
		storage=(raw_data(source^))[:cap(source^)],
		allocator=source.allocator,
	}
	source^ = {}
	return
}

// Moves caller-owned pool/custom storage. On invalid arguments, both the
// original slice and its owner remain unchanged. release receives all storage.
take_custom :: proc(source: ^[]u8, payload_length: int, release: Release_Proc, user_data: rawptr) -> (chunk: Chunk, error: Error) {
	if source == nil || release == nil || payload_length < 0 {return {}, {kind=.Invalid_Input}}
	if payload_length > len(source^) || (len(source^) > 0 && raw_data(source^) == nil) {return {}, {kind=.Invalid_Input}}
	chunk = {data=source^[:payload_length], storage=source^, release=release, user_data=user_data}
	source^ = nil
	return
}

// Whole-owner move. An occupied destination, invalid source or self-move is
// rejected without changing either owner. A successful move clears the source.
move :: proc(destination, source: ^Chunk) -> bool {
	if destination == nil || source == nil || destination == source ||
	   (destination.release != nil || destination.allocator.procedure != nil) || !valid(source) {return false}
	destination^ = source^
	source^ = {}
	return true
}

// Clears before invoking user code, making repeated/reentrant destruction of
// this exact owner harmless. Copies of the old struct are still invalid aliases.
destroy :: proc(chunk: ^Chunk) {
	if chunk == nil {return}
	old := chunk^
	chunk^ = {}
	if old.release != nil {
		old.release(old.storage, old.user_data)
	} else if old.allocator.procedure != nil {
		delete(old.storage, old.allocator)
	}
}
