package mem_budget

import "core:mem"

// The standard allocator enum cannot carry budget errors. Both a denied budget
// and backing OOM map to Out_Of_Memory; use typed allocate/resize for attribution.
@(private)
allocator_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	// Empty moved owners may be destroyed after their Binding owner retires.
	if mode == .Free && old_memory == nil do return nil, nil
	if mode == .Query_Features {
		if old_memory == nil do return nil, .Invalid_Argument
		(cast(^mem.Allocator_Mode_Set)old_memory)^ = {
			.Alloc,
			.Alloc_Non_Zeroed,
			.Free,
			.Resize,
			.Resize_Non_Zeroed,
			.Query_Features,
			.Query_Info,
		}
		return nil, nil
	}
	if mode == .Free_All do return nil, .Mode_Not_Implemented
	if data == nil do return nil, .Invalid_Argument
	state := cast(^State)data
	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		bytes, error := allocate_in_scope(
			state,
			state.default_scope,
			size,
			alignment,
			mode == .Alloc,
		)
		return bytes, allocator_error(error)
	case .Free:
		header := find_header(state, old_memory)
		if header == nil do return nil, .Invalid_Pointer
		return nil, allocator_error(free_header(state, header))
	case .Resize, .Resize_Non_Zeroed:
		if old_memory == nil {
			if old_size != 0 do return nil, .Invalid_Argument
			bytes, error := allocate_in_scope(
				state,
				state.default_scope,
				size,
				alignment,
				mode == .Resize,
			)
			return bytes, allocator_error(error)
		}
		header := find_header(state, old_memory)
		if header == nil do return nil, .Invalid_Pointer
		if old_size != header.size do return nil, .Invalid_Argument
		bytes, error := resize_header(state, header, size, alignment, mode == .Resize)
		return bytes, allocator_error(error)
	case .Query_Info:
		return nil, query_info(state, old_memory)
	case .Free_All, .Query_Features:
		unreachable()
	}
	return nil, .Mode_Not_Implemented
}

@(private)
query_info :: proc(state: ^State, data: rawptr) -> mem.Allocator_Error {
	if data == nil do return .Invalid_Argument
	info := cast(^mem.Allocator_Query_Info)data
	header := find_header(state, info.pointer)
	if header == nil do return .Invalid_Pointer
	info.size, info.alignment = header.size, header.alignment
	return nil
}

@(private)
allocator_error :: proc(error: Error) -> mem.Allocator_Error {
	switch error.kind {
	case .None:
		return nil
	case .Budget_Rejected:
		return .Out_Of_Memory
	case .Allocation_Failed, .Backing_Failed:
		if error.allocation != nil do return error.allocation
		return .Out_Of_Memory
	case .Invalid_Pointer:
		return .Invalid_Pointer
	case .Unsupported_Mode:
		return .Mode_Not_Implemented
	case .Invalid_Argument, .Invalid_Config, .Invalid_Handle, .Overflow:
		return .Invalid_Argument
	}
	return .Invalid_Argument
}
