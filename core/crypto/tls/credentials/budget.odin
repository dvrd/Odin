package credentials
import "core:crypto"
import "core:mem"

// Free the whole granted range, including abnormal allocator returns.
@(private)
wipe_grant :: proc(allocator: mem.Allocator, grant: []u8, alignment: int) {
	if raw_data(grant) == nil {
		return
	}
	crypto.zero_explicit(raw_data(grant), len(grant))
	_, _ = allocator.procedure(allocator.data, .Free, 0, alignment, raw_data(grant), len(grant))
}

@(private)
release :: proc(owner: ^Owner, a: ^Allocation) {
	wipe_grant(owner.backing, (cast([^]u8)a.pointer)[:a.size], a.alignment)
	owner.used -= a.size
	a^ = {}
}

// Fixed metadata lives inside the prepaid owner. Resize charges the overlap
// before wiping/freeing the old grant; parser temporaries share the same budget.
@(private)
budget_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	owner := cast(^Owner)data
	switch mode {
	case .Query_Features:
		(cast(^mem.Allocator_Mode_Set)old)^ = {
			.Alloc,
			.Alloc_Non_Zeroed,
			.Resize,
			.Resize_Non_Zeroed,
			.Free,
			.Query_Features,
			.Query_Info,
		}
		return nil, .None
	case .Query_Info:
		info := cast(^mem.Allocator_Query_Info)old
		for a in owner.allocations {
			if a.pointer == info.pointer && a.pointer != nil {
				info.size = a.size
				info.alignment = a.alignment
				return nil, .None
			}
		}
		return nil, .Invalid_Pointer
	case .Free_All:
		return nil, .Mode_Not_Implemented
	case .Free:
		if old == nil {
			return nil, .None
		}
		for &a in owner.allocations {
			if a.pointer == old {
				release(owner, &a)
				return nil, .None
			}
		}
		return nil, .Invalid_Pointer
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		if size < 0 || alignment <= 0 {
			return nil, .Invalid_Argument
		}
		prior: ^Allocation
		if mode == .Resize || mode == .Resize_Non_Zeroed {
			if old != nil {
				for &a in owner.allocations {
					if a.pointer == old {
						prior = &a
						break
					}
				}
				if prior == nil {
					return nil, .Invalid_Pointer
				}
			}
		}
		if size == 0 {
			if prior != nil {
				release(owner, prior)
			}
			return nil, .None
		}
		if size > owner.limits.max_storage_bytes - owner.used {
			owner.limit_hit = true
			return nil, .Out_Of_Memory
		}
		slot: ^Allocation
		for &a in owner.allocations {
			if a.pointer == nil {
				slot = &a
				break
			}
		}
		if slot == nil {
			owner.limit_hit = true
			return nil, .Out_Of_Memory
		}
		allocated, error := owner.backing.procedure(owner.backing.data, .Alloc, size, alignment, nil, 0, loc)
		if error != nil || len(allocated) != size || raw_data(allocated) == nil {
			wipe_grant(owner.backing, allocated, alignment)
			owner.allocation_failed = true
			return nil, .Out_Of_Memory
		}
		for &b in allocated {b = 0}
		slot^ = {raw_data(allocated), size, alignment}
		owner.used += size
		owner.peak = max(owner.peak, owner.used)
		if prior != nil {
			copy(allocated, (cast([^]u8)prior.pointer)[:min(prior.size, size)])
			release(owner, prior)
		}
		return allocated, .None
	}
	return nil, .Mode_Not_Implemented
}
