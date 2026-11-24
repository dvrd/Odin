package test_core_pem

import "core:mem"
import "core:encoding/pem"
import "core:testing"

PEM_Allocation :: struct {
	pointer: rawptr,
	size:    int,
	payload: bool,
}

PEM_Audit :: struct {
	backing:                                    mem.Allocator,
	slots:                                      [64]PEM_Allocation,
	allocations, live, dirty_releases, fail_at: int,
	nil_failure:                                bool,
}

pem_audit_release :: proc(s: ^PEM_Audit, pointer: rawptr) {
	for &slot in s.slots {
		if slot.pointer != pointer {
			continue
		}
		if slot.payload {
			for b in (cast([^]u8)pointer)[:slot.size] {
				if b != 0 {
					s.dirty_releases += 1
					break
				}
			}
		}
		slot = {}
		s.live -= 1
		return
	}
	assert(false, "unknown owned allocation")
}

pem_audit_allocate :: proc(
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
	s := cast(^PEM_Audit)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed {
		s.allocations += 1
		if s.fail_at == s.allocations {
			if s.nil_failure {
				return nil, .None
			}
			return nil, .Out_Of_Memory
		}
		// Force relocation, so an ordinary resize cannot hide stale secret bytes
		// by happening to grow in place in the underlying heap.
		fresh, error := s.backing.procedure(s.backing.data, .Alloc, size, alignment, nil, 0, location)
		if error != .None || raw_data(fresh) == nil {
			return fresh, error
		}
		if old_memory != nil {
			old_length := old_size
			for slot in s.slots {
				if slot.pointer == old_memory {
					old_length = slot.size
					break
				}
			}
			copy(fresh, (cast([^]u8)old_memory)[:min(old_length, len(fresh))])
			pem_audit_release(s, old_memory)
			_, _ = s.backing.procedure(s.backing.data, .Free, 0, alignment, old_memory, old_length, location)
		}
		for &slot in s.slots {
			if slot.pointer == nil {
				// The first allocation is PEM Block metadata; the11-byte label is
				// not secret. Other >=32B allocations are the decoded byte backing.
				slot = {raw_data(fresh), len(fresh), s.allocations > 1 && size >= 32}
				s.live += 1
				return fresh, .None
			}
		}
		assert(false, "audit storage exhausted")
	}
	if mode == .Free && old_memory != nil {
		pem_audit_release(s, old_memory)
	}
	return s.backing.procedure(s.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(test)
pem_decode_erases_each_replaced_backing_and_full_final_capacity :: proc(t: ^testing.T) {
	payload: [1025]u8
	for &b in payload {b = 0x6d}
	encoded, encode_error := pem.encode("PRIVATE KEY", payload[:])
	assert(encode_error == nil)
	defer delete(encoded)
	state := PEM_Audit {
		backing = context.allocator,
	}
	block, _, error := pem.decode(encoded, {procedure = pem_audit_allocate, data = &state})
	assert(error == nil && block != nil && len(block.data) == len(payload))
	// Poison all spare owned capacity too; block_delete must erase the backing,
	// even when its logical payload is shorter than its allocation.
	for &b in (raw_data(block.data))[len(block.data):cap(block.data)] {b = 0x6d}
	pem.block_delete(block)
	testing.expect_value(t, state.dirty_releases, 0)
	testing.expect_value(t, state.live, 0)
}

@(test)
pem_growth_failure_releases_only_erased_owned_backings :: proc(t: ^testing.T) {
	payload: [1025]u8
	for &b in payload {b = 0x6d}
	encoded, encode_error := pem.encode("PRIVATE KEY", payload[:])
	assert(encode_error == nil)
	defer delete(encoded)
	probe := PEM_Audit {
		backing = context.allocator,
	}
	block, _, error := pem.decode(encoded, {procedure = pem_audit_allocate, data = &probe})
	assert(error == nil && block != nil)
	pem.block_delete(block)
	for nil_failure in ([?]bool{false, true}) {
		for fail_at in 1 ..= probe.allocations {
			state := PEM_Audit {
				backing     = context.allocator,
				fail_at     = fail_at,
				nil_failure = nil_failure,
			}
			block, _, error = pem.decode(encoded, {procedure = pem_audit_allocate, data = &state})
			testing.expect(t, error != nil && block == nil)
			testing.expect_value(t, state.live, 0)
			testing.expect_value(t, state.dirty_releases, 0)
		}
	}
	malformed := make([]u8, len(encoded))
	defer delete(malformed)
	copy(malformed, encoded)
	malformed[len(malformed) - 1] = '?'
	failed := PEM_Audit {
		backing = context.allocator,
	}
	block, _, error = pem.decode(malformed, {procedure = pem_audit_allocate, data = &failed})
	testing.expect(t, error != nil && block == nil)
	testing.expect_value(t, failed.live, 0)
	testing.expect_value(t, failed.dirty_releases, 0)
	block, _, error = pem.decode(encoded, mem.nil_allocator())
	testing.expect(t, error != nil && block == nil)
}
