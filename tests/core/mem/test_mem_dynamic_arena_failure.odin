package test_core_mem

import rt "base:runtime"
import "core:mem"
import "core:testing"

Arena_Failure :: struct {
	backing:                   mem.Allocator,
	attempts, fail_at, nil_at: int,
	reject:                    bool,
}

arena_failure_allocator :: proc(
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
	state := cast(^Arena_Failure)data
	allocating := mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed
	if size > 0 && allocating {
		state.attempts += 1
		if state.attempts == state.nil_at do return nil, nil
		if state.reject || state.attempts == state.fail_at do return nil, .Out_Of_Memory
	}
	return state.backing.procedure(state.backing.data, mode, size, alignment, old_memory, old_size, location)
}

// Keep a red ownership regression from leaking the test's actual process heap.
// The assertions run first, so this cleanup cannot turn a lost owner green.
arena_failure_cleanup :: proc(track: ^mem.Tracking_Allocator) {
	pointers: [64]rawptr
	count := 0
	for pointer in track.allocation_map {
		assert(count < len(pointers))
		pointers[count] = pointer
		count += 1
	}
	for pointer in pointers[:count] do free(pointer, mem.tracking_allocator(track))
	mem.tracking_allocator_destroy(track)
}

@(test)
test_dynamic_arena_failed_block_bookkeeping_preserves_old_owner :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer arena_failure_cleanup(&track)
	backing := mem.tracking_allocator(&track)
	failure := Arena_Failure {
		backing = backing,
		fail_at = 1,
	}
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = backing,
		array_allocator = {arena_failure_allocator, &failure},
		block_size = 32,
		out_band_size = 64,
	)
	allocator := mem.dynamic_arena_allocator(&arena)
	old, first := mem.alloc_bytes(32, allocator = allocator)
	assert(first == nil)
	old[0], old[31] = 17, 42
	_, error := mem.alloc_bytes(1, allocator = allocator)
	testing.expect_value(t, error, .Out_Of_Memory)
	testing.expect_value(t, old[0], u8(17))
	testing.expect_value(t, old[31], u8(42))
	failure.fail_at = 0
	retried, retry := mem.alloc_bytes(1, allocator = allocator)
	testing.expect_value(t, retry, mem.Allocator_Error.None)
	testing.expect(t, raw_data(retried) != nil)
	if raw_data(retried) != nil {
		retried[0] = 55
		testing.expect_value(t, retried[0], u8(55))
	}
	mem.dynamic_arena_destroy(&arena)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

@(test)
test_dynamic_arena_failed_out_band_bookkeeping_releases_unpublished_payload :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer arena_failure_cleanup(&track)
	failure := Arena_Failure {
		backing = mem.tracking_allocator(&track),
		fail_at = 2,
	}
	allocator := mem.Allocator{arena_failure_allocator, &failure}
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = allocator,
		array_allocator = allocator,
		block_size = 32,
		out_band_size = 64,
	)
	data, error := mem.alloc_bytes(64, allocator = mem.dynamic_arena_allocator(&arena))
	testing.expect_value(t, error, .Out_Of_Memory)
	testing.expect_value(t, len(data), 0)
	mem.dynamic_arena_destroy(&arena)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

@(test)
test_dynamic_arena_failed_next_block_can_retry_without_losing_previous_block :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer arena_failure_cleanup(&track)
	backing := mem.tracking_allocator(&track)
	failure := Arena_Failure {
		backing = backing,
		fail_at = 2,
	}
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = {arena_failure_allocator, &failure},
		array_allocator = backing,
		block_size = 32,
		out_band_size = 64,
	)
	allocator := mem.dynamic_arena_allocator(&arena)
	old, first := mem.alloc_bytes(32, allocator = allocator)
	assert(first == nil)
	old[0], old[31] = 11, 29
	_, failed := mem.alloc_bytes(1, allocator = allocator)
	testing.expect_value(t, failed, .Out_Of_Memory)
	failure.fail_at = 0
	retried, retry := mem.alloc_bytes(1, allocator = allocator)
	testing.expect_value(t, retry, mem.Allocator_Error.None)
	testing.expect(t, raw_data(retried) != nil)
	if raw_data(retried) != nil {
		retried[0] = 55
		testing.expect_value(t, retried[0], u8(55))
	}
	testing.expect_value(t, old[0], u8(11))
	testing.expect_value(t, old[31], u8(29))
	mem.dynamic_arena_destroy(&arena)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

@(test)
test_dynamic_arena_reset_and_destroy_need_no_new_allocations :: proc(t: ^testing.T) {
	for reset in ([2]bool{false, true}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		failure := Arena_Failure {
			backing = mem.tracking_allocator(&track),
		}
		allocator := mem.Allocator{arena_failure_allocator, &failure}
		arena: mem.Dynamic_Arena
		mem.dynamic_arena_init(
			&arena,
			block_allocator = allocator,
			array_allocator = allocator,
			block_size = 32,
			out_band_size = 64,
		)
		for _ in 0 ..< 4 {
			_, error := mem.alloc_bytes(32, allocator = mem.dynamic_arena_allocator(&arena))
			assert(error == nil)
		}
		attempts := failure.attempts
		failure.reject = true
		if reset {
			mem.dynamic_arena_reset(&arena)
			testing.expect_value(t, failure.attempts, attempts)
			// Existing retained blocks remain usable without allocating storage.
			_, reuse := mem.alloc_bytes(16, allocator = mem.dynamic_arena_allocator(&arena))
			testing.expect_value(t, reuse, mem.Allocator_Error.None)
		}
		mem.dynamic_arena_destroy(&arena)
		testing.expect_value(t, failure.attempts, attempts)
		testing.expect_value(t, track.current_memory_allocated, i64(0))
		testing.expect_value(t, len(track.bad_free_array), 0)
		arena_failure_cleanup(&track)
	}
}

@(test)
test_dynamic_arena_nil_success_backend_is_oom_and_can_retry :: proc(t: ^testing.T) {
	for out_band in ([2]bool{false, true}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		failure := Arena_Failure {
			backing = mem.tracking_allocator(&track),
			nil_at  = 1,
		}
		allocator := mem.Allocator{arena_failure_allocator, &failure}
		arena: mem.Dynamic_Arena
		mem.dynamic_arena_init(
			&arena,
			block_allocator = allocator,
			array_allocator = allocator,
			block_size = 32,
			out_band_size = 64,
		)
		size := 64 if out_band else 32
		data, error := mem.alloc_bytes(size, allocator = mem.dynamic_arena_allocator(&arena))
		testing.expect_value(t, error, .Out_Of_Memory)
		testing.expect_value(t, len(data), 0)
		failure.nil_at = 0
		retried, retry := mem.alloc_bytes(size, allocator = mem.dynamic_arena_allocator(&arena))
		testing.expect_value(t, retry, mem.Allocator_Error.None)
		testing.expect(t, raw_data(retried) != nil)
		if raw_data(retried) != nil {
			retried[0] = 91
			testing.expect_value(t, retried[0], u8(91))
		}
		mem.dynamic_arena_destroy(&arena)
		testing.expect_value(t, track.current_memory_allocated, i64(0))
		testing.expect_value(t, len(track.bad_free_array), 0)
		arena_failure_cleanup(&track)
	}
}

@(test)
test_dynamic_arena_repeated_partial_reuse_reset_keeps_blocks_and_alignment :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer arena_failure_cleanup(&track)
	failure := Arena_Failure {
		backing = mem.tracking_allocator(&track),
	}
	allocator := mem.Allocator{arena_failure_allocator, &failure}
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = allocator,
		array_allocator = allocator,
		block_size = 64,
		out_band_size = 128,
	)
	for _ in 0 ..< 4 {
		data, error := mem.alloc_bytes(64, 64, mem.dynamic_arena_allocator(&arena))
		assert(error == nil)
		data[0] = 93
	}
	mem.dynamic_arena_reset(&arena)
	// Reuse only part of the cache, leaving both used and unused pointers at
	// the next reset. Pre-existing tables must suffice even under rejection.
	for _ in 0 ..< 2 {
		data, error := mem.alloc_bytes(64, 64, mem.dynamic_arena_allocator(&arena))
		assert(error == nil)
		data[0] = 94
	}
	attempts := failure.attempts
	failure.reject = true
	for _ in 0 ..< 3 {
		mem.dynamic_arena_reset(&arena)
		for _ in 0 ..< 4 {
			data, error := mem.alloc_bytes(64, 64, mem.dynamic_arena_allocator(&arena))
			testing.expect_value(t, error, mem.Allocator_Error.None)
			if error == nil {
				testing.expect(t, raw_data(data) != nil && uintptr(raw_data(data)) % 64 == 0)
				testing.expect_value(t, data[0], u8(0))
				data[0] = 95
			}
		}
	}
	mem.dynamic_arena_free_all(&arena)
	testing.expect_value(t, failure.attempts, attempts)
	mem.dynamic_arena_destroy(&arena)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
	testing.expect_value(t, len(track.bad_free_array), 0)
}

@(test)
test_dynamic_arena_zero_size_out_band_allocation_remains_successful :: proc(t: ^testing.T) {
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = mem.nil_allocator(),
		array_allocator = mem.nil_allocator(),
		block_size = 32,
		out_band_size = 0,
	)
	defer mem.dynamic_arena_destroy(&arena)
	zeroed, zeroed_error := mem.dynamic_arena_alloc_bytes(&arena, 0)
	non_zeroed, non_zeroed_error := mem.dynamic_arena_alloc_bytes_non_zeroed(&arena, 0)
	testing.expect_value(t, zeroed_error, mem.Allocator_Error.None)
	testing.expect_value(t, non_zeroed_error, mem.Allocator_Error.None)
	testing.expect_value(t, len(zeroed), 0)
	testing.expect_value(t, len(non_zeroed), 0)
	_, positive_error := mem.dynamic_arena_alloc_bytes(&arena, 1)
	testing.expect_value(t, positive_error, .Out_Of_Memory)
}
