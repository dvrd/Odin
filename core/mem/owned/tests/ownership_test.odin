package tests

import owned ".."
import "core:mem"
import "core:testing"

Pool_Slot :: struct {
	bytes: [16]u8,
	returned: int,
	available: bool,
	owner: ^owned.Chunk,
}
return_slot :: proc(storage: []u8, user_data: rawptr) {
	slot := cast(^Pool_Slot)user_data
	assert(raw_data(storage) == &slot.bytes[0] || len(storage) == 0)
	slot.returned += 1
	slot.available = true
	// The exact owner must already be cleared when user release code runs.
	if slot.owner != nil {
		assert(!owned.valid(slot.owner))
		owned.destroy(slot.owner)
	}
}
pooled :: proc(slot: ^Pool_Slot, payload: string, retained := 16) -> owned.Chunk {
	copy(slot.bytes[:], payload)
	storage := slot.bytes[:retained]
	chunk, error := owned.take_custom(&storage, len(payload), return_slot, slot)
	assert(error.kind == .None && storage == nil)
	return chunk
}

@(test)
whole_chunk_backpressure_and_delayed_release :: proc(t: ^testing.T) {
	queue: owned.Queue
	testing.expect_value(t, owned.queue_init(&queue, 2, 16).kind, .None)
	defer owned.queue_destroy(&queue)
	first, second: Pool_Slot
	chunk := pooled(&first, "body")
	other := pooled(&second, "next")
	defer owned.destroy(&chunk)
	defer owned.destroy(&other)
	testing.expect_value(t, owned.queue_submit(&queue, &chunk), .Accepted)
	testing.expect(t, !owned.valid(&chunk), "acceptance clears producer owner")
	original := raw_data(other.data)
	testing.expect_value(t, owned.queue_submit(&queue, &other), .Backpressure)
	testing.expect(t, owned.valid(&other) && raw_data(other.data) == original)
	testing.expect_value(t, queue.retained_bytes, 16)
	// Sending or losing packets does not release retransmission backing. Only
	// the consumer's later ACK/discard policy explicitly releases the front.
	for _ in 0..<8 {
		data, ok := owned.queue_front(&queue)
		testing.expect(t, ok && string(data) == "body")
		testing.expect_value(t, first.returned, 0)
	}
	testing.expect(t, owned.queue_release_front(&queue))
	testing.expect_value(t, first.returned, 1)
	testing.expect_value(t, owned.queue_submit(&queue, &other), .Accepted)
	owned.queue_close(&queue)
	owned.queue_close(&queue)
	testing.expect_value(t, second.returned, 1)
	testing.expect_value(t, queue.retained_bytes, 0)
	testing.expect(t, !owned.queue_release_front(&queue))
	late := pooled(&first, "late")
	testing.expect_value(t, owned.queue_submit(&queue, &late), .Closed)
	testing.expect(t, owned.valid(&late), "closed queue preserves rejected owner")
	owned.destroy(&late)
}

@(test)
zero_byte_chunks_still_consume_slots_and_cancel_once :: proc(t: ^testing.T) {
	queue: owned.Queue
	testing.expect_value(t, owned.queue_init(&queue, 2, 0).kind, .None)
	defer owned.queue_destroy(&queue)
	a, b, c: Pool_Slot
	first := pooled(&a, "", 0)
	second := pooled(&b, "", 0)
	third := pooled(&c, "", 0)
	defer owned.destroy(&first)
	defer owned.destroy(&second)
	defer owned.destroy(&third)
	testing.expect_value(t, owned.queue_submit(&queue, &first), .Accepted)
	testing.expect_value(t, owned.queue_submit(&queue, &second), .Accepted)
	testing.expect_value(t, owned.queue_submit(&queue, &third), .Backpressure)
	testing.expect(t, owned.valid(&third) && len(third.data) == 0 && len(third.storage) == 0 && raw_data(third.storage) == &c.bytes[0])
	empty: owned.Chunk
	testing.expect_value(t, owned.queue_submit(&queue, &empty), .Invalid)
	testing.expect(t, !owned.valid(&empty) && empty.data == nil)
	testing.expect_value(t, queue.count, 2)
	testing.expect_value(t, queue.retained_bytes, 0)
	owned.queue_clear(&queue) // cancellation/reset without closing admission
	owned.queue_clear(&queue)
	testing.expect(t, a.returned == 1 && b.returned == 1 && c.returned == 0)
	testing.expect_value(t, owned.queue_submit(&queue, &third), .Accepted)
	owned.queue_destroy(&queue)
	owned.queue_destroy(&queue)
	testing.expect_value(t, c.returned, 1)
}

@(test)
dynamic_move_charges_capacity_and_frees_with_original_allocator :: proc(t: ^testing.T) {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	allocator := mem.tracking_allocator(&tracker)
	array := make([dynamic]u8, 3, 64, allocator)
	copy(array[:], "abc")
	original := raw_data(array)
	chunk, error := owned.take_dynamic(&array)
	testing.expect_value(t, error.kind, .None)
	testing.expect(t, len(array) == 0 && cap(array) == 0 && raw_data(array) == nil)
	testing.expect(t, raw_data(chunk.data) == original && string(chunk.data) == "abc")
	testing.expect_value(t, len(chunk.storage), 64)
	queue: owned.Queue
	testing.expect_value(t, owned.queue_init(&queue, 1, 63).kind, .None)
	testing.expect_value(t, owned.queue_submit(&queue, &chunk), .Backpressure)
	testing.expect(t, owned.valid(&chunk))
	owned.queue_destroy(&queue)
	testing.expect_value(t, owned.queue_init(&queue, 1, 64).kind, .None)
	defer owned.queue_destroy(&queue)
	testing.expect_value(t, owned.queue_submit(&queue, &chunk), .Accepted)
	testing.expect_value(t, queue.retained_bytes, 64)
	owned.queue_close(&queue)
	testing.expect_value(t, tracker.total_free_count, 1)
	testing.expect_value(t, tracker.current_memory_allocated, 0)
	delete(array) // moved source remains safe to destroy
	owned.destroy(&chunk)
	testing.expect_value(t, tracker.total_free_count, 1)
}

failing_allocate :: proc(data: rawptr, mode: mem.Allocator_Mode, size, alignment: int,
	old_memory: rawptr, old_size: int, loc := #caller_location,
) -> ([]u8, mem.Allocator_Error) {
	return nil, .Out_Of_Memory
}

@(test)
bounded_copy_and_allocation_failures_preserve_owners :: proc(t: ^testing.T) {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	allocator := mem.tracking_allocator(&tracker)
	bytes := []u8{'a', 'b', 'c'}
	_, limit_error := owned.copy_bounded(bytes, 2, allocator)
	testing.expect_value(t, limit_error.kind, .Limit_Exceeded)
	testing.expect_value(t, tracker.total_allocation_count, 0)
	chunk, error := owned.copy_bounded(bytes, 3, allocator)
	testing.expect_value(t, error.kind, .None)
	bytes[0] = 'z'
	testing.expect_value(t, string(chunk.data), "abc")
	owned.destroy(&chunk)
	owned.destroy(&chunk)
	testing.expect_value(t, tracker.total_free_count, 1)
	failure := mem.Allocator{procedure=failing_allocate}
	_, allocation_error := owned.copy_bounded(bytes, 3, failure)
	testing.expect(t, allocation_error.kind == .Allocation_Failed && allocation_error.allocation == .Out_Of_Memory)
	queue: owned.Queue
	testing.expect_value(t, owned.queue_init(&queue, 2, 6, failure).kind, .Allocation_Failed)
	testing.expect(t, queue.slots == nil && queue.count == 0 && !queue.closed)
	testing.expect_value(t, owned.queue_init(&queue, max(int), max(int), allocator).kind, .Invalid_Input)
	testing.expect_value(t, tracker.total_allocation_count, 1)
	owned.queue_destroy(&queue)
}

@(test)
move_rejection_adoption_failure_and_reentrant_destroy :: proc(t: ^testing.T) {
	first, second: Pool_Slot
	source := pooled(&first, "one")
	destination := pooled(&second, "two")
	defer owned.destroy(&destination)
	original := raw_data(source.data)
	testing.expect(t, !owned.move(&destination, &source))
	testing.expect(t, !owned.move(&source, &source))
	testing.expect(t, raw_data(source.data) == original && string(destination.data) == "two")
	empty: owned.Chunk
	testing.expect(t, !owned.move(&empty, &empty))
	testing.expect(t, !owned.move(&empty, nil))
	testing.expect(t, owned.move(&empty, &source))
	testing.expect(t, !owned.valid(&source))
	first.owner = &empty
	owned.destroy(&empty)
	owned.destroy(&empty)
	testing.expect_value(t, first.returned, 1)
	storage := second.bytes[:]
	_, invalid := owned.take_custom(&storage, 17, return_slot, &second)
	testing.expect(t, invalid.kind == .Invalid_Input && len(storage) == 16)
	invalid_array: [dynamic]u8
	_, dynamic_error := owned.take_dynamic(&invalid_array)
	testing.expect(t, dynamic_error.kind == .Invalid_Input && cap(invalid_array) == 0)
}

@(test)
fifo_wrap_and_byte_admission_are_independent :: proc(t: ^testing.T) {
	queue: owned.Queue
	testing.expect_value(t, owned.queue_init(&queue, 2, 2).kind, .None)
	defer owned.queue_destroy(&queue)
	a, b, c: Pool_Slot
	first := pooled(&a, "a", 1)
	second := pooled(&b, "b", 1)
	third := pooled(&c, "c", 1)
	testing.expect_value(t, owned.queue_submit(&queue, &first), .Accepted)
	testing.expect_value(t, owned.queue_submit(&queue, &second), .Accepted)
	testing.expect(t, owned.queue_release_front(&queue))
	testing.expect_value(t, owned.queue_submit(&queue, &third), .Accepted)
	data, ok := owned.queue_front(&queue)
	testing.expect(t, ok && string(data) == "b")
	testing.expect(t, owned.queue_release_front(&queue))
	data, ok = owned.queue_front(&queue)
	testing.expect(t, ok && string(data) == "c")
	owned.queue_close(&queue)
	testing.expect(t, a.returned == 1 && b.returned == 1 && c.returned == 1)
	testing.expect_value(t, queue.retained_bytes, 0)
}

@(test)
invalid_payload_view_cannot_bypass_backing_budget :: proc(t: ^testing.T) {
	queue: owned.Queue
	testing.expect_value(t, owned.queue_init(&queue, 1, 16).kind, .None)
	defer owned.queue_destroy(&queue)
	slot: Pool_Slot
	chunk := pooled(&slot, "body")
	defer owned.destroy(&chunk)
	outside := []u8{'o', 't', 'h', 'e', 'r'}
	chunk.data = outside
	testing.expect(t, !owned.valid(&chunk))
	testing.expect_value(t, owned.queue_submit(&queue, &chunk), .Invalid)
	testing.expect(t, raw_data(chunk.data) == raw_data(outside) && queue.count == 0 && slot.returned == 0)
	// A live owner remains occupied even if its payload view is malformed.
	other_slot: Pool_Slot
	other := pooled(&other_slot, "next")
	defer owned.destroy(&other)
	testing.expect(t, !owned.move(&chunk, &other))
	testing.expect(t, owned.valid(&other))
	chunk.data = slot.bytes[4:8]
	testing.expect(t, owned.valid(&chunk), "interior payload may borrow the full retained backing")
	testing.expect_value(t, owned.queue_submit(&queue, &chunk), .Accepted)
	testing.expect_value(t, queue.retained_bytes, 16)
}

@(test)
failed_dynamic_adoption_preserves_nonempty_source :: proc(t: ^testing.T) {
	array := make([dynamic]u8, 3, 8)
	original := raw_data(array)
	allocator := array.allocator
	array.allocator = {}
	_, error := owned.take_dynamic(&array)
	testing.expect_value(t, error.kind, .Invalid_Input)
	testing.expect(t, raw_data(array) == original && len(array) == 3 && cap(array) == 8)
	array.allocator = allocator
	delete(array)
}
