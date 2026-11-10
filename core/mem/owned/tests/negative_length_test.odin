package tests

import owned ".."
import "core:mem"
import "core:testing"

@(test)
negative_slice_lengths_cannot_be_valid_or_consume_queue_credit :: proc(t: ^testing.T) {
	for shape in ([]struct{data_len, storage_len: int}{
		{-1, 16}, {1, -1}, {-1, -1}, {0, -1},
	}) {
		slot: Pool_Slot
		source := pooled(&slot, "x")
		source.data=transmute([]u8)mem.Raw_Slice{data=raw_data(source.data), len=shape.data_len}
		source.storage=transmute([]u8)mem.Raw_Slice{data=raw_data(source.storage), len=shape.storage_len}
		before := source
		testing.expect(t, !owned.valid(&source))
		queue: owned.Queue
		assert(owned.queue_init(&queue, 1, 16).kind == .None)
		status := owned.queue_submit(&queue, &source)
		testing.expect_value(t, status, .Invalid)
		testing.expect(t, raw_data(source.data) == raw_data(before.data) && len(source.data) == len(before.data))
		testing.expect(t, raw_data(source.storage) == raw_data(before.storage) && len(source.storage) == len(before.storage))
		testing.expect(t, queue.count == 0 && queue.retained_bytes == 0 && slot.returned == 0)
		// The custom release callback observes the real stack buffer address and
		// does not free based on the deliberately malformed length, even on red.
		owned.queue_destroy(&queue)
		owned.destroy(&source)
	}
}

@(test)
negative_slice_adoption_rejects_without_moving_source :: proc(t: ^testing.T) {
	actual := make([]u8, 4)
	source := transmute([]u8)mem.Raw_Slice{data=raw_data(actual), len=-1}
	owner, error := owned.take_slice(&source)
	testing.expect_value(t, error.kind, .Invalid_Input)
	testing.expect(t, raw_data(source) == raw_data(actual) && len(source) == -1)
	if owner.allocator.procedure != nil {
		// Preserve clean teardown when demonstrating the old erroneous move.
		owner.data=actual; owner.storage=actual; owned.destroy(&owner)
	} else {
		delete(actual)
	}
}
