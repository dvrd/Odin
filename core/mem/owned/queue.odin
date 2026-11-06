package owned

import "core:mem"

// A serialized-owner FIFO. No internal synchronization; callers serialize all
// operations and keep the queue, allocators and release contexts alive until
// teardown. Storage and bytes are bounded independently, including empty data.
Queue :: struct {
	slots: []Chunk,
	head, count: int,
	retained_bytes, byte_limit: int,
	allocator: mem.Allocator,
	closed: bool,
}
Submit_Result :: enum {Accepted, Backpressure, Closed, Invalid}

queue_init :: proc(queue: ^Queue, capacity, byte_limit: int, allocator := context.allocator) -> Error {
	if queue == nil || len(queue.slots) != 0 || capacity < 1 ||
	   capacity > max(int) / size_of(Chunk) || byte_limit < 0 || allocator.procedure == nil {
		return {kind=.Invalid_Input}
	}
	slots, allocation_error := make([]Chunk, capacity, allocator)
	if allocation_error != nil {return {kind=.Allocation_Failed, allocation=allocation_error}}
	if raw_data(slots) == nil {return {kind=.Allocation_Failed, allocation=.Out_Of_Memory}}
	queue^ = {slots=slots, byte_limit=byte_limit, allocator=allocator}
	return {}
}

// Whole-chunk admission. Rejection leaves source intact. Acceptance clears it
// without another payload allocation/copy. Charge retained backing, not data len.
queue_submit :: proc(queue: ^Queue, source: ^Chunk) -> Submit_Result {
	if queue == nil || source == nil {return .Invalid}
	if queue.closed || len(queue.slots) == 0 {return .Closed}
	if !valid(source) {return .Invalid}
	cost := len(source.storage)
	if queue.count == len(queue.slots) || cost > queue.byte_limit - queue.retained_bytes {
		return .Backpressure
	}
	index := (queue.head + queue.count) % len(queue.slots)
	if !move(&queue.slots[index], source) {return .Invalid}
	queue.count += 1
	queue.retained_bytes += cost
	return .Accepted
}

// A borrowed payload: valid only until front release/clear/close/destroy. The
// producer must not modify pending bytes or any aliases after submission. A
// packet send does not release ownership; transport completion/ACK policy does.
queue_front :: proc(queue: ^Queue) -> (data: []u8, ok: bool) {
	if queue == nil || queue.count == 0 {return nil, false}
	return queue.slots[queue.head].data, true
}

// Release only when the consumer no longer needs this backing storage. This is
// a memory event, not proof of delivery; reset/cancel/failure may also release it.
queue_release_front :: proc(queue: ^Queue) -> bool {
	if queue == nil || queue.count == 0 {return false}
	index := queue.head
	chunk := queue.slots[index]
	queue.slots[index] = {}
	queue.head = (index + 1) % len(queue.slots)
	queue.count -= 1
	queue.retained_bytes -= len(chunk.storage)
	destroy(&chunk)
	return true
}

// Cancels/discards pending owners while preserving the queue's allocated slots
// and open/closed state. Reusable queues can accept new work after a clear.
queue_clear :: proc(queue: ^Queue) {
	if queue == nil {return}
	for queue_release_front(queue) {}
}

// Shutdown/reset/error paths can close repeatedly: no new admissions, and all
// accepted owners are released. No transport delivery acknowledgment is implied.
queue_close :: proc(queue: ^Queue) {
	if queue == nil {return}
	queue.closed = true
	queue_clear(queue)
}

queue_destroy :: proc(queue: ^Queue) {
	if queue == nil {return}
	queue_close(queue)
	old := queue^
	queue^ = {closed=true}
	if old.allocator.procedure != nil {delete(old.slots, old.allocator)}
}
