package conn

import "core:crypto"
import "core:mem"

// Stream bytes live in fixed blocks drawn from one pool for the connection, so
// a stream holds memory for the bytes it has buffered, not for its window.
// Block k of a stream covers absolute offsets [k*block, (k+1)*block). A block
// carries its data and two bitmaps: acknowledged and retry when it is sent,
// present when it is received.
//
// The default pool is embedded in the Connection and gives every record a full
// STREAM_BYTES window in both directions. A larger window puts the pool on the
// heap: adoption or init allocates it once from Stream_Windows.allocator and
// destroy frees it. Nothing allocates after that. A pool that is smaller than
// its worst case refuses with Capacity on write and discards an unbufferable
// packet unacknowledged on receive.
STREAM_WINDOW_MAX :: 1 << 24
POOL_BLOCK :: 1024

@(private)
INLINE_BLOCK :: 128
@(private)
INLINE_SLOTS :: STREAM_BYTES / INLINE_BLOCK + 1
@(private)
INLINE_BLOCKS :: STREAMS * 2 * INLINE_SLOTS
@(private)
INLINE_STRIDE :: INLINE_BLOCK + INLINE_BLOCK / 4

Stream_Windows :: struct {
	// Bytes one stream may buffer: unacknowledged when sent, unread when
	// received. Zero is STREAM_BYTES. Above STREAM_BYTES needs the allocator.
	send, recv:           int,
	// Bytes all streams together may buffer in a heap pool. Zero sizes the
	// pool so it cannot run out: every record's full send window, and for
	// receive the connection receive window plus two blocks per record.
	send_pool, recv_pool: int,
	allocator:            mem.Allocator,
}

Direction :: enum u8 {
	Send,
	Recv,
}

@(private)
Bits :: enum u8 {
	Acked,
	Retry,
}
// A received block uses the first bitmap for the bytes it holds.
@(private)
PRESENT :: Bits.Acked

Stream_Pool :: struct {
	block, stride: int,
	shift:         uint,
	window:        [Direction]int,
	// Ring entries per record, blocks a direction may hold, blocks it holds.
	slots:         [Direction]int,
	quota:         [Direction]int,
	held:          [Direction]int,
	blocks:        []u8,
	// One ring per record and direction. An entry is a block number plus one.
	table:         []u32,
	free:          u32,
	heap:          bool,
	allocator:     mem.Allocator,
}

// Bytes a stream may buffer in each direction on this connection.
stream_windows :: proc(c: ^Connection) -> (send, recv: int) {
	if c == nil || !c.initialized {
		return 0, 0
	}
	return c.streams.window[.Send], c.streams.window[.Recv]
}

// Largest write the stream's send window and the pool accept now. Peer flow
// control can still refuse it.
stream_send_room :: proc(c: ^Connection, id: u64) -> int {
	if usable(c) != .None || !send_direction(c, id) {
		return 0
	}
	p := &c.streams
	if p.block == 0 {
		return 0
	}
	buffered := 0; tail := 0
	if b := find_buf(c, id); b != nil {
		if b.reset || b.fin || b.stop {
			return 0
		}
		acked := win_run(c, b, .Send, .Acked, b.send_base, b.n, true)
		buffered = b.n - acked
		// Room left in the block that already holds the last buffered byte.
		if buffered > 0 {
			tail = (p.block - int((b.send_base + u64(b.n)) & u64(p.block - 1))) & (p.block - 1)
		}
	}
	room := p.window[.Send] - buffered
	spare := (p.quota[.Send] - p.held[.Send]) * p.block + tail
	return max(0, min(room, spare))
}

@(private)
pool_inline :: proc(c: ^Connection) {
	p := &c.streams
	p^ = {
		block  = INLINE_BLOCK,
		stride = INLINE_STRIDE,
		shift  = 7,
		window = {.Send = STREAM_BYTES, .Recv = STREAM_BYTES},
		slots  = {.Send = INLINE_SLOTS, .Recv = INLINE_SLOTS},
		quota  = {.Send = STREAMS * INLINE_SLOTS, .Recv = STREAMS * INLINE_SLOTS},
		blocks = c.stream_mem[:],
		table  = c.stream_table[:],
	}
	pool_chain(p)
}

#assert(1 << 7 == INLINE_BLOCK)
#assert(1 << 10 == POOL_BLOCK)

// Call on a zeroed, uninitialized connection. Failure leaves no pool behind.
@(private)
pool_setup :: proc(c: ^Connection, w: Stream_Windows, recv_max_data: u64) -> Error {
	send := w.send if w.send != 0 else STREAM_BYTES
	recv := w.recv if w.recv != 0 else STREAM_BYTES
	if send < 1 ||
	   recv < 1 ||
	   send > STREAM_WINDOW_MAX ||
	   recv > STREAM_WINDOW_MAX ||
	   w.send_pool < 0 ||
	   w.recv_pool < 0 {
		return .Invalid
	}
	if send <= STREAM_BYTES && recv <= STREAM_BYTES {
		if w.send_pool != 0 || w.recv_pool != 0 {
			return .Invalid
		}
		pool_inline(c)
		c.streams.window = {.Send = send, .Recv = recv}
		return .None
	}
	if w.allocator.procedure == nil {
		return .Invalid
	}
	if w.send_pool != 0 && w.send_pool < send || w.recv_pool != 0 && w.recv_pool < recv {
		return .Invalid
	}
	p := &c.streams
	p^ = {
		block     = POOL_BLOCK,
		stride    = POOL_BLOCK + POOL_BLOCK / 4,
		shift     = 10,
		window    = {.Send = send, .Recv = recv},
		heap      = true,
		allocator = w.allocator,
	}
	p.slots = {.Send = (send + POOL_BLOCK - 1) / POOL_BLOCK + 1, .Recv = (recv + POOL_BLOCK - 1) / POOL_BLOCK + 1}
	p.quota = {.Send = STREAMS * p.slots[.Send], .Recv = STREAMS * p.slots[.Recv]}
	// Unread bytes never exceed the connection receive window, and a stream
	// wastes at most two partial blocks around them.
	if bound := recv_max_data / POOL_BLOCK + 1 + 2 * STREAMS; bound < u64(p.quota[.Recv]) {
		p.quota[.Recv] = int(bound)
	}
	// One extra block lets a single stream hold a full window at any offset.
	if w.send_pool != 0 {
		p.quota[.Send] = min(p.quota[.Send], (w.send_pool + POOL_BLOCK - 1) / POOL_BLOCK + 1)
	}
	if w.recv_pool != 0 {
		p.quota[.Recv] = min(p.quota[.Recv], (w.recv_pool + POOL_BLOCK - 1) / POOL_BLOCK + 1)
	}
	blocks := p.quota[.Send] + p.quota[.Recv]
	table, te := make([]u32, STREAMS * (p.slots[.Send] + p.slots[.Recv]), w.allocator)
	if te != nil {
		p^ = {}
		return .Allocation
	}
	memory, me := make([]u8, blocks * p.stride, w.allocator)
	if me != nil {
		delete(table, w.allocator); p^ = {}
		return .Allocation
	}
	p.table = table; p.blocks = memory
	pool_chain(p)
	return .None
}

@(private)
pool_release :: proc(c: ^Connection) {
	p := &c.streams
	if p.heap {
		crypto.zero_explicit(raw_data(p.blocks), len(p.blocks))
		delete(p.blocks, p.allocator); delete(p.table, p.allocator)
	}
	p^ = {}
}

// Drops every stream byte and returns all blocks. Records must be cleared too.
@(private)
pool_reset :: proc(c: ^Connection) {
	p := &c.streams
	if p.block == 0 {
		return
	}
	crypto.zero_explicit(raw_data(p.blocks), len(p.blocks))
	for &entry in p.table {entry = 0}
	p.held = {}
	pool_chain(p)
}

@(private)
pool_chain :: proc(p: ^Stream_Pool) {
	count := len(p.blocks) / p.stride
	for i in 0 ..< count {
		next := u32(i + 2) if i + 1 < count else 0
		pool_link(p.blocks[i * p.stride:], next)
	}
	p.free = 1 if count > 0 else 0
}

@(private)
pool_link :: proc(block: []u8, next: u32) {
	block[0] = u8(next); block[1] = u8(next >> 8); block[2] = u8(next >> 16); block[3] = u8(next >> 24)
}

@(private)
pool_block :: proc(p: ^Stream_Pool, entry: u32) -> []u8 {
	at := int(entry - 1) * p.stride
	return p.blocks[at:at + p.stride]
}

@(private)
pool_take :: proc(p: ^Stream_Pool, d: Direction) -> u32 {
	if p.free == 0 || p.held[d] >= p.quota[d] {
		return 0
	}
	entry := p.free; block := pool_block(p, entry)
	p.free = u32(block[0]) | u32(block[1]) << 8 | u32(block[2]) << 16 | u32(block[3]) << 24
	pool_link(block, 0); p.held[d] += 1
	return entry
}

@(private)
pool_give :: proc(p: ^Stream_Pool, d: Direction, entry: u32) {
	block := pool_block(p, entry)
	crypto.zero_explicit(raw_data(block), len(block))
	pool_link(block, p.free); p.free = entry; p.held[d] -= 1
}

@(private)
pool_room :: proc(c: ^Connection, d: Direction) -> int {
	return c.streams.quota[d] - c.streams.held[d]
}

@(private)
win_ring :: proc(c: ^Connection, b: ^Buf, d: Direction) -> []u32 {
	p := &c.streams
	if p.block == 0 {
		return nil
	}
	index := buf_index(c, b); n := p.slots[d]
	at := index * p.slots[.Send]
	if d == .Recv {
		at = STREAMS * p.slots[.Send] + index * n
	}
	return p.table[at:at + n]
}

@(private)
win_base :: proc(b: ^Buf, d: Direction) -> (u64, ^int) {
	if d == .Send {
		return b.send_base, &b.send_head
	}
	return b.recv_base, &b.recv_head
}

// Ring position of block number k (offset >> shift), or -1 outside the ring.
@(private)
win_slot :: proc(c: ^Connection, b: ^Buf, d: Direction, ring: []u32, k: u64) -> int {
	base, head := win_base(b, d); first := base >> c.streams.shift
	if k < first || k - first >= u64(len(ring)) {
		return -1
	}
	return (head^ + int(k - first)) % len(ring)
}

// The block covering off (nil when none is held), the position of off in it,
// and how many of the n bytes from off it covers.
@(private)
win_segment :: proc(c: ^Connection, b: ^Buf, d: Direction, off: u64, n: int) -> (block: []u8, at, count: int) {
	p := &c.streams
	if p.block == 0 {
		return nil, 0, n
	}
	at = int(off & u64(p.block - 1)); count = min(n, p.block - at)
	ring := win_ring(c, b, d)
	if slot := win_slot(c, b, d, ring, off >> p.shift); slot >= 0 && ring[slot] != 0 {
		block = pool_block(p, ring[slot])
	}
	return
}

// Blocks [lo, hi) still needs. Counts blocks outside the window as missing.
@(private)
win_missing :: proc(c: ^Connection, b: ^Buf, d: Direction, lo, hi: u64) -> int {
	p := &c.streams
	if hi <= lo || p.block == 0 {
		return 0
	}
	first := lo >> p.shift; last := (hi - 1) >> p.shift
	if b == nil {
		return int(last - first + 1)
	}
	ring := win_ring(c, b, d); missing := 0
	for k := first; k <= last; k += 1 {
		slot := win_slot(c, b, d, ring, k)
		if slot < 0 || ring[slot] == 0 {
			missing += 1
		}
	}
	return missing
}

// Takes the blocks [lo, hi) needs, all or none. The range must be in the window.
@(private)
win_reserve :: proc(c: ^Connection, b: ^Buf, d: Direction, lo, hi: u64) -> bool {
	p := &c.streams
	if hi <= lo {
		return true
	}
	if p.block == 0 || win_missing(c, b, d, lo, hi) > pool_room(c, d) {
		return false
	}
	ring := win_ring(c, b, d)
	for k := lo >> p.shift; k <= (hi - 1) >> p.shift; k += 1 {
		slot := win_slot(c, b, d, ring, k)
		if slot < 0 {
			return false
		}
		if ring[slot] == 0 {
			ring[slot] = pool_take(p, d)
			if ring[slot] == 0 {
				return false
			}
		}
	}
	return true
}

// Returns the blocks wholly below to. The caller then moves the base to to.
@(private)
win_advance :: proc(c: ^Connection, b: ^Buf, d: Direction, to: u64) {
	p := &c.streams; ring := win_ring(c, b, d)
	base, head := win_base(b, d)
	if len(ring) == 0 || to <= base {
		return
	}
	steps := (to >> p.shift) - (base >> p.shift)
	if steps >= u64(len(ring)) {
		win_clear(c, b, d)
		return
	}
	for _ in 0 ..< int(steps) {
		if ring[head^] != 0 {
			pool_give(p, d, ring[head^]); ring[head^] = 0
		}
		head^ = (head^ + 1) % len(ring)
	}
}

@(private)
win_clear :: proc(c: ^Connection, b: ^Buf, d: Direction) {
	ring := win_ring(c, b, d)
	for &entry in ring {
		if entry != 0 {
			pool_give(&c.streams, d, entry); entry = 0
		}
	}
	_, head := win_base(b, d); head^ = 0
}

// Every block under src must be held.
@(private)
win_write :: proc(c: ^Connection, b: ^Buf, d: Direction, off: u64, src: []u8) {
	done := 0
	for done < len(src) {
		block, at, count := win_segment(c, b, d, off + u64(done), len(src) - done)
		if block != nil {
			copy(block[at:at + count], src[done:done + count])
		}
		done += count
	}
}

@(private)
win_read :: proc(c: ^Connection, b: ^Buf, d: Direction, off: u64, dst: []u8) {
	done := 0
	for done < len(dst) {
		block, at, count := win_segment(c, b, d, off + u64(done), len(dst) - done)
		if block != nil {
			copy(dst[done:done + count], block[at:at + count])
		} else {
			for &v in dst[done:done + count] {v = 0}
		}
		done += count
	}
}

@(private)
win_bitmap :: proc(c: ^Connection, block: []u8, which: Bits) -> []u8 {
	size := c.streams.block; at := size + int(which) * (size / 8)
	return block[at:at + size / 8]
}

// Length of the run of bits equal to value starting at off, at most limit.
@(private)
win_run :: proc(c: ^Connection, b: ^Buf, d: Direction, which: Bits, off: u64, limit: int, value: bool) -> int {
	done := 0
	for done < limit {
		block, at, count := win_segment(c, b, d, off + u64(done), limit - done)
		if block == nil {
			// Bytes without a block have no bit set.
			if value {
				return done
			}
			done += count
			continue
		}
		bits := win_bitmap(c, block, which); whole: u8 = 0xff if value else 0
		for i := 0; i < count; {
			bit := at + i
			if bit & 7 == 0 && count - i >= 8 && bits[bit >> 3] == whole {
				i += 8
				continue
			}
			if (bits[bit >> 3] & (1 << uint(bit & 7)) != 0) != value {
				return done + i
			}
			i += 1
		}
		done += count
	}
	return limit
}

@(private)
win_bit :: proc(c: ^Connection, b: ^Buf, d: Direction, which: Bits, off: u64) -> bool {
	block, at, _ := win_segment(c, b, d, off, 1)
	if block == nil {
		return false
	}
	return win_bitmap(c, block, which)[at >> 3] & (1 << uint(at & 7)) != 0
}

// Sets or clears n bits from off and returns how many changed. Bytes without
// a block are skipped.
@(private)
win_set :: proc(c: ^Connection, b: ^Buf, d: Direction, which: Bits, off: u64, n: int, value: bool) -> int {
	done, changed := 0, 0
	for done < n {
		block, at, count := win_segment(c, b, d, off + u64(done), n - done)
		if block != nil {
			bits := win_bitmap(c, block, which)
			for i in 0 ..< count {
				bit := at + i; mask := u8(1) << uint(bit & 7)
				if (bits[bit >> 3] & mask != 0) != value {
					bits[bit >> 3] ~= mask; changed += 1
				}
			}
		}
		done += count
	}
	return changed
}

// Marks the unacknowledged bytes of [off, off+n) for retransmission.
@(private)
win_retry :: proc(c: ^Connection, b: ^Buf, off: u64, n: int) {
	done := 0
	for done < n {
		block, at, count := win_segment(c, b, .Send, off + u64(done), n - done)
		if block != nil {
			acked := win_bitmap(c, block, .Acked); retry := win_bitmap(c, block, .Retry)
			for i in 0 ..< count {
				bit := at + i; mask := u8(1) << uint(bit & 7)
				if acked[bit >> 3] & mask == 0 {
					retry[bit >> 3] |= mask; b.retry_pending = true
				}
			}
		}
		done += count
	}
}

// Marks the newly acknowledged bytes of [off, off+n) and returns their count.
@(private)
win_ack :: proc(c: ^Connection, b: ^Buf, off: u64, n: int) -> int {
	done, fresh := 0, 0
	for done < n {
		block, at, count := win_segment(c, b, .Send, off + u64(done), n - done)
		if block != nil {
			acked := win_bitmap(c, block, .Acked); retry := win_bitmap(c, block, .Retry)
			for i in 0 ..< count {
				bit := at + i; mask := u8(1) << uint(bit & 7)
				if acked[bit >> 3] & mask == 0 {
					acked[bit >> 3] |= mask; retry[bit >> 3] &~= mask; fresh += 1
				}
			}
		}
		done += count
	}
	return fresh
}

// Every retained stream byte, FIN and RESET_STREAM that is not acknowledged is
// sent again. For a caller that knows its earlier packets were not processed,
// such as after a Retry.
retransmit_unacknowledged :: proc(c: ^Connection) {
	if c == nil || !c.initialized {
		return
	}
	for &b in c.bufs {
		if !b.used {
			continue
		}
		win_retry(c, &b, b.send_base, b.n)
		b.fin_retry = b.fin && !b.fin_acked
		b.reset_retry = b.reset && !b.reset_acked
	}
}
