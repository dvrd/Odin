package conn

import "core:testing"

@(test)
stream_pool_blocks_follow_buffered_bytes :: proc(t: ^testing.T) {
	c := new(Connection)
	defer free(c)
	windows := Stream_Windows {
		send      = 4096,
		recv      = 4096,
		send_pool = 4096,
		recv_pool = 4096,
		allocator = context.allocator,
	}
	testing.expect_value(t, pool_setup(c, windows, 1 << 20), Error.None)
	defer pool_release(c)
	p := &c.streams
	testing.expect(t, p.heap && p.quota[.Recv] == 5 && p.slots[.Recv] == 5)

	// Out-of-order bytes take only the blocks they touch, at any base offset.
	a := &c.bufs[3]
	a.used = true
	a.recv_base = 900
	testing.expect_value(t, win_missing(c, a, .Recv, 1000, 3000), 3)
	testing.expect(t, win_reserve(c, a, .Recv, 1000, 3000) && p.held[.Recv] == 3)
	data: [2000]u8
	for &v, i in data {v = u8(i * 7)}
	win_write(c, a, .Recv, 1000, data[:])
	testing.expect_value(t, win_set(c, a, .Recv, PRESENT, 1000, 2000, true), 2000)
	testing.expect_value(t, win_set(c, a, .Recv, PRESENT, 1000, 2000, true), 0)
	testing.expect_value(t, win_run(c, a, .Recv, PRESENT, 900, 4096, false), 100)
	testing.expect_value(t, win_run(c, a, .Recv, PRESENT, 1000, 3996, true), 2000)
	testing.expect(t, win_bit(c, a, .Recv, PRESENT, 2999) && !win_bit(c, a, .Recv, PRESENT, 3000))
	got: [2000]u8
	win_read(c, a, .Recv, 1000, got[:])
	testing.expect(t, got == data)

	// Moving the base returns whole blocks; the survivors keep their bytes.
	win_advance(c, a, .Recv, 2100)
	a.recv_base = 2100
	testing.expect_value(t, p.held[.Recv], 1)
	win_read(c, a, .Recv, 2100, got[:900])
	testing.expect(t, got[0] == data[1100] && got[899] == data[1999])
	// The window reaches base + 4096 and wraps around the ring.
	testing.expect(t, win_reserve(c, a, .Recv, 2100, 2100 + 4096) && p.held[.Recv] == 5)
	testing.expect_value(t, win_missing(c, a, .Recv, 2100, 2100 + 4096), 0)

	// The pool is shared: a second record finds it empty until the first lets go.
	b := &c.bufs[4]
	b.used = true
	testing.expect_value(t, win_missing(c, b, .Recv, 0, 10), 1)
	testing.expect(t, !win_reserve(c, b, .Recv, 0, 10) && pool_room(c, .Recv) == 0)
	// Receive blocks do not come out of the send quota.
	testing.expect(t, win_reserve(c, b, .Send, 0, 10) && p.held[.Send] == 1)
	win_clear(c, a, .Recv)
	testing.expect(t, p.held[.Recv] == 0 && win_reserve(c, b, .Recv, 0, 10))
	// A returned block comes back zeroed, bitmaps included.
	testing.expect(t, !win_bit(c, b, .Recv, PRESENT, 5))
	win_read(c, b, .Recv, 0, got[:10])
	for v in got[:10] {testing.expect_value(t, v, u8(0))}
}

@(test)
stream_pool_acknowledgment_and_retry_bits_stay_disjoint :: proc(t: ^testing.T) {
	c := new(Connection)
	defer free(c)
	pool_inline(c)
	p := &c.streams
	testing.expect(t, !p.heap && p.window[.Send] == STREAM_BYTES && p.quota[.Send] == STREAMS * INLINE_SLOTS)
	b := &c.bufs[0]
	b.used = true
	b.send_base = 1000
	b.n = 256
	testing.expect(t, win_reserve(c, b, .Send, 1000, 1256))
	win_retry(c, b, 1100, 50)
	testing.expect(t, b.retry_pending)
	testing.expect_value(t, win_run(c, b, .Send, .Retry, 1000, 256, false), 100)
	// Acknowledging clears the retry mark, and an acknowledged byte is not marked again.
	testing.expect_value(t, win_ack(c, b, 1090, 30), 30)
	testing.expect_value(t, win_ack(c, b, 1090, 40), 10)
	testing.expect_value(t, win_run(c, b, .Send, .Retry, 1000, 256, false), 130)
	testing.expect_value(t, win_run(c, b, .Send, .Retry, 1130, 126, true), 20)
	win_retry(c, b, 1000, 256)
	testing.expect_value(t, win_run(c, b, .Send, .Retry, 1000, 256, true), 90)
	testing.expect_value(t, win_run(c, b, .Send, .Retry, 1090, 166, false), 40)
	// Compaction releases the acknowledged prefix and an idle stream holds nothing.
	testing.expect_value(t, win_ack(c, b, 1000, 256), 216)
	compact_send(c, b)
	testing.expect(t, b.n == 0 && b.send_base == 1256 && p.held[.Send] == 0)
	// Every record can hold a full default window in both directions at once.
	for &r in c.bufs {
		r = {
			used      = true,
			send_base = 77,
			recv_base = 131,
		}
		testing.expect(t, win_reserve(c, &r, .Send, 77, 77 + STREAM_BYTES))
		testing.expect(t, win_reserve(c, &r, .Recv, 131, 131 + STREAM_BYTES))
	}
	pool_reset(c)
	testing.expect(t, p.held[.Send] == 0 && p.held[.Recv] == 0)
}
