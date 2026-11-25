#+build darwin
#+private
package nbio

import "core:c"
import kq "core:sys/kqueue"
import "core:sys/posix"

Darwin_KEvent64 :: struct {
	ident:  u64,
	filter: i16,
	flags:  u16,
	fflags: u32,
	data:   i64,
	udata:  u64,
	ext:    [2]u64,
}

foreign import darwin_kqueue "system:System"

foreign darwin_kqueue {
	@(link_name = "kevent64")
	darwin_kevent64 :: proc(fd: posix.FD, changes: [^]Darwin_KEvent64, n_changes: c.int, events: [^]Darwin_KEvent64, n_events: c.int, flags: c.uint, timeout: ^posix.timespec) -> c.int ---
}

// Keep the existing KEvent representation outside this Darwin syscall boundary.
// Every call on a queue, including wake submissions, must use the same ABI.
darwin_kevent :: proc(
	fd: kq.KQ,
	changes: []kq.KEvent,
	events: []kq.KEvent,
	timeout: ^posix.timespec,
) -> (
	n: c.int,
	err: posix.Errno,
) {
	assert(size_of(Darwin_KEvent64) == 48)
	change_buffer: [#config(ODIN_NBIO_QUEUE_SIZE, 256)]Darwin_KEvent64
	event_buffer: [128]Darwin_KEvent64
	assert(len(changes) <= len(change_buffer) && len(events) <= len(event_buffer))

	for ev, i in changes {
		change_buffer[i] = {
			ident  = u64(ev.ident),
			filter = i16(ev.filter),
			flags  = transmute(u16)ev.flags,
			fflags = transmute(u32)ev.fflags,
			data   = i64(ev.data),
			udata  = u64(uintptr(ev.udata)),
		}
	}

	// A zero timespec still enters XNU's wait path. IMMEDIATE skips that path.
	// Preserve the existing semantics for positive timeouts and indefinite waits.
	KEVENT_FLAG_IMMEDIATE :: c.uint(0x1)
	flags: c.uint
	if timeout != nil && timeout.tv_sec == 0 && timeout.tv_nsec == 0 {
		flags = KEVENT_FLAG_IMMEDIATE
	}
	n = darwin_kevent64(
		fd,
		raw_data(change_buffer[:]),
		c.int(len(changes)),
		raw_data(event_buffer[:]),
		c.int(len(events)),
		flags,
		timeout,
	)
	if n < 0 {
		err = posix.errno()
		n = 0
		return
	}
	for i in 0 ..< int(n) {
		ev := event_buffer[i]
		events[i] = {
			ident  = uintptr(ev.ident),
			filter = kq.Filter(ev.filter),
			flags  = transmute(kq.Flags)ev.flags,
			fflags = transmute(type_of(events[i].fflags))ev.fflags,
			data   = c.long(ev.data),
			udata  = rawptr(uintptr(ev.udata)),
		}
	}
	return
}
