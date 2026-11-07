// Deterministic test link. This package has no wall clock, sockets or callbacks.
package sim

import "core:bytes"
import "core:mem"

Tick :: distinct i64
Address :: struct {
	peer, path: u32,
}
Error :: enum {
	None,
	Invalid_Config,
	Invalid_State,
	Invalid_Time,
	Packet_Too_Large,
	Capacity,
	Destination_Undersized,
	Overlap,
	Exhausted,
}
Packet_Slot :: struct {
	active:              bool,
	at:                  Tick,
	sequence:            u64,
	source, destination: Address,
	size:                int,
}
Timer_Slot :: struct {
	active:               bool,
	generation, sequence: u64,
	at:                   Tick,
	peer:                 u32,
	tag:                  u64,
}
// Handles belong to this Link's initialized lifetime, not another Link or a
// destroyed/reinitialized instance. clear preserves generation safety.
Timer :: struct {
	slot:       int,
	generation: u64,
	owner:      ^Link,
}
Plan :: struct {
	drop:            bool,
	delay:           Tick,
	duplicate:       bool,
	duplicate_delay: Tick,
}
Event_Kind :: enum {
	Datagram,
	Timer,
}
Event :: struct {
	kind:                Event_Kind,
	at:                  Tick,
	sequence:            u64,
	source, destination: Address,
	size:                int,
	timer:               Timer,
	tag:                 u64,
}
Stats :: struct {
	packets, bytes, timers:                int,
	peak_packets, peak_bytes, peak_timers: int,
}
// Caller-owned, single-threaded, noncopyable after init. All storage must remain
// stable/exclusive until destroy. No allocation occurs, including on failure.
Link :: struct {
	initialized: bool,
	packets:     []Packet_Slot,
	payloads:    []u8,
	timers:      []Timer_Slot,
	stride:      int,
	now:         Tick,
	sequence:    u64,
	stats:       Stats,
}

init :: proc(
	link: ^Link,
	packets: []Packet_Slot,
	payloads: []u8,
	max_datagram: int,
	timers: []Timer_Slot,
	start: Tick = 0,
) -> Error {
	if link == nil {
		return .Invalid_State
	}
	if link.initialized {
		return .Invalid_State
	}
	if start < 0 ||
	   max_datagram <= 0 ||
	   len(packets) == 0 ||
	   len(packets) > max(int) / max_datagram ||
	   len(payloads) != len(packets) * max_datagram {
		return .Invalid_Config
	}
	p, t := mem.slice_to_bytes(packets), mem.slice_to_bytes(timers)
	owner := (cast([^]u8)link)[:size_of(Link)]
	if bytes.alias(p, t) ||
	   bytes.alias(p, payloads) ||
	   bytes.alias(t, payloads) ||
	   bytes.alias(owner, p) ||
	   bytes.alias(owner, t) ||
	   bytes.alias(owner, payloads) {
		return .Overlap
	}
	for &slot in packets {slot = {}}
	for &slot in timers {slot = {}}
	link^ = {
		initialized = true,
		packets     = packets,
		payloads    = payloads,
		timers      = timers,
		stride      = max_datagram,
		now         = start,
	}
	return .None
}

now :: proc(link: ^Link) -> Tick {return link.now}
stats :: proc(link: ^Link) -> Stats {return link.stats}

@(private)
after :: proc(link: ^Link, delay: Tick) -> (Tick, bool) {
	if delay < 0 || delay > max(Tick) - link.now {
		return 0, false
	}
	return link.now + delay, true
}

@(private)
overlaps_storage :: proc(link: ^Link, data: []u8) -> bool {
	return(
		bytes.alias(data, link.payloads) ||
		bytes.alias(data, mem.slice_to_bytes(link.packets)) ||
		bytes.alias(data, mem.slice_to_bytes(link.timers)) ||
		bytes.alias(data, (cast([^]u8)link)[:size_of(Link)]) \
	)
}

// Copies the datagram immediately. Plans are explicit and replayable; different
// delivery delays produce reordering, and source.path models address migration.
// Duplicate admission is atomic: a rejected pair queues neither copy.
send :: proc(link: ^Link, source, destination: Address, payload: []u8, plan: Plan = {}) -> Error {
	if link == nil || !link.initialized {
		return .Invalid_State
	}
	if len(payload) > link.stride {
		return .Packet_Too_Large
	}
	at, valid := after(link, plan.delay)
	duplicate_at, duplicate_valid := after(link, plan.duplicate_delay)
	if !valid ||
	   !duplicate_valid ||
	   (!plan.duplicate && plan.duplicate_delay != 0) ||
	   (plan.drop && plan.duplicate) {
		return .Invalid_Time
	}
	if overlaps_storage(link, payload) {
		return .Overlap
	}
	if plan.drop {
		return .None
	}
	count := 1
	if plan.duplicate {
		count = 2
	}
	if link.sequence > max(u64) - u64(count) {
		return .Exhausted
	}
	slots: [2]int
	found := 0
	for slot, i in link.packets {
		if !slot.active {
			slots[found] = i; found += 1; if found == count {
				break
			}
		}
	}
	if found != count {
		return .Capacity
	}
	for n in 0 ..< count {
		i := slots[n]
		link.sequence += 1
		link.packets[i] = {
			active      = true,
			at          = at if n == 0 else duplicate_at,
			sequence    = link.sequence,
			source      = source,
			destination = destination,
			size        = len(payload),
		}
		copy(link.payloads[i * link.stride:(i + 1) * link.stride], payload)
	}
	link.stats.packets += count
	link.stats.bytes += len(payload) * count
	link.stats.peak_packets = max(link.stats.peak_packets, link.stats.packets)
	link.stats.peak_bytes = max(link.stats.peak_bytes, link.stats.bytes)
	return .None
}

schedule :: proc(link: ^Link, peer: u32, at: Tick, tag: u64 = 0) -> (Timer, Error) {
	if link == nil || !link.initialized {
		return {}, .Invalid_State
	}
	if at < link.now {
		return {}, .Invalid_Time
	}
	if link.sequence == max(u64) {
		return {}, .Exhausted
	}
	for &slot, i in link.timers {
		if slot.active || slot.generation == max(u64) {
			continue
		}
		slot.generation += 1
		link.sequence += 1
		slot.active = true; slot.sequence = link.sequence; slot.at = at; slot.peer = peer
		slot.tag = tag
		link.stats.timers += 1
		link.stats.peak_timers = max(link.stats.peak_timers, link.stats.timers)
		return {slot = i, generation = slot.generation, owner = link}, .None
	}
	return {}, .Capacity
}

cancel :: proc(link: ^Link, timer: Timer) -> bool {
	if link == nil ||
	   !link.initialized ||
	   timer.owner != link ||
	   timer.slot < 0 ||
	   timer.slot >= len(link.timers) {
		return false
	}
	slot := &link.timers[timer.slot]
	if !slot.active || timer.generation != slot.generation {
		return false
	}
	slot.active = false
	link.stats.timers -= 1
	return true
}

// Delivers the earliest event at/before until; insertion sequence breaks ties
// across packet and timer queues. The driver dispatches it synchronously and
// may enqueue new work at now(). With no event, the clock advances to until.
// Datagram bytes are copied into dst. Undersized/overlapping dst leaves clock,
// queues and ownership unchanged, so the driver can retry with a larger buffer.
step :: proc(link: ^Link, until: Tick, dst: []u8) -> (Event, bool, Error) {
	if link == nil || !link.initialized {
		return {}, false, .Invalid_State
	}
	if until < link.now {
		return {}, false, .Invalid_Time
	}
	index, timer_index := -1, -1
	at := until
	sequence := max(u64)
	for slot, i in link.packets {
		if slot.active &&
		   slot.at <= until &&
		   (slot.at < at || (slot.at == at && slot.sequence <= sequence)) {
			at, sequence, index, timer_index = slot.at, slot.sequence, i, -1
		}
	}
	for slot, i in link.timers {
		if slot.active &&
		   slot.at <= until &&
		   (slot.at < at || (slot.at == at && slot.sequence <= sequence)) {
			at, sequence, index, timer_index = slot.at, slot.sequence, -1, i
		}
	}
	if index >= 0 {
		slot := &link.packets[index]
		event := Event {
			kind        = .Datagram,
			at          = at,
			sequence    = sequence,
			source      = slot.source,
			destination = slot.destination,
			size        = slot.size,
		}
		if len(dst) < slot.size {
			return event, false, .Destination_Undersized
		}
		out := dst[:slot.size]
		if overlaps_storage(link, out) {
			return event, false, .Overlap
		}
		copy(out, link.payloads[index * link.stride:index * link.stride + slot.size])
		link.stats.packets -= 1; link.stats.bytes -= slot.size; slot.active = false
		link.now = at
		return event, true, .None
	}
	if timer_index >= 0 {
		slot := &link.timers[timer_index]
		event := Event {
			kind = .Timer,
			at = at,
			sequence = sequence,
			destination = {peer = slot.peer},
			timer = {slot = timer_index, generation = slot.generation, owner = link},
			tag = slot.tag,
		}
		slot.active = false; link.stats.timers -= 1; link.now = at
		return event, true, .None
	}
	link.now = until
	return {}, false, .None
}

// Cancels pending events without resetting time/sequence/timer generations.
// It releases no caller storage and does not promise secure payload erasure.
clear :: proc(link: ^Link) {
	if link == nil || !link.initialized {
		return
	}
	for &slot in link.packets {slot.active = false}
	for &slot in link.timers {slot.active = false}
	link.stats.packets, link.stats.bytes, link.stats.timers = 0, 0, 0
}

// Invalidates all views/handles. Storage ownership always stays with the caller.
destroy :: proc(link: ^Link) {
	if link == nil {
		return
	}
	clear(link)
	link^ = {}
}
