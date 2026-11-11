package quic

import "core:crypto"

// Fixed span table. The byte cap is the caller storage length.
CRYPTO_SPAN_CAP :: 32

Crypto_Error :: enum {
	None,
	Discarded,
	Cap_Overflow,
	Overlap_Mismatch,
	Span_Exhausted,
	Invalid_Input,
}

Crypto_Span :: struct {
	start, end: int,
}

// buf is borrowed. Cap overflow, conflicting overlap and span exhaustion
// zero that storage and stick in the discarded state.
Crypto_Reassembly :: struct {
	buf:        []u8,
	spans:      [CRYPTO_SPAN_CAP]Crypto_Span,
	span_count: int,
	contiguous: int,
	discarded:  bool,
}

crypto_reassembly_init :: proc(r: ^Crypto_Reassembly, storage: []u8) -> Crypto_Error {
	if r == nil {
		return .Invalid_Input
	}
	r^ = {}
	r.buf = storage
	return .None
}

crypto_reassembly_discard :: proc(r: ^Crypto_Reassembly) {
	if r == nil {
		return
	}
	if len(r.buf) > 0 && raw_data(r.buf) != nil {
		crypto.zero_explicit(raw_data(r.buf), len(r.buf))
	}
	buf := r.buf
	r^ = {}
	r.buf = buf
	r.discarded = true
}

crypto_reassembly_bytes :: proc(r: ^Crypto_Reassembly) -> ([]u8, Crypto_Error) {
	if r == nil || r.discarded {
		return nil, .Discarded
	}
	return r.buf[:r.contiguous], .None
}

// Identical overlap is a no-op. A different byte at the same offset fails
// closed. offset is absolute from the start of this encryption level.
crypto_reassembly_write :: proc(r: ^Crypto_Reassembly, offset: u64, data: []u8) -> Crypto_Error {
	if r == nil || r.discarded {
		return .Discarded
	}
	if len(data) == 0 {
		if offset > u64(len(r.buf)) {
			crypto_reassembly_discard(r)
			return .Cap_Overflow
		}
		return .None
	}
	if offset > u64(len(r.buf)) || u64(len(data)) > u64(len(r.buf)) - offset {
		crypto_reassembly_discard(r)
		return .Cap_Overflow
	}
	start := int(offset)
	end := start + len(data)
	for i in 0 ..< r.span_count {
		span := r.spans[i]
		lo := max(span.start, start)
		hi := min(span.end, end)
		if lo >= hi {
			continue
		}
		for p in lo ..< hi {
			if r.buf[p] != data[p - start] {
				crypto_reassembly_discard(r)
				return .Overlap_Mismatch
			}
		}
	}
	merged: [CRYPTO_SPAN_CAP]Crypto_Span
	count, ok := crypto_spans_insert(r.spans[:r.span_count], merged[:], start, end)
	if !ok {
		crypto_reassembly_discard(r)
		return .Span_Exhausted
	}
	copy(r.buf[start:end], data)
	for i in 0 ..< count {
		r.spans[i] = merged[i]
	}
	r.span_count = count
	c := 0
	for i in 0 ..< count {
		if r.spans[i].start > c {
			break
		}
		if r.spans[i].end > c {
			c = r.spans[i].end
		}
	}
	r.contiguous = c
	return .None
}

@(private)
crypto_spans_insert :: proc(existing, dst: []Crypto_Span, start, end: int) -> (int, bool) {
	items: [CRYPTO_SPAN_CAP + 1]Crypto_Span
	if len(existing) > CRYPTO_SPAN_CAP {
		return 0, false
	}
	copy(items[:len(existing)], existing)
	items[len(existing)] = {start, end}
	n := len(existing) + 1
	for i in 1 ..< n {
		value := items[i]
		j := i
		for j > 0 && items[j - 1].start > value.start {
			items[j] = items[j - 1]
			j -= 1
		}
		items[j] = value
	}
	cur := items[0]
	written := 0
	for i in 1 ..< n {
		if items[i].start <= cur.end {
			if items[i].end > cur.end {
				cur.end = items[i].end
			}
			continue
		}
		if written == len(dst) {
			return 0, false
		}
		dst[written] = cur
		written += 1
		cur = items[i]
	}
	if written == len(dst) {
		return 0, false
	}
	dst[written] = cur
	return written + 1, true
}

// One CRYPTO frame at the front of src. data borrows src.
crypto_frame_decode :: proc(src: []u8) -> (offset: u64, data: []u8, consumed: int, err: Error) {
	typ, w, e := varint_decode(src)
	if e != .None {
		return 0, nil, 0, e
	}
	if typ != 6 {
		return 0, nil, 0, .Invalid_Input
	}
	p := w
	offset, w, e = varint_decode(src[p:])
	if e != .None {
		return 0, nil, 0, e
	}
	p += w
	length: u64
	length, w, e = varint_decode(src[p:])
	if e != .None {
		return 0, nil, 0, e
	}
	p += w
	if length > u64(len(src) - p) {
		return 0, nil, 0, .Truncated
	}
	n := int(length)
	return offset, src[p:p + n], p + n, .None
}
