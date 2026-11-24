package tests

import "core:crypto"
import "core:fmt"
import "core:mem"
import "core:net/quic"
import "core:testing"

@(private)
crypto_owner_unchanged :: proc(a, b: ^quic.Crypto_Reassembly) -> bool {
	return raw_data(a.buf) == raw_data(b.buf) &&
		len(a.buf) == len(b.buf) &&
		a.span_count == b.span_count &&
		a.contiguous == b.contiguous &&
		a.received_bytes == b.received_bytes &&
		a.discarded == b.discarded &&
		raw_data(a._external_coverage) == raw_data(b._external_coverage) &&
		len(a._external_coverage) == len(b._external_coverage) &&
		a._inline_coverage == b._inline_coverage
}

@(test)
crypto_minimum_sparse_bytes_bridge_and_overlap_without_allocation :: proc(t: ^testing.T) {
	storage: [16384]u8
	r: quic.Crypto_Reassembly
	one := [1]u8{0xab}
	prefix: [4096]u8
	for &b in prefix {b = 0xab}
	saved := context.allocator
	context.allocator = mem.panic_allocator()
	defer {context.allocator = saved}
	assert(quic.crypto_reassembly_init(&r, storage[:]) == .None)
	// An odd permutation visits every one of4096 nonadjacent offsets. The old
	// span table failed on byte33, although every offset is within this window.
	for i in 0 ..< 4096 {
		slot := (i * 2053) % 4096
		assert(quic.crypto_reassembly_write(&r, u64(4096 + slot * 2), one[:]) == .None)
	}
	assert(r.received_bytes == 4096 && r.span_count == 4096 && r.contiguous == 0)
	for i in 0 ..< 4095 {assert(quic.crypto_reassembly_write(&r, u64(4097 + i * 2), one[:]) == .None)}
	assert(r.received_bytes == 8191 && r.span_count == 1 && r.contiguous == 0)
	assert(quic.crypto_reassembly_write(&r, 0, prefix[:]) == .None)
	assert(r.contiguous == 12287 && r.span_count == 1 && r.received_bytes == 12287)
	assert(quic.crypto_reassembly_write(&r, 4096, prefix[:]) == .None && r.received_bytes == 12287)
	assert(quic.crypto_reassembly_write(&r, 7000, []u8{0xcd}) == .Overlap_Mismatch)
	assert(r.discarded && crypto.is_zero_constant_time(storage[:]) == 1)
	context.allocator = saved
	testing.expect_value(t, len(r.buf), len(storage))
}

@(test)
crypto_coverage_init_failure_is_atomic_and_large_windows_are_explicit :: proc(t: ^testing.T) {
	small: [16]u8
	r: quic.Crypto_Reassembly
	assert(quic.crypto_reassembly_init(&r, small[:]) == .None)
	assert(quic.crypto_reassembly_write(&r, 0, []u8{42}) == .None)
	before := r
	large := make([]u8, quic.CRYPTO_INLINE_WINDOW_MAX + 8193)
	defer delete(large)
	required := quic.crypto_reassembly_coverage_size(len(large))
	coverage := make([]u8, required + 8)
	defer delete(coverage)
	for &b in coverage {b = 0x77}; large[0] = 0x66
	testing.expect_value(t, quic.crypto_reassembly_init(&r, large), .Coverage_Required)
	testing.expect(t, crypto_owner_unchanged(&r, &before))
	testing.expect_value(t, quic.crypto_reassembly_init(&r, large, coverage[:required - 1]), .Coverage_Required)
	testing.expect(t, crypto_owner_unchanged(&r, &before))
	testing.expect_value(t, coverage[0], u8(0x77))
	testing.expect_value(t, large[0], u8(0x66))
	testing.expect_value(t, quic.crypto_reassembly_init(&r, large, large[:required]), .Invalid_Input)
	testing.expect(t, crypto_owner_unchanged(&r, &before))
	testing.expect_value(t, large[0], u8(0x66))
	testing.expect_value(t, quic.crypto_reassembly_init(&r, small[:], r._inline_coverage[:2]), .Invalid_Input)
	testing.expect(t, crypto_owner_unchanged(&r, &before))
	testing.expect_value(t, quic.crypto_reassembly_init(&r, r._inline_coverage[:16]), .Invalid_Input)
	testing.expect(t, crypto_owner_unchanged(&r, &before))
	testing.expect_value(t, quic.crypto_reassembly_init(&r, large, coverage), .None)
	testing.expect_value(t, len(r.buf), len(large))
	testing.expect_value(t, coverage[0], u8(0))
	testing.expect_value(t, coverage[required], u8(0x77))
	testing.expect_value(t, quic.crypto_reassembly_write(&r, u64(len(large) - 1), []u8{0xab}), .None)
	testing.expect_value(t, r.received_bytes, 1)
	testing.expect_value(t, r.span_count, 1)
	quic.crypto_reassembly_discard(&r)
	testing.expect(
		t,
		r.discarded &&
		crypto.is_zero_constant_time(large) == 1 &&
		crypto.is_zero_constant_time(coverage[:required]) == 1,
	)
	testing.expect_value(t, coverage[required], u8(0x77))
}

@(test)
crypto_external_coverage_preview_clone_is_independent_and_rejects_aliases :: proc(t: ^testing.T) {
	size := quic.CRYPTO_INLINE_WINDOW_MAX + 17
	data := make([]u8, size)
	defer delete(data)
	bits := make([]u8, quic.crypto_reassembly_coverage_size(size))
	defer delete(bits)
	scratch := make([]u8, size)
	defer delete(scratch)
	scratch_bits := make([]u8, len(bits))
	defer delete(scratch_bits)
	source, preview: quic.Crypto_Reassembly
	assert(quic.crypto_reassembly_init(&source, data, bits) == .None)
	assert(quic.crypto_reassembly_write(&source, u64(size - 1), []u8{42}) == .None)
	testing.expect_value(t, quic.crypto_reassembly_clone(&preview, &source, scratch), .Coverage_Required)
	testing.expect_value(t, quic.crypto_reassembly_clone(&preview, &source, scratch, scratch_bits), .None)
	assert(quic.crypto_reassembly_write(&preview, 0, []u8{17}) == .None)
	testing.expect(t, preview.contiguous == 1 && source.contiguous == 0 && source.received_bytes == 1)
	testing.expect_value(t, data[0], u8(0))
	testing.expect_value(t, bits[0], u8(0))
	testing.expect_value(t, scratch[0], u8(17))
	before := preview
	testing.expect_value(t, quic.crypto_reassembly_clone(&preview, &source, data, scratch_bits), .Invalid_Input)
	testing.expect(t, crypto_owner_unchanged(&preview, &before))
	testing.expect_value(t, data[size - 1], u8(42))
	testing.expect_value(t, quic.crypto_reassembly_clone(&preview, &source, scratch, bits), .Invalid_Input)
	testing.expect(t, crypto_owner_unchanged(&preview, &before))
	testing.expect_value(t, bits[0], u8(0))
	testing.expect_value(t, scratch[0], u8(17))
	testing.expect_value(t, quic.crypto_reassembly_clone(&source, &source, scratch, scratch_bits), .Invalid_Input)
	quic.crypto_reassembly_discard(&preview)
	testing.expect(t, crypto.is_zero_constant_time(scratch) == 1 && crypto.is_zero_constant_time(scratch_bits) == 1)
	testing.expect_value(t, data[size - 1], u8(42))
	testing.expect_value(t, source.received_bytes, 1)
	quic.crypto_reassembly_discard(&source)
}

@(test)
crypto_inline_clone_owns_external_source_metadata_and_aliasing_payload_is_memmove_safe :: proc(t: ^testing.T) {
	data: [128]u8
	bits: [16]u8
	scratch: [128]u8
	source, preview: quic.Crypto_Reassembly
	assert(quic.crypto_reassembly_init(&source, data[:], bits[:]) == .None)
	assert(quic.crypto_reassembly_write(&source, 2, []u8{1, 2, 3}) == .None)
	testing.expect_value(t, quic.crypto_reassembly_clone(&preview, &source, scratch[:]), .None)
	assert(quic.crypto_reassembly_write(&preview, 0, []u8{9}) == .None)
	testing.expect_value(t, bits[0], u8(0x1c))
	testing.expect_value(t, source.contiguous, 0)
	// Copying an overlapping unreceived source range must snapshot its bytes
	// before coverage updates; the direct write has the same memmove semantics.
	assert(quic.crypto_reassembly_write(&source, 0, data[2:4]) == .None)
	testing.expect_value(t, data[0], u8(1))
	testing.expect_value(t, data[1], u8(2))
	testing.expect_value(t, source.contiguous, 5)
	quic.crypto_reassembly_discard(&source)
	quic.crypto_reassembly_discard(&preview)
}

@(test)
crypto_handshake_larger_explicit_coverage_and_size_accounting :: proc(t: ^testing.T) {
	window := make([]u8, quic.CRYPTO_INLINE_WINDOW_MAX + 1)
	defer delete(window)
	coverage := make([]u8, quic.crypto_reassembly_coverage_size(len(window)))
	defer delete(coverage)
	h: quic.Handshake
	testing.expect_value(
		t,
		quic.handshake_init(&h, .Client, []string{"h3"}, window, nil, nil, {coverage, nil, nil}),
		.None,
	)
	testing.expect_value(t, len(h.crypto[0].buf), len(window))
	testing.expect_value(t, quic.handshake_ingest_crypto(&h, .Initial, u64(len(window) - 1), []u8{42}), .None)
	testing.expect_value(t, h.crypto[0].received_bytes, 1)
	quic.handshake_fail(&h)
	testing.expect(t, crypto.is_zero_constant_time(window) == 1 && crypto.is_zero_constant_time(coverage) == 1)
	testing.expect_value(t, quic.CRYPTO_INLINE_COVERAGE_BYTES, 8320)
	fmt.printf(
		"CRYPTO bitmap metadata=%d owner=%d Handshake=%d external_74753_window_metadata=%d no-frame-allocation\n",
		quic.CRYPTO_INLINE_COVERAGE_BYTES,
		size_of(quic.Crypto_Reassembly),
		size_of(quic.Handshake),
		quic.crypto_reassembly_coverage_size(74753),
	)
}
