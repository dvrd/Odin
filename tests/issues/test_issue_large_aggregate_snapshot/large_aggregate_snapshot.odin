package test_issue_large_aggregate_snapshot

import "core:testing"

Large :: struct {first, second, third: i64, bytes: [31329]u8}
Overlap :: struct #packed {bytes: [128]u8}
Tuple_Record :: struct {first: i64, bytes: [128]u8, last: i64}

fill :: proc(value: ^Large, byte: u8, first: i64) {
	value.first = first; value.second = first + 1; value.third = first + 2
	for &item in value.bytes {item = byte}
}

matches :: proc(value: ^Large, byte: u8, first: i64) -> bool {
	if value.first != first || value.second != first + 1 || value.third != first + 2 {return false}
	for item in value.bytes {if item != byte {return false}}
	return true
}

mutate :: proc(value: ^Large) -> i64 {fill(value, 99, 90); return 7}

@(test)
large_rhs_is_captured_before_another_rhs_call_mutates_the_source :: proc(t: ^testing.T) {
	source, destination: Large
	fill(&source, 17, 10)
	flag: i64
	destination, flag = source, mutate(&source)
	testing.expect(t, matches(&destination, 17, 10))
	testing.expect(t, matches(&source, 99, 90))
	testing.expect_value(t, flag, 7)
}

@(test)
large_swap_and_self_assignment_preserve_all_fields :: proc(t: ^testing.T) {
	a, b: Large
	fill(&a, 11, 1); fill(&b, 22, 2)
	a, b = b, a
	testing.expect(t, matches(&a, 22, 2)); testing.expect(t, matches(&b, 11, 1))
	flag := 3
	a, flag = a, flag + 1
	testing.expect(t, matches(&a, 22, 2)); testing.expect_value(t, flag, 4)
}

@(test)
large_destination_overlaps_source_and_an_earlier_scalar_target :: proc(t: ^testing.T) {
	storage: [130]u8
	for &value, index in storage {value = u8(index)}
	source := cast(^Overlap)(&storage[0])
	destination := cast(^Overlap)(&storage[1])
	storage[0], destination^ = 7, source^
	testing.expect_value(t, storage[0], 7)
	for value, index in destination.bytes {testing.expect_value(t, value, u8(index))}
}

make_tuple :: proc(seed: i64) -> (Tuple_Record, i64) {
	value: Tuple_Record
	value.first = seed; value.last = seed + 1
	for &byte in value.bytes {byte = u8(seed)}
	return value, seed + 2
}

@(test)
large_tuple_and_multiple_consumers_retain_value_semantics :: proc(t: ^testing.T) {
	value, count := make_tuple(12)
	a, b: Tuple_Record
	a, b = value, value
	value.first = 99; value.bytes[0] = 99
	testing.expect_value(t, a.first, 12); testing.expect_value(t, b.first, 12)
	testing.expect_value(t, a.last, 13); testing.expect_value(t, b.last, 13)
	testing.expect_value(t, a.bytes[0], 12); testing.expect_value(t, b.bytes[0], 12)
	testing.expect_value(t, count, 14)
}

choose :: proc(a, b: Tuple_Record, pick: bool) -> Tuple_Record {
	if pick {return a}; return b
}

@(test)
large_branch_values_and_size_boundaries_remain_correct :: proc(t: ^testing.T) {
	a, _ := make_tuple(3); b, _ := make_tuple(8)
	for pick in ([2]bool{false, true}) {
		value := choose(a, b, pick)
		testing.expect_value(t, value.first, 3 if pick else 8)
	}
	small: [64]u8; large: [65]u8
	for &value in small {value = 4}; for &value in large {value = 5}
	small_copy, large_copy := small, large
	small[0] = 99; large[0] = 99
	testing.expect_value(t, small_copy[0], 4); testing.expect_value(t, large_copy[0], 5)
}
