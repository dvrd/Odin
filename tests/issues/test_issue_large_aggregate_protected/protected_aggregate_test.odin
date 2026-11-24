package protected_aggregate_snapshot

import "base:intrinsics"
import "core:os"
import "core:testing"

// The ordinary snapshot/swap/overlap/tuple cases belong to the compiler owner's
// package. These complementary cases exercise protected loads and runtime choices.
Record_80 :: struct {
	words: [10]u64,
}

Record_31KiB :: struct {
	words: [3968]u64,
}

pattern :: proc(seed: u64, index: int) -> u64 {return seed + u64(index) * 17}

fill :: proc(value: ^$T, seed: u64) {
	for &word, index in value.words {word = pattern(seed, index)}
}

expect_pattern :: proc(t: ^testing.T, value: ^$T, seed: u64) {
	for word, index in value.words {testing.expect_value(t, word, pattern(seed, index))}
}

mutate :: proc(value: ^$T, seed: u64) -> u64 {fill(value, seed); return seed + 1}
runtime_seed :: proc() -> u64 {return u64(len(os.args)) * 23 + 11}

protected_load_snapshot :: proc(t: ^testing.T, $T: typeid) {
	source, captured: T
	seed := runtime_seed()
	fill(&source, seed)
	flag: u64
	captured, flag = intrinsics.volatile_load(&source), mutate(&source, seed + 7)
	expect_pattern(t, &captured, seed)
	expect_pattern(t, &source, seed + 7)
	testing.expect_value(t, flag, seed + 8)
}

@(test)
volatile_80_byte_load_retains_first_rhs_snapshot :: proc(t: ^testing.T) {
	testing.expect_value(t, size_of(Record_80), 80)
	protected_load_snapshot(t, Record_80)
}

@(test)
volatile_31KiB_load_retains_first_rhs_snapshot :: proc(t: ^testing.T) {
	testing.expect_value(t, size_of(Record_31KiB), 31744)
	protected_load_snapshot(t, Record_31KiB)
}

@(test)
volatile_store_and_multiple_value_consumers_keep_independent_copies :: proc(t: ^testing.T) {
	seed := runtime_seed()
	source, destination, second: Record_80
	fill(&source, seed)
	intrinsics.volatile_store(&destination, source)
	second = intrinsics.volatile_load(&destination)
	fill(&source, seed + 1)
	fill(&destination, seed + 2)
	expect_pattern(t, &source, seed + 1)
	expect_pattern(t, &destination, seed + 2)
	expect_pattern(t, &second, seed)
}

choose_and_mutate :: proc(first, second: ^Record_80, choose_first: bool, replacement: u64) -> Record_80 {
	selected: Record_80
	if choose_first {
		selected = first^
	} else {
		selected = second^
	}
	fill(first, replacement)
	fill(second, replacement + 1)
	return selected
}

@(test)
runtime_branch_value_survives_mutation_and_multiple_consumers :: proc(t: ^testing.T) {
	seed := runtime_seed()
	for branch in ([2]bool{seed & 1 == 0, seed & 1 != 0}) {
		first, second, a, b: Record_80
		fill(&first, seed)
		fill(&second, seed + 3)
		selected := choose_and_mutate(&first, &second, branch, seed + 9)
		a, b = selected, selected
		fill(&selected, seed + 20)
		expected := seed if branch else seed + 3
		expect_pattern(t, &a, expected)
		expect_pattern(t, &b, expected)
		expect_pattern(t, &first, seed + 9)
		expect_pattern(t, &second, seed + 10)
	}
}
