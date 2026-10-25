// regression test for -cached: changing a static foreign lib should force a rebuild.
// run.sh drives the actual cache checks.

package main

import "core:testing"

foreign import foo "build/libcached_foreign_libs.a"

@(default_calling_convention="c")
foreign foo {
	cached_foreign_add :: proc(a, b: i32) -> i32 ---
}

main :: proc() {
	assert(cached_foreign_add(2, 3) == 5) // call in, so the lib is actually linked
}

@(test)
test_cached_foreign_add :: proc(t: ^testing.T) {
	testing.expect_value(t, cached_foreign_add(2, 3), 5)
}
