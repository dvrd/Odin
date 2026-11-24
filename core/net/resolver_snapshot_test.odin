package net

import rt "base:runtime"
import "core:mem"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

snapshot_test_forbid_alloc :: proc(
	_: rawptr,
	mode: mem.Allocator_Mode,
	_: int,
	_: int,
	old_memory: rawptr,
	_: int,
	_ := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	if mode == .Query_Features {
		(cast(^mem.Allocator_Mode_Set)old_memory)^ = {.Alloc, .Free, .Query_Features}
		return nil, nil
	}
	panic("invalid preparation touched backing allocator")
}

snapshot_test_file :: proc(data: string) -> string {
	f, error := os.create_temp_file("/tmp", "webtools101-resolver-*")
	assert(error == nil)
	path := strings.clone(os.name(f))
	os.close(f)
	assert(os.write_entire_file(path, data) == nil)
	return path
}

snapshot_test_remove :: proc(path: string) {_ = os.remove(path); delete(path)}

snapshot_test_options :: proc(resolv, hosts: string) -> Resolver_Snapshot_Options {
	return {resolv_conf_path = resolv, hosts_file_path = hosts, limits = DEFAULT_RESOLVER_SNAPSHOT_LIMITS}
}

@(test)
snapshot_explicit_servers_clone_and_bypass_files :: proc(t: ^testing.T) {
	input := [2]Endpoint{{IP4_Address{127, 0, 0, 9}, 5353}, {IP6_Loopback, 53}}
	expected := input
	options := snapshot_test_options("/nonexistent/webtools101-resolv", "/nonexistent/webtools101-hosts")
	options.name_servers = input[:]
	owner: Resolver_Snapshot
	error := resolver_snapshot_prepare(&owner, options, context.allocator)
	testing.expect_value(t, error.kind, .None)
	if error.kind != .None do return
	defer resolver_snapshot_destroy(&owner)
	input[0] = {IP4_Address{10, 0, 0, 1}, 999}
	servers, valid := resolver_snapshot_name_servers(&owner)
	testing.expect(t, valid)
	testing.expect_value(t, len(servers), 2)
	if len(servers) == 2 {
		testing.expect_value(t, servers[0], expected[0])
		testing.expect_value(t, servers[1], expected[1])
		testing.expect(t, raw_data(servers) != raw_data(input[:]))
	}
	destination: [2]Endpoint
	count, found, cause := resolver_snapshot_lookup(&owner, "unknown.example", destination[:], 443)
	testing.expect_value(t, count, 0)
	testing.expect_value(t, found, false)
	testing.expect_value(t, cause.kind, .None)
}

@(test)
snapshot_explicit_empty_and_invalid_endpoints_never_fall_back :: proc(t: ^testing.T) {
	storage: [1]Endpoint
	options := snapshot_test_options("/nonexistent/101", "/nonexistent/101")
	options.name_servers = storage[:0]
	testing.expect(t, options.name_servers != nil)
	owner: Resolver_Snapshot
	error := resolver_snapshot_prepare(&owner, options, mem.Allocator{snapshot_test_forbid_alloc, nil})
	testing.expect_value(t, error.kind, .Invalid_Config)
	_, valid := resolver_snapshot_name_servers(&owner)
	testing.expect(t, !valid)
	for port in ([4]int{-1, 0, 65536, max(int)}) {
		storage[0] = {IP4_Loopback, port}
		options.name_servers = storage[:]
		error = resolver_snapshot_prepare(&owner, options, mem.Allocator{snapshot_test_forbid_alloc, nil})
		testing.expect_value(t, error.kind, .Invalid_Config)
	}
	storage[0] = {
		port = 53,
	}
	options.name_servers = storage[:]
	error = resolver_snapshot_prepare(&owner, options, mem.Allocator{snapshot_test_forbid_alloc, nil})
	testing.expect_value(t, error.kind, .Invalid_Config)
	resolver_snapshot_destroy(&owner)
}

@(test)
snapshot_literal_files_lookup_alias_case_dot_and_atomic_short_output :: proc(t: ^testing.T) {
	when ODIN_OS == .Windows do return
	resolv := snapshot_test_file("# fixture\nnameserver 127.0.0.1\nnameserver ::1\n")
	defer snapshot_test_remove(resolv)
	hosts := snapshot_test_file("127.0.0.2 Example.test Alias.test\n::1 example.test\n127.0.0.3 example.test\n")
	defer snapshot_test_remove(hosts)
	owner: Resolver_Snapshot
	error := resolver_snapshot_prepare(&owner, snapshot_test_options(resolv, hosts), context.allocator)
	testing.expect_value(t, error.kind, .None)
	if error.kind != .None do return
	defer resolver_snapshot_destroy(&owner)
	// Destroy the source contents before observing the copied snapshot.
	testing.expect_value(t, os.write_entire_file(resolv, "broken"), nil)
	testing.expect_value(t, os.write_entire_file(hosts, "broken"), nil)
	expected := [3]Endpoint{{IP4_Address{127, 0, 0, 2}, 8443}, {IP6_Loopback, 8443}, {IP4_Address{127, 0, 0, 3}, 8443}}
	out := [3]Endpoint{{IP4_Address{9, 9, 9, 9}, 9}, {IP4_Address{8, 8, 8, 8}, 8}, {IP4_Address{7, 7, 7, 7}, 7}}
	before := out
	count, found, cause := resolver_snapshot_lookup(&owner, "EXAMPLE.TEST.", out[:2], 8443)
	testing.expect_value(t, count, 3)
	testing.expect_value(t, found, true)
	testing.expect_value(t, cause.kind, .Destination_Undersized)
	testing.expect_value(t, out, before)
	count, found, cause = resolver_snapshot_lookup(&owner, "eXaMpLe.TeSt", out[:], 8443)
	testing.expect_value(t, count, 3)
	testing.expect_value(t, found, true)
	testing.expect_value(t, cause.kind, .None)
	testing.expect_value(t, out, expected)
	count, found, cause = resolver_snapshot_lookup(&owner, "ALIAS.TEST.", out[:], 9443)
	testing.expect_value(t, count, 1)
	testing.expect_value(t, found, true)
	testing.expect_value(t, cause.kind, .None)
	testing.expect_value(t, out[0], Endpoint{IP4_Address{127, 0, 0, 2}, 9443})
}

@(test)
snapshot_failed_file_and_limits_do_not_publish_partial_policy :: proc(t: ^testing.T) {
	when ODIN_OS == .Windows do return
	resolv := snapshot_test_file("nameserver 127.0.0.1\n")
	defer snapshot_test_remove(resolv)
	hosts := snapshot_test_file("127.0.0.2 example.test alias.test\n")
	defer snapshot_test_remove(hosts)
	options := snapshot_test_options(resolv, hosts)
	for field in 0 ..< 5 {
		limits := DEFAULT_RESOLVER_SNAPSHOT_LIMITS
		switch field {
		case 0:
			limits.file_bytes = 1
		case 1:
			limits.line_bytes = 1
		case 2:
			limits.host_entries = 0
		case 3:
			limits.host_name_bytes = 0
		case 4:
			limits.name_servers = 0
		}
		options.limits = limits
		owner: Resolver_Snapshot
		error := resolver_snapshot_prepare(&owner, options, context.allocator)
		testing.expect_value(t, error.kind, .Limit_Exceeded)
		_, valid := resolver_snapshot_name_servers(&owner)
		testing.expect(t, !valid)
		resolver_snapshot_destroy(&owner)
	}
	owner: Resolver_Snapshot
	options = snapshot_test_options("/nonexistent/webtools101", hosts)
	error := resolver_snapshot_prepare(&owner, options, context.allocator)
	testing.expect_value(t, error.kind, .Read_Failed)
	_, valid := resolver_snapshot_name_servers(&owner)
	testing.expect(t, !valid)
	resolver_snapshot_destroy(&owner)
}

Snapshot_Test_Grant_Mode :: enum {
	Normal,
	Nil_Error,
	Grant_Error,
	Nil_Success,
	Short,
	Long,
	Misaligned,
}

Snapshot_Test_Grant :: struct {
	raw, reported: []u8,
}

Snapshot_Test_Allocator :: struct {
	mode:                                         Snapshot_Test_Grant_Mode,
	fail_at, calls, frees, live_bytes, bad_frees: int,
	grants:                                       [64]Snapshot_Test_Grant,
	destroy_header:                               ^Resolver_Snapshot,
	header_freed:                                 bool,
}

snapshot_test_allocator :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	p := cast(^Snapshot_Test_Allocator)data
	heap := rt.heap_allocator()
	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		p.calls += 1
		selected := Snapshot_Test_Grant_Mode.Normal
		if p.calls == p.fail_at {
			selected = p.mode
		}
		if selected == .Nil_Error do return nil, .Out_Of_Memory
		if selected == .Nil_Success do return nil, nil
		actual := size
		if selected == .Short {
			actual = max(0, size - 1)
		}
		if selected == .Long || selected == .Misaligned {
			actual = size + 1
		}
		raw, error := heap.procedure(heap.data, .Alloc, actual, max(alignment, 16), nil, 0, location)
		assert(error == nil && len(raw) == actual)
		reported := raw
		if selected == .Misaligned {
			reported = raw[1:]
		}
		recorded := false
		for &grant in p.grants {
			if raw_data(grant.raw) == nil {
				grant = {raw, reported}
				recorded = true
				break
			}
		}
		assert(recorded)
		p.live_bytes += len(raw)
		if selected == .Grant_Error do return reported, .Out_Of_Memory
		return reported, nil
	case .Free:
		if old_memory == nil do return nil, nil
		for &grant in p.grants {
			if raw_data(grant.raw) != nil && old_memory == raw_data(grant.reported) {
				if old_size != len(grant.reported) {
					p.bad_frees += 1
				}
				raw := grant.raw
				grant = {}
				p.live_bytes -= len(raw)
				p.frees += 1
				if p.destroy_header != nil {
					owner := p.destroy_header
					p.destroy_header = nil
					_, valid := resolver_snapshot_name_servers(owner)
					assert(!valid, "destroy must invalidate original owner before physical callback")
					free(owner, heap)
					p.header_freed = true
				}
				return heap.procedure(heap.data, .Free, 0, max(alignment, 16), raw_data(raw), len(raw), location)
			}
		}
		p.bad_frees += 1
		return nil, nil
	case .Resize:
		return mem.default_resize_bytes_align(
			mem.byte_slice(old_memory, old_size),
			size,
			alignment,
			{snapshot_test_allocator, p},
			location,
		)
	case .Resize_Non_Zeroed:
		return mem.default_resize_bytes_align_non_zeroed(
			mem.byte_slice(old_memory, old_size),
			size,
			alignment,
			{snapshot_test_allocator, p},
			location,
		)
	case .Query_Features:
		(cast(^mem.Allocator_Mode_Set)old_memory)^ = {
			.Alloc,
			.Alloc_Non_Zeroed,
			.Resize,
			.Resize_Non_Zeroed,
			.Free,
			.Query_Features,
		}
		return nil, nil
	case .Free_All, .Query_Info:
		return nil, .Mode_Not_Implemented
	}
	return nil, .Mode_Not_Implemented
}

@(test)
snapshot_all_backing_grants_fail_atomically_with_exact_physical_rollback :: proc(t: ^testing.T) {
	when ODIN_OS == .Windows do return
	resolv := snapshot_test_file("nameserver 127.0.0.1\nnameserver ::1\n")
	defer snapshot_test_remove(resolv)
	hosts := snapshot_test_file("127.0.0.2 a.test b.test\n::1 a.test\n")
	defer snapshot_test_remove(hosts)
	options := snapshot_test_options(resolv, hosts)
	healthy: Snapshot_Test_Allocator
	owner: Resolver_Snapshot
	error := resolver_snapshot_prepare(&owner, options, {snapshot_test_allocator, &healthy})
	testing.expect_value(t, error.kind, .None)
	if error.kind != .None do return
	points := healthy.calls
	testing.expect(t, points > 0 && points < 64)
	resolver_snapshot_destroy(&owner)
	testing.expect_value(t, healthy.live_bytes, 0)
	testing.expect_value(t, healthy.bad_frees, 0)
	cases := 0
	for mode in ([6]Snapshot_Test_Grant_Mode{.Nil_Error, .Grant_Error, .Nil_Success, .Short, .Long, .Misaligned}) {
		for at in 1 ..= points {
			probe := Snapshot_Test_Allocator {
				mode    = mode,
				fail_at = at,
			}
			failed: Resolver_Snapshot
			cause := resolver_snapshot_prepare(&failed, options, {snapshot_test_allocator, &probe})
			testing.expect(t, cause.kind != .None)
			_, valid := resolver_snapshot_name_servers(&failed)
			testing.expect(t, !valid)
			// Observe rollback before fixture cleanup; cleanup must not conceal a leak.
			testing.expect_value(t, probe.live_bytes, 0)
			testing.expect_value(t, probe.bad_frees, 0)
			resolver_snapshot_destroy(&failed)
			testing.expect_value(t, probe.live_bytes, 0)
			cases += 1
		}
	}
	testing.expect_value(t, cases, points * 6)
	fmt.printf("RESOLVER_SNAPSHOT_RAW points=%d malformed_cells=%d before_cleanup_live_bytes=0\n", points, cases)
}

@(test)
snapshot_destroy_invalidates_owner_before_callback_can_free_header :: proc(t: ^testing.T) {
	owner := new(Resolver_Snapshot, rt.heap_allocator())
	probe: Snapshot_Test_Allocator
	endpoints := [1]Endpoint{{IP4_Loopback, 53}}
	options := snapshot_test_options("/nonexistent/101", "/nonexistent/101")
	options.name_servers = endpoints[:]
	error := resolver_snapshot_prepare(owner, options, {snapshot_test_allocator, &probe})
	testing.expect_value(t, error.kind, .None)
	if error.kind != .None {
		free(owner, rt.heap_allocator())
		return
	}
	probe.destroy_header = owner
	resolver_snapshot_destroy(owner)
	// The header is physically gone; only detached allocator state is inspected.
	testing.expect(t, probe.header_freed)
	testing.expect_value(t, probe.live_bytes, 0)
	testing.expect_value(t, probe.bad_frees, 0)
}

Snapshot_Test_Parser_Allocator :: struct {
	backing:        mem.Allocator,
	calls, fail_at: int,
	modes:          [128]mem.Allocator_Mode,
	sizes:          [128]int,
}

snapshot_test_parser_allocator :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	p := cast(^Snapshot_Test_Parser_Allocator)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed {
		assert(p.calls < len(p.modes))
		p.modes[p.calls] = mode
		p.sizes[p.calls] = size
		p.calls += 1
		if p.calls == p.fail_at do return nil, .Out_Of_Memory
	}
	return p.backing.procedure(p.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(test)
snapshot_every_legacy_parser_allocation_failure_is_latched_without_partial_policy :: proc(t: ^testing.T) {
	when ODIN_OS == .Darwin || ODIN_OS == .Linux || ODIN_OS == .FreeBSD || ODIN_OS == .OpenBSD || ODIN_OS == .NetBSD {
		// The enclosing scratch owns even a legacy parser's orphaned hostname clone.
		scratch := make([]u8, 1 << 20)
		defer delete(scratch)
		arena: mem.Arena
		mem.arena_init(&arena, scratch)
		resolv_text: string = "nameserver 127.0.0.1\nnameserver ::1\n"
		resolv := transmute([]u8)resolv_text
		small: string = "127.0.0.2 alpha.test beta.test\n::1 alpha.test\n"
		growth: string = "127.0.0.2 alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test alias.test \n"
		for text, index in ([2]string{small, growth}) {
			mem.arena_free_all(&arena)
			hosts := transmute([]u8)text
			healthy := Snapshot_Test_Parser_Allocator {
				backing = mem.arena_allocator(&arena),
			}
			servers, entries, error := resolver_snapshot_parse(
				resolv,
				hosts,
				DEFAULT_RESOLVER_SNAPSHOT_LIMITS,
				{snapshot_test_parser_allocator, &healthy},
			)
			testing.expect_value(t, error.kind, .None)
			testing.expect_value(t, len(servers), 2)
			testing.expect_value(t, len(entries), 3 if index == 0 else 80)
			testing.expect(t, healthy.calls > 3)
			scanner_resize, growth_resize := false, false
			for i in 0 ..< healthy.calls {
				if healthy.sizes[i] == 256 {
					scanner_resize = true
				}
				if healthy.modes[i] == .Resize || healthy.modes[i] == .Resize_Non_Zeroed {
					growth_resize = true
				}
			}
			testing.expect(
				t,
				scanner_resize,
				"must exercise the initial scanner resize allocation whose failure the legacy parser ignores",
			)
			fmt.printf(
				"RESOLVER_SNAPSHOT_PARSER points=%d modes=%v sizes=%v\n",
				healthy.calls,
				healthy.modes[:healthy.calls],
				healthy.sizes[:healthy.calls],
			)
			if index == 1 {
				testing.expect(t, growth_resize, "growth corpus must reach a real allocator resize")
			}
			for at in 1 ..= healthy.calls {
				mem.arena_free_all(&arena)
				probe := Snapshot_Test_Parser_Allocator {
					backing = mem.arena_allocator(&arena),
					fail_at = at,
				}
				result_servers, result_hosts, cause := resolver_snapshot_parse(
					resolv,
					hosts,
					DEFAULT_RESOLVER_SNAPSHOT_LIMITS,
					{snapshot_test_parser_allocator, &probe},
				)
				testing.expect_value(t, cause.kind, .Allocation_Failed)
				testing.expect_value(t, cause.allocation, .Out_Of_Memory)
				testing.expect_value(t, len(result_servers), 0)
				testing.expect_value(t, len(result_hosts), 0)
			}
		}
	}
}

@(test)
snapshot_lookup_rejects_aliases_and_moved_headers_without_mutating_inputs :: proc(t: ^testing.T) {
	endpoints := [1]Endpoint{{IP4_Loopback, 53}}
	options := snapshot_test_options("/nonexistent/101", "/nonexistent/101")
	options.name_servers = endpoints[:]
	owner: Resolver_Snapshot
	cause := resolver_snapshot_prepare(&owner, options, context.allocator)
	testing.expect_value(t, cause.kind, .None)
	if cause.kind != .None do return
	defer resolver_snapshot_destroy(&owner)
	servers, valid := resolver_snapshot_name_servers(&owner)
	testing.expect(t, valid)
	before := servers[0]
	_, _, error := resolver_snapshot_lookup(&owner, "host.test", servers, 443)
	testing.expect_value(t, error.kind, .Overlapping_Buffers)
	testing.expect_value(t, servers[0], before)
	moved := owner
	_, valid = resolver_snapshot_name_servers(&moved)
	testing.expect(t, !valid)
	resolver_snapshot_destroy(&moved)
	_, valid = resolver_snapshot_name_servers(&owner)
	testing.expect(t, valid)
	for host in ([5]string{"", "two..dots", "a\x00b", "bad space", "-bad.test"}) {
		dst: [1]Endpoint
		_, _, bad := resolver_snapshot_lookup(&owner, host, dst[:], 443)
		testing.expect_value(t, bad.kind, .Invalid_Hostname)
	}
	cause = resolver_snapshot_prepare(&owner, options, mem.Allocator{snapshot_test_forbid_alloc, nil})
	testing.expect_value(t, cause.kind, .Invalid_State)
	testing.expect_value(t, servers[0], before)
}

@(test)
snapshot_exact_file_caps_and_no_server_policy_are_explicit :: proc(t: ^testing.T) {
	when ODIN_OS == .Windows do return
	data :: "nameserver 127.0.0.1\n"
	resolv := snapshot_test_file(data)
	defer snapshot_test_remove(resolv)
	hosts := snapshot_test_file("")
	defer snapshot_test_remove(hosts)
	options := snapshot_test_options(resolv, hosts)
	options.limits.file_bytes = len(data)
	options.limits.line_bytes = len(data) - 1
	options.limits.host_entries = 0
	options.limits.host_name_bytes = 0
	owner: Resolver_Snapshot
	cause := resolver_snapshot_prepare(&owner, options, context.allocator)
	testing.expect_value(t, cause.kind, .None)
	resolver_snapshot_destroy(&owner)
	options.limits.file_bytes = len(data) - 1
	cause = resolver_snapshot_prepare(&owner, options, context.allocator)
	testing.expect_value(t, cause.kind, .Limit_Exceeded)
	options = snapshot_test_options(resolv, "/nonexistent/101-hosts")
	testing.expect_value(t, os.write_entire_file(resolv, "# no servers\n"), nil)
	cause = resolver_snapshot_prepare(&owner, options, context.allocator)
	testing.expect_value(t, cause.kind, .No_Servers)
	_, valid := resolver_snapshot_name_servers(&owner)
	testing.expect(t, !valid)
}

@(test)
snapshot_rejects_invalid_and_overflowing_limits_before_any_allocator :: proc(t: ^testing.T) {
	endpoints := [1]Endpoint{{IP4_Loopback, 53}}
	for field in 0 ..< 5 {
		for value in ([2]int{-1, max(int)}) {
			options := snapshot_test_options("/nonexistent/101", "/nonexistent/101")
			options.name_servers = endpoints[:]
			fields := [5]^int {
				&options.limits.file_bytes,
				&options.limits.line_bytes,
				&options.limits.host_entries,
				&options.limits.host_name_bytes,
				&options.limits.name_servers,
			}
			fields[field]^ = value
			owner: Resolver_Snapshot
			cause := resolver_snapshot_prepare(&owner, options, mem.Allocator{snapshot_test_forbid_alloc, nil})
			testing.expect_value(t, cause.kind, .Invalid_Config)
			_, valid := resolver_snapshot_name_servers(&owner)
			testing.expect(t, !valid)
		}
	}
	options := snapshot_test_options("/nonexistent/101", "/nonexistent/101")
	options.name_servers = endpoints[:]
	options.limits = {}
	owner: Resolver_Snapshot
	cause := resolver_snapshot_prepare(&owner, options, mem.Allocator{snapshot_test_forbid_alloc, nil})
	testing.expect_value(t, cause.kind, .Invalid_Config)
}

@(test)
snapshot_nonregular_and_embedded_nul_paths_fail_without_policy_or_backing :: proc(t: ^testing.T) {
	when ODIN_OS == .Windows do return
	owner: Resolver_Snapshot
	options := snapshot_test_options("/tmp", "/nonexistent/101")
	cause := resolver_snapshot_prepare(&owner, options, mem.Allocator{snapshot_test_forbid_alloc, nil})
	testing.expect_value(t, cause.kind, .Read_Failed)
	options.resolv_conf_path = "/tmp/invalid\x00suffix"
	cause = resolver_snapshot_prepare(&owner, options, mem.Allocator{snapshot_test_forbid_alloc, nil})
	testing.expect_value(t, cause.kind, .Invalid_Config)
	_, valid := resolver_snapshot_name_servers(&owner)
	testing.expect(t, !valid)
}
