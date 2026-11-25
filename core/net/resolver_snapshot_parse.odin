#+build darwin,linux,freebsd,openbsd,netbsd
package net

import "core:mem"
import "core:strings"
import posix "core:sys/posix"

@(private)
Resolver_Snapshot_Parse_Allocator :: struct {
	backing: mem.Allocator,
	failed:  bool,
	cause:   mem.Allocator_Error,
}

// Parser allocations are TEMPORARY and bulk-owned by the enclosing scratch
// buffer. Individual frees are intentionally no-ops. Every failed allocation or
// resize is latched, including errors legacy parsers ignore before recovering.
@(private)
resolver_snapshot_parse_allocator :: proc(
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
	state := cast(^Resolver_Snapshot_Parse_Allocator)data
	if mode == .Free {
		return nil, nil
	}
	if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed {
		if state.failed {
			return nil, state.cause
		}
		if size == 0 {
			return nil, nil
		}
		required := max(alignment, RESOLVER_SNAPSHOT_ALIGNMENT)
		grant, error := state.backing.procedure(
			state.backing.data,
			mode,
			size,
			required,
			old_memory,
			old_size,
			location,
		)
		if error != nil ||
		   raw_data(grant) == nil ||
		   len(grant) != size ||
		   uintptr(raw_data(grant)) % uintptr(required) != 0 {
			state.failed = true
			state.cause = error if error != nil else .Out_Of_Memory
			// This grant belongs to the bounded scratch arena even on error. Its one
			// enclosing backing is freed by the caller, including orphaned partial data.
			return nil, state.cause
		}
		return grant, nil
	}
	return state.backing.procedure(state.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(private)
resolver_snapshot_lines_fit :: proc(data: []u8, limit: int) -> bool {
	length := 0
	for char in data {
		if char == '\n' {
			length = 0
			continue
		}
		if length == limit {
			return false
		}
		length += 1
	}
	return true
}

// Actual shared parsing path. temporary MUST provide a fixed bulk scratch
// lifetime; no returned view outlives it. An outermost latch permits independent
// fault injection at every parser allocation/resize without exposing SDK knobs.
@(private)
resolver_snapshot_parse :: proc(
	resolv, hosts: []u8,
	limits: Resolver_Snapshot_Limits,
	temporary: mem.Allocator,
) -> (
	[]Endpoint,
	[]DNS_Host_Entry,
	Resolver_Snapshot_Error,
) {
	if temporary.procedure == nil {
		return nil, nil, .Invalid_Config
	}
	if !resolver_snapshot_lines_fit(resolv, limits.line_bytes) ||
	   !resolver_snapshot_lines_fit(hosts, limits.line_bytes) {
		return nil, nil, .Limit_Exceeded
	}
	state := Resolver_Snapshot_Parse_Allocator {
		backing = temporary,
	}
	allocator := mem.Allocator{resolver_snapshot_parse_allocator, &state}
	servers := parse_resolv_conf(string(resolv), allocator)
	if state.failed {
		return nil, nil, .Allocation_Failed
	}
	if len(servers) == 0 {
		return nil, nil, .No_Servers
	}
	if len(servers) > limits.name_servers {
		return nil, nil, .Limit_Exceeded
	}
	for server in servers {
		if !resolver_snapshot_endpoint_valid(server) {
			return nil, nil, .Parse_Failed
		}
	}
	reader: strings.Reader
	strings.reader_init(&reader, string(hosts))
	entries, ok := parse_hosts(strings.reader_to_stream(&reader), allocator)
	if state.failed {
		return nil, nil, .Allocation_Failed
	}
	if !ok {
		return nil, nil, .Parse_Failed
	}
	if len(entries) > limits.host_entries {
		return nil, nil, .Limit_Exceeded
	}
	names := 0
	for entry in entries {
		if len(entry.name) > limits.host_name_bytes - names {
			return nil, nil, .Limit_Exceeded
		}
		names += len(entry.name)
	}
	return servers, entries, .None
}

@(private)
resolver_snapshot_read_file :: proc(
	path: string,
	limit: int,
	allocator: mem.Allocator,
) -> (
	[]u8,
	int,
	Resolver_Snapshot_Error,
) {
	if len(path) == 0 || len(path) > RESOLVER_SNAPSHOT_PATH_BYTES || raw_data(path) == nil {
		return nil, 0, .Invalid_Config
	}
	name: [RESOLVER_SNAPSHOT_PATH_BYTES + 1]u8
	for char, index in transmute([]u8)path {
		if char == 0 {
			return nil, 0, .Invalid_Config
		}
		name[index] = char
	}
	// NONBLOCK prevents opening a FIFO from waiting for a writer; descriptor fstat
	// then rejects every nonregular source. Normal resolv.conf symlinks still work.
	descriptor := posix.open(cast(cstring)&name[0], {.CLOEXEC, .NONBLOCK})
	if descriptor < 0 {
		return nil, 0, .Read_Failed
	}
	defer _ = posix.close(descriptor)
	metadata: posix.stat_t
	if posix.fstat(descriptor, &metadata) != .OK {
		return nil, 0, .Read_Failed
	}
	if !posix.S_ISREG(metadata.st_mode) || metadata.st_size < 0 {
		return nil, 0, .Read_Failed
	}
	if metadata.st_size > posix.off_t(limit) {
		return nil, 0, .Limit_Exceeded
	}
	storage, error := resolver_snapshot_grant(limit + 1, allocator)
	if error != nil {
		return nil, 0, error
	}
	success := false
	defer if !success {
		resolver_snapshot_free(storage, allocator)
	}
	at, retries := 0, 0
	for {
		remaining := len(storage) - at
		n := posix.read(descriptor, raw_data(storage[at:]), uint(remaining))
		if n < 0 {
			cause := posix.errno()
			if cause == .EINTR && retries < 16 {
				retries += 1
				continue
			}
			return nil, 0, .Read_Failed
		}
		if n == 0 {
			break
		}
		if n > len(storage) - at {
			return nil, 0, .Read_Failed
		}
		at += int(n)
		if at > limit {
			return nil, 0, .Limit_Exceeded
		}
	}
	success = true
	return storage, at, .None
}

@(private)
resolver_snapshot_scratch_size :: proc(l: Resolver_Snapshot_Limits) -> (int, bool) {
	// Finite geometric array-growth allowance + all retained hostname bytes and
	// per-name alignment + scanner growth. Limits have already been hard-bounded.
	total := 4096
	counts := [5]int{l.host_entries, l.host_name_bytes, l.line_bytes, l.name_servers, l.host_entries}
	sizes := [5]int{8 * size_of(DNS_Host_Entry), 1, 4, 8 * size_of(Endpoint), RESOLVER_SNAPSHOT_ALIGNMENT}
	for count, index in counts {
		if count < 0 || count > (max(int) - total) / sizes[index] {
			return 0, false
		}
		total += count * sizes[index]
	}
	return total, true
}

@(private)
resolver_snapshot_prepare_system :: proc(
	options: Resolver_Snapshot_Options,
	allocator: mem.Allocator,
) -> (
	Resolver_Snapshot,
	Resolver_Snapshot_Error,
) {
	resolv_path := options.resolv_conf_path
	hosts_path := options.hosts_file_path
	if resolv_path == "" {
		resolv_path = dns_configuration.resolv_conf
	}
	if hosts_path == "" {
		hosts_path = dns_configuration.hosts_file
	}
	resolv, resolv_count, error := resolver_snapshot_read_file(resolv_path, options.limits.file_bytes, allocator)
	if error != nil {
		return {}, error
	}
	defer resolver_snapshot_free(resolv, allocator)
	// Scratch is fixed once, never grown and never retained by a prepared owner.
	size, valid := resolver_snapshot_scratch_size(options.limits)
	if !valid {
		return {}, .Limit_Exceeded
	}
	scratch, failure := resolver_snapshot_grant(size, allocator)
	if failure != nil {
		return {}, failure
	}
	defer resolver_snapshot_free(scratch, allocator)
	arena: mem.Arena
	mem.arena_init(&arena, scratch)
	// Preserve the old Unix no-server behavior: hosts is not opened or used when
	// no valid server exists. Latch first-parser failure before touching hosts.
	if !resolver_snapshot_lines_fit(resolv[:resolv_count], options.limits.line_bytes) {
		return {}, .Limit_Exceeded
	}
	first := Resolver_Snapshot_Parse_Allocator {
		backing = mem.arena_allocator(&arena),
	}
	servers := parse_resolv_conf(string(resolv[:resolv_count]), {resolver_snapshot_parse_allocator, &first})
	if first.failed {
		return {}, .Allocation_Failed
	}
	if len(servers) == 0 {
		return {}, .No_Servers
	}
	if len(servers) > options.limits.name_servers {
		return {}, .Limit_Exceeded
	}
	hosts, host_count, host_error := resolver_snapshot_read_file(hosts_path, options.limits.file_bytes, allocator)
	if host_error != nil {
		return {}, host_error
	}
	defer resolver_snapshot_free(hosts, allocator)
	// Rewind only unpublished scratch; the checked common path parses both files
	// and is also the independent verifier's parser-allocation injection surface.
	mem.arena_free_all(&arena)
	name_servers, entries, parse_error := resolver_snapshot_parse(
		resolv[:resolv_count],
		hosts[:host_count],
		options.limits,
		mem.arena_allocator(&arena),
	)
	if parse_error != nil {
		return {}, parse_error
	}
	return resolver_snapshot_pack(name_servers, entries, allocator)
}
