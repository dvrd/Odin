package net

import "core:bytes"
import "core:mem"
import "core:os"

Resolver_Snapshot_Limits :: struct {
	file_bytes, line_bytes, host_entries, host_name_bytes, name_servers: int,
}

// Concrete limits: callers must pass this value explicitly. An all-zero limit
// aggregate is invalid; individual zero capacities remain literal zero.
// host_name_bytes is the TOTAL copied hostname octet budget, not per entry.
DEFAULT_RESOLVER_SNAPSHOT_LIMITS :: Resolver_Snapshot_Limits{256 << 10, 4 << 10, 1024, 64 << 10, 8}
MAX_RESOLVER_SNAPSHOT_FILE_BYTES :: 1 << 20
MAX_RESOLVER_SNAPSHOT_LINE_BYTES :: 32 << 10
MAX_RESOLVER_SNAPSHOT_HOST_ENTRIES :: 4096
MAX_RESOLVER_SNAPSHOT_HOST_NAME_BYTES :: 1 << 20
MAX_RESOLVER_SNAPSHOT_NAME_SERVERS :: 8

@(private)
RESOLVER_SNAPSHOT_ALIGNMENT :: max(align_of(Endpoint), align_of(DNS_Host_Entry))

@(private)
RESOLVER_SNAPSHOT_PATH_BYTES :: 4096

Resolver_Snapshot_Options :: struct {
	// Nil selects system files. Nonnil-empty is rejected before allocation/I/O.
	// Nonempty explicit endpoints bypass BOTH system files, including hosts.
	name_servers:                      []Endpoint,
	// Empty paths use the existing Unix dns_configuration paths. No globals are
	// changed. These strings are borrowed only through synchronous preparation.
	resolv_conf_path, hosts_file_path: string,
	limits:                            Resolver_Snapshot_Limits,
}

Resolver_Snapshot_General_Error :: enum u32 {
	None,
	Invalid_Config,
	Invalid_State,
	Invalid_Hostname,
	No_Servers,
	Unsupported,
	Parse_Failed,
	Limit_Exceeded,
	Destination_Undersized,
	Overlapping_Buffers,
}

// What went wrong, or the allocator's or the operating system's own error
// when the snapshot could not be allocated or a configuration file not read.
Resolver_Snapshot_Error :: union #shared_nil {
	Resolver_Snapshot_General_Error,
	mem.Allocator_Error,
	os.Error,
}

// Stable, serialized owner; do not copy or mutate its fields. All published
// endpoint/host/name views point into one independently freeable backing.
// Destroy only after all borrowed views/lookups have finished. Core does not
// depend on an async runtime: callers enforce off-worker file preparation.
Resolver_Snapshot :: struct {
	_self:      ^Resolver_Snapshot,
	_servers:   []Endpoint,
	_hosts:     []DNS_Host_Entry,
	_storage:   []u8,
	_allocator: mem.Allocator,
}

@(private)
resolver_snapshot_limits_valid :: proc(l: Resolver_Snapshot_Limits) -> bool {
	return l != (Resolver_Snapshot_Limits{}) &&
		l.file_bytes >= 0 &&
		l.file_bytes <= MAX_RESOLVER_SNAPSHOT_FILE_BYTES &&
		l.line_bytes >= 0 &&
		l.line_bytes <= MAX_RESOLVER_SNAPSHOT_LINE_BYTES &&
		l.host_entries >= 0 &&
		l.host_entries <= MAX_RESOLVER_SNAPSHOT_HOST_ENTRIES &&
		l.host_name_bytes >= 0 &&
		l.host_name_bytes <= MAX_RESOLVER_SNAPSHOT_HOST_NAME_BYTES &&
		l.name_servers >= 0 &&
		l.name_servers <= MAX_RESOLVER_SNAPSHOT_NAME_SERVERS
}

@(private)
resolver_snapshot_endpoint_valid :: proc(e: Endpoint) -> bool {
	return e.port >= 1 &&
		e.port <= 65535 &&
		e.address != nil &&
		(family_from_address(e.address) == .IP4 || family_from_address(e.address) == .IP6)
}

@(private)
resolver_snapshot_grant :: proc(size: int, allocator: mem.Allocator) -> ([]u8, Resolver_Snapshot_Error) {
	if size == 0 {
		return nil, nil
	}
	if size < 0 || allocator.procedure == nil {
		return nil, .Invalid_Config
	}
	data, error := allocator.procedure(allocator.data, .Alloc, size, RESOLVER_SNAPSHOT_ALIGNMENT, nil, 0)
	if error != nil ||
	   raw_data(data) == nil ||
	   len(data) != size ||
	   uintptr(raw_data(data)) % RESOLVER_SNAPSHOT_ALIGNMENT != 0 {
		if raw_data(data) != nil {
			_, _ = allocator.procedure(
				allocator.data,
				.Free,
				0,
				RESOLVER_SNAPSHOT_ALIGNMENT,
				raw_data(data),
				len(data),
			)
		}
		return nil, error if error != nil else mem.Allocator_Error.Out_Of_Memory
	}
	return data, nil
}

@(private)
resolver_snapshot_free :: proc(data: []u8, allocator: mem.Allocator) {
	if raw_data(data) != nil {
		_, _ = allocator.procedure(allocator.data, .Free, 0, RESOLVER_SNAPSHOT_ALIGNMENT, raw_data(data), len(data))
	}
}

@(private)
resolver_snapshot_pack :: proc(
	servers: []Endpoint,
	hosts: []DNS_Host_Entry,
	allocator: mem.Allocator,
) -> (
	Resolver_Snapshot,
	Resolver_Snapshot_Error,
) {
	total := len(servers) * size_of(Endpoint)
	align := align_of(DNS_Host_Entry)
	if total > max(int) - (align - 1) {
		return {}, .Limit_Exceeded
	}
	hosts_at := (total + align - 1) &~ (align - 1)
	if len(hosts) > (max(int) - hosts_at) / size_of(DNS_Host_Entry) {
		return {}, .Limit_Exceeded
	}
	names_at := hosts_at + len(hosts) * size_of(DNS_Host_Entry)
	total = names_at
	for host in hosts {
		if len(host.name) > max(int) - total {
			return {}, .Limit_Exceeded
		}
		total += len(host.name)
	}
	storage, error := resolver_snapshot_grant(total, allocator)
	if error != nil {
		return {}, error
	}
	result := Resolver_Snapshot {
		_storage   = storage,
		_allocator = allocator,
	}
	result._servers = (cast([^]Endpoint)raw_data(storage))[:len(servers)]
	copy(result._servers, servers)
	if len(hosts) > 0 {
		result._hosts = (cast([^]DNS_Host_Entry)raw_data(storage[hosts_at:]))[:len(hosts)]
	}
	at := names_at
	for host, index in hosts {
		copy(storage[at:at + len(host.name)], host.name)
		result._hosts[index] = {
			name = string(storage[at:at + len(host.name)]),
			addr = host.addr,
		}
		at += len(host.name)
	}
	return result, nil
}

// Synchronous preparation only: no DNS query, entropy, OS resolver call or global
// configuration mutation. File reads/allocation callbacks are non-preemptible;
// byte limits do not constitute a wall-clock deadline. The destination is
// published once after full success and remains unchanged on every rejection.
resolver_snapshot_prepare :: proc(
	s: ^Resolver_Snapshot,
	options: Resolver_Snapshot_Options,
	allocator: mem.Allocator,
) -> Resolver_Snapshot_Error {
	if s == nil {
		return .Invalid_State
	}
	if s._self != nil || s._storage != nil || s._servers != nil || s._hosts != nil || s._allocator.procedure != nil {
		return .Invalid_State
	}
	if options.name_servers != nil && len(options.name_servers) == 0 {
		return .Invalid_Config
	}
	if !resolver_snapshot_limits_valid(options.limits) ||
	   allocator.procedure == nil ||
	   .Free not_in mem.query_features(allocator) {
		return .Invalid_Config
	}
	if options.name_servers != nil {
		if len(options.name_servers) > options.limits.name_servers {
			return .Limit_Exceeded
		}
		if raw_data(options.name_servers) == nil {
			return .Invalid_Config
		}
		for server in options.name_servers {
			if !resolver_snapshot_endpoint_valid(server) {
				return .Invalid_Config
			}
		}
		prepared, error := resolver_snapshot_pack(options.name_servers, nil, allocator)
		if error != nil {
			return error
		}
		prepared._self = s
		s^ = prepared
		return nil
	}
	when ODIN_OS == .Darwin || ODIN_OS == .Linux || ODIN_OS == .FreeBSD || ODIN_OS == .OpenBSD || ODIN_OS == .NetBSD {
		prepared, error := resolver_snapshot_prepare_system(options, allocator)
		if error != nil {
			return error
		}
		prepared._self = s
		s^ = prepared
		return nil
	} else {
		return Resolver_Snapshot_General_Error.Unsupported
	}
}

// Borrowed immutable view, valid only while the original snapshot owner lives.
resolver_snapshot_name_servers :: proc(s: ^Resolver_Snapshot) -> ([]Endpoint, bool) {
	if s == nil || s._self != s {
		return nil, false
	}
	return s._servers, true
}

@(private)
resolver_snapshot_without_dot :: proc(host: string) -> string {
	if len(host) > 0 && host[len(host) - 1] == '.' {
		return host[:len(host) - 1]
	}
	return host
}

@(private)
resolver_snapshot_name_equal :: proc(a, b: string) -> bool {
	left, right := resolver_snapshot_without_dot(a), resolver_snapshot_without_dot(b)
	if len(left) != len(right) {
		return false
	}
	for char, index in transmute([]u8)left {
		other := right[index]
		first := char
		if first >= 'A' && first <= 'Z' {
			first += 'a' - 'A'
		}
		if other >= 'A' && other <= 'Z' {
			other += 'a' - 'A'
		}
		if first != other {
			return false
		}
	}
	return true
}

// Pure allocation-free hosts lookup, preserving matching file order and both
// address families. A trailing dot and ASCII case are ignored. Short dst returns
// REQUIRED count/found=true without modifying any destination byte. This does
// not perform DNS, select a family, or authorize origin/transport coalescing.
resolver_snapshot_lookup :: proc(
	s: ^Resolver_Snapshot,
	host: string,
	dst: []Endpoint,
	port: int,
) -> (
	count: int,
	found: bool,
	error: Resolver_Snapshot_Error,
) {
	if s == nil || s._self != s {
		return 0, false, .Invalid_State
	}
	if port < 1 || port > 65535 || len(dst) > max(int) / size_of(Endpoint) || len(dst) > 0 && raw_data(dst) == nil {
		return 0, false, .Invalid_Config
	}
	if len(host) > 0 && raw_data(host) == nil || !validate_hostname(resolver_snapshot_without_dot(host)) {
		return 0, false, .Invalid_Hostname
	}
	target := mem.byte_slice(raw_data(dst), len(dst) * size_of(Endpoint))
	if bytes.alias(target, s._storage) ||
	   bytes.alias(target, mem.byte_slice(s, size_of(Resolver_Snapshot))) ||
	   bytes.alias(target, transmute([]u8)host) {
		return 0, false, .Overlapping_Buffers
	}
	needed := 0
	for entry in s._hosts {
		if resolver_snapshot_name_equal(entry.name, host) {
			needed += 1
		}
	}
	if needed == 0 {
		return 0, false, nil
	}
	if needed > len(dst) {
		return needed, true, .Destination_Undersized
	}
	at := 0
	for entry in s._hosts {
		if resolver_snapshot_name_equal(entry.name, host) {
			dst[at] = {
				address = entry.addr,
				port    = port,
			}
			at += 1
		}
	}
	return needed, true, nil
}

resolver_snapshot_destroy :: proc(s: ^Resolver_Snapshot) {
	if s == nil || s._self != s {
		return
	}
	old := s^
	s^ = {}
	// The physical free may recursively destroy/free s. No owner access afterward.
	resolver_snapshot_free(old._storage, old._allocator)
}
