package main

import "core:fmt"
import "core:mem"
import charged "core:mem/budget"
import "core:net"
import "core:os"
import scopes "core:sync/budget"
import rt "base:runtime"

main :: proc() {
	assert(len(os.args) == 3, "provide owned resolv and hosts fixture paths")
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, rt.heap_allocator(), rt.heap_allocator())
	backing := mem.tracking_allocator(&tracker)
	scope, error := scopes.create_root({bytes = 4 << 20}, backing)
	assert(error == .None)
	observer, error2 := scopes.retain_scope(scope)
	assert(error2 == .None)
	binding, cause := charged.create(scope, {backing = backing, metadata_allocator = backing})
	assert(cause.kind == .None)
	allocator := charged.allocator(binding)
	owner: net.Resolver_Snapshot
	prepared := net.resolver_snapshot_prepare(
		&owner,
		{resolv_conf_path = os.args[1], hosts_file_path = os.args[2], limits = net.DEFAULT_RESOLVER_SNAPSHOT_LIMITS},
		allocator,
	)
	assert(prepared.kind == .None)
	// Allocation provenance retains the Binding/Scope after caller owners retire.
	charged.release(&binding)
	scopes.release_scope(&scope)
	endpoints, valid := net.resolver_snapshot_name_servers(&owner)
	assert(valid && len(endpoints) == 2)
	addresses: [3]net.Endpoint
	count, found, lookup := net.resolver_snapshot_lookup(&owner, "EXAMPLE.TEST.", addresses[:], 8443)
	assert(lookup.kind == .None && found && count == 3)
	assert(addresses[0] == net.Endpoint{net.IP4_Address{127, 0, 0, 2}, 8443})
	assert(addresses[1] == net.Endpoint{net.IP6_Loopback, 8443})
	assert(addresses[2] == net.Endpoint{net.IP4_Address{127, 0, 0, 3}, 8443})
	used, status := scopes.snapshot(observer)
	assert(status == .None && used.used.bytes > 0)
	net.resolver_snapshot_destroy(&owner)
	empty, status2 := scopes.snapshot(observer)
	assert(status2 == .None && empty.used.bytes == 0 && empty.used.streams == 0 && empty.used.jobs == 0)
	scopes.release_scope(&observer)
	assert(tracker.current_memory_allocated == 0 && len(tracker.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&tracker)
	fmt.println(
		"{\"passed\":true,\"servers\":2,\"matched_hosts\":3,\"scope_bytes\":0,\"heap_bytes\":0,\"binding_retired_before_lookup\":true}",
	)
}
