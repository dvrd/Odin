// Bounded publication and lifetime pins for immutable credential owners.
package store

import credentials ".."
import "base:intrinsics"
import "core:crypto"
import "core:mem"
import "core:sync"
import "core:time"

Store :: struct {}
Config :: struct {
	max_generations, max_leases, max_retained_bytes: int,
}
DEFAULT_CONFIG :: Config{4, 1024, 16 << 20}
Error_Kind :: enum {
	None,
	Invalid_Config,
	Invalid_Input,
	Invalid_Store,
	Invalid_Lease,
	Allocation_Failed,
	Closed,
	Empty,
	Busy,
	Capacity,
	Identity_Exhausted,
	Credential_Failed,
}
Error :: struct {
	kind:       Error_Kind,
	credential: credentials.Error,
	allocation: mem.Allocator_Error,
}

// An owning value. Do not copy, forge or release it while its borrows/signers
// are active. Distinct leases may be used concurrently on the same Store.
Lease :: struct {
	_epoch, _id, _generation: u64,
	_slot:                    int,
}
Stats :: struct {
	config:                                                                  Config,
	closed:                                                                  bool,
	current_generation:                                                      u64,
	generations, retired_generations, destroying_generations, active_leases: int,
	retained_bytes, metadata_bytes:                                          int,
}

@(private)
Generation_State :: enum u8 {
	Free,
	Current,
	Retired,
	Destroying,
}
@(private)
Generation :: struct {
	owner:         ^credentials.Credential,
	id:            u64,
	leases, bytes: int,
	state:         Generation_State,
}
@(private)
Lease_Record :: struct {
	id, generation: u64,
	index:          int,
	active:         bool,
}
@(private)
Owner :: struct {
	mutex:          sync.Mutex,
	allocator:      mem.Allocator,
	config:         Config,
	epoch,
	next_generation,
	next_lease:     u64,
	generations:    []Generation,
	leases:         []Lease_Record,
	current,
	free_lease:     int,
	closed:         bool,
	generation_count,
	retired_count,
	destroying_count,
	lease_count,
	retained_bytes,
	metadata_bytes: int,
}
@(private)
_next_store_epoch: u64

// Saturating CAS allocation: exhaustion never wraps into a live identity.
// The counter argument also permits testing exhaustion without resetting globals.
@(private)
next_identity :: proc(counter: ^u64) -> (u64, bool) {
	for {
		prior := intrinsics.atomic_load(counter)
		if prior == max(u64) {
			return 0, false
		}
		_, changed := intrinsics.atomic_compare_exchange_strong(counter, prior, prior + 1)
		if changed {
			return prior + 1, true
		}
	}
}
@(private)
next_local_identity :: proc(counter: ^u64) -> (u64, bool) {
	if counter^ == max(u64) {
		return 0, false
	}
	counter^ += 1
	return counter^, true
}
@(private)
normalize :: proc(config: Config) -> (Config, bool) {
	out := config
	if out.max_generations == 0 {
		out.max_generations = DEFAULT_CONFIG.max_generations
	}
	if out.max_leases == 0 {
		out.max_leases = DEFAULT_CONFIG.max_leases
	}
	if out.max_retained_bytes == 0 {
		out.max_retained_bytes = DEFAULT_CONFIG.max_retained_bytes
	}
	if out.max_generations < 1 || out.max_leases < 1 || out.max_retained_bytes < 1 {
		return out, false
	}
	if out.max_generations > (max(int) - size_of(Owner)) / size_of(Generation) {
		return out, false
	}
	remaining := max(int) - size_of(Owner) - out.max_generations * size_of(Generation)
	return out, out.max_leases <= remaining / size_of(Lease_Record)
}
@(private)
wipe_free :: proc(allocator: mem.Allocator, data: []u8, alignment: int) {
	if raw_data(data) == nil {
		return
	}
	crypto.zero_explicit(raw_data(data), len(data))
	_, _ = allocator.procedure(allocator.data, .Free, 0, alignment, raw_data(data), len(data))
}
@(private)
allocate :: proc(allocator: mem.Allocator, size, alignment: int) -> ([]u8, mem.Allocator_Error) {
	data, error := allocator.procedure(allocator.data, .Alloc, size, alignment, nil, 0)
	if error != nil || len(data) != size || raw_data(data) == nil {
		wipe_free(allocator, data, alignment)
		return nil, .Out_Of_Memory if error == nil else error
	}
	for &b in data {b = 0}
	return data, .None
}

// Allocates all store metadata up front. This does not load files, parse a key,
// choose a clock/policy or take ownership of any credential.
create :: proc(config: Config, allocator: mem.Allocator) -> (^Store, Error) {
	config, valid := normalize(config)
	if !valid || allocator.procedure == nil {
		return nil, {kind = .Invalid_Config}
	}
	storage, allocation := allocate(allocator, size_of(Owner), align_of(Owner))
	if allocation != nil {
		return nil, {kind = .Allocation_Failed, allocation = allocation}
	}
	owner := cast(^Owner)raw_data(storage)
	owner.allocator = allocator; owner.config = config; owner.current = -1
	success := false
	defer if !success {
		wipe_free(allocator, mem.slice_data_cast([]u8, owner.generations), align_of(Generation))
		wipe_free(allocator, mem.slice_data_cast([]u8, owner.leases), align_of(Lease_Record))
		wipe_free(allocator, storage, align_of(Owner))
	}
	generation_storage, ge := allocate(
		allocator,
		config.max_generations * size_of(Generation),
		align_of(Generation),
	)
	if ge != nil {
		return nil, {kind = .Allocation_Failed, allocation = ge}
	}
	owner.generations = mem.slice_data_cast([]Generation, generation_storage)
	lease_storage, le := allocate(
		allocator,
		config.max_leases * size_of(Lease_Record),
		align_of(Lease_Record),
	)
	if le != nil {
		return nil, {kind = .Allocation_Failed, allocation = le}
	}
	owner.leases = mem.slice_data_cast([]Lease_Record, lease_storage)
	for &record, index in owner.leases {record.index = index + 1 if index + 1 < len(owner.leases) else -1}
	epoch, available := next_identity(&_next_store_epoch)
	if !available {
		return nil, {kind = .Identity_Exhausted}
	}
	owner.epoch = epoch
	owner.metadata_bytes = size_of(Owner) + len(generation_storage) + len(lease_storage)
	success = true
	return cast(^Store)owner, {}
}

stats :: proc(store: ^Store) -> (Stats, Error) {
	if store == nil {
		return {}, {kind = .Invalid_Store}
	}
	owner := cast(^Owner)store
	sync.mutex_lock(&owner.mutex); defer sync.mutex_unlock(&owner.mutex)
	current: u64
	if owner.current >= 0 {
		current = owner.generations[owner.current].id
	}
	return {
		config = owner.config,
		closed = owner.closed,
		current_generation = current,
		generations = owner.generation_count,
		retired_generations = owner.retired_count,
		destroying_generations = owner.destroying_count,
		active_leases = owner.lease_count,
		retained_bytes = owner.retained_bytes,
		metadata_bytes = owner.metadata_bytes,
	}, {}
}

// Called under the metadata lock only. The record remains charged/unavailable
// until credentials.destroy completes outside the lock and finish_destroy clears it.
@(private)
mark_destroying :: proc(owner: ^Owner, index: int) {
	generation := &owner.generations[index]
	assert(generation.state == .Retired && generation.leases == 0)
	generation.state = .Destroying
	owner.retired_count -= 1; owner.destroying_count += 1
}
@(private)
finish_destroy :: proc(owner: ^Owner, index: int) {
	generation := &owner.generations[index]
	// No other operation can reuse/change a Destroying record.
	credential := generation.owner
	credentials.destroy(&credential)
	sync.mutex_lock(&owner.mutex)
	assert(generation.state == .Destroying && generation.leases == 0)
	owner.retained_bytes -= generation.bytes
	owner.generation_count -= 1; owner.destroying_count -= 1
	generation^ = {}
	sync.mutex_unlock(&owner.mutex)
}

// Consumes candidate only on success. Existing current/retired owners and the
// incoming candidate must fit simultaneously, including any in-flight destroys.
replace :: proc(store: ^Store, candidate: ^^credentials.Credential) -> Error {
	if store == nil {
		return {kind = .Invalid_Store}
	}
	if candidate == nil || candidate^ == nil {
		return {kind = .Invalid_Input}
	}
	owner := cast(^Owner)store
	incoming := candidate^
	usage := credentials.storage_usage(incoming)
	sync.mutex_lock(&owner.mutex)
	if owner.closed {
		sync.mutex_unlock(&owner.mutex); return {kind = .Closed}
	}
	slot := -1
	for generation, index in owner.generations {
		if generation.state != .Free && generation.owner == incoming {
			sync.mutex_unlock(&owner.mutex); return {kind = .Invalid_Input}
		}
		if generation.state == .Free && slot < 0 {
			slot = index
		}
	}
	if slot < 0 || usage.retained_bytes > owner.config.max_retained_bytes - owner.retained_bytes {
		sync.mutex_unlock(&owner.mutex); return {kind = .Capacity}
	}
	identity, available := next_local_identity(&owner.next_generation)
	if !available {
		sync.mutex_unlock(&owner.mutex); return {kind = .Identity_Exhausted}
	}
	prior := owner.current
	owner.generations[slot] = {
		owner = incoming,
		id    = identity,
		bytes = usage.retained_bytes,
		state = .Current,
	}
	owner.current = slot; owner.generation_count += 1; owner.retained_bytes += usage.retained_bytes
	candidate^ = nil
	dispose := -1
	if prior >= 0 {
		owner.generations[prior].state = .Retired; owner.retired_count += 1
		if owner.generations[prior].leases == 0 {
			mark_destroying(owner, prior); dispose = prior
		}
	}
	sync.mutex_unlock(&owner.mutex)
	if dispose >= 0 {
		finish_destroy(owner, dispose)
	}
	return {}
}

acquire :: proc(store: ^Store) -> (Lease, Error) {
	if store == nil {
		return {}, {kind = .Invalid_Store}
	}
	owner := cast(^Owner)store
	sync.mutex_lock(&owner.mutex); defer sync.mutex_unlock(&owner.mutex)
	if owner.closed {
		return {}, {kind = .Closed}
	}
	if owner.current < 0 {
		return {}, {kind = .Empty}
	}
	slot := owner.free_lease
	if slot < 0 {
		return {}, {kind = .Capacity}
	}
	identity, available := next_local_identity(&owner.next_lease)
	if !available {
		return {}, {kind = .Identity_Exhausted}
	}
	owner.free_lease = owner.leases[slot].index
	generation := &owner.generations[owner.current]
	generation.leases += 1; owner.lease_count += 1
	owner.leases[slot] = {
		id         = identity,
		generation = generation.id,
		index      = owner.current,
		active     = true,
	}
	return {_epoch = owner.epoch, _id = identity, _generation = generation.id, _slot = slot}, {}
}

@(private)
lookup_lease :: proc(owner: ^Owner, lease: Lease) -> (int, Error) {
	if lease._epoch != owner.epoch ||
	   lease._id == 0 ||
	   lease._slot < 0 ||
	   lease._slot >= len(owner.leases) {
		return -1, {kind = .Invalid_Lease}
	}
	record := owner.leases[lease._slot]
	if !record.active || record.id != lease._id || record.generation != lease._generation {
		return -1, {kind = .Invalid_Lease}
	}
	generation := &owner.generations[record.index]
	if generation.id != lease._generation ||
	   (generation.state != .Current && generation.state != .Retired) {
		return -1, {kind = .Invalid_Lease}
	}
	return record.index, {}
}

// Failure preserves the input lease (e.g. retry on its correct store). Success
// clears it before any destruction callback; an already cleared lease is a no-op.
release :: proc(store: ^Store, lease: ^Lease) -> Error {
	if lease == nil {
		return {kind = .Invalid_Input}
	}
	if lease^ == (Lease{}) {
		return {}
	}
	if store == nil {
		return {kind = .Invalid_Store}
	}
	owner := cast(^Owner)store
	sync.mutex_lock(&owner.mutex)
	index, error := lookup_lease(owner, lease^)
	if error.kind != .None {
		sync.mutex_unlock(&owner.mutex); return error
	}
	slot := lease._slot
	owner.leases[slot] = {
		index = owner.free_lease,
	}; owner.free_lease = slot
	lease^ = {}
	generation := &owner.generations[index]
	generation.leases -= 1; owner.lease_count -= 1
	dispose := generation.state == .Retired && generation.leases == 0
	if dispose {
		mark_destroying(owner, index)
	}
	sync.mutex_unlock(&owner.mutex)
	if dispose {
		finish_destroy(owner, index)
	}
	return {}
}

// Stop publication/admission. Existing leases remain usable until release.
// Closing is idempotent and may race ordinary lease operations.
close :: proc(store: ^Store) -> Error {
	if store == nil {
		return {kind = .Invalid_Store}
	}
	owner := cast(^Owner)store
	sync.mutex_lock(&owner.mutex)
	owner.closed = true
	if owner.current >= 0 {
		owner.generations[owner.current].state = .Retired; owner.retired_count += 1
		owner.current = -1
	}
	sync.mutex_unlock(&owner.mutex)
	for {
		sync.mutex_lock(&owner.mutex)
		dispose := -1
		for generation, index in owner.generations {
			if generation.state == .Retired && generation.leases == 0 {
				mark_destroying(owner, index); dispose = index; break
			}
		}
		sync.mutex_unlock(&owner.mutex)
		if dispose < 0 {
			return {}
		}
		finish_destroy(owner, dispose)
	}
}

// Host must quiesce API calls before destruction. Busy preserves the store and
// its open/closed state. close is a separate explicit admission decision.
destroy :: proc(store: ^^Store) -> Error {
	if store == nil {
		return {kind = .Invalid_Input}
	}
	if store^ == nil {
		return {}
	}
	owner := cast(^Owner)store^
	sync.mutex_lock(&owner.mutex)
	busy := owner.lease_count > 0 || owner.destroying_count > 0
	sync.mutex_unlock(&owner.mutex)
	if busy {
		return {kind = .Busy}
	}
	if error := close(store^); error.kind != .None {
		return error
	}
	assert(owner.generation_count == 0)
	allocator := owner.allocator
	generations := owner.generations; leases := owner.leases
	store^ = nil
	wipe_free(allocator, mem.slice_data_cast([]u8, generations), align_of(Generation))
	wipe_free(allocator, mem.slice_data_cast([]u8, leases), align_of(Lease_Record))
	wipe_free(allocator, (cast([^]u8)owner)[:size_of(Owner)], align_of(Owner))
	return {}
}

// Internal borrow only: caller keeps this owning Lease live through the entire
// forwarded call and every returned DER borrow. No owning pointer is published.
@(private)
borrow :: proc(store: ^Store, lease: Lease) -> (^credentials.Credential, Error) {
	if store == nil {
		return nil, {kind = .Invalid_Store}
	}
	owner := cast(^Owner)store
	sync.mutex_lock(&owner.mutex); defer sync.mutex_unlock(&owner.mutex)
	index, error := lookup_lease(owner, lease)
	if error.kind != .None {
		return nil, error
	}
	return owner.generations[index].owner, {}
}
certificate_count :: proc(store: ^Store, lease: Lease) -> (int, Error) {
	credential, error := borrow(store, lease)
	if error.kind != .None {
		return 0, error
	}
	return credentials.certificate_count(credential), {}
}
certificate_der :: proc(store: ^Store, lease: Lease, index: int) -> ([]u8, Error) {
	credential, error := borrow(store, lease)
	if error.kind != .None {
		return nil, error
	}
	data, cause := credentials.certificate_der(credential, index)
	return data,
		Error{} if cause == .None else Error{kind = .Credential_Failed, credential = cause}
}
fingerprint :: proc(store: ^Store, lease: Lease) -> ([32]u8, Error) {
	credential, error := borrow(store, lease)
	if error.kind != .None {
		return {}, error
	}
	digest, cause := credentials.fingerprint(credential)
	return digest,
		Error{} if cause == .None else Error{kind = .Credential_Failed, credential = cause}
}
check_server_leaf :: proc(store: ^Store, lease: Lease, now: time.Time) -> Error {
	credential, error := borrow(store, lease)
	if error.kind != .None {
		return error
	}
	cause := credentials.check_server_leaf(credential, now)
	return {} if cause == .None else Error{kind = .Credential_Failed, credential = cause}
}
sign_digest_pss_sha256 :: proc(
	store: ^Store,
	lease: Lease,
	digest: [32]u8,
	out: []u8,
) -> (
	int,
	Error,
) {
	credential, error := borrow(store, lease)
	if error.kind != .None {
		return 0, error
	}
	n, cause := credentials.sign_digest_pss_sha256(credential, digest, out)
	return n, Error{} if cause == .None else Error{kind = .Credential_Failed, credential = cause}
}

certificate_algorithms :: proc(store: ^Store, lease: Lease, index: int) -> (credentials.Certificate_Algorithms, Error) {
	credential, error := borrow(store, lease)
	if error.kind != .None {return {}, error}
	metadata, cause := credentials.certificate_algorithms(credential, index)
	return metadata, Error{} if cause == .None else Error{kind=.Credential_Failed, credential=cause}
}
