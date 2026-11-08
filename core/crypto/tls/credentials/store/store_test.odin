package store

import credentials ".."
import "base:intrinsics"
import "core:crypto/hash"
import "core:fmt"
import "core:mem"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

fixture_key :: #load("../../../../../tests/core/crypto/tls/credentials/testdata/rsa2048.pem")
fixture_cert :: #load(
	"../../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-valid.pem",
)

make_credential :: proc(allocator := context.allocator) -> ^credentials.Credential {
	credential, error := credentials.create(fixture_cert, fixture_key, {}, allocator)
	assert(error == .None)
	return credential
}
make_store :: proc(config: Config = {}, allocator := context.allocator) -> ^Store {
	store, error := create(config, allocator); assert(error.kind == .None)
	return store
}

@(test)
store_rotation_keeps_lease_borrows_and_signatures_until_release :: proc(t: ^testing.T) {
	store := make_store(); defer destroy(&store)
	first := make_credential()
	assert(replace(store, &first).kind == .None && first == nil)
	old, e := acquire(store); assert(e.kind == .None)
	der, de := certificate_der(store, old, 0); assert(de.kind == .None)
	before, fe := fingerprint(store, old); assert(fe.kind == .None)
	second, second_error := credentials.create(
		#load("../../../../../tests/core/crypto/tls/credentials/testdata/rsa4096-valid.pem"),
		#load("../../../../../tests/core/crypto/tls/credentials/testdata/rsa4096.pem"),
		{},
		context.allocator,
	)
	assert(second_error == .None)
	assert(replace(store, &second).kind == .None && second == nil)
	snapshot, _ := stats(store)
	testing.expect_value(t, snapshot.generations, 2)
	testing.expect_value(t, snapshot.retired_generations, 1)
	testing.expect_value(t, snapshot.active_leases, 1)
	digest: [32]u8; hash.hash_string_to_buffer(.SHA256, "leased credential", digest[:])
	output: [512]u8
	n, se := sign_digest_pss_sha256(store, old, digest, output[:])
	testing.expect(t, se.kind == .None && n == 256)
	after: [32]u8; hash.hash_bytes_to_buffer(.SHA256, der, after[:])
	testing.expect_value(t, before, after)
	testing.expect_value(
		t,
		check_server_leaf(store, old, time.from_nanoseconds(1790000000 * 1000000000)).kind,
		.None,
	)
	newer, ne := acquire(store); assert(ne.kind == .None)
	testing.expect(t, newer._generation != old._generation)
	newer_n, newer_sign := sign_digest_pss_sha256(store, newer, digest, output[:])
	testing.expect(t, newer_sign.kind == .None && newer_n == 512)
	_, bad_index := certificate_der(store, old, 1)
	testing.expect(
		t,
		bad_index.kind == .Credential_Failed && bad_index.credential == .Invalid_Index,
	)
	_, too_small := sign_digest_pss_sha256(store, old, digest, output[:1])
	testing.expect(
		t,
		too_small.kind == .Credential_Failed && too_small.credential == .Output_Too_Small,
	)
	early := check_server_leaf(store, old, time.from_nanoseconds(min(i64)))
	testing.expect(t, early.kind == .Credential_Failed && early.credential == .Not_Yet_Valid)
	testing.expect_value(t, destroy(&store).kind, .Busy)
	still_open, _ := stats(store); testing.expect(t, !still_open.closed)
	assert(release(store, &old).kind == .None)
	snapshot, _ = stats(store); testing.expect_value(t, snapshot.generations, 1)
	testing.expect_value(t, close(store).kind, .None)
	_, closed := acquire(store); testing.expect_value(t, closed.kind, .Closed)
	count, count_error := certificate_count(store, newer)
	testing.expect(t, count_error.kind == .None && count == 1)
	testing.expect_value(t, release(store, &newer).kind, .None)
	testing.expect_value(t, release(store, &newer).kind, .None)
	snapshot, _ = stats(store)
	testing.expect(t, snapshot.closed && snapshot.generations == 0 && snapshot.retained_bytes == 0)
	testing.expect_value(t, destroy(&store).kind, .None)
	testing.expect(t, store == nil)
	testing.expect_value(t, destroy(&store).kind, .None)
}

@(test)
store_capacity_and_foreign_stale_handles_preserve_owners :: proc(t: ^testing.T) {
	store := make_store({max_generations = 2, max_leases = 1}); defer destroy(&store)
	other := make_store(); defer destroy(&other)
	first := make_credential(); assert(replace(store, &first).kind == .None)
	old, _ := acquire(store); stale := old
	_, full := acquire(store); testing.expect_value(t, full.kind, .Capacity)
	testing.expect_value(t, release(other, &old).kind, .Invalid_Lease)
	testing.expect_value(t, old, stale)
	candidate := make_credential(); assert(replace(store, &candidate).kind == .None)
	blocked := make_credential(); defer credentials.destroy(&blocked)
	original := blocked
	before, _ := stats(store)
	testing.expect_value(t, replace(store, &blocked).kind, .Capacity)
	testing.expect_value(t, blocked, original)
	after, _ := stats(store); testing.expect_value(t, before, after)
	assert(release(store, &old).kind == .None)
	current, _ := acquire(store)
	testing.expect_value(t, current._slot, stale._slot)
	testing.expect(t, current._id != stale._id)
	testing.expect_value(t, release(store, &stale).kind, .Invalid_Lease)
	forged := current; forged._generation += 1
	_, wrong := certificate_der(store, forged, 0)
	testing.expect_value(t, wrong.kind, .Invalid_Lease)
	assert(release(store, &current).kind == .None)
	// A zero-lease generation also requires overlap headroom until destruction.
	one := make_store({max_generations = 1}); defer destroy(&one)
	first = make_credential(); assert(replace(one, &first).kind == .None)
	testing.expect_value(t, replace(one, &blocked).kind, .Capacity)
	testing.expect_value(t, blocked, original)
	tiny := make_store({max_retained_bytes = 1}); defer destroy(&tiny)
	testing.expect_value(t, replace(tiny, &blocked).kind, .Capacity)
	testing.expect_value(t, blocked, original)
	assert(close(store).kind == .None)
	testing.expect_value(t, replace(store, &blocked).kind, .Closed)
	testing.expect_value(t, blocked, original)
}

@(test)
store_identity_exhaustion_does_not_wrap_into_live_aliases :: proc(t: ^testing.T) {
	isolated := max(u64) - 1
	final, ok := next_identity(&isolated)
	testing.expect(t, ok && final == max(u64))
	exhausted, no := next_identity(&isolated)
	testing.expect(t, !no && exhausted == 0 && isolated == max(u64))
	store := make_store(); defer destroy(&store)
	owner := cast(^Owner)store
	owner.next_generation = max(u64) - 1
	first := make_credential(); assert(replace(store, &first).kind == .None)
	owner.next_lease = max(u64) - 1
	lease, e := acquire(store); assert(e.kind == .None)
	testing.expect_value(t, lease._id, max(u64))
	assert(release(store, &lease).kind == .None)
	_, le := acquire(store); testing.expect_value(t, le.kind, .Identity_Exhausted)
	candidate := make_credential(); defer credentials.destroy(&candidate)
	before, _ := stats(store)
	testing.expect_value(t, replace(store, &candidate).kind, .Identity_Exhausted)
	after, _ := stats(store); testing.expect_value(t, before, after)
	testing.expect(t, candidate != nil)
}

Audit_Mode :: enum {
	Normal,
	OOM,
	Nil_Success,
	Undergrant,
	Overgrant,
	Error_Grant,
}
Grant :: struct {
	pointer:         rawptr,
	size, alignment: int,
	freeing:         bool,
}
Audit :: struct {
	mutex:                                                                             sync.Mutex,
	backing:                                                                           mem.Allocator,
	grants:                                                                            [256]Grant,
	mode:                                                                              Audit_Mode,
	fail_at, calls, live, peak, dirty_frees, bad_frees, lock_violations, observations: int,
	store_ref:                                                                         ^^Store,
	block_next_free, blocked:                                                          bool,
	entered, proceed:                                                                  sync.Sema,
}
audit_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	a := cast(^Audit)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
		sync.mutex_lock(&a.mutex)
		a.calls += 1; failing := a.calls == a.fail_at
		kind := a.mode
		sync.mutex_unlock(&a.mutex)
		if failing && kind == .OOM {
			return nil, .Out_Of_Memory
		}
		if failing && kind == .Nil_Success {
			return nil, .None
		}
		requested := size
		if failing && kind == .Undergrant {
			requested = max(size - 1, 0)
		}
		if failing && kind == .Overgrant {
			requested = size + 7
		}
		result, error := a.backing.procedure(
			a.backing.data,
			.Alloc,
			requested,
			alignment,
			nil,
			0,
			loc,
		)
		if error != nil {
			return result, error
		}
		if raw_data(result) != nil {
			sync.mutex_lock(&a.mutex)
			stored := false
			for &grant in a.grants {
				if grant.pointer == nil {
					grant = {
						pointer   = raw_data(result),
						size      = len(result),
						alignment = alignment,
					}; stored = true; break
				}
			}
			assert(stored)
			for &b in result {b = 0xa5}
			a.live += len(result); a.peak = max(a.peak, a.live)
			sync.mutex_unlock(&a.mutex)
		}
		if failing && kind == .Error_Grant {
			return result, .Out_Of_Memory
		}
		return result, .None
	}
	if mode == .Free && old != nil {
		sync.mutex_lock(&a.mutex)
		slot := -1
		for grant, index in a.grants {
			if grant.pointer == old && !grant.freeing {
				slot = index; break
			}
		}
		assert(slot >= 0)
		grant := a.grants[slot]
		// A concurrent allocation may reuse this address after the backing free
		// returns but before our final bookkeeping lock. Do not mistake that new
		// owner's subsequent free for this still-finishing record.
		a.grants[slot].freeing = true
		if grant.size != old_size || grant.alignment != alignment {
			a.bad_frees += 1
		}
		for b in (cast([^]u8)old)[:grant.size] {
			if b != 0 {
				a.dirty_frees += 1; break
			}
		}
		watching := a.store_ref != nil && a.store_ref^ != nil
		store: ^Store
		if watching {
			store = a.store_ref^
		}
		block := a.block_next_free && !a.blocked
		if block {
			a.blocked = true
		}
		sync.mutex_unlock(&a.mutex)
		if watching {
			owner := cast(^Owner)store
			if sync.mutex_try_lock(&owner.mutex) {
				sync.mutex_unlock(&owner.mutex)
				snapshot, error := stats(store)
				assert(error.kind == .None && snapshot.destroying_generations > 0)
				sync.mutex_lock(&a.mutex); a.observations += 1; sync.mutex_unlock(&a.mutex)
			} else {
				sync.mutex_lock(&a.mutex); a.lock_violations += 1; sync.mutex_unlock(&a.mutex)
			}
		}
		if block {
			sync.sema_post(&a.entered); sync.sema_wait(&a.proceed)
		}
		result, error := a.backing.procedure(
			a.backing.data,
			.Free,
			0,
			grant.alignment,
			old,
			grant.size,
			loc,
		)
		sync.mutex_lock(&a.mutex)
		a.live -= grant.size; a.grants[slot] = {}
		sync.mutex_unlock(&a.mutex)
		return result, error
	}
	return a.backing.procedure(a.backing.data, mode, size, alignment, old, old_size, loc)
}
audit_allocator :: proc(a: ^Audit) -> mem.Allocator {return {audit_proc, a}}
audit_clean :: proc(t: ^testing.T, a: ^Audit) {
	testing.expect_value(t, a.live, 0)
	testing.expect_value(t, a.dirty_frees, 0)
	testing.expect_value(t, a.bad_frees, 0)
	testing.expect_value(t, a.lock_violations, 0)
}

@(test)
store_metadata_allocation_failures_clean_every_grant :: proc(t: ^testing.T) {
	for mode in Audit_Mode {
		if mode == .Normal {
			continue
		}
		for position in 1 ..= 3 {
			audit := Audit {
				backing = context.allocator,
				mode    = mode,
				fail_at = position,
			}
			store, error := create({}, audit_allocator(&audit))
			testing.expect(t, store == nil && error.kind == .Allocation_Failed)
			audit_clean(t, &audit)
		}
	}
	audit := Audit {
		backing = context.allocator,
	}
	store := make_store({}, audit_allocator(&audit))
	snapshot, _ := stats(store)
	testing.expect_value(t, snapshot.metadata_bytes, audit.live)
	_, empty := acquire(store); testing.expect_value(t, empty.kind, .Empty)
	credential := make_credential(); assert(replace(store, &credential).kind == .None)
	allocations := audit.calls
	for _ in 0 ..< 256 {
		lease, error := acquire(store); assert(error.kind == .None)
		assert(release(store, &lease).kind == .None)
	}
	testing.expect_value(t, audit.calls, allocations)
	fmt.printfln(
		"STORE owner_bytes=%d generation_bytes=%d lease_record_bytes=%d lease_bytes=%d metadata_bytes=%d",
		size_of(Owner),
		size_of(Generation),
		size_of(Lease_Record),
		size_of(Lease),
		snapshot.metadata_bytes,
	)
	assert(destroy(&store).kind == .None); audit_clean(t, &audit)
	for config in ([]Config {
			{max_generations = -1},
			{max_leases = -1},
			{max_retained_bytes = -1},
			{max_generations = max(int)},
			{max_leases = max(int)},
		}) {
		invalid, error := create(config, context.allocator)
		testing.expect(t, invalid == nil && error.kind == .Invalid_Config)
	}
}

@(test)
store_retirement_callbacks_run_unlocked_and_erase_owned_storage :: proc(t: ^testing.T) {
	audit := Audit {
		backing = context.allocator,
	}
	store := make_store()
	first := make_credential(audit_allocator(&audit))
	assert(replace(store, &first).kind == .None)
	lease, _ := acquire(store)
	second := make_credential(audit_allocator(&audit)); audit.store_ref = &store
	assert(replace(store, &second).kind == .None)
	testing.expect_value(t, audit.observations, 0)
	assert(release(store, &lease).kind == .None)
	testing.expect(t, audit.observations > 0)
	assert(destroy(&store).kind == .None)
	audit_clean(t, &audit)
}

@(test)
store_destroying_generation_stays_charged_until_free_completes :: proc(t: ^testing.T) {
	for maximum in ([?]int{2, 3}) {
		audit := Audit {
			backing = context.allocator,
		}
		first := make_credential(audit_allocator(&audit))
		bytes := credentials.storage_usage(first).retained_bytes
		second := make_credential(audit_allocator(&audit))
		candidate := make_credential(); defer credentials.destroy(&candidate)
		store := make_store({max_generations = maximum, max_retained_bytes = 2 * bytes})
		audit.store_ref = &store
		assert(replace(store, &first).kind == .None)
		lease, _ := acquire(store)
		assert(replace(store, &second).kind == .None)
		audit.block_next_free = true
		work := struct {
			store: ^Store,
			lease: Lease,
			error: Error,
		}{store, lease, {}}
		lease = {}
		worker := thread.create_and_start_with_poly_data(&work, proc(w: ^struct {
				store: ^Store,
				lease: Lease,
				error: Error,
			}) {w.error = release(w.store, &w.lease)})
		assert(worker != nil)
		assert(sync.sema_wait_with_timeout(&audit.entered, 5 * time.Second))
		snapshot, _ := stats(store)
		testing.expect_value(t, snapshot.destroying_generations, 1)
		testing.expect_value(t, snapshot.generations, 2)
		testing.expect_value(t, snapshot.retained_bytes, 2 * bytes)
		testing.expect_value(t, destroy(&store).kind, .Busy)
		preserved := candidate
		testing.expect_value(t, replace(store, &candidate).kind, .Capacity)
		testing.expect_value(t, candidate, preserved)
		current, error := acquire(store); testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, release(store, &current).kind, .None)
		sync.sema_post(&audit.proceed)
		thread.join(worker); thread.destroy(worker)
		testing.expect_value(t, work.error.kind, .None)
		snapshot, _ = stats(store)
		testing.expect_value(t, snapshot.retained_bytes, bytes)
		testing.expect_value(t, snapshot.destroying_generations, 0)
		assert(replace(store, &candidate).kind == .None && candidate == nil)
		assert(destroy(&store).kind == .None)
		audit_clean(t, &audit)
	}
}

Epoch_Work :: struct {
	counter: ^u64,
	ids:     [32]u64,
}
epoch_worker :: proc(work: ^Epoch_Work) {
	for &id in work.ids {id, _ = next_identity(work.counter)}
}
@(test)
store_epoch_counter_saturates_under_concurrent_allocation :: proc(t: ^testing.T) {
	counter := max(u64) - 100
	work: [4]Epoch_Work
	threads: [4]^thread.Thread
	for &job, index in work {
		job.counter = &counter
		threads[index] = thread.create_and_start_with_poly_data(&job, epoch_worker)
		assert(threads[index] != nil)
	}
	for worker in threads {thread.join(worker); thread.destroy(worker)}
	seen: [100]bool
	count := 0
	for job in work {
		for id in job.ids {
			if id == 0 {
				continue
			}
			offset := int(id - (max(u64) - 99))
			testing.expect(t, offset >= 0 && offset < 100)
			testing.expect(t, !seen[offset]); seen[offset] = true; count += 1
		}
	}
	testing.expect_value(t, count, 100)
	testing.expect_value(t, counter, max(u64))
}

Race_Work :: struct {
	store:               ^Store,
	start, held, finish: ^sync.Sema,
	successes, failures: int,
}
race_reader :: proc(work: ^Race_Work) {
	sync.sema_wait(work.start)
	digest: [32]u8; hash.hash_string_to_buffer(.SHA256, "racing lease", digest[:])
	for attempt in 0 ..< 128 {
		lease, error := acquire(work.store)
		if error.kind == .Closed {
			return
		}
		if error.kind == .Capacity {
			continue
		}
		if error.kind != .None {
			work.failures += 1; return
		}
		der, de := certificate_der(work.store, lease, 0)
		fingerprint, fe := fingerprint(work.store, lease)
		if de.kind != .None || fe.kind != .None {
			work.failures += 1
		} else {
			actual: [32]u8; hash.hash_bytes_to_buffer(.SHA256, der, actual[:])
			if actual != fingerprint {
				work.failures += 1
			}
		}
		if attempt % 16 == 0 {
			output: [512]u8
			n, se := sign_digest_pss_sha256(work.store, lease, digest, output[:])
			if se.kind != .None || n != 256 {
				work.failures += 1
			}
		}
		time.sleep(200 * time.Microsecond)
		if release(work.store, &lease).kind != .None {
			work.failures += 1
		}
		work.successes += 1
	}
	// Keep eight distinct pins live while close races half the final readers;
	// the other half resumes only after close has completed.
	final, error := acquire(work.store)
	assert(error.kind == .None)
	sync.sema_post(work.held)
	sync.sema_wait(work.finish)
	der, de := certificate_der(work.store, final, 0)
	expected, fe := fingerprint(work.store, final)
	actual: [32]u8; hash.hash_bytes_to_buffer(.SHA256, der, actual[:])
	if de.kind != .None || fe.kind != .None || actual != expected {
		work.failures += 1
	}
	if release(work.store, &final).kind != .None {
		work.failures += 1
	}
	work.successes += 1
}
@(test)
store_races_distinct_leases_rotation_and_close_with_bounded_storage :: proc(t: ^testing.T) {
	audit := Audit {
		backing = context.allocator,
	}
	store := make_store({max_generations = 4, max_leases = 16}, audit_allocator(&audit))
	first := make_credential(audit_allocator(&audit)); assert(replace(store, &first).kind == .None)
	start, held, racing_finish, closed_finish: sync.Sema
	work: [8]Race_Work
	threads: [8]^thread.Thread
	for &job, index in work {
		job.store = store; job.start = &start; job.held = &held
		job.finish = &racing_finish if index % 2 == 0 else &closed_finish
		threads[index] = thread.create_and_start_with_poly_data(&job, race_reader)
		assert(threads[index] != nil)
	}
	sync.sema_post(&start, len(work))
	accepted := 0
	for _ in 0 ..< 16 {
		candidate := make_credential(audit_allocator(&audit))
		error := replace(store, &candidate)
		testing.expect(t, error.kind == .None || error.kind == .Capacity)
		if error.kind == .None {
			accepted += 1
		}
		credentials.destroy(&candidate)
		snapshot, _ := stats(store)
		testing.expect(
			t,
			snapshot.generations <= 4 &&
			snapshot.active_leases <= 16 &&
			snapshot.retained_bytes <= snapshot.config.max_retained_bytes,
		)
	}
	for _ in 0 ..< len(work) {assert(sync.sema_wait_with_timeout(&held, 5 * time.Second))}
	pinned, _ := stats(store); testing.expect_value(t, pinned.active_leases, len(work))
	sync.sema_post(&racing_finish, len(work) / 2)
	assert(close(store).kind == .None)
	sync.sema_post(&closed_finish, len(work) / 2)
	for worker in threads {thread.join(worker); thread.destroy(worker)}
	total := 0
	for job in work {testing.expect_value(t, job.failures, 0); total += job.successes}
	testing.expect(t, total > 0 && accepted > 0)
	snapshot, _ := stats(store)
	testing.expect(
		t,
		snapshot.closed &&
		snapshot.generations == 0 &&
		snapshot.active_leases == 0 &&
		snapshot.retained_bytes == 0,
	)
	assert(destroy(&store).kind == .None)
	audit_clean(t, &audit)
	fmt.printfln(
		"STORE race rotations=%d lease_cycles=%d zero_retained_bytes=true",
		accepted,
		total,
	)
}

@(test)
store_typed_algorithms_survive_cross_algorithm_rotation_and_close :: proc(t:^testing.T) {
	store:=make_store();defer destroy(&store)
	ec,e:=credentials.create(#load("../../../../../tests/core/crypto/tls/credentials/testdata/p256-valid.pem"),#load("../../../../../tests/core/crypto/tls/credentials/testdata/p256.pem"),{},context.allocator);assert(e==.None)
	assert(replace(store,&ec).kind==.None && ec==nil)
	old,ae:=acquire(store);assert(ae.kind==.None)
	scheme,se:=signature_scheme(store,old);testing.expect_value(t,se.kind,.None);testing.expect_value(t,scheme,.ECDSA_SECP256R1_SHA256)
	before,_:=fingerprint(store,old)
	rsa:=make_credential();assert(replace(store,&rsa).kind==.None)
	newer,ne:=acquire(store);assert(ne.kind==.None)
	rs,re:=signature_scheme(store,newer);testing.expect_value(t,re.kind,.None);testing.expect_value(t,rs,.RSA_PSS_RSAE_SHA256)
	assert(close(store).kind==.None)
	out:[512]u8
	for lease in ([]Lease{old,newer}) {
		sc,ce:=signature_scheme(store,lease);testing.expect_value(t,ce.kind,.None)
		n,sign_error:=sign_sha256(store,lease,sc,[]u8{1,2,3},out[:]);testing.expect_value(t,sign_error.kind,.None);testing.expect(t,n>0)
	}
	after,_:=fingerprint(store,old);testing.expect_value(t,before,after)
	_,wrong:=sign_sha256(store,old,.RSA_PSS_RSAE_SHA256,[]u8{1},out[:]);testing.expect_value(t,wrong.credential,.Unsupported_Signature_Scheme)
	stale:=old;assert(release(store,&old).kind==.None);assert(release(store,&newer).kind==.None)
	_,stale_error:=signature_scheme(store,stale);testing.expect(t,stale_error.kind!=.None)
	for &b in out {b=0xa5}
	_,stale_sign:=sign_sha256(store,stale,.ECDSA_SECP256R1_SHA256,[]u8{1},out[:]);testing.expect(t,stale_sign.kind!=.None)
	for b in out {testing.expect_value(t,b,u8(0xa5))}
	stats,_:=stats(store);testing.expect_value(t,stats.generations,0);testing.expect_value(t,stats.active_leases,0)
}

@(test)
store_pss_parameters_follow_pinned_generation_without_borrows :: proc(t:^testing.T) {
	store:=make_store();defer destroy(&store)
	pss,e:=credentials.create(#load("../../../../../tests/core/crypto/tls/credentials/testdata/pss-rsa-chain.pem"),fixture_key,{},context.allocator);assert(e==.None)
	assert(replace(store,&pss).kind==.None)
	lease,le:=acquire(store);assert(le.kind==.None)
	metadata,me:=certificate_pss_parameters(store,lease,0);testing.expect_value(t,me.kind,.None);testing.expect_value(t,metadata,credentials.Certificate_PSS_Parameters{.SHA256,.SHA256,32})
	next:=make_credential();assert(replace(store,&next).kind==.None)
	newer,ne:=acquire(store);assert(ne.kind==.None)
	_,not_pss:=certificate_pss_parameters(store,newer,0);testing.expect_value(t,not_pss.credential,.Unsupported_Signature_Scheme)
	assert(close(store).kind==.None)
	again,ae:=certificate_pss_parameters(store,lease,0);testing.expect_value(t,ae.kind,.None);testing.expect_value(t,again,metadata)
	_,invalid:=certificate_pss_parameters(store,lease,2);testing.expect_value(t,invalid.credential,.Invalid_Index)
	stale:=lease;assert(release(store,&lease).kind==.None);assert(release(store,&newer).kind==.None)
	_,gone:=certificate_pss_parameters(store,stale,0);testing.expect(t,gone.kind!=.None)
	stats,_:=stats(store);testing.expect_value(t,stats.active_leases,0);testing.expect_value(t,stats.generations,0)
}
