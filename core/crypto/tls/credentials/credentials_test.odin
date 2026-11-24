package credentials

import "core:bytes"
import "core:crypto/hash"
import "core:crypto/rsa"
import "core:fmt"
import "core:mem"
import "core:slice"
import "core:strings"
import "core:testing"
import "core:time"

fixture_key :: #load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048.pem")
fixture_pkcs1 :: #load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-pkcs1.pem")
fixture_cert :: #load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-valid.pem")

Audit_Mode :: enum {
	Normal,
	OOM,
	Nil_Success,
	Undergrant,
	Overgrant,
	Error_Grant,
}

Audit :: struct {
	backing:                                            mem.Allocator,
	mode:                                               Audit_Mode,
	fail_at, calls, live, peak, dirty_frees, bad_frees: int,
	grants:                                             [128]Allocation,
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
		a.calls += 1
		failing := a.calls == a.fail_at
		if failing && a.mode == .OOM {
			return nil, .Out_Of_Memory
		}
		if failing && a.mode == .Nil_Success {
			return nil, .None
		}
		granted := size
		if failing && a.mode == .Undergrant {
			granted = max(size - 1, 0)
		}
		if failing && a.mode == .Overgrant {
			granted = size + 7
		}
		out, error := a.backing.procedure(a.backing.data, .Alloc, granted, alignment, nil, 0, loc)
		if error != nil {
			return out, error
		}
		if raw_data(out) != nil {
			for &record in a.grants {
				if record.pointer == nil {
					record = {raw_data(out), len(out), alignment}
					break
				}
			}
			for &b in out {b = 0xa5}
			a.live += len(out)
			a.peak = max(a.peak, a.live)
		}
		if failing && a.mode == .Error_Grant {
			return out, .Out_Of_Memory
		}
		return out, .None
	}
	if mode == .Free && old != nil {
		for &record in a.grants {
			if record.pointer == old {
				if old_size != record.size || alignment != record.alignment {
					a.bad_frees += 1
				}
				for b in (cast([^]u8)old)[:record.size] {
					if b != 0 {
						a.dirty_frees += 1
						break
					}
				}
				a.live -= record.size
				result, error := a.backing.procedure(a.backing.data, .Free, 0, record.alignment, old, record.size, loc)
				record = {}
				return result, error
			}
		}
		a.bad_frees += 1
		return nil, .Invalid_Pointer
	}
	return a.backing.procedure(a.backing.data, mode, size, alignment, old, old_size, loc)
}

audit_allocator :: proc(a: ^Audit) -> mem.Allocator {return {audit_proc, a}}

audit_clean :: proc(t: ^testing.T, a: ^Audit) {
	testing.expect_value(t, a.live, 0)
	testing.expect_value(t, a.dirty_frees, 0)
	testing.expect_value(t, a.bad_frees, 0)
}

@(test)
credential_construction_owns_inputs_and_matches_key :: proc(t: ^testing.T) {
	chain := slice.clone(fixture_cert) or_else panic("fixture allocation")
	defer delete(chain)
	key := slice.clone(fixture_key) or_else panic("fixture allocation")
	defer delete(key)
	a := Audit {
		backing = context.allocator,
	}
	handle, error := create(chain, key, {}, audit_allocator(&a))
	assert(error == .None)
	testing.expect_value(t, certificate_count(handle), 1)
	der, de := certificate_der(handle, 0)
	assert(de == .None)
	expected: [32]u8
	hash.hash_bytes_to_buffer(.SHA256, der, expected[:])
	actual, fe := fingerprint(handle)
	testing.expect(t, fe == .None && actual == expected)
	for &b in chain {b = 0}
	for &b in key {b = 0}
	after, _ := fingerprint(handle)
	testing.expect_value(t, after, expected)
	usage := storage_usage(handle)
	testing.expect_value(t, usage.retained_bytes, a.live)
	testing.expect_value(t, usage.peak_bytes, a.peak)
	fmt.printfln(
		"CREDENTIAL owner_bytes=%d retained_bytes=%d peak_bytes=%d allocations=%d",
		size_of(Owner),
		a.live,
		a.peak,
		a.calls,
	)
	destroy(&handle)
	destroy(&handle)
	testing.expect(t, handle == nil)
	audit_clean(t, &a)
	pkcs1, e := create(fixture_cert, fixture_pkcs1, {}, context.allocator)
	testing.expect_value(t, e, .None)
	destroy(&pkcs1)
}

@(test)
credential_every_allocation_failure_erases_full_grants :: proc(t: ^testing.T) {
	baseline := Audit {
		backing = context.allocator,
	}
	h, e := create(fixture_cert, fixture_key, {}, audit_allocator(&baseline))
	assert(e == .None)
	destroy(&h)
	audit_clean(t, &baseline)
	for mode in Audit_Mode {
		if mode == .Normal {
			continue
		}
		for fail_at in 1 ..= baseline.calls {
			a := Audit {
				backing = context.allocator,
				mode    = mode,
				fail_at = fail_at,
			}
			owner, error := create(fixture_cert, fixture_key, {}, audit_allocator(&a))
			testing.expect(
				t,
				owner == nil && error == .Allocation_Failed,
				fmt.tprintf("mode=%v allocation=%d error=%v", mode, fail_at, error),
			)
			destroy(&owner)
			audit_clean(t, &a)
		}
	}
}

@(test)
credential_storage_and_input_limits_are_independent :: proc(t: ^testing.T) {
	a := Audit {
		backing = context.allocator,
	}
	h, e := create(fixture_cert, fixture_key, {}, audit_allocator(&a))
	assert(e == .None)
	peak := storage_usage(h).peak_bytes
	destroy(&h)
	exact, ee := create(fixture_cert, fixture_key, {max_storage_bytes = peak}, context.allocator)
	testing.expect_value(t, ee, .None)
	destroy(&exact)
	below, be := create(fixture_cert, fixture_key, {max_storage_bytes = peak - 1}, context.allocator)
	testing.expect(t, below == nil && be == .Storage_Limit)
	for limit in ([]Limits {
			{max_storage_bytes = size_of(Owner) - 1},
			{max_der_bytes = 1},
			{max_chain_pem_bytes = 1},
			{max_key_pem_bytes = 1},
			{max_certificates = -1},
			{max_storage_bytes = (4 << 20) + 1},
		}) {
		owner, error := create(fixture_cert, fixture_key, limit, context.allocator)
		testing.expect(t, owner == nil && error != .None)
		destroy(&owner)
	}
	builder: strings.Builder
	defer strings.builder_destroy(&builder)
	for _ in 0 ..< 16 {strings.write_string(&builder, string(fixture_cert))}
	full, full_error := create(transmute([]u8)strings.to_string(builder), fixture_key, {}, context.allocator)
	testing.expect_value(t, full_error, .None)
	testing.expect_value(t, certificate_count(full), 16)
	destroy(&full)
	strings.write_string(&builder, string(fixture_cert))
	many, me := create(transmute([]u8)strings.to_string(builder), fixture_key, {}, context.allocator)
	testing.expect(t, many == nil && me == .Input_Limit)
	destroy(&many)
}

@(test)
credential_malformed_wrong_and_unsupported_keys_fail_closed :: proc(t: ^testing.T) {
	for c in ([]struct {
			chain, key: []u8,
			want:       Error,
		} {
			{fixture_cert, #load("../../../../tests/core/crypto/tls/credentials/testdata/rsa4096.pem"), .Key_Mismatch},
			{
				#load("../../../../tests/core/crypto/tls/credentials/testdata/rsa1024-valid.pem"),
				#load("../../../../tests/core/crypto/tls/credentials/testdata/rsa1024.pem"),
				.Unsupported_Key,
			},
			{transmute([]u8)string("garbage"), fixture_key, .Malformed_PEM},
			{fixture_cert, transmute([]u8)string("garbage"), .Malformed_PEM},
			{
				fixture_cert,
				transmute([]u8)string(
					"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n",
				),
				.Unsupported_Key,
			},
			{
				transmute([]u8)string("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"),
				fixture_key,
				.Malformed_Certificate,
			},
		}) {
		a := Audit {
			backing = context.allocator,
		}
		handle, error := create(c.chain, c.key, {}, audit_allocator(&a))
		testing.expect(t, handle == nil)
		testing.expect_value(t, error, c.want)
		destroy(&handle)
		audit_clean(t, &a)
	}
	for suffix in ([]string{"trailing", string(fixture_key)}) {
		text := fmt.aprintf("%s%s", string(fixture_key), suffix)
		defer delete(text)
		h, e := create(fixture_cert, transmute([]u8)text, {}, context.allocator)
		testing.expect(t, h == nil && e == .Malformed_PEM)
		destroy(&h)
	}
	// The shared native decoder must not skip a malformed first block and let
	// later valid material turn the complete input into an accepted credential.
	for first in ([]string {
			"-----BEGIN PRIVATE KEY-----\nAA==\n",
			"-----BEGIN PRIVATE KEY-----\n",
			"-----BEGIN PRIVATE KEY-----\nAA==\n-----END CERTIFICATE-----\n",
			"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
			"-----BEGIN PRIVATE KEY-----garbage\n",
		}) {
		text := fmt.aprintf("%s%s", first, string(fixture_key))
		defer delete(text)
		owner, error := create(fixture_cert, transmute([]u8)text, {}, context.allocator)
		testing.expect(t, owner == nil && error != .None)
		destroy(&owner)
	}
	for first in ([]string {
			"-----BEGIN CERTIFICATE-----\nAA==\n",
			"-----BEGIN CERTIFICATE-----\n",
			"-----BEGIN CERTIFICATE-----\nAA==\n-----END PRIVATE KEY-----\n",
			"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
			"-----BEGIN CERTIFICATE-----garbage\n",
		}) {
		text := fmt.aprintf("%s%s", first, string(fixture_cert))
		defer delete(text)
		owner, error := create(transmute([]u8)text, fixture_key, {}, context.allocator)
		testing.expect(t, owner == nil && error != .None)
		destroy(&owner)
	}
	crlf_chain, _ := strings.replace_all(string(fixture_cert), "\n", "\r\n")
	defer delete(crlf_chain)
	crlf_key, _ := strings.replace_all(string(fixture_key), "\n", "\r\n")
	defer delete(crlf_key)
	wrapped_chain := fmt.aprintf(" \t\r\n%s \t\r\n", crlf_chain)
	defer delete(wrapped_chain)
	wrapped_key := fmt.aprintf(" \t\r\n%s \t\r\n", crlf_key)
	defer delete(wrapped_key)
	owner, error := create(transmute([]u8)wrapped_chain, transmute([]u8)wrapped_key, {}, context.allocator)
	testing.expect_value(t, error, .None)
	destroy(&owner)
}

@(test)
credential_leaf_policy_uses_explicit_inclusive_clock :: proc(t: ^testing.T) {
	for item in ([]struct {
			chain: []u8,
			want:  Error,
		} {
			{fixture_cert, .None},
			{#load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-badku.pem"), .Key_Usage},
			{#load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-badeku.pem"), .Extended_Key_Usage},
			{
				#load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-critical.pem"),
				.Unhandled_Critical,
			},
			{#load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-absent.pem"), .None},
			{#load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-any.pem"), .None},
		}) {
		h, e := create(item.chain, fixture_key, {}, context.allocator)
		assert(e == .None)
		owner := cast(^Owner)h
		leaf := &owner.certs[0]
		testing.expect_value(t, check_server_leaf(h, leaf.not_before), item.want)
		testing.expect_value(t, check_server_leaf(h, leaf.not_after), item.want)
		testing.expect_value(t, check_server_leaf(h, time.from_nanoseconds(min(i64))), .Not_Yet_Valid)
		testing.expect_value(t, check_server_leaf(h, time.from_nanoseconds(max(i64))), .Expired)
		destroy(&h)
	}
}

@(test)
credential_signing_is_transactional_and_rejects_owned_aliases :: proc(t: ^testing.T) {
	h, e := create(fixture_cert, fixture_key, {}, context.allocator)
	assert(e == .None)
	defer destroy(&h)
	digest: [32]u8
	hash.hash_string_to_buffer(.SHA256, "credential fixture", digest[:])
	out: [512]u8
	for &b in out {b = 0xa5}
	_, short := sign_digest_pss_sha256(h, digest, out[:255])
	testing.expect_value(t, short, .Output_Too_Small)
	for b in out {testing.expect_value(t, b, u8(0xa5))}
	der, _ := certificate_der(h, 0)
	before, _ := fingerprint(h)
	_, alias := sign_digest_pss_sha256(h, digest, der)
	testing.expect_value(t, alias, .Output_Aliases_Owner)
	after, _ := fingerprint(h)
	testing.expect_value(t, before, after)
	owner := cast(^Owner)h
	_, owner_alias := sign_digest_pss_sha256(h, digest, (cast([^]u8)owner)[:size_of(Owner)])
	testing.expect_value(t, owner_alias, .Output_Aliases_Owner)
	n, se := sign_digest_pss_sha256(h, digest, out[:])
	testing.expect(t, se == .None && n == 256)
	pub: rsa.Public_Key
	assert(rsa.public_key_set_bytes(&pub, owner.certs[0].rsa_n, owner.certs[0].rsa_e))
	testing.expect(t, rsa.verify_pss(&pub, .SHA256, 32, digest[:], out[:n], is_prehashed = true, mgf1_algo = .SHA256))
	for b in out[n:] {testing.expect_value(t, b, u8(0xa5))}
	_, nilerr := sign_digest_pss_sha256(nil, digest, out[:])
	testing.expect_value(t, nilerr, .Invalid_Handle)
	_, indexerr := certificate_der(h, 1)
	testing.expect_value(t, indexerr, .Invalid_Index)
	testing.expect(t, bytes.equal(der, owner.certs[0].raw))
}
