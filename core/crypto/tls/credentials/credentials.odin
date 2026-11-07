// Immutable, bounded RSA server credential snapshots. No transport or file I/O.
package credentials

import "core:bytes"
import "core:crypto"
import "core:crypto/hash"
import "core:crypto/rsa"
import "core:crypto/x509"
import "core:encoding/pem"
import "core:mem"
import "core:slice"
import "core:time"

// Opaque owned handle. Never construct, dereference, or copy its storage.
// Borrowed aliases acquire no ownership; destroy requires exclusive access.
Credential :: struct {}
Limits :: struct {
	// Zero selects defaults. Nonzero limits may only lower the fixed profile.
	max_certificates, max_der_bytes, max_chain_pem_bytes: int,
	max_key_pem_bytes, max_storage_bytes:                 int,
}
Error :: enum {
	None,
	Invalid_Input,
	Invalid_Limits,
	Input_Limit,
	Storage_Limit,
	Allocation_Failed,
	Malformed_PEM,
	Malformed_Certificate,
	Malformed_Key,
	Unsupported_Key,
	Key_Mismatch,
	Invalid_Handle,
	Invalid_Index,
	Not_Yet_Valid,
	Expired,
	Key_Usage,
	Extended_Key_Usage,
	Unhandled_Critical,
	Output_Too_Small,
	Output_Aliases_Owner,
	Entropy_Unavailable,
	Signing_Failed,
}
Storage_Usage :: struct {
	retained_bytes, peak_bytes: int,
}

@(private)
MAX_CERTIFICATES :: 16
@(private)
Allocation :: struct {
	pointer:         rawptr,
	size, alignment: int,
}
@(private)
Owner :: struct {
	backing:                      mem.Allocator,
	limits:                       Limits,
	used, peak:                   int,
	limit_hit, allocation_failed: bool,
	allocations:                  [128]Allocation,
	key:                          rsa.Private_Key,
	certs:                        [MAX_CERTIFICATES]x509.Certificate,
	count:                        int,
}

@(private)
limits_normalize :: proc(limits: Limits) -> (Limits, bool) {
	out := limits
	defaults := Limits{16, 1 << 20, 2 << 20, 96 << 10, 4 << 20}
	if out.max_certificates == 0 {
		out.max_certificates = defaults.max_certificates
	}
	if out.max_der_bytes == 0 {
		out.max_der_bytes = defaults.max_der_bytes
	}
	if out.max_chain_pem_bytes == 0 {
		out.max_chain_pem_bytes = defaults.max_chain_pem_bytes
	}
	if out.max_key_pem_bytes == 0 {
		out.max_key_pem_bytes = defaults.max_key_pem_bytes
	}
	if out.max_storage_bytes == 0 {
		out.max_storage_bytes = defaults.max_storage_bytes
	}
	return out,
		out.max_certificates > 0 &&
		out.max_certificates <= defaults.max_certificates &&
		out.max_der_bytes > 0 &&
		out.max_der_bytes <= defaults.max_der_bytes &&
		out.max_chain_pem_bytes > 0 &&
		out.max_chain_pem_bytes <= defaults.max_chain_pem_bytes &&
		out.max_key_pem_bytes > 0 &&
		out.max_key_pem_bytes <= defaults.max_key_pem_bytes &&
		out.max_storage_bytes > 0 &&
		out.max_storage_bytes <= defaults.max_storage_bytes
}

// Copies leaf-first certificate DER and one unencrypted PKCS1/PKCS8 RSA key.
// Construction checks structure/key matching, not trust or current validity.
@(require_results)
create :: proc(
	chain_pem, key_pem: []u8,
	limits: Limits,
	allocator: mem.Allocator,
) -> (
	^Credential,
	Error,
) {
	l, valid := limits_normalize(limits)
	if !valid {
		return nil, .Invalid_Limits
	}
	if len(chain_pem) == 0 || len(key_pem) == 0 || allocator.procedure == nil {
		return nil, .Invalid_Input
	}
	if len(chain_pem) > l.max_chain_pem_bytes || len(key_pem) > l.max_key_pem_bytes {
		return nil, .Input_Limit
	}
	if size_of(Owner) > l.max_storage_bytes {
		return nil, .Storage_Limit
	}
	storage, allocation := allocator.procedure(
		allocator.data,
		.Alloc,
		size_of(Owner),
		align_of(Owner),
		nil,
		0,
	)
	if allocation != nil || len(storage) != size_of(Owner) || raw_data(storage) == nil {
		wipe_grant(allocator, storage, align_of(Owner))
		return nil, .Allocation_Failed
	}
	for &b in storage {b = 0}
	owner := cast(^Owner)raw_data(storage)
	owner.backing = allocator; owner.limits = l; owner.used = size_of(Owner)
	owner.peak = owner.used
	handle := cast(^Credential)owner
	success := false
	defer if !success {
		destroy(&handle)
	}
	budget := mem.Allocator{budget_proc, owner}
	key_input := trim_whitespace(key_pem)
	if !bytes.has_prefix(key_input, transmute([]u8)string("-----BEGIN ")) {
		return nil, .Malformed_PEM
	}
	block, rest, pe := pem.decode(key_input, budget)
	if pe != nil || block == nil {
		return nil, allocation_error(owner, .Malformed_PEM)
	}
	key_error := Error.None
	if len(trim_whitespace(rest)) != 0 {
		key_error = .Malformed_PEM
	} else if len(block.data) > x509.MAX_RSA_PKCS8_DER_SIZE {
		key_error = .Input_Limit
	} else {
		parse_error: x509.Private_Key_Error
		switch block.label {
		case "PRIVATE KEY":
			parse_error = x509.parse_pkcs8_rsa(&owner.key, block.data[:])
		case "RSA PRIVATE KEY":
			parse_error = x509.parse_pkcs1_rsa(&owner.key, block.data[:])
		case:
			key_error = .Unsupported_Key
		}
		if key_error == .None && parse_error.kind != .None {
			key_error = .Malformed_Key
		}
	}
	pem.block_delete(block)
	if key_error != .None {
		return nil, key_error
	}
	modulus: [512]u8
	n := rsa.private_key_n(&owner.key, modulus[:])
	if n < 256 || n > 512 || (n == 256 && modulus[0] < 0x80) {
		return nil, .Unsupported_Key
	}
	remaining := trim_whitespace(chain_pem)
	der_sum := 0
	for len(remaining) > 0 {
		if owner.count == l.max_certificates {
			return nil, .Input_Limit
		}
		if !bytes.has_prefix(remaining, transmute([]u8)string("-----BEGIN CERTIFICATE-----")) {
			return nil, .Malformed_PEM
		}
		cert_block, tail, ce := pem.decode(remaining, budget)
		if ce != nil || cert_block == nil {
			return nil, allocation_error(owner, .Malformed_PEM)
		}
		cert_error := Error.None
		if cert_block.label != "CERTIFICATE" {
			cert_error = .Malformed_PEM
		} else if len(cert_block.data) == 0 || len(cert_block.data) > l.max_der_bytes - der_sum {
			cert_error = .Input_Limit
		} else {
			der, de := slice.clone(cert_block.data[:], budget)
			if de != nil || len(der) != len(cert_block.data) {
				cert_error = allocation_error(owner, .Allocation_Failed)
			} else {
				cert, xe := x509.parse(der, budget)
				if xe != .None {
					cert_error = allocation_error(owner, .Malformed_Certificate)
				} else {
					owner.certs[owner.count] = cert; owner.count += 1; der_sum += len(der)
				}
			}
		}
		pem.block_delete(cert_block)
		if cert_error != .None {
			return nil, cert_error
		}
		remaining = trim_whitespace(tail)
	}
	if owner.count == 0 {
		return nil, .Malformed_PEM
	}
	leaf := &owner.certs[0]
	exponent: u32
	if len(leaf.rsa_e) > 4 {
		return nil, .Key_Mismatch
	}
	for b in leaf.rsa_e {exponent = (exponent << 8) | u32(b)}
	if leaf.public_key_algorithm != .RSA ||
	   !bytes.equal(leaf.rsa_n, modulus[:n]) ||
	   exponent != rsa.private_key_e(&owner.key) {
		return nil, .Key_Mismatch
	}
	success = true
	return handle, .None
}

// Idempotent for this owning variable. All borrowers/signers must have ended.
destroy :: proc(handle: ^^Credential) {
	if handle == nil || handle^ == nil {
		return
	}
	owner := cast(^Owner)handle^
	handle^ = nil
	for &a in owner.allocations {
		if a.pointer != nil {
			release(owner, &a)
		}
	}
	allocator := owner.backing
	wipe_grant(allocator, (cast([^]u8)owner)[:size_of(Owner)], align_of(Owner))
}
certificate_count :: proc(credential: ^Credential) -> int {
	if credential == nil {
		return 0
	}; return (cast(^Owner)credential).count
}
// Immutable borrow: do not modify/free; valid until exclusive destruction.
@(require_results)
certificate_der :: proc(credential: ^Credential, index: int) -> ([]u8, Error) {
	if credential == nil {
		return nil, .Invalid_Handle
	}
	owner := cast(^Owner)credential
	if index < 0 || index >= owner.count {
		return nil, .Invalid_Index
	}
	return owner.certs[index].raw, .None
}
@(require_results)
fingerprint :: proc(credential: ^Credential) -> ([32]u8, Error) {
	if credential == nil {
		return {}, .Invalid_Handle
	}
	result: [32]u8
	hash.hash_bytes_to_buffer(.SHA256, (cast(^Owner)credential).certs[0].raw, result[:])
	return result, .None
}
storage_usage :: proc(credential: ^Credential) -> Storage_Usage {
	if credential == nil {
		return {}
	}
	owner := cast(^Owner)credential
	return {owner.used, owner.peak}
}
// Explicit leaf policy only; no chain verification or trust establishment.
check_server_leaf :: proc(credential: ^Credential, now: time.Time) -> Error {
	if credential == nil {
		return .Invalid_Handle
	}
	leaf := &(cast(^Owner)credential).certs[0]
	if time.to_unix_nanoseconds(now) < time.to_unix_nanoseconds(leaf.not_before) {
		return .Not_Yet_Valid
	}
	if time.to_unix_nanoseconds(now) > time.to_unix_nanoseconds(leaf.not_after) {
		return .Expired
	}
	if leaf.unhandled_critical {
		return .Unhandled_Critical
	}
	if leaf.has_key_usage && .Digital_Signature not_in leaf.key_usage {
		return .Key_Usage
	}
	if leaf.has_ext_key_usage &&
	   .Server_Auth not_in leaf.ext_key_usage &&
	   .Any not_in leaf.ext_key_usage {
		return .Extended_Key_Usage
	}
	return .None
}

// Read-only signing supports concurrent calls with distinct output storage.
// Catastrophic native entropy failures retain core:crypto's panic policy.
@(require_results)
sign_digest_pss_sha256 :: proc(
	credential: ^Credential,
	digest: [32]u8,
	out: []u8,
) -> (
	int,
	Error,
) {
	if credential == nil {
		return 0, .Invalid_Handle
	}
	if !crypto.HAS_RAND_BYTES {
		return 0, .Entropy_Unavailable
	}
	owner := cast(^Owner)credential
	n := rsa.private_key_size(&owner.key)
	if len(out) < n {
		return 0, .Output_Too_Small
	}
	if overlaps(raw_data(out), len(out), owner, size_of(Owner)) {
		return 0, .Output_Aliases_Owner
	}
	for a in owner.allocations {
		if a.pointer != nil && overlaps(raw_data(out), len(out), a.pointer, a.size) {
			return 0, .Output_Aliases_Owner
		}
	}
	digest_copy := digest
	defer crypto.zero_explicit(&digest_copy, size_of(digest_copy))
	scratch: [512]u8
	defer crypto.zero_explicit(&scratch, size_of(scratch))
	if !rsa.sign_pss(
		&owner.key,
		.SHA256,
		32,
		digest_copy[:],
		scratch[:n],
		is_prehashed = true,
		mgf1_algo = .SHA256,
	) {
		return 0, .Signing_Failed
	}
	copy(out[:n], scratch[:n])
	return n, .None
}
@(private)
trim_whitespace :: proc(data: []u8) -> []u8 {
	start, end := 0, len(data)
	for start < end && is_whitespace(data[start]) {start += 1}
	for end > start && is_whitespace(data[end - 1]) {end -= 1}
	return data[start:end]
}
@(private)
overlaps :: proc(a: rawptr, an: int, b: rawptr, bn: int) -> bool {
	if an <= 0 || bn <= 0 {
		return false
	}
	x, y := uintptr(a), uintptr(b)
	if x <= y {
		return y - x < uintptr(an)
	}
	return x - y < uintptr(bn)
}
@(private)
allocation_error :: proc(owner: ^Owner, fallback: Error) -> Error {
	if owner.limit_hit {
		return .Storage_Limit
	}
	if owner.allocation_failed {
		return .Allocation_Failed
	}
	return fallback
}
@(private)
is_whitespace :: proc(b: u8) -> bool {return b == 32 || b == 9 || b == 13 || b == 10}

// Parsed construction-time metadata by value; never exposes mutable X509/key storage.
Certificate_Algorithms :: struct {
	signature: x509.Signature_Algorithm,
	subject_key: x509.Public_Key_Algorithm,
}
certificate_algorithms :: proc(credential: ^Credential, index: int) -> (Certificate_Algorithms, Error) {
	if credential == nil {return {}, .Invalid_Handle}
	owner := cast(^Owner)credential
	if index < 0 || index >= owner.count {return {}, .Invalid_Index}
	cert := &owner.certs[index]
	return {cert.signature_algorithm, cert.public_key_algorithm}, .None
}
