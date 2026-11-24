package x509

import "core:bytes"
import "core:crypto/rsa"
import "core:encoding/asn1"

MAX_RSA_PKCS8_DER_SIZE :: 64 * 1024

Private_Key_Error_Kind :: enum {
	None,
	Invalid_Input,
	Input_Oversized,
	Overlap,
	Malformed,
	Unsupported_Profile,
	Unsupported_Version,
	Unsupported_Algorithm,
	Key_Oversized,
	Invalid_Key,
}

Private_Key_Error :: struct {
	kind: Private_Key_Error_Kind,
	asn1: asn1.Error,
}

// Imports a bounded, unencrypted two-prime RSA PKCS8 version0 key. DER is
// borrowed only for this call and must not overlap dst. Success clears/replaces
// the old native key; every failure preserves it. No DER view is retained and
// no allocation occurs. The caller owns dst and must eventually clear it.
// Normalization/self-test uses rsa.private_key_set_bytes; it does not establish
// primality or consistency of the redundant private exponent d. Usage-specific
// strength policy belongs to the caller, within the native RSA size limits.
@(require_results)
parse_pkcs8_rsa :: proc(dst: ^rsa.Private_Key, der: []u8) -> Private_Key_Error {
	if error := rsa_import_preflight(dst, der); error.kind != .None {
		return error
	}
	parts, error := pkcs8_rsa_parts(der)
	if error.kind != .None {
		return error
	}
	return rsa_import_components(dst, parts)
}

// Strict raw two-prime PKCS1 import. Uses the same bounds, transaction and
// ownership contract as parse_pkcs8_rsa, without allocating an outer envelope.
@(require_results)
parse_pkcs1_rsa :: proc(dst: ^rsa.Private_Key, der: []u8) -> Private_Key_Error {
	if error := rsa_import_preflight(dst, der); error.kind != .None {
		return error
	}
	parts, error := pkcs1_rsa_parts(der)
	if error.kind != .None {
		return error
	}
	return rsa_import_components(dst, parts)
}

@(private)
rsa_import_preflight :: proc(dst: ^rsa.Private_Key, der: []u8) -> Private_Key_Error {
	if dst == nil || len(der) == 0 || raw_data(der) == nil {
		return {kind = .Invalid_Input}
	}
	if len(der) > MAX_RSA_PKCS8_DER_SIZE {
		return {kind = .Input_Oversized}
	}
	destination := (cast([^]u8)dst)[:size_of(rsa.Private_Key)]
	if bytes.alias(destination, der) {
		return {kind = .Overlap}
	}
	return {}
}

@(private)
rsa_import_components :: proc(dst: ^rsa.Private_Key, parts: [8][]u8) -> Private_Key_Error {
	candidate: rsa.Private_Key
	defer rsa.private_key_clear(&candidate)
	if !rsa.private_key_set_bytes(
		&candidate,
		parts[0],
		parts[1],
		parts[2],
		parts[3],
		parts[4],
		parts[5],
		parts[6],
		parts[7],
	) {
		return {kind = .Invalid_Key}
	}
	// private_key_set copies normalized fields, not necessarily unused tails.
	// Erase the entire previous representation before installing a smaller key.
	rsa.private_key_clear(dst)
	rsa.private_key_set(dst, &candidate)
	return {}
}

@(private)
pkcs8_rsa_parts :: proc(der: []u8) -> (parts: [8][]u8, error: Private_Key_Error) {
	outer := asn1.Cursor {
		data = der,
	}
	info, parse_error := asn1.read_sequence(&outer)
	if parse_error != .None {
		return {}, {kind = .Malformed, asn1 = parse_error}
	}
	if parse_error = asn1.done(&outer); parse_error != .None {
		return {}, {kind = .Malformed, asn1 = parse_error}
	}
	version, version_error := asn1.read_i64(&info)
	if version_error != .None {
		// EncryptedPrivateKeyInfo starts with AlgorithmIdentifier, not version.
		if version_error == .Unexpected_Tag {
			return {}, {kind = .Unsupported_Profile, asn1 = version_error}
		}
		return {}, {kind = .Malformed, asn1 = version_error}
	}
	if version != 0 {
		return {}, {kind = .Unsupported_Version}
	}
	algorithm, algorithm_error := asn1.read_sequence(&info)
	if algorithm_error != .None {
		return {}, {kind = .Malformed, asn1 = algorithm_error}
	}
	oid, oid_error := asn1.read_oid(&algorithm)
	if oid_error != .None {
		return {}, {kind = .Malformed, asn1 = oid_error}
	}
	if !bytes.equal(oid, _OID_KEY_RSA) {
		return {}, {kind = .Unsupported_Algorithm}
	}
	// Keep existing Google compatibility: parameters may be absent or DER NULL.
	if !asn1.is_empty(&algorithm) {
		if parse_error = asn1.read_null(&algorithm); parse_error != .None {
			return {}, {kind = .Malformed, asn1 = parse_error}
		}
	}
	if parse_error = asn1.done(&algorithm); parse_error != .None {
		return {}, {kind = .Malformed, asn1 = parse_error}
	}
	encoded, key_error := asn1.read_octet_string(&info)
	if key_error != .None {
		return {}, {kind = .Malformed, asn1 = key_error}
	}
	// Attributes/extra fields are outside this deliberately narrow v0 profile.
	if parse_error = asn1.done(&info); parse_error != .None {
		return {}, {kind = .Malformed, asn1 = parse_error}
	}
	return pkcs1_rsa_parts(encoded)
}

@(private)
pkcs1_rsa_parts :: proc(encoded: []u8) -> (parts: [8][]u8, error: Private_Key_Error) {
	parse_error: asn1.Error
	inner := asn1.Cursor {
		data = encoded,
	}
	sequence, sequence_error := asn1.read_sequence(&inner)
	if sequence_error != .None {
		return {}, {kind = .Malformed, asn1 = sequence_error}
	}
	if parse_error = asn1.done(&inner); parse_error != .None {
		return {}, {kind = .Malformed, asn1 = parse_error}
	}
	version, version_error := asn1.read_i64(&sequence)
	if version_error != .None {
		return {}, {kind = .Malformed, asn1 = version_error}
	}
	if version != 0 {
		return {}, {kind = .Unsupported_Version}
	}
	limits := [8]int {
		rsa.MODULUS_MAX_SIZE / 8,
		rsa.EXPONENT_MAX_SIZE / 8,
		rsa.MODULUS_MAX_SIZE / 8,
		rsa.FACTOR_MAX_SIZE / 8,
		rsa.FACTOR_MAX_SIZE / 8,
		rsa.FACTOR_MAX_SIZE / 8,
		rsa.FACTOR_MAX_SIZE / 8,
		rsa.FACTOR_MAX_SIZE / 8,
	}
	for &part, i in parts {
		magnitude, integer_error := asn1.read_unsigned_integer_bytes(&sequence)
		if integer_error != .None {
			return {}, {kind = .Malformed, asn1 = integer_error}
		}
		if len(magnitude) == 0 || (len(magnitude) == 1 && magnitude[0] == 0) {
			return {}, {kind = .Invalid_Key}
		}
		if len(magnitude) > limits[i] {
			return {}, {kind = .Key_Oversized}
		}
		part = magnitude
	}
	if parse_error = asn1.done(&sequence); parse_error != .None {
		return {}, {kind = .Malformed, asn1 = parse_error}
	}
	return parts, {}
}
