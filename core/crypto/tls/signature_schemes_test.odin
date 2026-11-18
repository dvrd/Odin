package tls

import "core:crypto/ecdsa"
import "core:crypto/ed25519"
import "core:crypto/hash"
import "core:crypto/rsa"
import "core:testing"

// CertificateVerify under every scheme of upstream's SIGNATURE_SCHEMES, over
// a SHA-256 and a SHA-384 transcript digest. The signer here is core:crypto
// itself with fresh (EC, Ed25519) or RFC 9500 test (RSA) keys; the leaf is a
// bare certificate value carrying only the public key the verifier reads.
Scheme_Test_Keys :: struct {
	rsa_key:     rsa.Private_Key,
	rsa_n:       [512]u8,
	rsa_n_size:  int,
	rsa_e:       [3]u8,
	p256:        ecdsa.Private_Key,
	p256_point:  [65]u8,
	p384:        ecdsa.Private_Key,
	p384_point:  [97]u8,
	ed:          ed25519.Private_Key,
	ed_point:    [32]u8,
}

scheme_test_keys_init :: proc(keys: ^Scheme_Test_Keys) {
	rsa_ok := rsa.private_key_set_insecure_test(&keys.rsa_key)
	assert(rsa_ok)
	keys.rsa_n_size = rsa.private_key_n(&keys.rsa_key, keys.rsa_n[:])
	exponent := rsa.private_key_e(&keys.rsa_key)
	keys.rsa_e = {u8(exponent >> 16), u8(exponent >> 8), u8(exponent)}

	p256_ok := ecdsa.private_key_generate(&keys.p256, .SECP256R1)
	p384_ok := ecdsa.private_key_generate(&keys.p384, .SECP384R1)
	ed_ok := ed25519.private_key_generate(&keys.ed)
	assert(p256_ok && p384_ok && ed_ok)

	ecdsa.private_key_public_bytes(&keys.p256, keys.p256_point[:])
	ecdsa.private_key_public_bytes(&keys.p384, keys.p384_point[:])
	ed25519.private_key_public_bytes(&keys.ed, keys.ed_point[:])
}

// Signs content under scheme and returns the CertificateVerify message and
// the leaf whose key verifies it.
scheme_test_sign :: proc(
	keys: ^Scheme_Test_Keys,
	scheme: Signature_Scheme,
	content: []u8,
	certs: ^Server_Certificates,
	message: ^[dynamic]u8,
) {
	algorithm := SIGNATURE_SCHEME_HASH[scheme]
	leaf := &certs.chain[0]
	certs.count = 1
	leaf.public_key_algorithm = SIGNATURE_SCHEME_TO_X509_PUBLIC_KEY[scheme]

	signature: [512]u8
	size := 0
	#partial switch leaf.public_key_algorithm {
	case .Ed25519:
		leaf.ec_point = keys.ed_point[:]
		size = ed25519.SIGNATURE_SIZE
		ed25519.sign(&keys.ed, content, signature[:size])
	case .ECDSA_P256, .ECDSA_P384:
		key := &keys.p256
		leaf.ec_point = keys.p256_point[:]
		if leaf.public_key_algorithm == .ECDSA_P384 {
			key = &keys.p384
			leaf.ec_point = keys.p384_point[:]
		}

		encoded, ok := ecdsa.sign_asn1(key, algorithm, content, context.allocator)
		assert(ok)
		size = copy(signature[:], encoded)
		delete(encoded)
	case .RSA:
		leaf.rsa_n = keys.rsa_n[:keys.rsa_n_size]
		leaf.rsa_e = keys.rsa_e[:]
		size = keys.rsa_n_size
		ok: bool
		if signature_scheme_is_pkcs1(scheme) {
			ok = rsa.sign_pkcs1(&keys.rsa_key, algorithm, content, signature[:size])
		} else {
			ok = rsa.sign_pss(&keys.rsa_key, algorithm, hash.DIGEST_SIZES[algorithm], content, signature[:size], mgf1_algo = algorithm)
		}
		assert(ok)
	}

	clear(message)
	append(message, u8(Handshake_Type.Certificate_Verify), 0, u8((4 + size) >> 8), u8(4 + size))
	append(message, u8(u16(scheme) >> 8), u8(u16(scheme)), u8(size >> 8), u8(size))
	append(message, ..signature[:size])
}

@(test)
certificate_verify_accepts_every_upstream_scheme :: proc(t: ^testing.T) {
	keys := new(Scheme_Test_Keys)
	defer free(keys)
	scheme_test_keys_init(keys)

	message: [dynamic]u8
	defer delete(message)

	digest: [MAX_TRANSCRIPT_HASH_SIZE]u8
	for i in 0 ..< len(digest) {
		digest[i] = u8(0xa0 + i)
	}

	for scheme in SIGNATURE_SCHEMES {
		for digest_size in ([?]int{32, 48}) {
			content_storage: [MAX_CERTIFICATE_VERIFY_INPUT_SIZE]u8
			content := certificate_verify_content(content_storage[:], digest[:digest_size], true)

			certs := new(Server_Certificates)
			defer free(certs)
			scheme_test_sign(keys, scheme, content, certs, &message)

			accepted := verify_certificate_signature(certs, message[:], digest[:digest_size], true, SIGNATURE_SCHEMES)
			testing.expectf(t, accepted.kind == .None, "%v over a %d-byte digest: %v", scheme, digest_size, accepted)

			// The client role's context string is a different signed content.
			swapped := verify_certificate_signature(certs, message[:], digest[:digest_size], false, SIGNATURE_SCHEMES)
			testing.expectf(t, swapped.kind == .Invalid_Signature, "%v role swap: %v", scheme, swapped)

			// Another transcript.
			digest[0] ~= 1
			moved := verify_certificate_signature(certs, message[:], digest[:digest_size], true, SIGNATURE_SCHEMES)
			digest[0] ~= 1
			testing.expectf(t, moved.kind == .Invalid_Signature, "%v transcript change: %v", scheme, moved)

			// A scheme outside the verifier's offer never reaches the key.
			compatible := verify_certificate_signature(certs, message[:], digest[:digest_size], true)
			expected := Authentication_Error_Kind.Unsupported_Signature_Scheme
			if signature_scheme_offered(COMPATIBLE_SIGNATURE_SCHEMES, scheme) {
				expected = .None
			}
			testing.expectf(t, compatible.kind == expected, "%v under the Compatible offer: %v", scheme, compatible)

			// The scheme must match the leaf's key type.
			certs.chain[0].public_key_algorithm = .ECDSA_P521
			mismatched := verify_certificate_signature(certs, message[:], digest[:digest_size], true, SIGNATURE_SCHEMES)
			testing.expectf(t, mismatched.kind == .Signature_Key_Mismatch, "%v key mismatch: %v", scheme, mismatched)
		}
	}
}

@(test)
certificate_verify_rejects_schemes_never_offered :: proc(t: ^testing.T) {
	certs := new(Server_Certificates)
	defer free(certs)
	certs.count = 1
	certs.chain[0].public_key_algorithm = .RSA

	digest: [32]u8
	for scheme in ([?]u16{0x0201, 0x0203, 0x0603, 0x0808, 0x0000, 0xffff}) {
		message := [?]u8{u8(Handshake_Type.Certificate_Verify), 0, 0, 5, u8(scheme >> 8), u8(scheme), 0, 1, 0}
		result := verify_certificate_signature(certs, message[:], digest[:], true, SIGNATURE_SCHEMES)
		testing.expectf(t, result.kind == .Unsupported_Signature_Scheme, "scheme %x: %v", scheme, result)
	}
}
