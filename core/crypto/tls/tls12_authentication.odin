package tls

import "core:bytes"
import "core:crypto/ecdh"
import "core:crypto/rsa"
import "core:crypto/x509"
import "core:time"

TLS12_MAX_SIGNATURE_SIZE :: rsa.MODULUS_MAX_SIZE / 8
TLS12_MAX_SERVER_KEY_EXCHANGE_SIZE :: 4 + 4 + 65 + 4 + TLS12_MAX_SIGNATURE_SIZE
TLS12_SERVER_KEY_EXCHANGE_TYPE :: u8(12)

TLS12_Authentication_Error_Kind :: enum {
	None,
	Truncated,
	Length_Mismatch,
	Unexpected_Message,
	Message_Oversized,
	Unsupported_Curve,
	Unoffered_Curve,
	Invalid_Point,
	Unsupported_Signature,
	Unoffered_Signature,
	Invalid_Certificates,
	Cipher_Key_Mismatch,
	Invalid_Signature,
}
TLS12_Authentication_Error :: struct {
	kind: TLS12_Authentication_Error_Kind,
	authentication: Authentication_Error,
}

// Borrowed immutable views into one complete ServerKeyExchange message.
// parse alone establishes NO authentication. Never mutate any backing until
// verification/use finishes. The verifying entrypoints reparse the exact message,
// not a caller-modifiable view. No shared secret is computed or returned here.
TLS12_Server_Key_Exchange :: struct {
	group: Named_Group,
	public_key: []u8,
	parameters: []u8,
	scheme: Signature_Scheme,
	signature: []u8,
}

// RFC5246 section7.4.2: TLS1.2 has no certificate_request_context or per-entry
// extension vectors. Returned certificates borrow message DER and own parsed
// tables through the current allocator; destroy with server_certificates_destroy
// under that same allocator. Every failed parse destroys all admitted entries.
tls12_server_certificates_parse :: proc(
	message: []u8,
) -> (Server_Certificates, Authentication_Error) {
	certs: Server_Certificates;
	success := false
	defer if !success {server_certificates_destroy(&certs)}
	if len(message) > MAX_CERTIFICATE_MESSAGE_SIZE {return {}, {kind = .Message_Oversized}}
	if len(message) < 7 {return {}, {kind = .Truncated}}
	if message[0] != u8(Handshake_Type.Certificate) {return {}, {kind = .Unexpected_Handshake_Type}}
	if handshake_body_size(message) + 4 != len(message) || authentication_u24(message, 4) != len(message)-7 {
		return {}, {kind = .Length_Mismatch}
	}
	if len(message) == 7 {return {}, {kind = .Empty_Certificate_List}}
	at := 7
	for at < len(message) {
		if certs.count == MAX_SERVER_CERTIFICATES {return {}, {kind = .Too_Many_Certificates}}
		if len(message)-at < 3 {return {}, {kind = .Truncated}}
		size := authentication_u24(message, at); at += 3
		if size == 0 {return {}, {kind = .Invalid_Certificate}}
		if size > len(message)-at {return {}, {kind = .Truncated}}
		cert, parsed := x509.parse(message[at:at+size])
		if parsed != .None {return {}, {kind = .Invalid_Certificate, x509 = parsed}}
		certs.chain[certs.count] = cert; certs.count += 1; at += size
	}
	success = true
	return certs, {}
}

// RFC8422 section5.4: named X25519/P256 only; P256 must be uncompressed and
// on curve. X25519 decoding accepts its32-byte u-coordinate; the eventual ECDH
// operation MUST reject an all-zero shared secret (core:crypto/ecdh does so).
// Signatures are bounded to the existing native RSA4096/P256 profile. This pure
// syntax/offers decoder returns an UNAUTHENTICATED view and performs no ECDH.
tls12_server_key_exchange_parse :: proc(
	message: []u8,
	offered_groups: []Named_Group,
	offered_schemes: []Signature_Scheme,
) -> (view: TLS12_Server_Key_Exchange, error: TLS12_Authentication_Error) {
	if len(message) > TLS12_MAX_SERVER_KEY_EXCHANGE_SIZE {return {}, {kind = .Message_Oversized}}
	if len(message) < 8 {return {}, {kind = .Truncated}}
	if message[0] != TLS12_SERVER_KEY_EXCHANGE_TYPE {return {}, {kind = .Unexpected_Message}}
	if handshake_body_size(message)+4 != len(message) {return {}, {kind = .Length_Mismatch}}
	if message[4] != 3 {return {}, {kind = .Unsupported_Curve}}
	view.group = Named_Group(authentication_u16(message, 5))
	size := int(message[7])
	curve: ecdh.Curve
	switch view.group {
	case .X25519:
		if size != 32 {return {}, {kind = .Invalid_Point}}
		curve = .X25519
	case .SECP256R1:
		if size != 65 {return {}, {kind = .Invalid_Point}}
		curve = .SECP256R1
	case: return {}, {kind = .Unsupported_Curve}
	}
	if !tls12_group_offered(offered_groups, view.group) {return {}, {kind = .Unoffered_Curve}}
	if len(message)-8 < size+4 {return {}, {kind = .Truncated}}
	view.public_key = message[8:8+size]
	point: ecdh.Public_Key
	defer ecdh.public_key_clear(&point)
	if !ecdh.public_key_set_bytes(&point, curve, view.public_key) {return {}, {kind = .Invalid_Point}}
	at := 8+size
	view.parameters = message[4:at]
	view.scheme = Signature_Scheme(authentication_u16(message, at)); at += 2
	#partial switch view.scheme {
	case .RSA_PKCS1_SHA256, .RSA_PSS_RSAE_SHA256, .ECDSA_SECP256R1_SHA256:
	case: return {}, {kind = .Unsupported_Signature}
	}
	if !tls12_scheme_offered(offered_schemes, view.scheme) {return {}, {kind = .Unoffered_Signature}}
	signature_size := int(authentication_u16(message, at)); at += 2
	if signature_size < 1 || signature_size > TLS12_MAX_SIGNATURE_SIZE || signature_size != len(message)-at {
		return {}, {kind = .Length_Mismatch}
	}
	view.signature = message[at:]
	return view, {}
}

// Verifies ONLY possession of the selected certificate key and its binding to
// this exact pair of randoms/parameters (RFC5246/8422). The caller must separately
// establish certificate trust/name/time/usage, e.g. through its platform policy.
// Use authenticate below for the existing native certificate policy. Only success
// returns a view; no ECDH/shared secret occurs before certificate+SKE validation.
tls12_verify_server_key_exchange :: proc(
	certs: ^Server_Certificates,
	message: []u8,
	client_random, server_random: [32]u8,
	cipher_suite: u16,
	offered_groups: []Named_Group,
	offered_schemes: []Signature_Scheme,
) -> (TLS12_Server_Key_Exchange, TLS12_Authentication_Error) {
	view, parsed := tls12_server_key_exchange_parse(message, offered_groups, offered_schemes)
	if parsed.kind != .None {return {}, parsed}
	if certs == nil || certs.count < 1 || certs.count > MAX_SERVER_CERTIFICATES {
		return {}, {kind = .Invalid_Certificates}
	}
	leaf := &certs.chain[0]
	if leaf.has_key_usage && .Digital_Signature not_in leaf.key_usage {
		return {}, {kind = .Invalid_Certificates, authentication = {kind = .Invalid_Certificate_Usage}}
	}
	if cipher_suite == TLS12_ECDHE_RSA_AES128_GCM_SHA256 {
		if leaf.public_key_algorithm != .RSA || (view.scheme != .RSA_PKCS1_SHA256 && view.scheme != .RSA_PSS_RSAE_SHA256) {
			return {}, {kind = .Cipher_Key_Mismatch}
		}
		// RFC9325 section4.5 requires at least2048 RSA bits for authentication.
		modulus := bytes.trim_left(leaf.rsa_n, []u8{0})
		if len(modulus) < 256 || len(modulus) > TLS12_MAX_SIGNATURE_SIZE || (len(modulus) == 256 && modulus[0] < 0x80) {
			return {}, {kind = .Invalid_Certificates, authentication = {kind = .Invalid_Public_Key}}
		}
	} else if cipher_suite == TLS12_ECDHE_ECDSA_AES128_GCM_SHA256 {
		if leaf.public_key_algorithm != .ECDSA_P256 || view.scheme != .ECDSA_SECP256R1_SHA256 {
			return {}, {kind = .Cipher_Key_Mismatch}
		}
	} else {return {}, {kind = .Cipher_Key_Mismatch}}
	signed: [64 + 4 + 65]u8
	for value, i in client_random {signed[i] = value}
	for value, i in server_random {signed[32+i] = value}
	copy(signed[64:], view.parameters)
	message_to_verify := signed[:64+len(view.parameters)]
	valid: bool
	if view.scheme == .RSA_PKCS1_SHA256 {
		key: rsa.Public_Key
		defer rsa.public_key_clear(&key)
		if !rsa.public_key_set_bytes(&key, leaf.rsa_n, leaf.rsa_e) {
			return {}, {kind = .Invalid_Certificates, authentication = {kind = .Invalid_Public_Key}}
		}
		valid = rsa.verify_pkcs1(&key, .SHA256, message_to_verify, view.signature)
	} else {
		verified, cause := authentication_signature_check(leaf, view.scheme, message_to_verify, view.signature)
		if cause.kind != .None {return {}, {kind = .Invalid_Signature, authentication = cause}}
		valid = verified
	}
	if !valid {return {}, {kind = .Invalid_Signature, authentication = {kind = .Invalid_Signature, x509 = .Signature_Invalid}}}
	return view, {}
}

// Atomic native-policy entrypoint: first authenticate the complete leaf-first
// chain/name/time/usage, then bind the exact SKE to the selected key/cipher.
// Roots, certificates, message and offer slices must remain stable/immutable
// throughout. Caller retains certificate/message ownership on every path.
tls12_authenticate_server_key_exchange :: proc(
	certs: ^Server_Certificates,
	message: []u8,
	config: Config,
	client_random, server_random: [32]u8,
	cipher_suite: u16,
	offered_groups: []Named_Group,
	offered_schemes: []Signature_Scheme,
	now: time.Time,
) -> (TLS12_Server_Key_Exchange, TLS12_Authentication_Error) {
	if cause := verify_server_certificates(certs, config.server_name, config.root_cas, now); cause.kind != .None {
		return {}, {kind = .Invalid_Certificates, authentication = cause}
	}
	return tls12_verify_server_key_exchange(certs, message, client_random, server_random, cipher_suite, offered_groups, offered_schemes)
}

@(private)
tls12_group_offered :: proc(groups: []Named_Group, group: Named_Group) -> bool {
	for offered in groups {if offered == group {return true}}
	return false
}
@(private)
tls12_scheme_offered :: proc(schemes: []Signature_Scheme, scheme: Signature_Scheme) -> bool {
	for offered in schemes {if offered == scheme {return true}}
	return false
}
