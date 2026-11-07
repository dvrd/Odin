package tls

import "core:crypto/ecdsa"
import "core:crypto/ed25519"
import "core:crypto/rsa"
import "core:crypto/x509"
import "core:time"

MAX_SERVER_CERTIFICATES :: 16
MAX_CERTIFICATE_MESSAGE_SIZE :: 1 << 20
SERVER_CERTIFICATE_VERIFY_CONTEXT :: "TLS 1.3, server CertificateVerify"

Authentication_Error_Kind :: enum {
	None,
	Truncated,
	Length_Mismatch,
	Message_Oversized,
	Unexpected_Handshake_Type,
	Invalid_Certificate_Context,
	Empty_Certificate_List,
	Too_Many_Certificates,
	Invalid_Certificate,
	Unsupported_Certificate_Extension,
	Invalid_Trust_Roots,
	Invalid_Server_Name,
	Invalid_Certificate_Usage,
	Certificate_Chain_Invalid,
	Unsupported_Signature_Scheme,
	Signature_Key_Mismatch,
	Invalid_Public_Key,
	Invalid_Signature,
}

Authentication_Error :: struct {
	kind: Authentication_Error_Kind,
	x509: x509.Error,
}

// Owns the parsed certificates' allocated tables, but borrows their DER from
// the Certificate handshake message. Keep that message alive and unchanged
// until this value is destroyed. Do not copy an owning value after parsing.
Server_Certificates :: struct {
	chain: [MAX_SERVER_CERTIFICATES]x509.Certificate,
	count: int,
}

// RFC 8446 section 4.4.2, X.509 server authentication. Our ClientHello offers
// no CertificateEntry extensions, so any nonempty entry extensions are an
// unsolicited extension. Failure releases all partially parsed certificates.
server_certificates_parse :: proc(message: []u8) -> (Server_Certificates, Authentication_Error) {
	certs: Server_Certificates
	err := authentication_certificates_parse_into(&certs, message)
	if err.kind != .None {
		server_certificates_destroy(&certs)
	}

	return certs, err
}

server_certificates_destroy :: proc(certs: ^Server_Certificates) {
	if certs == nil do return

	for i in 0 ..< certs.count do x509.destroy(&certs.chain[i])
	certs^ = {}
}

verify_server_certificates :: proc(
	certs: ^Server_Certificates,
	server_name: string,
	roots: []^x509.Certificate,
	now: time.Time,
) -> Authentication_Error {
	if certs == nil || certs.count < 1 || certs.count > MAX_SERVER_CERTIFICATES {
		return {kind = .Empty_Certificate_List}
	}

	if !server_name_valid(server_name) {
		return {kind = .Invalid_Server_Name}
	}

	if len(roots) == 0 {
		return {kind = .Invalid_Trust_Roots}
	}

	for root in roots {
		if root == nil {
			return {kind = .Invalid_Trust_Roots}
		}
	}
	leaf := &certs.chain[0]
	if leaf.has_key_usage && .Digital_Signature not_in leaf.key_usage {
		return {kind = .Invalid_Certificate_Usage, x509 = .Incompatible_Usage}
	}

	intermediates: [MAX_SERVER_CERTIFICATES - 1]^x509.Certificate
	for i in 1 ..< certs.count do intermediates[i - 1] = &certs.chain[i]
	chain, err := x509.verify_chain(
		leaf,
		{
			roots = roots,
			intermediates = intermediates[:certs.count - 1],
			current_time = now,
			dns_name = server_name,
			required_eku = x509.EKU_Bit.Server_Auth,
		},
	)
	if err != .None {
		return {kind = .Certificate_Chain_Invalid, x509 = err}
	}

	delete(chain)
	return {}
}

// Checks proof of possession, independently of path validation above. The
// transcript hash must cover ClientHello through Certificate (inclusive),
// excluding CertificateVerify itself. RFC 8446 section 4.4.3.
verify_server_certificate_signature :: proc(
	certs: ^Server_Certificates,
	message: []u8,
	transcript_hash: [32]u8,
) -> Authentication_Error {
	if certs == nil || certs.count < 1 || certs.count > MAX_SERVER_CERTIFICATES {
		return {kind = .Empty_Certificate_List}
	}

	if len(message) < 8 do return {kind = .Truncated}

	if message[0] != cast(u8)Handshake_Type.Certificate_Verify {
		return {kind = .Unexpected_Handshake_Type}
	}

	if handshake_body_size(message) + 4 != len(message) {
		return {kind = .Length_Mismatch}
	}

	scheme := cast(Signature_Scheme)authentication_u16(message, 4)
	signature_size := cast(int)authentication_u16(message, 6)
	if signature_size == 0 || signature_size != len(message) - 8 {
		return {kind = .Length_Mismatch}
	}

	signature := message[8:]
	signed := certificate_verify_input(transcript_hash, server = true)
	valid, signature_error := authentication_signature_check(
		&certs.chain[0],
		scheme,
		signed[:],
		signature,
	)
	if signature_error.kind != .None do return signature_error
	if !valid {
		return {kind = .Invalid_Signature, x509 = .Signature_Invalid}
	}

	return {}
}

authentication_signature_check :: proc(
	leaf: ^x509.Certificate,
	scheme: Signature_Scheme,
	signed, signature: []u8,
) -> (
	bool,
	Authentication_Error,
) {
	valid: bool
	#partial switch scheme {
	case .Ed25519:
		if leaf.public_key_algorithm != .Ed25519 {
			return false, {kind = .Signature_Key_Mismatch}
		}

		pub: ed25519.Public_Key
		if !ed25519.public_key_set_bytes(&pub, leaf.ec_point) {
			return false, {kind = .Invalid_Public_Key}
		}

		defer ed25519.public_key_clear(&pub)
		valid = ed25519.verify(&pub, signed, signature)
	case .ECDSA_SECP256R1_SHA256:
		if leaf.public_key_algorithm != .ECDSA_P256 {
			return false, {kind = .Signature_Key_Mismatch}
		}

		pub: ecdsa.Public_Key
		if !ecdsa.public_key_set_bytes(&pub, .SECP256R1, leaf.ec_point) {
			return false, {kind = .Invalid_Public_Key}
		}

		defer ecdsa.public_key_clear(&pub)
		valid = ecdsa.verify_asn1(&pub, .SHA256, signed, signature)
	case .RSA_PSS_RSAE_SHA256:
		if leaf.public_key_algorithm != .RSA {
			return false, {kind = .Signature_Key_Mismatch}
		}

		pub: rsa.Public_Key
		if !rsa.public_key_set_bytes(&pub, leaf.rsa_n, leaf.rsa_e) {
			return false, {kind = .Invalid_Public_Key}
		}

		defer rsa.public_key_clear(&pub)
		// TLS requires MGF1 with the same hash and a digest-sized salt.
		valid = rsa.verify_pss(&pub, .SHA256, 32, signed, signature, mgf1_algo = .SHA256)
	case:
		return false, {kind = .Unsupported_Signature_Scheme}
	}
	return valid, {}
}

authentication_certificates_parse_into :: proc(
	certs: ^Server_Certificates,
	message: []u8,
) -> Authentication_Error {
	if len(message) > MAX_CERTIFICATE_MESSAGE_SIZE {
		return {kind = .Message_Oversized}
	}

	if len(message) < 8 do return {kind = .Truncated}

	if message[0] != cast(u8)Handshake_Type.Certificate {
		return {kind = .Unexpected_Handshake_Type}
	}

	if handshake_body_size(message) + 4 != len(message) {
		return {kind = .Length_Mismatch}
	}

	if message[4] != 0 {
		return {kind = .Invalid_Certificate_Context}
	}

	list_size := authentication_u24(message, 5)
	if list_size != len(message) - 8 {
		return {kind = .Length_Mismatch}
	}

	if list_size == 0 {
		return {kind = .Empty_Certificate_List}
	}

	return authentication_certificate_entries_parse(certs, message)
}

authentication_certificate_entries_parse :: proc(
	certs: ^Server_Certificates,
	message: []u8,
) -> Authentication_Error {
	at := 8
	for at < len(message) {
		if certs.count == MAX_SERVER_CERTIFICATES {
			return {kind = .Too_Many_Certificates}
		}

		if len(message) - at < 5 {
			return {kind = .Truncated}
		}

		certificate_size := authentication_u24(message, at)
		at += 3
		if certificate_size == 0 {
			return {kind = .Invalid_Certificate}
		}

		if certificate_size > len(message) - at - 2 {
			return {kind = .Truncated}
		}

		der := message[at:at + certificate_size]
		at += certificate_size
		extensions_size := cast(int)authentication_u16(message, at)
		at += 2
		if extensions_size > len(message) - at {
			return {kind = .Truncated}
		}

		if extensions_size != 0 {
			return {kind = .Unsupported_Certificate_Extension}
		}

		cert, err := x509.parse(der)
		if err != .None {
			return {kind = .Invalid_Certificate, x509 = err}
		}

		certs.chain[certs.count] = cert
		certs.count += 1
	}
	return {}
}

authentication_u16 :: proc(data: []u8, at: int) -> u16 {
	return cast(u16)data[at] << 8 | cast(u16)data[at + 1]
}

authentication_u24 :: proc(data: []u8, at: int) -> int {
	return cast(int)data[at] << 16 | cast(int)data[at + 1] << 8 | cast(int)data[at + 2]
}
