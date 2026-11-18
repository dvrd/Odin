package tls

import "core:net"
import "core:strings"

// ClientHello wire format

// Handshake_Type, Extension_Type, Cipher_Suite, Named_Group and
// Signature_Scheme are the declarations in tls_internal.odin and
// tls_params.odin. The values below are the ones this client needs that
// those enumerations do not name.

// extended_master_secret, RFC 7627. Offered only for the TLS 1.2 fallback.
EXTENSION_EXTENDED_MASTER_SECRET :: Extension_Type(23)

VERSION_TLS_1_3 :: cast(u16)0x0304
MAX_SERVER_NAME_SIZE :: 253
// Includes the four-byte handshake header; excludes the record header.
// The extra 32 bytes cover the dual TLS 1.3/1.2 offer used by the live
// handshake. client_hello_encode itself stays the TLS 1.3-only profile.
// MAX_RESUMPTION_EXTENSION fits one psk_dhe_ke offer and no early_data.
// The extra 4 bytes are the empty early_data extension used only when opted in.
// The Upstream offer replaces the fixed 139-byte TLS 1.3 part by
// MAX_UPSTREAM_OFFER_SIZE: three suites, every upstream signature scheme and
// a key share for each of the five groups.
MAX_CLIENT_HELLO_SIZE :: MAX_UPSTREAM_OFFER_SIZE + MAX_SERVER_NAME_SIZE + 6 + MAX_ALPN_OFFER_BYTES + 32 + MAX_RESUMPTION_EXTENSION + 4

// Header, version, random, empty session, suites, compression, extension
// length, supported_versions, server_name framing, signature_algorithms,
// supported_groups and key_share for the Upstream offer.
MAX_UPSTREAM_OFFER_SIZE :: 4 + 2 + 32 + 1 + 2 + 2 * 3 + 2 + 2 + 7 + 9 + 6 + 2 * 16 + 6 + 2 * 5 + 6 + 5 * 4 + 1216 + 56 + 97 + 32 + 65

Client_Hello :: struct {
	server_name:       string,
	random:            [32]u8,
	x25519_public_key: [32]u8,
	alpn_protocols:    []string,
}

Client_Hello_Error :: enum {
	None,
	Invalid_Server_Name,
	Destination_Undersized,
	Invalid_ALPN,
}

// Accept IP literals for certificate verification, but omit them from SNI.
// DNS names must already be ASCII (use IDNA conversion before configuring).
server_name_valid :: proc(server_name: string) -> bool {
	name := server_name
	if len(name) == 0 do return false

	if strings.contains(name, ":") {
		// Accept bare IPv6, excluding bracketed endpoints and IPv4:port.
		_, valid_ipv6 := net.parse_ip6_address(name)
		return valid_ipv6 && name[0] != '['
	}

	if net.parse_address(name) != nil do return true

	name = strings.trim_suffix(name, ".")
	if len(name) == 0 || len(name) > MAX_SERVER_NAME_SIZE {
		return false
	}

	label_size := 0
	for c, i in name {
		if c == '.' {
			if label_size == 0 || name[i - 1] == '-' {
				return false
			}

			label_size = 0
			continue
		}

		if !((c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') || c == '-') {
			return false
		}

		if label_size == 0 && c == '-' do return false

		label_size += 1
		if label_size > 63 do return false
	}
	return label_size > 0 && name[len(name) - 1] != '-'
}

// RFC 8446 sections 4.1.2 and 4.2. Pure encoding: randomness and key generation
// belong to the connection. This initial profile has no resumption or
// middlebox compatibility session ID. dst must not alias the hello fields.
client_hello_encode :: proc(
	dst: []u8,
	hello: Client_Hello,
) -> (
	written: int,
	err: Client_Hello_Error,
) {
	if !server_name_valid(hello.server_name) {
		return 0, .Invalid_Server_Name
	}

	alpn_size, alpn_valid := alpn_protocols_size(hello.alpn_protocols)
	if !alpn_valid {return 0,.Invalid_ALPN}
	name := strings.trim_suffix(hello.server_name, ".")
	if net.parse_address(hello.server_name) != nil {
		name = ""
	}

	sni_size := 0
	if len(name) > 0 do sni_size = 9 + len(name)

	// supported_versions, groups, signatures, certificate signatures, key_share.
	extensions_size := sni_size + 7 + 8 + 12 + 14 + 42
	if alpn_size > 0 {extensions_size += 6 + alpn_size}
	body_size := 43 + extensions_size
	if len(dst) < 4 + body_size {
		return 0, .Destination_Undersized
	}

	dst[0] = cast(u8)Handshake_Type.Client_Hello
	dst[1] = cast(u8)(body_size >> 16)
	dst[2] = cast(u8)(body_size >> 8)
	dst[3] = cast(u8)body_size
	written = 4
	hello_put_u16(dst, &written, cast(u16)LEGACY_TLS_1_2)
	for value, i in hello.random do dst[written + i] = value
	written += 32
	dst[written] = 0 // Empty legacy_session_id.
	written += 1
	hello_put_u16(dst, &written, 2)
	hello_put_u16(dst, &written, cast(u16)Cipher_Suite.TLS_AES_128_GCM_SHA256)
	dst[written] = 1 // One legacy compression method: null.
	dst[written + 1] = 0
	written += 2
	hello_put_u16(dst, &written, cast(u16)extensions_size)

	if len(name) > 0 {
		hello_put_extension(dst, &written, .Server_Name, 5 + len(name))
		hello_put_u16(dst, &written, cast(u16)(3 + len(name)))
		dst[written] = 0 // host_name
		written += 1
		hello_put_u16(dst, &written, cast(u16)len(name))
		copy(dst[written:][:len(name)], transmute([]u8)name)
		written += len(name)
	}

	client_hello_extensions_encode(dst, hello, &written)
	if alpn_size > 0 {
		hello_put_extension(dst, &written, .Application_Layer_Protocol_Negotiation, 2 + alpn_size)
		hello_put_u16(dst, &written, u16(alpn_size))
		for protocol in hello.alpn_protocols {
			dst[written] = u8(len(protocol))
			written += 1
			copy(dst[written:][:len(protocol)], transmute([]u8)protocol)
			written += len(protocol)
		}
	}
	return written, .None
}

client_hello_extensions_encode :: proc(dst: []u8, hello: Client_Hello, at: ^int) {
	hello_put_extension(dst, at, .Supported_Versions, 3)
	dst[at^] = 2
	at^ += 1
	hello_put_u16(dst, at, VERSION_TLS_1_3)
	hello_put_extension(dst, at, .Supported_Groups, 4)
	hello_put_u16(dst, at, 2)
	hello_put_u16(dst, at, cast(u16)Named_Group.X25519)

	// PKCS#1 is allowed for certificate signatures, but not CertificateVerify.
	verify_schemes := [?]Signature_Scheme{.Ecdsa_Secp256r1_Sha256, .Rsa_Pss_Rsae_Sha256, .Ed25519}
	cert_schemes := [?]Signature_Scheme {
		.Ecdsa_Secp256r1_Sha256,
		.Rsa_Pss_Rsae_Sha256,
		.Ed25519,
		.Rsa_Pkcs1_Sha256,
	}
	signature_extensions := [?]Extension_Type{.Signature_Algorithms, .Signature_Algorithms_Cert}
	for extension in signature_extensions {
		schemes := verify_schemes[:]
		if extension == .Signature_Algorithms_Cert {
			schemes = cert_schemes[:]
		}

		hello_put_extension(dst, at, extension, 2 + 2 * len(schemes))
		hello_put_u16(dst, at, cast(u16)(2 * len(schemes)))
		for scheme in schemes do hello_put_u16(dst, at, cast(u16)scheme)
	}
	hello_put_extension(dst, at, .Key_Share, 38)
	hello_put_u16(dst, at, 36)
	hello_put_u16(dst, at, cast(u16)Named_Group.X25519)
	hello_put_u16(dst, at, 32)
	for value, i in hello.x25519_public_key do dst[at^ + i] = value
	at^ += 32
}

// First flight for the live client. TLS 1.3 stays preferred: supported_versions
// lists 1.3 before 1.2, and the only key share is X25519. TLS 1.2 is the same
// connection when the peer selects one of the two AES-128-GCM ECDHE suites.
// No session id is written here. A resumption PSK is appended later, without
// early_data. client_hello_encode is unchanged.
compatible_client_hello_encode :: proc(
	dst: []u8,
	hello: Client_Hello,
) -> (
	written: int,
	err: Client_Hello_Error,
) {
	if !server_name_valid(hello.server_name) {
		return 0, .Invalid_Server_Name
	}
	alpn_size, alpn_valid := alpn_protocols_size(hello.alpn_protocols)
	if !alpn_valid {
		return 0, .Invalid_ALPN
	}
	name := strings.trim_suffix(hello.server_name, ".")
	if net.parse_address(hello.server_name) != nil {
		name = ""
	}
	sni_size := 0
	if len(name) > 0 {
		sni_size = 9 + len(name)
	}
	// versions, groups, points, signatures, certificate signatures, key share,
	// extended master secret, renegotiation info.
	extensions_size := sni_size + 9 + 10 + 6 + 14 + 14 + 42 + 4 + 5
	if alpn_size > 0 {
		extensions_size += 6 + alpn_size
	}
	// version, random, empty session, three ciphers, null compression, extensions.
	body_size := 47 + extensions_size
	if len(dst) < 4+body_size {
		return 0, .Destination_Undersized
	}
	dst[0] = u8(Handshake_Type.Client_Hello)
	dst[1] = u8(body_size >> 16)
	dst[2] = u8(body_size >> 8)
	dst[3] = u8(body_size)
	at := 4
	hello_put_u16(dst, &at, u16(LEGACY_TLS_1_2))
	for value, i in hello.random {
		dst[at+i] = value
	}
	at += 32
	dst[at] = 0
	at += 1
	hello_put_u16(dst, &at, 6)
	hello_put_u16(dst, &at, u16(Cipher_Suite.TLS_AES_128_GCM_SHA256))
	hello_put_u16(dst, &at, u16(Tls12_Cipher_Suite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
	hello_put_u16(dst, &at, u16(Tls12_Cipher_Suite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256))
	dst[at] = 1
	dst[at+1] = 0
	at += 2
	hello_put_u16(dst, &at, u16(extensions_size))
	if len(name) > 0 {
		hello_put_extension(dst, &at, .Server_Name, 5+len(name))
		hello_put_u16(dst, &at, u16(3+len(name)))
		dst[at] = 0
		at += 1
		hello_put_u16(dst, &at, u16(len(name)))
		copy(dst[at:][:len(name)], transmute([]u8)name)
		at += len(name)
	}
	hello_put_extension(dst, &at, .Supported_Versions, 5)
	dst[at] = 4
	at += 1
	hello_put_u16(dst, &at, VERSION_TLS_1_3)
	hello_put_u16(dst, &at, TLS12_VERSION)
	hello_put_extension(dst, &at, .Supported_Groups, 6)
	hello_put_u16(dst, &at, 4)
	hello_put_u16(dst, &at, u16(Named_Group.X25519))
	hello_put_u16(dst, &at, u16(Named_Group.Secp256r1))
	hello_put_extension(dst, &at, .Ec_Point_Formats, 2)
	dst[at] = 1
	at += 1
	dst[at] = 0
	at += 1
	schemes := [?]Signature_Scheme {
		.Ecdsa_Secp256r1_Sha256,
		.Rsa_Pss_Rsae_Sha256,
		.Ed25519,
		.Rsa_Pkcs1_Sha256,
	}
	hello_put_extension(dst, &at, .Signature_Algorithms, 2+2*len(schemes))
	hello_put_u16(dst, &at, u16(2*len(schemes)))
	for scheme in schemes {
		hello_put_u16(dst, &at, u16(scheme))
	}
	hello_put_extension(dst, &at, .Signature_Algorithms_Cert, 2+2*len(schemes))
	hello_put_u16(dst, &at, u16(2*len(schemes)))
	for scheme in schemes {
		hello_put_u16(dst, &at, u16(scheme))
	}
	hello_put_extension(dst, &at, .Key_Share, 38)
	hello_put_u16(dst, &at, 36)
	hello_put_u16(dst, &at, u16(Named_Group.X25519))
	hello_put_u16(dst, &at, 32)
	for value, i in hello.x25519_public_key {
		dst[at+i] = value
	}
	at += 32
	hello_put_extension(dst, &at, EXTENSION_EXTENDED_MASTER_SECRET, 0)
	hello_put_extension(dst, &at, .Renegotiaton_Info, 1)
	dst[at] = 0
	at += 1
	if alpn_size > 0 {
		hello_put_extension(dst, &at, .Application_Layer_Protocol_Negotiation, 2+alpn_size)
		hello_put_u16(dst, &at, u16(alpn_size))
		for protocol in hello.alpn_protocols {
			dst[at] = u8(len(protocol))
			at += 1
			copy(dst[at:][:len(protocol)], transmute([]u8)protocol)
			at += len(protocol)
		}
	}
	if at != 4+body_size {
		return 0, .Destination_Undersized
	}
	return at, .None
}

// First flight of the Upstream offer: upstream's ClientHello (suites in the
// given order, supported_versions 1.3 only, server_name, SIGNATURE_SCHEMES,
// every group of keys with its key share, ALPN) without its legacy session
// id. hello.x25519_public_key is ignored: the shares come from keys.
upstream_client_hello_encode :: proc(
	dst: []u8,
	hello: Client_Hello,
	suites: []Cipher_Suite,
	keys: ^Ephemeral_Keys,
) -> (
	written: int,
	err: Client_Hello_Error,
) {
	if !server_name_valid(hello.server_name) {
		return 0, .Invalid_Server_Name
	}

	alpn_size, alpn_valid := alpn_protocols_size(hello.alpn_protocols)
	if !alpn_valid {
		return 0, .Invalid_ALPN
	}

	name := strings.trim_suffix(hello.server_name, ".")
	if net.parse_address(hello.server_name) != nil {
		name = ""
	}

	groups := keys.supported_groups
	shares_size := 0
	for group in groups {
		shares_size += 4 + named_group_share_size(group, false)
	}

	extensions_size := 7 + 6 + 2 * len(SIGNATURE_SCHEMES) + 6 + 2 * len(groups) + 6 + shares_size
	if len(name) > 0 {
		extensions_size += 9 + len(name)
	}
	if alpn_size > 0 {
		extensions_size += 6 + alpn_size
	}

	body_size := 2 + 32 + 1 + 2 + 2 * len(suites) + 2 + 2 + extensions_size
	if len(dst) < 4 + body_size || extensions_size > 0xffff {
		return 0, .Destination_Undersized
	}

	at := 0
	dst[0] = u8(Handshake_Type.Client_Hello)
	dst[1] = u8(body_size >> 16)
	dst[2] = u8(body_size >> 8)
	dst[3] = u8(body_size)
	at = 4
	hello_put_u16(dst, &at, u16(LEGACY_TLS_1_2))
	random := hello.random
	at += copy(dst[at:], random[:])
	dst[at] = 0 // Empty legacy_session_id.
	at += 1

	hello_put_u16(dst, &at, u16(2 * len(suites)))
	for suite in suites {
		hello_put_u16(dst, &at, u16(suite))
	}
	dst[at] = 1 // One legacy compression method: null.
	dst[at + 1] = 0
	at += 2
	hello_put_u16(dst, &at, u16(extensions_size))

	hello_put_extension(dst, &at, .Supported_Versions, 3)
	dst[at] = 2
	at += 1
	hello_put_u16(dst, &at, VERSION_TLS_1_3)

	if len(name) > 0 {
		hello_put_extension(dst, &at, .Server_Name, 5 + len(name))
		hello_put_u16(dst, &at, u16(3 + len(name)))
		dst[at] = 0 // host_name
		at += 1
		hello_put_u16(dst, &at, u16(len(name)))
		at += copy(dst[at:], name)
	}

	hello_put_extension(dst, &at, .Signature_Algorithms, 2 + 2 * len(SIGNATURE_SCHEMES))
	hello_put_u16(dst, &at, u16(2 * len(SIGNATURE_SCHEMES)))
	for scheme in SIGNATURE_SCHEMES {
		hello_put_u16(dst, &at, u16(scheme))
	}

	hello_put_extension(dst, &at, .Supported_Groups, 2 + 2 * len(groups))
	hello_put_u16(dst, &at, u16(2 * len(groups)))
	for group in groups {
		hello_put_u16(dst, &at, u16(group))
	}

	hello_put_extension(dst, &at, .Key_Share, 2 + shares_size)
	hello_put_u16(dst, &at, u16(shares_size))
	for group in groups {
		size := named_group_share_size(group, false)
		hello_put_u16(dst, &at, u16(group))
		hello_put_u16(dst, &at, u16(size))
		client_key_share_bytes(keys, group, dst[at:at + size])
		at += size
	}

	if alpn_size > 0 {
		hello_put_extension(dst, &at, .Application_Layer_Protocol_Negotiation, 2 + alpn_size)
		hello_put_u16(dst, &at, u16(alpn_size))
		for protocol in hello.alpn_protocols {
			dst[at] = u8(len(protocol))
			at += 1
			at += copy(dst[at:], protocol)
		}
	}

	if at != 4 + body_size {
		return 0, .Destination_Undersized
	}
	return at, .None
}

hello_put_u16 :: proc(dst: []u8, at: ^int, value: u16) {
	dst[at^] = cast(u8)(value >> 8)
	dst[at^ + 1] = cast(u8)value
	at^ += 2
}

hello_put_extension :: proc(dst: []u8, at: ^int, extension: Extension_Type, size: int) {
	hello_put_u16(dst, at, cast(u16)extension)
	hello_put_u16(dst, at, cast(u16)size)
}

// ServerHello wire format

// Our offer has an empty session ID, one cipher, and one key share. A full
// handshake response is 90 bytes. Resumption adds a 6-byte pre_shared_key
// extension and no early_data, so the cap is 96 including the handshake header.
MAX_SERVER_HELLO_SIZE :: 96
// The same message with the largest key_share of the Upstream offer.
MAX_UPSTREAM_SERVER_HELLO_SIZE :: MAX_SERVER_HELLO_SIZE - 32 + MAX_KEY_SHARE_SIZE

Server_Hello :: struct {
	random:            [32]u8,
	version:           u16,
	cipher_suite:      Cipher_Suite,
	// Set when the server selected X25519.
	x25519_public_key: [32]u8,
	// True only when decode was asked to allow resumption identity 0.
	psk_selected:      bool,
	// The selected group and the server's share for it.
	group:             Named_Group,
	key_share:         [MAX_KEY_SHARE_SIZE]u8,
	key_share_size:    int,
}

Server_Hello_Error :: enum {
	None,
	Truncated,
	Unexpected_Handshake_Type,
	Length_Mismatch,
	Invalid_Legacy_Version,
	Session_ID_Mismatch,
	Unoffered_Cipher,
	Invalid_Compression,
	Extension_Length_Mismatch,
	Duplicate_Extension,
	Unsupported_Extension,
	Missing_Supported_Versions,
	Unsupported_Version,
	Missing_Key_Share,
	Unoffered_Group,
	Invalid_Key_Share_Length,
	Hello_Retry_Unsupported,
	Invalid_Hello_Retry_Request,
	Missing_Retry_Cookie,
	Invalid_Retry_Cookie,
	Retry_Cookie_Oversized,
	Invalid_Retry_Group,
	Repeated_Hello_Retry,
	Invalid_Retry_Client_Hello,
}

// RFC 8446 sections 4.1.3, 4.1.4, 4.2.1, and 4.2.8. Validates against the
// fixed offer in client_hello_encode. This does not authenticate the peer.
server_hello_decode :: proc(wire: []u8, allow_psk: bool = false) -> (hello: Server_Hello, err: Server_Hello_Error) {
	return server_hello_decode_offered(wire, COMPATIBLE_CIPHER_SUITES, COMPATIBLE_GROUPS, allow_psk)
}

// The same validation against an offer: the suite and the group must be ones
// the client offered, and the share must have the size of its group.
server_hello_decode_offered :: proc(
	wire: []u8,
	suites: []Cipher_Suite,
	groups: []Named_Group,
	allow_psk: bool = false,
) -> (
	hello: Server_Hello,
	err: Server_Hello_Error,
) {
	if len(wire) < 4 do return {}, .Truncated

	if wire[0] != cast(u8)Handshake_Type.Server_Hello {
		return {}, .Unexpected_Handshake_Type
	}

	if handshake_body_size(wire) + 4 != len(wire) {
		return {}, .Length_Mismatch
	}

	if len(wire) < 44 do return {}, .Truncated

	if hello_u16(wire, 4) != cast(u16)LEGACY_TLS_1_2 {
		return {}, .Invalid_Legacy_Version
	}

	for i in 0 ..< 32 do hello.random[i] = wire[6 + i]

	if hello_is_retry(wire) {
		return {}, .Hello_Retry_Unsupported
	}

	if wire[38] != 0 do return {}, .Session_ID_Mismatch

	suite := Cipher_Suite(hello_u16(wire, 39))
	if !cipher_suite_offered(suites, suite) {
		return {}, .Unoffered_Cipher
	}

	if wire[41] != 0 do return {}, .Invalid_Compression

	if cast(int)hello_u16(wire, 42) != len(wire) - 44 {
		return {}, .Extension_Length_Mismatch
	}

	hello.cipher_suite = suite
	return server_hello_extensions_decode(wire, &hello, allow_psk, groups)
}

server_hello_extensions_decode :: proc(
	wire: []u8,
	hello: ^Server_Hello,
	allow_psk: bool = false,
	groups: []Named_Group = COMPATIBLE_GROUPS,
) -> (
	Server_Hello,
	Server_Hello_Error,
) {
	version_seen, share_seen, psk_seen: bool
	at := 44
	for at < len(wire) {
		if len(wire) - at < 4 do return {}, .Truncated

		extension := hello_u16(wire, at)
		size := cast(int)hello_u16(wire, at + 2)
		at += 4
		if size > len(wire) - at do return {}, .Truncated

		switch extension {
		case cast(u16)Extension_Type.Supported_Versions:
			if version_seen {
				return {}, .Duplicate_Extension
			}

			version_seen = true

			if size != 2 {
				return {}, .Extension_Length_Mismatch
			}

			hello.version = hello_u16(wire, at)

			if hello.version != VERSION_TLS_1_3 {
				return {}, .Unsupported_Version
			}

		case cast(u16)Extension_Type.Key_Share:
			if share_seen do return {}, .Duplicate_Extension

			share_seen = true

			if size < 4 {
				return {}, .Invalid_Key_Share_Length
			}

			group := Named_Group(hello_u16(wire, at))
			if !named_group_offered(groups, group) {
				return {}, .Unoffered_Group
			}

			share_size := named_group_share_size(group, true)
			if share_size == 0 || size != 4 + share_size || int(hello_u16(wire, at + 2)) != share_size {
				return {}, .Invalid_Key_Share_Length
			}

			hello.group = group
			hello.key_share_size = copy(hello.key_share[:], wire[at + 4:at + 4 + share_size])
			if group == .X25519 {
				copy(hello.x25519_public_key[:], hello.key_share[:share_size])
			}
		case 41: // pre_shared_key, identity 0 only. Early data is not accepted here.
			if !allow_psk || psk_seen || size != 2 || hello_u16(wire, at) != 0 {
				return {}, .Unsupported_Extension
			}
			psk_seen = true
			hello.psk_selected = true
		case 42:
			return {}, .Unsupported_Extension
		case:
			return {}, .Unsupported_Extension
		}
		at += size
	}

	if !version_seen {
		return {}, .Missing_Supported_Versions
	}

	if !share_seen do return {}, .Missing_Key_Share

	return hello^, .None
}

handshake_body_size :: proc(wire: []u8) -> int {
	return cast(int)wire[1] << 16 | cast(int)wire[2] << 8 | cast(int)wire[3]
}

hello_u16 :: proc(wire: []u8, at: int) -> u16 {
	return cast(u16)wire[at] << 8 | cast(u16)wire[at + 1]
}
