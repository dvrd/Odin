package tls

import "core:net"
import "core:strings"

// ClientHello wire format

Handshake_Type :: enum u8 {
	Client_Hello         = 1,
	Server_Hello         = 2,
	Encrypted_Extensions = 8,
	Certificate          = 11,
	Certificate_Request  = 13,
	Certificate_Verify   = 15,
	Finished             = 20,
	Key_Update           = 24,
}

Extension_Type :: enum u16 {
	Server_Name               = 0,
	Supported_Groups          = 10,
	Signature_Algorithms      = 13,
	Application_Layer_Protocol_Negotiation = 16,
	Supported_Versions        = 43,
	Signature_Algorithms_Cert = 50,
	Key_Share                 = 51,
}

Cipher_Suite :: enum u16 {
	AES_128_GCM_SHA256 = 0x1301,
}

Named_Group :: enum u16 {
	X25519 = 0x001d,
}

Signature_Scheme :: enum u16 {
	RSA_PKCS1_SHA256       = 0x0401,
	ECDSA_SECP256R1_SHA256 = 0x0403,
	RSA_PSS_RSAE_SHA256    = 0x0804,
	Ed25519                = 0x0807,
}

VERSION_TLS_1_3 :: cast(u16)0x0304
MAX_SERVER_NAME_SIZE :: 253
// Includes the four-byte handshake header; excludes the record header.
MAX_CLIENT_HELLO_SIZE :: 139 + MAX_SERVER_NAME_SIZE + 6 + MAX_ALPN_OFFER_BYTES

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
	hello_put_u16(dst, &written, cast(u16)Cipher_Suite.AES_128_GCM_SHA256)
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
	verify_schemes := [?]Signature_Scheme{.ECDSA_SECP256R1_SHA256, .RSA_PSS_RSAE_SHA256, .Ed25519}
	cert_schemes := [?]Signature_Scheme {
		.ECDSA_SECP256R1_SHA256,
		.RSA_PSS_RSAE_SHA256,
		.Ed25519,
		.RSA_PKCS1_SHA256,
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

// Our offer has an empty session ID, one cipher, and one key share. A normal
// response therefore has exactly 90 bytes, including its handshake header.
MAX_SERVER_HELLO_SIZE :: 90

HELLO_RETRY_REQUEST_RANDOM :: [32]u8 {
	0xcf,
	0x21,
	0xad,
	0x74,
	0xe5,
	0x9a,
	0x61,
	0x11,
	0xbe,
	0x1d,
	0x8c,
	0x02,
	0x1e,
	0x65,
	0xb8,
	0x91,
	0xc2,
	0xa2,
	0x11,
	0x16,
	0x7a,
	0xbb,
	0x8c,
	0x5e,
	0x07,
	0x9e,
	0x09,
	0xe2,
	0xc8,
	0xa8,
	0x33,
	0x9c,
}

Server_Hello :: struct {
	random:            [32]u8,
	version:           u16,
	cipher_suite:      Cipher_Suite,
	x25519_public_key: [32]u8,
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
server_hello_decode :: proc(wire: []u8) -> (hello: Server_Hello, err: Server_Hello_Error) {
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

	if hello.random == HELLO_RETRY_REQUEST_RANDOM {
		return {}, .Hello_Retry_Unsupported
	}

	if wire[38] != 0 do return {}, .Session_ID_Mismatch

	if hello_u16(wire, 39) != cast(u16)Cipher_Suite.AES_128_GCM_SHA256 {
		return {}, .Unoffered_Cipher
	}

	if wire[41] != 0 do return {}, .Invalid_Compression

	if cast(int)hello_u16(wire, 42) != len(wire) - 44 {
		return {}, .Extension_Length_Mismatch
	}

	return server_hello_extensions_decode(wire, &hello)
}

server_hello_extensions_decode :: proc(
	wire: []u8,
	hello: ^Server_Hello,
) -> (
	Server_Hello,
	Server_Hello_Error,
) {
	version_seen, share_seen: bool
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

			if hello_u16(wire, at) != cast(u16)Named_Group.X25519 {
				return {}, .Unoffered_Group
			}

			if size != 36 || hello_u16(wire, at + 2) != 32 {
				return {}, .Invalid_Key_Share_Length
			}

			for i in 0 ..< 32 do hello.x25519_public_key[i] = wire[at + 4 + i]
		case:
			return {}, .Unsupported_Extension
		}
		at += size
	}

	if !version_seen {
		return {}, .Missing_Supported_Versions
	}

	if !share_seen do return {}, .Missing_Key_Share

	hello.cipher_suite = .AES_128_GCM_SHA256

	return hello^, .None
}

handshake_body_size :: proc(wire: []u8) -> int {
	return cast(int)wire[1] << 16 | cast(int)wire[2] << 8 | cast(int)wire[3]
}

hello_u16 :: proc(wire: []u8, at: int) -> u16 {
	return cast(u16)wire[at] << 8 | cast(u16)wire[at + 1]
}
