package tls

import "core:net"

// TLS 1.2 hello codec. The live client offers these suites on the same
// connection as TLS 1.3; this encoder itself stays TLS 1.2-only for tests.
@(private)
TLS12_VERSION :: u16(0x0303)

// The TLS 1.2 suites of the fallback profile. Cipher_Suite holds the TLS 1.3
// suites only, and its tables are indexed by every member, so these stay in
// their own enumeration.
@(private)
Tls12_Cipher_Suite :: enum u16 {
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   = 0xc02f,
}

@(private)
TLS12_ECDHE_RSA_AES128_GCM_SHA256 :: u16(Tls12_Cipher_Suite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
@(private)
TLS12_ECDHE_ECDSA_AES128_GCM_SHA256 :: u16(Tls12_Cipher_Suite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
TLS12_MAX_SERVER_HELLO_SIZE :: 1024

@(private)
TLS12_Client_Hello :: struct {
	server_name:    string,
	random:         [32]u8,
	alpn_protocols: []string,
}

@(private)
TLS12_Server_Hello :: struct {
	random:                 [32]u8,
	cipher_suite:           u16,
	// Borrowed from the wire; this profile does not resume sessions.
	session_id:             []u8,
	alpn_selected:          []u8,
	extended_master_secret: bool,
	secure_renegotiation:   bool,
}

@(private)
TLS12_Hello_Error :: enum {
	None,
	Invalid_Server_Name,
	Invalid_ALPN,
	Destination_Undersized,
	Truncated,
	Length_Mismatch,
	Unexpected_Message,
	Unsupported_Version,
	Invalid_Session_ID,
	Unoffered_Cipher,
	Invalid_Compression,
	Duplicate_Extension,
	Unsupported_Extension,
	Invalid_Extension,
	Missing_Extended_Master_Secret,
	Missing_Secure_Renegotiation,
	Downgrade_Detected,
}

@(private)
tls12_hello_extension :: proc(dst: []u8, at: ^int, kind: u16, size: int) {
	hello_put_u16(dst, at, kind)
	hello_put_u16(dst, at, u16(size))
}

// Validates complete handshake framing and exactly the offered extensions.
// tls13_offered enables RFC8446 downgrade-sentinel enforcement for a future
// dual-version offer; do not retry a failed TLS1.3 connection as TLS1.2.
@(private)
tls12_server_hello_decode :: proc(
	wire: []u8,
	offer: TLS12_Client_Hello,
	tls13_offered := false,
) -> (
	hello: TLS12_Server_Hello,
	error: TLS12_Hello_Error,
) {
	if !server_name_valid(offer.server_name) {
		return {}, .Invalid_Server_Name
	}
	if _, valid := alpn_protocols_size(offer.alpn_protocols); !valid {
		return {}, .Invalid_ALPN
	}
	if len(wire) < 4 {
		return {}, .Truncated
	}
	if wire[0] != 2 {
		return {}, .Unexpected_Message
	}
	if handshake_body_size(wire) + 4 != len(wire) {
		return {}, .Length_Mismatch
	}
	if len(wire) < 42 || len(wire) > TLS12_MAX_SERVER_HELLO_SIZE {
		return {}, .Truncated
	}
	if hello_u16(wire, 4) != TLS12_VERSION {
		return {}, .Unsupported_Version
	}
	copy(hello.random[:], wire[6:38])
	if tls13_offered && (string(hello.random[24:]) == "DOWNGRD\x01" || string(hello.random[24:]) == "DOWNGRD\x00") {
		return {}, .Downgrade_Detected
	}
	session_size := int(wire[38])
	at := 39
	if session_size > 32 {
		return {}, .Invalid_Session_ID
	}
	if len(wire) - at < session_size + 5 {
		return {}, .Truncated
	}
	hello.session_id = wire[at:at + session_size]
	at += session_size
	hello.cipher_suite = hello_u16(wire, at)
	at += 2
	if hello.cipher_suite != TLS12_ECDHE_RSA_AES128_GCM_SHA256 &&
	   hello.cipher_suite != TLS12_ECDHE_ECDSA_AES128_GCM_SHA256 {
		return {}, .Unoffered_Cipher
	}
	if wire[at] != 0 {
		return {}, .Invalid_Compression
	}
	at += 1
	extension_size := int(hello_u16(wire, at))
	at += 2
	if extension_size != len(wire) - at {
		return {}, .Length_Mismatch
	}
	seen: u8
	for at < len(wire) {
		if len(wire) - at < 4 {
			return {}, .Truncated
		}
		kind := hello_u16(wire, at)
		size := int(hello_u16(wire, at + 2))
		at += 4
		if size > len(wire) - at {
			return {}, .Truncated
		}
		data := wire[at:at + size]
		at += size
		bit: u8
		switch kind {
		case 0:
			bit = 1
		case 11:
			bit = 2
		case 16:
			bit = 4
		case 23:
			bit = 8
		case 0xff01:
			bit = 16
		case:
			return {}, .Unsupported_Extension
		}
		if seen & bit != 0 {
			return {}, .Duplicate_Extension
		}
		seen |= bit
		switch kind {
		case 0:
			if len(data) != 0 || net.parse_address(offer.server_name) != nil {
				return {}, .Invalid_Extension
			}
		case 11:
			// RFC8422 5.2: server capabilities may include formats not in
			// our offer; we still send/accept only uncompressed EC points.
			if len(data) < 2 || int(data[0]) != len(data) - 1 {
				return {}, .Invalid_Extension
			}
			uncompressed := false
			for format in data[1:] {
				if format == 0 {
					uncompressed = true
				}
			}
			if !uncompressed {
				return {}, .Invalid_Extension
			}
		case 16:
			selected, status := alpn_selection_decode(data, offer.alpn_protocols)
			if status.kind != .None {
				return {}, .Invalid_ALPN
			}
			hello.alpn_selected = selected
		case 23:
			if len(data) != 0 {
				return {}, .Invalid_Extension
			}
			hello.extended_master_secret = true
		case 0xff01:
			if len(data) != 1 || data[0] != 0 {
				return {}, .Invalid_Extension
			}
			hello.secure_renegotiation = true
		}
	}
	if !hello.extended_master_secret {
		return {}, .Missing_Extended_Master_Secret
	}
	if !hello.secure_renegotiation {
		return {}, .Missing_Secure_Renegotiation
	}
	return hello, .None
}
