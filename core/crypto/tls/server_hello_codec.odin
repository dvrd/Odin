package tls

import "core:net"

// Pure, allocation-free server-side ClientHello inspection (RFC 8446 4.1.2,
// 4.2). Every slice borrows wire, including successful negotiation results.
// The caller must keep wire immutable and alive until all views are discarded.
// These local ceilings are deliberately below some legal TLS wire maxima.
SERVER_CLIENT_HELLO_MAX_WIRE :: 65536
SERVER_CLIENT_HELLO_MAX_ENTRIES :: 128

Server_Hello_Codec_Status :: enum {
	None,
	Need_Input, // Only the header probe can return this.
	Malformed,
	Unsupported,
	Limit,
	Retry_Required, // Selected group offered without a share; owner may send one HRR.
}

Server_Client_Hello_Limits :: struct {
	max_wire_bytes: int,
	max_extensions: int,
}

Server_Client_Hello_View :: struct {
	wire, random, session_id: []u8,
	cipher_suites, versions, groups: []u8, // Big-endian u16 lists, no vector prefix.
	signature_algorithms, signature_algorithms_cert: []u8,
	key_shares: []u8, // KeyShareEntry list, no vector prefix.
	server_name, alpn_protocols: []u8, // host_name bytes; raw length-prefixed ALPN list.
	psk_identities, psk_binders, psk_modes: []u8,
	quic_transport_parameters: []u8,
	has_key_share, has_psk, early_data, has_quic_transport_parameters: bool,
}

Server_Client_Hello_Selection :: struct {
	version: u16,
	cipher: Cipher_Suite,
	group: Named_Group,
	signature: Signature_Scheme,
	peer_key_share: []u8,
}

// Inspect a complete or partial four-byte header without retaining it. A
// coalesced suffix is allowed here; decode requires exactly one full message.
server_client_hello_size :: proc(prefix: []u8, limits := Server_Client_Hello_Limits{SERVER_CLIENT_HELLO_MAX_WIRE, SERVER_CLIENT_HELLO_MAX_ENTRIES}) -> (int, Server_Hello_Codec_Status) {
	if limits.max_wire_bytes < 4 || limits.max_wire_bytes > SERVER_CLIENT_HELLO_MAX_WIRE ||
	   limits.max_extensions < 1 || limits.max_extensions > SERVER_CLIENT_HELLO_MAX_ENTRIES {return 0, .Limit}
	if len(prefix) > 0 && prefix[0] != u8(Handshake_Type.Client_Hello) {return 0, .Malformed}
	if len(prefix) < 4 {return 0, .Need_Input}
	size := 4 + handshake_body_size(prefix)
	if size > limits.max_wire_bytes {return 0, .Limit}
	return size, .None
}

server_hello_vector :: proc(data: []u8, prefix: int, minimum: int, multiple: int) -> ([]u8, bool) {
	if len(data) < prefix {return nil, false}
	size := int(data[0])
	if prefix == 2 {size = int(hello_u16(data, 0))}
	if size != len(data)-prefix || size < minimum || size % multiple != 0 {return nil, false}
	return data[prefix:], true
}

server_hello_offer_contains :: proc(offers: []u8, value: u16) -> bool {
	if len(offers)%2 != 0 {return false}
	for at := 0; at < len(offers); at += 2 {
		if hello_u16(offers, at) == value {return true}
	}
	return false
}

server_client_hello_decode :: proc(wire: []u8, limits := Server_Client_Hello_Limits{SERVER_CLIENT_HELLO_MAX_WIRE, SERVER_CLIENT_HELLO_MAX_ENTRIES}) -> (hello: Server_Client_Hello_View, status: Server_Hello_Codec_Status) {
	size, probe := server_client_hello_size(wire, limits)
	if probe == .Need_Input {return {}, .Malformed}
	if probe != .None {return {}, probe}
	if len(wire) != size || size < 45 {return {}, .Malformed}
	if hello_u16(wire, 4) != 0x0303 {return {}, .Malformed}
	hello.wire, hello.random = wire, wire[6:38]
	at := 39
	session_size := int(wire[38])
	if session_size > 32 || session_size > len(wire)-at {return {}, .Malformed}
	hello.session_id = wire[at:at+session_size]
	at += session_size
	if len(wire)-at < 2 {return {}, .Malformed}
	cipher_size := int(hello_u16(wire, at)); at += 2
	if cipher_size < 2 || cipher_size%2 != 0 || cipher_size > len(wire)-at {return {}, .Malformed}
	hello.cipher_suites = wire[at:at+cipher_size]; at += cipher_size
	if len(wire)-at < 2 || wire[at] != 1 || wire[at+1] != 0 {return {}, .Malformed}
	at += 2
	if len(wire)-at < 2 {return {}, .Malformed}
	extension_size := int(hello_u16(wire, at)); at += 2
	if extension_size != len(wire)-at {return {}, .Malformed}
	extension_start := at
	count := 0
	for at < len(wire) {
		count += 1
		if count > limits.max_extensions {return {}, .Limit}
		if len(wire)-at < 4 {return {}, .Malformed}
		kind := hello_u16(wire, at)
		data_size := int(hello_u16(wire, at+2))
		// Rescan only previously validated entries. The hard count bound keeps
		// duplicate detection independent of attacker-selected wire lengths.
		for previous := extension_start; previous < at; {
			if hello_u16(wire, previous) == kind {return {}, .Malformed}
			previous += 4 + int(hello_u16(wire, previous+2))
		}
		at += 4
		if data_size > len(wire)-at {return {}, .Malformed}
		data := wire[at:at+data_size]; at += data_size
		valid := true
		switch kind {
		case 44: return {}, .Malformed // No stateful cookie was requested in this profile.
		case 21:
			for b in data {if b != 0 {return {}, .Malformed}}
		case 43: hello.versions, valid = server_hello_vector(data, 1, 2, 2)
		case 10:
			hello.groups, valid = server_hello_vector(data, 2, 2, 2)
			if valid {
				if len(hello.groups)/2 > SERVER_CLIENT_HELLO_MAX_ENTRIES {return {}, .Limit}
				for i := 0; i < len(hello.groups); i += 2 {
					if server_hello_offer_contains(hello.groups[:i], hello_u16(hello.groups,i)) {return {}, .Malformed}
				}
			}
		case 13: hello.signature_algorithms, valid = server_hello_vector(data, 2, 2, 2)
		case 50: hello.signature_algorithms_cert, valid = server_hello_vector(data, 2, 2, 2)
		case 51:
			hello.has_key_share = true
			hello.key_shares, valid = server_hello_vector(data, 2, 0, 1)
		case 0:
			list, ok := server_hello_vector(data, 2, 1, 1)
			if !ok {return {}, .Malformed}
			name_count := 0
			for n := 0; n < len(list); {
				name_count += 1
				if name_count > SERVER_CLIENT_HELLO_MAX_ENTRIES {return {}, .Limit}
				if len(list)-n < 3 {return {}, .Malformed}
				name_kind := list[n]
				for p := 0; p < n; {
					if list[p] == name_kind {return {}, .Malformed}
					p += 3 + int(hello_u16(list,p+1))
				}
				length := int(hello_u16(list,n+1)); n += 3
				if length == 0 || length > len(list)-n {return {}, .Malformed}
				if name_kind == 0 {
					hello.server_name = list[n:n+length]
					// RFC 6066 host_name is ASCII DNS, no trailing dot/IP.
					if !server_hello_dns_name_valid(hello.server_name) {return {}, .Malformed}
				}
				n += length
			}
		case 16:
			hello.alpn_protocols, valid = server_hello_vector(data, 2, 2, 1)
			if valid {
				protocol_count := 0
				for n := 0; n < len(hello.alpn_protocols); {
					protocol_count += 1
					if protocol_count > SERVER_CLIENT_HELLO_MAX_ENTRIES {return {}, .Limit}
					start := n
					length := int(hello.alpn_protocols[n]); n += 1
					if length == 0 || length > len(hello.alpn_protocols)-n {return {}, .Malformed}
					for previous := 0; previous < start; {
						p := int(hello.alpn_protocols[previous]); previous += 1
						if string(hello.alpn_protocols[previous:previous+p]) == string(hello.alpn_protocols[n:n+length]) {return {}, .Malformed}
						previous += p
					}
					n += length
				}
			}
		case 41:
			hello.has_psk = true
			if at != len(wire) {return {}, .Malformed} // MUST be the last extension.
			if len(data) < 2 {return {}, .Malformed}
			identities_size := int(hello_u16(data,0))
			if identities_size < 7 || identities_size > len(data)-2 {return {}, .Malformed}
			hello.psk_identities = data[2:2+identities_size]
			hello.psk_binders, valid = server_hello_vector(data[2+identities_size:], 2, 33, 1)
			if valid && !server_hello_psk_valid(hello.psk_identities, hello.psk_binders) {return {}, .Malformed}
		case 45: hello.psk_modes, valid = server_hello_vector(data, 1, 1, 1)
		case 42:
			hello.early_data = true
			valid = len(data) == 0
		case 57:
			hello.has_quic_transport_parameters = true
			hello.quic_transport_parameters = data // Binding validates opaque values/mode.
		case: // Unknown and GREASE extensions are ignored after framing checks.
		}
		if !valid {return {}, .Malformed}
	}
	if hello.has_psk && len(hello.psk_modes) == 0 || hello.early_data && !hello.has_psk {return {}, .Malformed}
	// RFC 8446 4.2.8: key_share requires supported_groups; each entry must
	// occur in supported_groups in the same relative order, without repeats.
	if hello.has_key_share != (len(hello.groups) > 0) {return {}, .Malformed}
	if !hello.has_psk && (len(hello.signature_algorithms) == 0 || len(hello.groups) == 0) {return {}, .Malformed}
	group_cursor, share_count := 0, 0
	for n := 0; n < len(hello.key_shares); {
		share_count += 1
		if share_count > SERVER_CLIENT_HELLO_MAX_ENTRIES {return {}, .Limit}
		if len(hello.key_shares)-n < 4 {return {}, .Malformed}
		group := hello_u16(hello.key_shares,n)
		length := int(hello_u16(hello.key_shares,n+2)); n += 4
		if length == 0 || length > len(hello.key_shares)-n {return {}, .Malformed}
		if group == u16(Named_Group.X25519) && length != 32 {return {}, .Malformed}
		if group == u16(Named_Group.Secp256r1) && (length != 65 || hello.key_shares[n] != 4) {
			return {}, .Malformed
		}
		for group_cursor < len(hello.groups) && hello_u16(hello.groups,group_cursor) != group {group_cursor += 2}
		if group_cursor == len(hello.groups) {return {}, .Malformed}
		group_cursor += 2
		n += length
	}
	// Missing TLS 1.3/certificate offers are unsupported policy, allowing a
	// well-formed PSK-only offer to be classified without pretending to select it.
	if !server_hello_offer_contains(hello.versions, VERSION_TLS_1_3) {return {}, .Unsupported}
	return hello, .None
}

server_hello_dns_name_valid :: proc(name: []u8) -> bool {
	if len(name) == 0 || len(name) > MAX_SERVER_NAME_SIZE || name[len(name)-1] == '.' {return false}
	_, ip := net.parse_ip4_address(string(name))
	if ip {return false}
	label := 0
	for c, i in name {
		if c == '.' {
			if label == 0 || name[i-1] == '-' {return false}
			label = 0
			continue
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {return false}
		if label == 0 && c == '-' {return false}
		label += 1
		if label > 63 {return false}
	}
	return label > 0 && name[len(name)-1] != '-'
}

server_hello_psk_valid :: proc(identities, binders: []u8) -> bool {
	identity_count, binder_count := 0, 0
	for n := 0; n < len(identities); {
		if len(identities)-n < 2 {return false}
		length := int(hello_u16(identities,n)); n += 2
		if length == 0 || length > len(identities)-n || len(identities)-n-length < 4 {return false}
		n += length+4
		identity_count += 1
	}
	for n := 0; n < len(binders); {
		length := int(binders[n]); n += 1
		if length < 32 || length > len(binders)-n {return false}
		n += length
		binder_count += 1
	}
	return identity_count > 0 && identity_count == binder_count
}

// Conservative full-handshake offer selection only. It neither authenticates
// keys nor admits a certificate chain. D153 must match the actual chain's
// signature metadata against signature_algorithms_cert (fallback: algorithms).
// No PSK, 0-RTT, ALPN selection, QUIC binding, or HRR state is implemented here.
server_client_hello_negotiate :: proc(
	hello: Server_Client_Hello_View,
	offer: Server_Offer = .Compatible,
	sha256_only: bool = false,
) -> (
	Server_Client_Hello_Selection,
	Server_Hello_Codec_Status,
) {
	if !server_hello_offer_contains(hello.versions, VERSION_TLS_1_3) {
		return {}, .Unsupported
	}

	cipher, cipher_found := server_negotiate_cipher(hello, offer, sha256_only)
	if !cipher_found {
		return {}, .Unsupported
	}

	// The credential store signs with RSA-PSS-SHA256 or ECDSA-P256-SHA256.
	pss := server_hello_offer_contains(hello.signature_algorithms, u16(Signature_Scheme.Rsa_Pss_Rsae_Sha256))
	ecdsa := server_hello_offer_contains(hello.signature_algorithms, u16(Signature_Scheme.Ecdsa_Secp256r1_Sha256))
	if !hello.has_psk && !pss && !ecdsa {
		return {}, .Unsupported
	}

	signature := Signature_Scheme.Rsa_Pss_Rsae_Sha256
	if !pss {
		signature = .Ecdsa_Secp256r1_Sha256
	}

	selection := Server_Client_Hello_Selection{version = VERSION_TLS_1_3, cipher = cipher, signature = signature}

	// Prefer, in server order, a group the client already sent a share for;
	// otherwise the first common group, which costs one HelloRetryRequest.
	// The Compatible offer keeps its strict order: X25519, then P-256.
	groups := server_offer_groups(offer)
	listed := Named_Group.Unallocated_RESERVED
	for group in groups {
		if !server_hello_offer_contains(hello.groups, u16(group)) {
			continue
		}

		if listed == .Unallocated_RESERVED {
			listed = group
		}

		if offer == .Compatible && group != listed {
			break
		}

		share, status := server_key_share_find(hello.key_shares, group)
		if status == .Malformed {
			return {}, .Malformed
		}

		if status == .None {
			selection.group = group
			selection.peer_key_share = share
			return selection, .None
		}
	}

	if listed == .Unallocated_RESERVED {
		return {}, .Unsupported
	}

	selection.group = listed
	return selection, .Retry_Required
}

// The first suite of the client's list this offer selects. sha256_only keeps
// the suites whose PSKs the ticket format can carry.
server_negotiate_cipher :: proc(
	hello: Server_Client_Hello_View,
	offer: Server_Offer,
	sha256_only: bool,
) -> (
	Cipher_Suite,
	bool,
) {
	suites := server_offer_cipher_suites(offer)
	for at := 0; at + 1 < len(hello.cipher_suites); at += 2 {
		suite := Cipher_Suite(hello_u16(hello.cipher_suites, at))
		if !cipher_suite_offered(suites, suite) {
			continue
		}

		if sha256_only && CIPHER_SUITE_HASH[suite] != .SHA256 {
			continue
		}
		return suite, true
	}
	return {}, false
}

// The client's share for group. Retry_Required when it sent none; Malformed
// when the list is damaged or the share has the wrong shape for its group.
server_key_share_find :: proc(key_shares: []u8, group: Named_Group) -> ([]u8, Server_Hello_Codec_Status) {
	for n := 0; n < len(key_shares); {
		if len(key_shares) - n < 4 {
			return nil, .Malformed
		}

		entry := hello_u16(key_shares, n)
		length := int(hello_u16(key_shares, n + 2))
		n += 4
		if length > len(key_shares) - n {
			return nil, .Malformed
		}

		if entry == u16(group) {
			share := key_shares[n:n + length]
			uncompressed := group != .Secp256r1 && group != .Secp384r1 || length > 0 && share[0] == 4
			if length != named_group_share_size(group, false) || !uncompressed {
				return nil, .Malformed
			}
			return share, .None
		}
		n += length
	}
	return nil, .Retry_Required
}
