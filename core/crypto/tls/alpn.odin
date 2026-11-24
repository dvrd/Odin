package tls

// A bounded client profile, below the RFC7301 wire vector limit. Names are
// opaque bytes; each length prefix and name counts toward the list-byte cap.
MAX_ALPN_PROTOCOLS :: 16
MAX_ALPN_PROTOCOL_SIZE :: 255
MAX_ALPN_OFFER_BYTES :: 1024

@(private)
alpn_protocols_size :: proc(protocols: []string, max_protocols: int = MAX_ALPN_PROTOCOLS) -> (int, bool) {
	if len(protocols) > max_protocols {
		return 0, false
	}
	size := 0
	for protocol in protocols {
		if len(protocol) == 0 || len(protocol) > MAX_ALPN_PROTOCOL_SIZE {
			return 0, false
		}
		if 1 + len(protocol) > MAX_ALPN_OFFER_BYTES - size {
			return 0, false
		}
		size += 1 + len(protocol)
	}
	return size, true
}

@(private)
alpn_selection_decode :: proc(data: []u8, offers: []string) -> ([]u8, Handshake_Error) {
	if len(offers) == 0 {
		return nil, {kind = .Unsupported_Extension}
	}
	if len(data) < 4 {
		return nil, {kind = .Malformed_Message}
	}
	list_size := int(data[0]) << 8 | int(data[1])
	name_size := int(data[2])
	if list_size != len(data) - 2 || name_size == 0 || name_size != len(data) - 3 {
		return nil, {kind = .Malformed_Message}
	}
	selected := data[3:]
	for offer in offers {
		if string(selected) == offer {
			return selected, {}
		}
	}
	return nil, {kind = .Invalid_ALPN}
}

@(private)
alpn_clear :: proc(conn: ^Conn) {
	conn.alpn_selected = {}
	conn.alpn_selected_size = 0
}

// Opaque HTTP tokens. Matching them does not implement HTTP/2 or HTTP/3.
@(private)
ALPN_HTTP11 :: "http/1.1"
@(private)
ALPN_H2 :: "h2"
ALPN_H3 :: "h3"

// TCP is the record stack. QUIC is offer policy only: no packets and no records.
ALPN_Transport :: enum {
	TCP,
	QUIC,
}

// No socket and no handshake. TCP allows a missing list (HTTP/1 fallback, with
// no implicit h2/h3) or only http/1.1 and h2. QUIC allows exactly one "h3".
alpn_transport_offers :: proc(transport: ALPN_Transport, protocols: []string) -> Client_Error {
	if _, valid := alpn_protocols_size(protocols); !valid {
		return .Invalid_ALPN
	}
	switch transport {
	case .TCP:
		for protocol in protocols {
			if protocol != ALPN_HTTP11 && protocol != ALPN_H2 {
				return .Invalid_ALPN
			}
		}
		return .None
	case .QUIC:
		if len(protocols) != 1 || protocols[0] != ALPN_H3 {
			return .Invalid_ALPN
		}
		return .None
	}
	unreachable()
}

// The QUIC token must not be written as TLS records. Other names stay opaque.
@(private)
alpn_tcp_rejects_h3 :: proc(protocols: []string) -> Client_Error {
	for protocol in protocols {
		if protocol == ALPN_H3 {
			return .Invalid_ALPN
		}
	}
	return .None
}
