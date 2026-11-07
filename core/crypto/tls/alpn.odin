package tls

// A bounded client profile, below the RFC7301 wire vector limit. Names are
// opaque bytes; each length prefix and name counts toward the list-byte cap.
MAX_ALPN_PROTOCOLS :: 16
MAX_ALPN_PROTOCOL_SIZE :: 255
MAX_ALPN_OFFER_BYTES :: 1024

@(private)
alpn_protocols_size :: proc(protocols: []string) -> (int, bool) {
	if len(protocols) > MAX_ALPN_PROTOCOLS {return 0,false}
	size := 0
	for protocol in protocols {
		if len(protocol) == 0 || len(protocol) > MAX_ALPN_PROTOCOL_SIZE {return 0,false}
		if 1 + len(protocol) > MAX_ALPN_OFFER_BYTES - size {return 0,false}
		size += 1 + len(protocol)
	}
	return size,true
}

@(private)
alpn_selection_decode :: proc(data: []u8, offers: []string) -> ([]u8, Handshake_Error) {
	if len(offers) == 0 {return nil,{kind=.Unsupported_Extension}}
	if len(data) < 4 {return nil,{kind=.Malformed_Message}}
	list_size:=int(data[0])<<8|int(data[1])
	name_size:=int(data[2])
	if list_size != len(data)-2 || name_size == 0 || name_size != len(data)-3 {
		return nil,{kind=.Malformed_Message}
	}
	selected:=data[3:]
	for offer in offers {
		if string(selected)==offer {return selected,{}}
	}
	return nil,{kind=.Invalid_ALPN}
}

@(private)
alpn_clear :: proc(conn: ^Conn) {
	conn.alpn_selected={}
	conn.alpn_selected_size=0
}
