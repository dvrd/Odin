package tls

import "core:bytes"

// Structural locations only: this does not authorize a version, suite or group.
// Keep the public TLS1.3 encoder and its output unchanged. Future larger offers
// require a separate sizing decision before changing Conn's fixed capacities.
@(private)
Client_Hello_Layout :: struct {
	session_size: int,
	cipher_offset, cipher_size: int,
	extensions_length_offset, extensions_offset, extensions_size: int,
	has_cookie: bool,
}

// Bounded, allocation-free and read-only. Session IDs are structurally bounded;
// callers still enforce the session policy of their particular handshake.
@(private)
client_hello_layout_decode :: proc(wire: []u8) -> (layout: Client_Hello_Layout, valid: bool) {
	if len(wire) < 47 || len(wire) > MAX_CLIENT_HELLO_SIZE do return
	if wire[0] != u8(Handshake_Type.Client_Hello) ||
	   handshake_body_size(wire) + 4 != len(wire) || hello_u16(wire, 4) != 0x0303 {
		return
	}
	layout.session_size = int(wire[38])
	if layout.session_size > 32 do return
	at := 39 + layout.session_size
	if len(wire) - at < 2 do return
	layout.cipher_size = int(hello_u16(wire, at)); at += 2
	if layout.cipher_size == 0 || layout.cipher_size % 2 != 0 ||
	   layout.cipher_size > len(wire) - at {
		return
	}
	layout.cipher_offset = at
	at += layout.cipher_size
	// TLS1.3 permits only null compression. This is also the existing native
	// TLS1.2 compatibility profile; do not accept an unimplemented compressor.
	if len(wire) - at < 2 || wire[at] != 1 || wire[at + 1] != 0 do return
	at += 2
	if len(wire) - at < 2 do return
	layout.extensions_length_offset = at
	layout.extensions_size = int(hello_u16(wire, at)); at += 2
	layout.extensions_offset = at
	if layout.extensions_size != len(wire) - at do return
	seen: [1024]u64
	for at < len(wire) {
		if len(wire) - at < 4 do return
		kind := int(hello_u16(wire, at))
		size := int(hello_u16(wire, at + 2)); at += 4
		if size > len(wire) - at do return
		index, bit := kind / 64, u64(1) << uint(kind % 64)
		if seen[index] & bit != 0 do return
		seen[index] |= bit
		if kind == int(RETRY_COOKIE_EXTENSION) do layout.has_cookie = true
		at += size
	}
	return layout, true
}

@(private)
client_hello_layout_has_cipher :: proc(wire: []u8, layout: Client_Hello_Layout, suite: u16) -> bool {
	for at := layout.cipher_offset; at < layout.cipher_offset + layout.cipher_size; at += 2 {
		if hello_u16(wire, at) == suite do return true
	}
	return false
}

// Cookie may borrow HRR or CH1. Inputs may overlap each other, but neither may
// overlap either output range: output assembly would otherwise clobber a future
// read. Reject exact and partial overlap before any state or output mutation.
@(private)
client_hello_retry_inputs_disjoint :: proc(conn: ^Conn, retry, cookie: []u8, new_size: int) -> bool {
	hello := conn.retry_client_hello[:new_size]
	transcript := conn.retry_transcript[:MAX_MESSAGE_HASH_SIZE + len(retry)]
	return !bytes.alias(hello, retry) && !bytes.alias(hello, cookie) &&
	       !bytes.alias(transcript, retry) && !bytes.alias(transcript, cookie)
}
