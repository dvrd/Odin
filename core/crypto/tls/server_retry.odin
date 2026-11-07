package tls

import "core:crypto"

// Reuses application-secret storage before any flight/credentials exist. The
// first hello stays immutable while the second is assembled in ordinary input.
@(private)
Server_Retry :: struct {first_hello: []u8}

@(private)
server_retry_active :: proc(owner: ^Server_Handshake) -> bool {
	return owner._flight.stage == .Retry_Wait
}
@(private)
server_retry_clear :: proc(owner: ^Server_Handshake) {
	grant := owner._flight.retry.first_hello
	owner._stats.live_bytes -= len(grant)
	server_handshake_wipe_free(owner, grant)
	crypto.zero_explicit(&owner._flight.transient, size_of(owner._flight.transient))
	owner._flight.stage = .None
}

// No cookie is emitted: this is a stateful single key-share retry. The cookie
// budget is zero; unsolicited cookies are rejected by the hello decoder.
@(private)
server_retry_begin :: proc(owner: ^Server_Handshake) -> Server_Handshake_Error {
	owner._flight.stage = .Retry_Wait
	owner._flight.retry.first_hello = owner._input
	owner._input = nil
	owner._received, owner._message_size = 0, 0
	crypto.zero_explicit(&owner._header, size_of(owner._header))
	transcript_retry(&owner._transcript)
	wire: [88]u8
	at := 4
	hello_put_u16(wire[:], &at, 0x0303)
	for b,i in HELLO_RETRY_REQUEST_RANDOM {wire[at+i]=b}; at += 32
	session := owner._hello.session_id
	wire[at] = u8(len(session)); at += 1; copy(wire[at:], session); at += len(session)
	hello_put_u16(wire[:], &at, 0x1301); wire[at] = 0; at += 1
	hello_put_u16(wire[:], &at, 12)
	hello_put_u16(wire[:], &at, 43); hello_put_u16(wire[:], &at, 2); hello_put_u16(wire[:], &at, 0x0304)
	hello_put_u16(wire[:], &at, 51); hello_put_u16(wire[:], &at, 2); hello_put_u16(wire[:], &at, u16(owner._selection.group))
	wire[0] = 2; server_flight_put24(wire[1:4], at-4)
	return server_flight_bytes(owner, transmute([]u8)wire[:at], true)
}

@(private)
server_retry_extensions_at :: proc(hello: Server_Client_Hello_View) -> int {
	at := 39 + len(hello.session_id)
	at += 2 + int(hello_u16(hello.wire, at))
	at += 1 + int(hello.wire[at])
	return at+2
}

// Both inputs have already passed the bounded codec. Unknown extensions and
// ordering must stay identical too. Only key_share, PSK update, early_data
// removal and zero padding are exceptions to exact equality.
@(private)
server_retry_invariants :: proc(first, second: Server_Client_Hello_View, group: Named_Group) -> bool {
	if second.early_data || len(second.key_shares) < 4 ||
	   hello_u16(second.key_shares,0) != u16(group) ||
	   int(hello_u16(second.key_shares,2)) != len(second.key_shares)-4 {return false}
	a, b := server_retry_extensions_at(first), server_retry_extensions_at(second)
	if string(first.wire[4:a-2]) != string(second.wire[4:b-2]) {return false}
	for {
		for a < len(first.wire) {
			kind := hello_u16(first.wire,a)
			if kind != 51 && kind != 41 && kind != 42 && kind != 21 {break}
			a += 4 + int(hello_u16(first.wire,a+2))
		}
		for b < len(second.wire) {
			kind := hello_u16(second.wire,b)
			if kind != 51 && kind != 41 && kind != 21 {break}
			b += 4 + int(hello_u16(second.wire,b+2))
		}
		if a == len(first.wire) || b == len(second.wire) {
			if a != len(first.wire) || b != len(second.wire) {return false}
			break
		}
		n := 4 + int(hello_u16(first.wire,a+2))
		m := 4 + int(hello_u16(second.wire,b+2))
		if n != m || string(first.wire[a:a+n]) != string(second.wire[b:b+m]) {return false}
		a += n; b += m
	}
	return server_retry_psk_invariants(first, second)
}

// We never select PSK. The client may update ages/binder values and remove
// identities incompatible with SHA256 (binder size !=32), retaining order and
// unchanged identity bytes/compatible binder sizes. No PSK may be added.
@(private)
server_retry_psk_invariants :: proc(first, second: Server_Client_Hello_View) -> bool {
	a, b, ab, bb := 0, 0, 0, 0
	for a < len(first.psk_identities) {
		n := int(hello_u16(first.psk_identities,a)); a += 2
		binder := int(first.psk_binders[ab]); ab += 1 + binder
		if b < len(second.psk_identities) {
			m := int(hello_u16(second.psk_identities,b))
			if n == m && string(first.psk_identities[a:a+n]) == string(second.psk_identities[b+2:b+2+m]) {
				if int(second.psk_binders[bb]) != binder {return false}
				b += 2 + m + 4; bb += 1 + binder
				a += n + 4; continue
			}
		}
		if binder == 32 {return false}
		a += n + 4
	}
	return b == len(second.psk_identities)
}
