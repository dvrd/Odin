package tls

import "core:bytes"

TLS12_Framing_Error :: enum {
	None, Invalid_State, Message_Oversized, Overlapping_Buffers,
}

// Single-writer framing cursor over caller-owned storage. Input is copied and
// never retained; returned complete messages borrow storage until next/reset.
// It frames handshake messages, not TLS records or authenticated protocol order.
TLS12_Handshake_Framer :: struct {
	storage: []u8,
	used, expected: int,
	failure: TLS12_Framing_Error,
}

tls12_framing_init :: proc(storage: []u8) -> (TLS12_Handshake_Framer, TLS12_Framing_Error) {
	if len(storage)<4 || len(storage)>MAX_CERTIFICATE_MESSAGE_SIZE {
		return {},.Invalid_State
	}
	return {storage=storage},.None
}

// Consumes no more than one message, leaving coalesced record tails with the
// caller. Empty message means more input is needed. A zero-body message still
// returns its four-byte handshake header. An oversized advertised body poisons
// the cursor after consuming its header; no body is copied or allocated.
// Alias/local state errors consume/write nothing. Ownership, record types and
// the per-operation deadline remain the connection driver's responsibility.
tls12_framing_push :: proc(
	state: ^TLS12_Handshake_Framer, input: []u8,
) -> (consumed: int, message: []u8, error: TLS12_Framing_Error) {
	if state==nil || len(state.storage)<4 || len(state.storage)>MAX_CERTIFICATE_MESSAGE_SIZE {
		return 0,nil,.Invalid_State
	}
	if state.failure!=.None {return 0,nil,state.failure}
	if state.used<0 || state.used>len(state.storage) ||
	   state.expected<0 || state.expected>len(state.storage) ||
	   state.expected!=0 && (state.expected<4 || state.used<4 || state.used>state.expected) ||
	   state.expected==0 && state.used>=4 {
		return 0,nil,.Invalid_State
	}
	if bytes.alias(input,state.storage) {return 0,nil,.Overlapping_Buffers}
	if state.expected>0 && state.used==state.expected {
		return 0,state.storage[:state.used],.None
	}
	if state.used<4 {
		n:=min(4-state.used,len(input))
		copy(state.storage[state.used:state.used+n],input[:n])
		state.used+=n; consumed+=n
		if state.used<4 {return consumed,nil,.None}
		size:=4+handshake_body_size(state.storage[:4])
		if size>len(state.storage) {
			state.failure=.Message_Oversized
			return consumed,nil,state.failure
		}
		state.expected=size
	}
	n:=min(state.expected-state.used,len(input)-consumed)
	copy(state.storage[state.used:state.used+n],input[consumed:consumed+n])
	state.used+=n; consumed+=n
	if state.used==state.expected {message=state.storage[:state.used]}
	return consumed,message,.None
}

// Reset only a complete accepted message. The owner must first discard all
// borrowed message views. A failed/partial cursor requires explicit reinit or
// teardown rather than silently forgetting consumed protocol bytes.
tls12_framing_next :: proc(state: ^TLS12_Handshake_Framer) -> TLS12_Framing_Error {
	if state==nil || len(state.storage)<4 || len(state.storage)>MAX_CERTIFICATE_MESSAGE_SIZE ||
	   state.failure!=.None || state.expected<4 ||
	   state.used!=state.expected || state.used>len(state.storage) {
		return .Invalid_State
	}
	state.used,state.expected=0,0
	return .None
}
