package tls

// Opaque local TLS state, not transport health or permission to free an owner.
// Closed includes closing/failed owners whose callbacks may still be pending.
Async_Idle_State :: enum {
	Ready,
	Busy,
	Buffered,
	Closed,
	Invalid,
}

// Call only on this Async_Conn's executor owner thread, serialized with its
// calls/callbacks. Async_Conn has no thread identity to check here. This reads
// fixed state only: no I/O, allocation, scheduling, key validation mutation or
// connection changes. Ready says nothing about bytes in the native receive
// queue, an external executor's unrelated work or a future peer closure.
//
// Precedence: nil/uninitialized Invalid; terminal/closing Closed; invalid local
// shape Invalid; handshake/accepted operation or queued work Busy; residual
// receive/control/output state Buffered; otherwise authenticated local Ready.
async_idle_state :: proc(conn: ^Async_Conn) -> Async_Idle_State {
	if conn == nil || !conn.initialized {
		return .Invalid
	}
	p := &conn.protocol
	state := &p.application
	if conn.closing ||
	   conn.transport_closing ||
	   conn.transport_closed ||
	   p.phase == .Closed ||
	   p.phase == .Failed ||
	   state.peer_closed ||
	   conn.notify_sent ||
	   conn.failure.kind != .None ||
	   conn.io_error.kind != .None ||
	   conn.close_error.kind != .None ||
	   p.handshake_error.kind != .None ||
	   state.failure.kind != .None ||
	   state.send.failure != .None ||
	   state.receive.failure != .None {
		return .Closed
	}
	if conn.transport.submit == nil ||
	   conn.transport.cancel == nil ||
	   conn.executor.schedule == nil ||
	   state.inbound_at < 0 ||
	   state.inbound_size < state.inbound_at ||
	   state.inbound_size > len(state.inbound) ||
	   state.post_used < 0 ||
	   state.post_used > len(state.post_handshake) ||
	   state.post_expected < 0 ||
	   state.post_expected > len(state.post_handshake) ||
	   conn.rx_used < 0 ||
	   conn.rx_used > len(conn.rx_wire) ||
	   conn.rx_expected < 0 ||
	   conn.rx_expected > len(conn.rx_wire) ||
	   conn.tx_size < 0 ||
	   conn.tx_size > len(conn.tx_wire) ||
	   conn.tx_plain_count < 0 ||
	   conn.tx_plain_count > MAX_PLAINTEXT_SIZE ||
	   conn.hello_used < 0 ||
	   conn.hello_used > len(conn.hello) ||
	   conn.flight_used < 0 ||
	   p.server_handshake_header_used < 0 ||
	   p.server_handshake_header_used > len(p.server_handshake_header) ||
	   p.server_handshake_remaining < 0 {
		return .Invalid
	}
	switch p.phase {
	case .Handshake_Pending,
	     .Awaiting_Server_Hello,
	     .Hello_Retry_Received,
	     .Server_Hello_Received,
	     .Handshake_Keys_Ready,
	     .Server_Finished_Received:
		return .Busy
	case .Established:
	case .Uninitialized, .Failed, .Closed:
		return .Invalid
	case:
		return .Invalid
	}
	if !p.handshake_complete || !state.initialized || !state.send.initialized || !state.receive.initialized {
		return .Invalid
	}
	// These directions cannot process another old-key record. Do not invoke
	// protection_state_validate: its key-usage failure path mutates the owner.
	if state.send.seq >= record_protection_limit(&state.send) ||
	   state.receive.seq >= record_protection_limit(&state.receive) {
		return .Closed
	}
	if conn.handshake_op != nil ||
	   conn.read_op != nil ||
	   conn.write_op != nil ||
	   conn.close_op != nil ||
	   conn.rx.pending ||
	   conn.tx.pending ||
	   conn.shutdown.pending ||
	   conn.queued ||
	   conn.tx_done {
		return .Busy
	}
	if state.inbound_at != state.inbound_size ||
	   state.post_used != 0 ||
	   state.post_expected != 0 ||
	   state.key_update_pending ||
	   application_send_key_exhausted(state) ||
	   conn.rx_used != 0 ||
	   conn.rx_expected != 0 ||
	   conn.rx_error.kind != .None ||
	   conn.tx_kind != .None ||
	   conn.notify_allowed ||
	   raw_data(conn.read_buffer) != nil ||
	   raw_data(conn.write_buffer) != nil ||
	   raw_data(conn.flight) != nil ||
	   conn.hello_used != 0 ||
	   p.server_handshake_header_used != 0 ||
	   p.server_handshake_remaining != 0 ||
	   p.handshake_send.initialized ||
	   p.handshake_receive.initialized {
		return .Buffered
	}
	// Handshake transcript/material and completed-record arrays retain HISTORY:
	// finishing remains true, flight_used survives freeing flight, tx_size and
	// tx_plain_count survive processing tx_kind=None. Deadlines/cancel flags,
	// raw op results and equal inbound_at/inbound_size are likewise historical.
	// None of those bytes/counters is an outstanding input/output owner.
	return .Ready
}
