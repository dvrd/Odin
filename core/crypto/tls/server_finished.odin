package tls

// Reuse the now unborrowed output grant for at most 36 input bytes. No new
// allocation or persistent owner storage is needed after draining the flight.
@(private)
server_handshake_finished_feed :: proc(owner: ^Server_Handshake, level: Server_Handshake_Level, input: []u8) -> (consumed: int, status: Server_Handshake_Status, error: Server_Handshake_Error) {
	if level != .Handshake {
		server_handshake_fail(owner, .Wrong_Level)
		return 0, .Terminal, .Wrong_Level
	}
	if len(owner._output) < FINISHED_MESSAGE_SIZE {
		server_handshake_fail(owner, .Invalid_State)
		return 0, .Terminal, .Invalid_State
	}
	for owner._received < 4 && consumed < len(input) {
		owner._header[owner._received] = input[consumed]
		owner._received += 1; consumed += 1
		if owner._header[0] != u8(Handshake_Type.Finished) {
			server_handshake_fail(owner, .Malformed)
			return consumed, .Terminal, .Malformed
		}
	}
	if owner._received < 4 {return consumed, .Need_Input, .None}
	if owner._header[1] != 0 || owner._header[2] != 0 || owner._header[3] != 32 {
		server_handshake_fail(owner, .Malformed)
		return consumed, .Terminal, .Malformed
	}
	copy(owner._output[:4], owner._header[:])
	n := min(len(input)-consumed, FINISHED_MESSAGE_SIZE-owner._received)
	copy(owner._output[owner._received:FINISHED_MESSAGE_SIZE], input[consumed:consumed+n])
	owner._received += n; consumed += n
	if owner._received < FINISHED_MESSAGE_SIZE {return consumed, .Need_Input, .None}
	if finished_verify(owner._output[:FINISHED_MESSAGE_SIZE], owner._flight.client_finished_secret, transcript_snapshot(&owner._transcript)) != .None {
		server_handshake_fail(owner, .Finished_Failed)
		return consumed, .Terminal, .Finished_Failed
	}
	// The binding supplies a single encryption level per call. A coalesced
	// suffix is still old-level data, never application data to silently drop.
	if consumed != len(input) {
		server_handshake_fail(owner, .Malformed)
		return consumed, .Terminal, .Malformed
	}
	// No post-handshake transcript consumers in this profile. Wipe handshake
	// transients before Complete; keep selected parameters until its acceptance.
	server_handshake_cleanup(owner, true)
	if !server_handshake_id(owner) {
		server_handshake_fail(owner, .Identity_Exhausted)
		return consumed, .Terminal, .Identity_Exhausted
	}
	owner._phase = .Complete
	owner._event = {id=owner._next_id, kind=.Complete}
	return consumed, .Need_Event_Drain, .None
}
