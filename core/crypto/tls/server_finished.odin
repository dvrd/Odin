package tls

import "core:crypto"
import "core:crypto/hash"

// Reuse the now unborrowed output grant for at most 36 input bytes. No new
// allocation or persistent owner storage is needed after draining the flight.
@(private)
server_handshake_finished_feed :: proc(
	owner: ^Server_Handshake,
	level: Server_Handshake_Level,
	input: []u8,
) -> (
	consumed: int,
	status: Server_Handshake_Status,
	error: Server_Handshake_Error,
) {
	if level != .Handshake {
		server_handshake_fail(owner, .Wrong_Level)
		return 0, .Terminal, .Wrong_Level
	}
	algorithm := CIPHER_SUITE_HASH[owner._flight.cipher]
	digest_size := hash.DIGEST_SIZES[algorithm]
	finished_size := 4 + digest_size
	if len(owner._output) < finished_size {
		server_handshake_fail(owner, .Invalid_State)
		return 0, .Terminal, .Invalid_State
	}
	for owner._received < 4 && consumed < len(input) {
		owner._header[owner._received] = input[consumed]
		owner._received += 1
		consumed += 1
		if owner._header[0] != u8(Handshake_Type.Finished) {
			server_handshake_fail(owner, .Malformed)
			return consumed, .Terminal, .Malformed
		}
	}
	if owner._received < 4 {
		return consumed, .Need_Input, .None
	}
	if owner._header[1] != 0 || owner._header[2] != 0 || int(owner._header[3]) != digest_size {
		server_handshake_fail(owner, .Malformed)
		return consumed, .Terminal, .Malformed
	}
	copy(owner._output[:4], owner._header[:])
	n := min(len(input) - consumed, finished_size - owner._received)
	copy(owner._output[owner._received:finished_size], input[consumed:consumed + n])
	owner._received += n
	consumed += n
	if owner._received < finished_size {
		return consumed, .Need_Input, .None
	}

	if !server_finished_matches(owner, owner._output[4:finished_size]) {
		server_handshake_fail(owner, .Finished_Failed)
		return consumed, .Terminal, .Finished_Failed
	}
	// The binding supplies a single encryption level per call. A coalesced
	// suffix is still old-level data, never application data to silently drop.
	if consumed != len(input) {
		server_handshake_fail(owner, .Malformed)
		return consumed, .Terminal, .Malformed
	}
	if owner._resumed {
		owner._peer_identity = {
			authenticated      = owner._resumption.claims.authenticated,
			certificate_sha256 = owner._resumption.claims.peer,
		}
		owner._peer_expires = owner._resumption.claims.peer_expires
	}
	ticket := server_resumption_issue(owner, owner._output[:finished_size])
	// Final authenticated transcript has been consumed by ticket derivation. Wipe handshake
	// transients before Complete; keep selected parameters until its acceptance.
	server_handshake_cleanup(owner, true)
	if !server_handshake_id(owner) {
		server_handshake_fail(owner, .Identity_Exhausted)
		return consumed, .Terminal, .Identity_Exhausted
	}
	owner._phase = .Complete
	owner._event = {
		id   = owner._next_id,
		kind = .Complete,
	}
	if ticket {
		owner._event = {
			id    = owner._next_id,
			kind  = .Handshake_Bytes,
			level = .Application,
			bytes = owner._resumption.wire[:owner._resumption.wire_size],
		}
	}
	return consumed, .Need_Event_Drain, .None
}

// Constant-time check of the client's verify_data against the MAC of the
// client handshake traffic secret over the transcript through server Finished
// and any client authentication flight.
@(private)
server_finished_matches :: proc(owner: ^Server_Handshake, verify_data: []u8) -> bool {
	algorithm := CIPHER_SUITE_HASH[owner._flight.cipher]
	digest_size := hash.DIGEST_SIZES[algorithm]

	digest_storage, expected_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
	defer crypto.zero_explicit(&expected_storage, size_of(expected_storage))

	digest := transcript_hash(&owner._transcript, digest_storage[:])
	expected := expected_storage[:digest_size]
	schedule_finished_mac(algorithm, owner._flight.client_handshake_secret[:digest_size], digest, expected)
	return crypto.compare_constant_time(verify_data, expected) == 1
}
