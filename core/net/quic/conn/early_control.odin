package conn

import "core:net"

// Authentication can precede authenticated transport-parameter admission.
// These records own every borrowed frame byte until migration initialization.
EARLY_CONTROL_CAP :: 64

Early_Control :: struct {
	kind:            enum {
		New_ID,
		Retire_ID,
		Challenge,
	},
	sequence, prior: u64,
	id:              [CID_CAP]u8,
	id_n:            int,
	token:           [16]u8,
	destination:     [CID_CAP]u8,
	destination_n:   int,
	origin:          net.Endpoint,
}

@(private)
early_defer_control :: proc(c: ^Connection, p: Parsed, destination: []u8) -> Error {
	if p.new_id_n > 0 && c.peer_cid_len == 0 || p.retire_id_n > 0 && c.local_cid_len == 0 {
		return .Protocol
	}
	state := &c.early_state
	pending := state.controls
	n := state.control_n
	for i in 0 ..< p.new_id_n + p.retire_id_n + p.path_n {
		item := Early_Control {
			destination_n = len(destination),
			origin        = state.incoming,
		}
		copy(item.destination[:], destination)
		if i < p.new_id_n {
			f := p.new_ids[i]
			item.kind = .New_ID
			item.sequence = f.sequence
			item.prior = f.retire_prior_to
			item.id_n = len(f.id)
			item.token = f.token
			copy(item.id[:], f.id)
		} else if i < p.new_id_n + p.retire_id_n {
			item.kind = .Retire_ID
			item.sequence = p.retire_ids[i - p.new_id_n]
		} else {
			item.kind = .Challenge
			path := p.paths[i - p.new_id_n - p.retire_id_n]
			copy(item.token[:], path.token[:])
		}
		duplicate := false
		for j in 0 ..< n {
			if pending[j] == item {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if n == len(pending) {
			return .Protocol
		}
		pending[n] = item
		n += 1
	}
	state.controls = pending
	state.control_n = n
	return early_flush_control(c)
}

@(private)
early_flush_control :: proc(c: ^Connection) -> Error {
	if !c.early_state.confirmed {
		return .None
	}
	state := &c.early_state
	at := 0
	for at < state.control_n {
		item := &state.controls[at]
		if item.kind == .Challenge && !c.migration.enabled {
			// A zero-length CID disables migration, but not path challenge responses.
			if c.local_cid_len != 0 && c.peer_cid_len != 0 {
				at += 1
				continue
			}
			if state.endpoint.address == nil || item.origin.address != nil && item.origin != state.endpoint {
				return .Protocol
			}
			if c.path_response_pending {
				at += 1
				continue
			}
			c.path_response_pending = true
			copy(c.path_response_token[:], item.token[:8])
		} else if item.kind == .Challenge {
			// Never create or promote a path from replayable traffic. The caller must
			// already have admitted this exact endpoint through the initial handshake.
			origin := item.origin
			if origin.address == nil {
				origin = c.migration.paths[c.migration.active].endpoint
			}
			index := path_index(c, origin)
			if index != c.migration.active || index < 0 {
				return .Protocol
			}
			path := &c.migration.paths[index]
			if !path.validated {
				return .Protocol
			}
			if path.response_pending {
				at += 1
				continue
			}
			path.response_pending = true
			copy(path.response[:], item.token[:8])
		} else {
			if !c.migration.enabled {
				at += 1
				continue
			}
			parsed: Parsed
			if item.kind == .New_ID {
				parsed.new_id_n = 1
				parsed.new_ids[0] = {
					sequence        = item.sequence,
					retire_prior_to = item.prior,
					id              = item.id[:item.id_n],
					token           = item.token,
				}
			} else {
				parsed.retire_id_n = 1
				parsed.retire_ids[0] = item.sequence
			}
			if e := apply_ids(c, parsed, item.destination[:item.destination_n]); e != .None {
				return e
			}
		}
		for j in at ..< state.control_n - 1 {state.controls[j] = state.controls[j + 1]}
		state.control_n -= 1
		state.controls[state.control_n] = {}
	}
	return .None
}
