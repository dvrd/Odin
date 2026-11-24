package tls

import "base:runtime"
import "core:io"
import "core:mem"
import "core:time"
import credential_store "credentials/store"

/*
The server handshake behind the package's `Error`.

A `Server_Handshake` does no I/O. The caller feeds it the bytes the peer sent
and takes events from it: bytes to send, traffic secrets, the client's offer to
answer, completion. That one engine serves TLS over TCP and QUIC alike.
*/

// server_handshake_init prepares a server handshake that owns its memory through `allocator`.
@(require_results)
server_handshake_init :: proc(
	owner: ^Server_Handshake,
	config: Server_Handshake_Config,
	allocator: mem.Allocator,
) -> Error {
	return server_handshake_error(engine_server_handshake_init(owner, config, allocator))
}

// server_handshake_feed gives the handshake bytes the peer sent at `level`, and returns how many it took.
@(require_results)
server_handshake_feed :: proc(
	owner: ^Server_Handshake,
	level: Server_Handshake_Level,
	input: []u8,
) -> (int, Server_Handshake_Status, Error) {
	r0, r1, failure := engine_server_handshake_feed(owner, level, input)
	return r0, r1, server_handshake_error(failure)
}

// server_handshake_peek returns the next event without removing it.
@(require_results)
server_handshake_peek :: proc(owner: ^Server_Handshake) -> (Server_Handshake_Event, Error) {
	r0, failure := engine_server_handshake_peek(owner)
	return r0, server_handshake_error(failure)
}

// server_handshake_accept removes the event `id` once the caller has acted on it.
@(require_results)
server_handshake_accept :: proc(owner: ^Server_Handshake, id: u64) -> Error {
	return server_handshake_error(engine_server_handshake_accept(owner, id))
}

// server_handshake_abort ends the handshake and wipes its secrets.
server_handshake_abort :: proc(owner: ^Server_Handshake) -> Error {
	return server_handshake_error(engine_server_handshake_abort(owner))
}

// server_handshake_destroy releases everything the handshake owns.
server_handshake_destroy :: proc(owner: ^Server_Handshake) -> Error {
	return server_handshake_error(engine_server_handshake_destroy(owner))
}

// server_handshake_stats reports what the handshake has allocated.
@(require_results)
server_handshake_stats :: proc(owner: ^Server_Handshake) -> (Server_Handshake_Stats, Error) {
	r0, failure := engine_server_handshake_stats(owner)
	return r0, server_handshake_error(failure)
}

// server_handshake_select_parameters answers the Peer_Parameters event `id` with the caller's choice.
@(require_results)
server_handshake_select_parameters :: proc(
	owner: ^Server_Handshake,
	id: u64,
	config: Server_Handshake_Parameters_Config,
) -> Error {
	return server_handshake_error(engine_server_handshake_select_parameters(owner, id, config))
}

// server_handshake_parameters returns what the client offered, while its Peer_Parameters event is pending.
@(require_results)
server_handshake_parameters :: proc(owner: ^Server_Handshake) -> (Server_Handshake_Parameters, Error) {
	r0, failure := engine_server_handshake_parameters(owner)
	return r0, server_handshake_error(failure)
}

// server_handshake_start_flight signs and queues the server's flight with a credential from `store`.
@(require_results)
server_handshake_start_flight :: proc(
	owner: ^Server_Handshake,
	store: ^credential_store.Store,
	now: time.Time,
) -> Error {
	return server_handshake_error(engine_server_handshake_start_flight(owner, store, now))
}

// server_ticket_keys_init creates the first ticket key.
@(require_results)
server_ticket_keys_init :: proc(keys: ^Server_Ticket_Keys, max_lifetime: time.Duration = 24 * time.Hour) -> Error {
	return ticket_error(engine_server_ticket_keys_init(keys, max_lifetime))
}

// server_ticket_keys_rotate replaces the ticket key, keeping the previous one for tickets already issued.
@(require_results)
server_ticket_keys_rotate :: proc(keys: ^Server_Ticket_Keys, now: time.Time) -> Error {
	return ticket_error(engine_server_ticket_keys_rotate(keys, now))
}

// anti_replay_init allocates the record of early data already accepted.
@(require_results)
anti_replay_init :: proc(
	owner: ^Anti_Replay,
	capacity: int = 1024,
	allocator: mem.Allocator = context.allocator,
) -> Error {
	return anti_replay_error(engine_anti_replay_init(owner, capacity, allocator))
}

@(private, require_results)
server_handshake_error :: proc(failure: Server_Handshake_Error) -> Error {
	switch failure {
	case .None:
		return nil
	case .Invalid_Config:
		return General_Error.Invalid_Config
	case .Invalid_Owner, .Invalid_State, .Invalid_Event, .Wrong_Level:
		return General_Error.Invalid_State
	case .Malformed:
		return Protocol_Error.Decode_Error
	case .Unsupported:
		return Protocol_Error.Handshake_Failure
	case .Limit, .Identity_Exhausted:
		return General_Error.Limit_Exceeded
	case .Allocation_Failed:
		return runtime.Allocator_Error.Out_Of_Memory
	case .Cancelled:
		return General_Error.Cancelled
	case .Credential_Failed, .Signing_Failed:
		return General_Error.Credential_Failed
	case .Entropy_Unavailable:
		return General_Error.Entropy_Unavailable
	case .Client_Authentication_Failed:
		return Protocol_Error.Bad_Certificate
	case .Binder_Failed, .Finished_Failed:
		return Protocol_Error.Decrypt_Error
	case .No_Application_Protocol:
		return Protocol_Error.No_Application_Protocol
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
ticket_error :: proc(failure: Server_Ticket_Error) -> Error {
	switch failure {
	case .None:
		return nil
	case .Invalid:
		return General_Error.Invalid_Config
	case .Closed:
		return io.Error.Closed
	case .Entropy:
		return General_Error.Entropy_Unavailable
	case .Clock:
		return General_Error.Clock_Unavailable
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
anti_replay_error :: proc(failure: Anti_Replay_Error) -> Error {
	switch failure {
	case .None:
		return nil
	case .Invalid:
		return General_Error.Invalid_Config
	case .Closed:
		return io.Error.Closed
	case .Capacity:
		return General_Error.Limit_Exceeded
	case .Replayed, .Expired:
		return General_Error.Early_Data_Rejected
	case .Clock:
		return General_Error.Clock_Unavailable
	case .Allocation:
		return runtime.Allocator_Error.Out_Of_Memory
	}
	return Protocol_Error.Internal_Error
}
