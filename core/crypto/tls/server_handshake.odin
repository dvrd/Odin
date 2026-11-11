package tls

import "core:crypto"
import "core:mem"

SERVER_HANDSHAKE_OUTPUT_CAP :: 2048
Server_Handshake_Level :: enum {Initial, Handshake, Application}
Server_Handshake_Direction :: enum {Read, Write} // Relative to the local server.
Server_Handshake_Event_Kind :: enum {None, Handshake_Bytes, Traffic_Secret, Peer_Parameters, Early_Traffic_Secret, Complete, Fatal}
Server_Handshake_Error :: enum {
	None, Invalid_Config, Invalid_Owner, Invalid_State, Invalid_Event,
	Wrong_Level, Malformed, Unsupported, Limit, Allocation_Failed, Cancelled, Identity_Exhausted, Credential_Failed, Signing_Failed, Entropy_Unavailable, Client_Authentication_Failed, Binder_Failed, Finished_Failed, No_Application_Protocol,
}
Server_Handshake_Status :: enum {Need_Input, Need_Event_Drain, Await_Flight, Await_Client_Finished, Terminal, Invalid_Owner}
Server_Handshake_Config :: struct {
	max_client_hello_bytes: int,
	max_extensions: int,
	client_auth: ^Client_Auth_Config,
	tickets: ^Server_Ticket_Config,
}
SERVER_HANDSHAKE_DEFAULT_CONFIG :: Server_Handshake_Config{SERVER_CLIENT_HELLO_MAX_WIRE, SERVER_CLIENT_HELLO_MAX_ENTRIES, nil, nil}

// All fields are tentative offers, never authenticated negotiated parameters.
Server_Handshake_Peer_Parameters :: struct {
	server_name, alpn_offers, quic_transport_parameters: []u8,
	has_quic_transport_parameters: bool,
}
// Payloads borrow immutable owner/pinned credential storage until accept,
// abort or destroy. A copied event is still a borrow, not an ownership transfer.
Server_Handshake_Event :: struct {
	id: u64,
	kind: Server_Handshake_Event_Kind,
	level: Server_Handshake_Level,
	direction: Server_Handshake_Direction,
	cipher: Cipher_Suite,
	bytes, secret: []u8,
	peer: Server_Handshake_Peer_Parameters,
	error: Server_Handshake_Error,
}
Server_Handshake_Stats :: struct {
	requested_bytes, peak_bytes, live_bytes: int,
	allocation_attempts: int,
}
@(private)
Server_Handshake_Phase :: enum {Uninitialized, Client_Hello, Retry_Client_Hello, Await_Flight, Await_Client_Finished, Complete, Failed, Aborted, Destroyed}

// Initialize zeroed storage once, at its final address. No copies, concurrent
// calls, reentry or field mutation. Destroy does not make storage reusable:
// identities must never alias a previous borrow in the same owner lifetime.
Server_Handshake :: struct {
	_self: ^Server_Handshake,
	_phase: Server_Handshake_Phase,
	_allocator: mem.Allocator,
	_config: Server_Handshake_Config,
	_stats: Server_Handshake_Stats,
	_header: [4]u8,
	_received, _message_size: int,
	_input, _output: []u8,
	_hello: Server_Client_Hello_View,
	_selection: Server_Client_Hello_Selection,
	_transcript: Handshake_Transcript,
	_secret: [32]u8,
	_event: Server_Handshake_Event,
	_next_id: u64,
	_error: Server_Handshake_Error,
	_flight: Server_Flight,
	_parameters: Server_Parameters,
	_client_auth: ^Server_Client_Auth,
	_peer_identity: Peer_Identity,
	_peer_expires:i64,
	_resumption:^Server_Resumption,
	_resumed:bool,
 _retried:bool,
	_binder_transcript:Handshake_Transcript,
}

server_handshake_init :: proc(owner: ^Server_Handshake, config: Server_Handshake_Config, allocator: mem.Allocator) -> Server_Handshake_Error {
	if owner == nil {return .Invalid_Owner}
	if owner._self != nil || owner._phase != .Uninitialized {return .Invalid_State}
	if !server_ticket_config_valid(config.tickets) || !client_auth_config_valid(config.client_auth) || allocator.procedure == nil || config.max_client_hello_bytes < 45 ||
	   config.max_client_hello_bytes > SERVER_CLIENT_HELLO_MAX_WIRE || config.max_extensions < 1 ||
	   config.max_extensions > SERVER_CLIENT_HELLO_MAX_ENTRIES {return .Invalid_Config}
	owner._self = owner
	owner._allocator, owner._config, owner._phase = allocator, config, .Client_Hello
	transcript_init(&owner._transcript)
	return .None
}
@(private)
server_handshake_valid :: proc(owner: ^Server_Handshake) -> bool {
	return owner != nil && owner._self == owner
}
@(private)
server_handshake_wipe_free :: proc(owner: ^Server_Handshake, grant: []u8, alignment:int=1) {
	if raw_data(grant) == nil {return}
	crypto.zero_explicit(raw_data(grant), len(grant))
	_, _ = owner._allocator.procedure(owner._allocator.data, .Free, 0, alignment, raw_data(grant), len(grant))
}
@(private)
server_handshake_allocate :: proc(owner: ^Server_Handshake, size: int, alignment:int=1) -> ([]u8, bool) {
	owner._stats.allocation_attempts += 1
	owner._stats.requested_bytes += size
	grant, error := owner._allocator.procedure(owner._allocator.data, .Alloc, size, alignment, nil, 0)
	// Reject unusual grants, but erase/free their full reported extent, even
	// when the allocator returns storage together with an error.
	if error != nil || len(grant) != size || raw_data(grant) == nil {
		server_handshake_wipe_free(owner, grant,alignment)
		return nil, false
	}
	for &b in grant {b = 0}
	owner._stats.live_bytes += size
	owner._stats.peak_bytes = max(owner._stats.peak_bytes, owner._stats.live_bytes)
	return grant, true
}
@(private)
server_handshake_release_input :: proc(owner: ^Server_Handshake) {
	owner._hello, owner._selection = {}, {}
	owner._stats.live_bytes -= len(owner._input)
	server_handshake_wipe_free(owner, owner._input)
	owner._input = nil
	crypto.zero_explicit(&owner._header, size_of(owner._header))
	owner._received, owner._message_size = 0, 0
}
@(private)
server_handshake_clear_event :: proc(owner: ^Server_Handshake) {
	crypto.zero_explicit(&owner._secret, size_of(owner._secret))
	if len(owner._output) > 0 {crypto.zero_explicit(raw_data(owner._output), len(owner._output))}
	owner._event = {}
}
@(private)
server_handshake_cleanup :: proc(owner: ^Server_Handshake, keep_parameters := false) {
	if !keep_parameters {server_resumption_clear(owner);server_parameters_clear(owner);owner._peer_identity={};owner._resumed=false;owner._peer_expires=0}
	server_handshake_clear_event(owner)
	server_client_auth_clear(owner)
	server_flight_cleanup(owner)
	server_handshake_release_input(owner)
	owner._stats.live_bytes -= len(owner._output)
	server_handshake_wipe_free(owner, owner._output)
	owner._output = nil
	crypto.zero_explicit(&owner._transcript, size_of(owner._transcript))
}
@(private)
server_handshake_id :: proc(owner: ^Server_Handshake) -> bool {
	if owner._next_id == max(u64) {return false}
	owner._next_id += 1
	return true
}
@(private)
server_handshake_fail :: proc(owner: ^Server_Handshake, error: Server_Handshake_Error) {
	// A producer may already have published failure. Preserve that borrow/ID.
	if owner._phase == .Failed {return}
	server_handshake_cleanup(owner)
	owner._phase, owner._error = .Failed, error
	if server_handshake_id(owner) {
		owner._event = {id=owner._next_id, kind=.Fatal, error=error}
	}
}

// Input borrows end on return. Only consumed bytes have transferred; resubmit
// the untouched suffix. Finished input must contain Handshake-level bytes only.
server_handshake_feed :: proc(owner: ^Server_Handshake, level: Server_Handshake_Level, input: []u8) -> (consumed: int, status: Server_Handshake_Status, error: Server_Handshake_Error) {
	if !server_handshake_valid(owner) {return 0, .Invalid_Owner, .Invalid_Owner}
	if owner._phase == .Failed || owner._phase == .Aborted || owner._phase == .Destroyed {return 0, .Terminal, owner._error}
	if owner._phase == .Complete {
		return 0, .Terminal, .Invalid_State if len(input) > 0 else .None
	}
	if owner._event.kind != .None {return 0, .Need_Event_Drain, .None}
	if owner._phase == .Await_Client_Finished {
		if !owner._resumed && owner._config.client_auth != nil && owner._config.client_auth.mode != .Disabled {return server_client_auth_feed(owner, level, input)}
		return server_handshake_finished_feed(owner, level, input)
	}
	if owner._phase == .Await_Flight {return 0, .Await_Flight, .None}
	if level != .Initial {
		server_handshake_fail(owner, .Wrong_Level)
		return 0, .Terminal, .Wrong_Level
	}
	for owner._received < 4 && consumed < len(input) {
		owner._header[owner._received] = input[consumed]
		owner._received += 1; consumed += 1
		// Wrong message type is known immediately; do not consume its body.
		if owner._header[0] != u8(Handshake_Type.Client_Hello) {
			server_handshake_fail(owner, .Malformed); return consumed, .Terminal, .Malformed
		}
	}
	if owner._received < 4 {return consumed, .Need_Input, .None}
	if owner._message_size == 0 {
		limits := Server_Client_Hello_Limits{owner._config.max_client_hello_bytes, owner._config.max_extensions}
		size, probe := server_client_hello_size(owner._header[:], limits)
		if probe != .None || size < 45 {
			e := Server_Handshake_Error.Malformed
			if probe == .Limit {e = .Limit}
			server_handshake_fail(owner, e); return consumed, .Terminal, e
		}
		grant, ok := server_handshake_allocate(owner, size)
		if !ok {server_handshake_fail(owner, .Allocation_Failed); return consumed, .Terminal, .Allocation_Failed}
		owner._input, owner._message_size = grant, size
		copy(owner._input, owner._header[:])
	}
	n := min(len(input)-consumed, owner._message_size-owner._received)
	copy(owner._input[owner._received:], input[consumed:consumed+n])
	consumed += n; owner._received += n
	if owner._received < owner._message_size {return consumed, .Need_Input, .None}
	hello, decoded := server_client_hello_decode(owner._input, {owner._config.max_client_hello_bytes, owner._config.max_extensions})
	selection: Server_Client_Hello_Selection
	if decoded == .None {selection, decoded = server_client_hello_negotiate(hello)}
	retry := owner._phase == .Retry_Client_Hello
	if retry {
		if decoded != .None || selection.group != owner._selection.group || !server_retry_invariants(owner._hello,hello,owner._selection.group) {
			server_handshake_fail(owner,.Malformed); return consumed,.Terminal,.Malformed
		}
		server_retry_clear(owner)
	}
	if decoded != .None && decoded != .Retry_Required {
		e := Server_Handshake_Error.Unsupported
		if decoded == .Malformed {e = .Malformed}
		if decoded == .Limit {e = .Limit}
		server_handshake_fail(owner, e); return consumed, .Terminal, e
	}
	owner._hello, owner._selection = hello, selection
	owner._binder_transcript=owner._transcript
	transcript_update(&owner._transcript, owner._input)
	owner._phase = .Await_Flight
	if decoded == .Retry_Required {
 owner._retried=true;
		e := server_retry_begin(owner)
		if e != .None {server_handshake_fail(owner,e); return consumed,.Terminal,e}
		return consumed,.Need_Event_Drain,.None
	}
	if !server_handshake_id(owner) {
		server_handshake_fail(owner, .Identity_Exhausted); return consumed, .Terminal, .Identity_Exhausted
	}
	owner._event = {id=owner._next_id, kind=.Peer_Parameters,
		peer={hello.server_name, hello.alpn_protocols, hello.quic_transport_parameters, hello.has_quic_transport_parameters}}
	return consumed, .Need_Event_Drain, .None
}

server_handshake_peek :: proc(owner: ^Server_Handshake) -> (Server_Handshake_Event, Server_Handshake_Error) {
	if !server_handshake_valid(owner) {return {}, .Invalid_Owner}
	if owner._event.kind == .None && owner._flight.stage != .None {
		e := server_flight_next(owner)
		if e != .None {server_handshake_fail(owner, e)}
	}
	return owner._event, .None
}
server_handshake_accept :: proc(owner: ^Server_Handshake, id: u64) -> Server_Handshake_Error {
	if !server_handshake_valid(owner) {return .Invalid_Owner}
	if id == 0 || owner._event.kind == .None || id != owner._event.id {return .Invalid_Event}
	if owner._event.kind == .Complete {server_resumption_clear(owner);server_parameters_clear(owner)}
	ticket:=owner._event.kind==.Handshake_Bytes&&owner._event.level==.Application
 if owner._event.kind==.Early_Traffic_Secret&&owner._resumption!=nil {crypto.zero_explicit(&owner._resumption.early_secret,size_of(owner._resumption.early_secret))}
	retry := server_retry_active(owner) && owner._event.kind == .Handshake_Bytes
	if owner._event.kind == .Handshake_Bytes && owner._event.level!=.Application {transcript_update(&owner._transcript, owner._event.bytes)}
	server_handshake_clear_event(owner)
	if ticket {
	 if !server_handshake_id(owner) {server_handshake_fail(owner,.Identity_Exhausted);return .Identity_Exhausted}
	 owner._event={id=owner._next_id,kind=.Complete}
	}
	if retry {owner._phase = .Retry_Client_Hello}
	if owner._flight.stage == .End {_ = server_flight_next(owner)}
	return .None
}
// No alert callback or network close: the transport owns those decisions.
server_handshake_abort :: proc(owner: ^Server_Handshake) -> Server_Handshake_Error {
	if !server_handshake_valid(owner) {return .Invalid_Owner}
	if owner._phase == .Aborted || owner._phase == .Destroyed {return .None}
	server_handshake_cleanup(owner)
	if owner._error == .None {owner._error = .Cancelled}
	owner._phase = .Aborted
	return .None
}
server_handshake_destroy :: proc(owner: ^Server_Handshake) -> Server_Handshake_Error {
	if !server_handshake_valid(owner) {return .Invalid_Owner}
	if owner._phase == .Destroyed {return .None}
	server_handshake_cleanup(owner)
	owner._allocator, owner._config = {}, {}
	owner._phase = .Destroyed
	return .None
}
server_handshake_stats :: proc(owner: ^Server_Handshake) -> (Server_Handshake_Stats, Server_Handshake_Error) {
	if !server_handshake_valid(owner) {return {}, .Invalid_Owner}
	return owner._stats, .None
}

// Internal producer seam for server flight fragments. No public caller can
// manufacture success or install keys through the event consumer interface.
// A borrowed DER chunk must remain pinned by its producer through acceptance
// or cleanup. The flight producer owns that pin.
@(private)
server_handshake_publish :: proc(owner: ^Server_Handshake, source: Server_Handshake_Event, borrow_bytes := false) -> Server_Handshake_Error {
	event := source
	if !server_handshake_valid(owner) {return .Invalid_Owner}
	if owner._phase != .Await_Flight || owner._event.kind != .None {return .Invalid_State}
	#partial switch event.kind {
	case .Handshake_Bytes:
		if len(event.bytes) == 0 || len(event.bytes) > SERVER_HANDSHAKE_OUTPUT_CAP || event.level == .Application {return .Invalid_Event}
		if !borrow_bytes {
			if len(owner._output) == 0 {
				grant, ok := server_handshake_allocate(owner, SERVER_HANDSHAKE_OUTPUT_CAP)
				if !ok {server_handshake_fail(owner, .Allocation_Failed); return .Allocation_Failed}
				owner._output = grant
			}
			copy(owner._output, event.bytes)
			event.bytes = owner._output[:len(event.bytes)]
		}
	case .Traffic_Secret:
		if len(event.secret) != 32 || event.level == .Initial || event.cipher != .AES_128_GCM_SHA256 {return .Invalid_Event}
		copy(owner._secret[:], event.secret)
		event.secret = owner._secret[:]
	case .Complete: return .Invalid_Event // Only Finished verification can publish success.
	case: return .Invalid_Event
	}
	if !server_handshake_id(owner) {server_handshake_fail(owner, .Identity_Exhausted); return .Identity_Exhausted}
	// Rebuild the payload so unrelated caller-provided slices cannot escape.
	#partial switch event.kind {
	case .Handshake_Bytes: owner._event = {kind=event.kind, level=event.level, bytes=event.bytes}
	case .Traffic_Secret: owner._event = {kind=event.kind, level=event.level, direction=event.direction, cipher=event.cipher, secret=event.secret}
	}
	owner._event.id = owner._next_id
	return .None
}
