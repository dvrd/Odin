package tls

import "core:mem"

// Local policy ceilings, not RFC transport-parameter limits. Both peer and
// server parameter blobs are opaque: only the QUIC binding knows their meaning.
SERVER_QUIC_PARAMETERS_CAP :: 1024

Server_Handshake_Mode :: enum {
	TCP,
	QUIC,
}

Server_Handshake_Parameters_Config :: struct {
	mode:                      Server_Handshake_Mode,
	alpn_protocols:            []string, // Server preference; copied selection only.
	require_alpn:              bool,
	quic_transport_parameters: []u8,
}

@(private)
Server_Handshake_Parameters :: struct {
	mode:                        Server_Handshake_Mode,
	alpn, peer_quic, local_quic: []u8,
	authenticated:               bool,
}

@(private)
Server_Parameters :: struct {
	storage:  []u8,
	value:    Server_Handshake_Parameters,
	selected: bool,
}

// Acknowledge the current Peer_Parameters event and choose its response. In
// QUIC mode this call is the binding's explicit acceptance hook: it MUST first
// validate peer transport-parameter semantics and its own local parameters.
// Configuration is borrowed for this call only. API/config errors preserve the
// pending event; protocol/resource rejection terminates and revokes all borrows.
server_handshake_select_parameters :: proc(
	owner: ^Server_Handshake,
	id: u64,
	config: Server_Handshake_Parameters_Config,
) -> Server_Handshake_Error {
	if !server_handshake_valid(owner) {
		return .Invalid_Owner
	}
	if owner._phase != .Await_Flight || owner._event.kind != .Peer_Parameters || owner._parameters.selected {
		return .Invalid_State
	}
	if id == 0 || id != owner._event.id {
		return .Invalid_Event
	}
	e := server_parameters_select(owner, config)
	if e == .Invalid_Config {
		return e
	}
	if e != .None {
		server_handshake_fail(owner, e)
		return e
	}
	return server_handshake_accept(owner, id)
}

// Borrowed final selections, tentative until Finished verification. Even an
// authenticated value does not permit application delivery until Complete is
// accepted. Copy durable values before accepting Complete; all borrows end then,
// or on failure/abort/destroy. This query never exposes the raw offer as selected.
server_handshake_parameters :: proc(
	owner: ^Server_Handshake,
) -> (
	Server_Handshake_Parameters,
	Server_Handshake_Error,
) {
	if !server_handshake_valid(owner) {
		return {}, .Invalid_Owner
	}
	if !owner._parameters.selected {
		return {}, .Invalid_State
	}
	value := owner._parameters.value
	value.authenticated = owner._phase == .Complete
	return value, .None
}

@(private)
server_parameters_select :: proc(
	owner: ^Server_Handshake,
	config: Server_Handshake_Parameters_Config,
) -> Server_Handshake_Error {
	_, valid := alpn_protocols_size(config.alpn_protocols)
	if !valid ||
	   (config.mode != .TCP && config.mode != .QUIC) ||
	   (config.require_alpn || config.mode == .QUIC) && len(config.alpn_protocols) == 0 ||
	   len(config.quic_transport_parameters) > SERVER_QUIC_PARAMETERS_CAP ||
	   config.mode == .TCP && len(config.quic_transport_parameters) != 0 {
		return .Invalid_Config
	}
	for name, i in config.alpn_protocols {
		for previous in config.alpn_protocols[:i] {
			if name == previous {
				return .Invalid_Config
			}
		}
	}
	hello := &owner._hello
	if config.mode == .TCP && hello.has_quic_transport_parameters {
		return .Unsupported
	}
	if config.mode == .QUIC {
		if !hello.has_quic_transport_parameters || len(hello.session_id) != 0 {
			return .Malformed
		}
		if len(hello.quic_transport_parameters) > SERVER_QUIC_PARAMETERS_CAP {
			return .Limit
		}
	}
	selected: []u8
	for name in config.alpn_protocols {
		for at := 0; at < len(hello.alpn_protocols); {
			n := int(hello.alpn_protocols[at])
			at += 1
			if string(hello.alpn_protocols[at:at + n]) == name {
				selected = hello.alpn_protocols[at:at + n]
				break
			}
			at += n
		}
		if len(selected) > 0 {
			break
		}
	}
	// An ALPN-capable server fails when both sides offered lists but cannot
	// agree (RFC7301 3.2). Optional permits absent offers, not failed overlap.
	if len(selected) == 0 &&
	   (config.require_alpn ||
			   config.mode == .QUIC ||
			   len(config.alpn_protocols) > 0 && len(hello.alpn_protocols) > 0) {
		return .No_Application_Protocol
	}
	size := len(selected)
	if config.mode == .QUIC {
		size += len(hello.quic_transport_parameters) + len(config.quic_transport_parameters)
	}
	storage: []u8
	if size > 0 {
		grant, ok := server_handshake_allocate(owner, size)
		if !ok {
			return .Allocation_Failed
		}
		storage = grant
	}
	p := &owner._parameters
	p.storage, p.selected, p.value.mode = storage, true, config.mode
	copy(storage, selected)
	p.value.alpn = storage[:len(selected)]
	if config.mode == .QUIC {
		at := len(selected)
		end := at + len(hello.quic_transport_parameters)
		copy(storage[at:end], hello.quic_transport_parameters)
		p.value.peer_quic = storage[at:end]
		copy(storage[end:], config.quic_transport_parameters)
		p.value.local_quic = storage[end:]
	}
	return .None
}

@(private)
server_parameters_clear :: proc(owner: ^Server_Handshake) {
	owner._stats.live_bytes -= len(owner._parameters.storage)
	server_handshake_wipe_free(owner, owner._parameters.storage)
	owner._parameters = {}
}

// Bounded by 6 + (4+2+1+255) + (4+1024) = 1296 bytes, below scratch.
@(private)
server_parameters_extensions :: proc(owner: ^Server_Handshake) -> Server_Handshake_Error {
	wire: [1300]u8
	at := 6
	p := &owner._parameters.value
	if len(p.alpn) > 0 {
		hello_put_u16(wire[:], &at, 16)
		hello_put_u16(wire[:], &at, u16(3 + len(p.alpn)))
		hello_put_u16(wire[:], &at, u16(1 + len(p.alpn)))
		wire[at] = u8(len(p.alpn))
		at += 1
		copy(wire[at:], p.alpn)
		at += len(p.alpn)
	}
	if p.mode == .QUIC {
		hello_put_u16(wire[:], &at, 57)
		hello_put_u16(wire[:], &at, u16(len(p.local_quic)))
		copy(wire[at:], p.local_quic)
		at += len(p.local_quic)
	}
	if server_handshake_early_accepted(owner) {
		hello_put_u16(wire[:], &at, 42)
		hello_put_u16(wire[:], &at, 0)
	}
	wire[0] = 8
	server_flight_put24(wire[1:4], at - 4)
	wire[4], wire[5] = u8((at - 6) >> 8), u8(at - 6)
	return server_flight_bytes(owner, mem.slice_ptr(cast(^u8)(cast(rawptr)&wire), at))
}
