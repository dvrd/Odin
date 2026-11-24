package quic
import "core:crypto"
import "core:crypto/tls"
import "core:time"

// Server read keys come only from the TLS engine's admitted early-secret event.
handshake_install_zero_rtt_read :: proc(h: ^Handshake, traffic_secret: []u8) -> Session_Error {
	if h == nil || h.failed || h.role != .Server || len(traffic_secret) != 32 || h.zero_rtt_read.initialized {
		return .Invalid_State
	}
	secret: [32]u8
	copy(secret[:], traffic_secret)
	defer crypto.zero_explicit(&secret, size_of(secret))
	keys, e := tls.quic_packet_keys_derive(secret, .Application)
	defer tls.quic_direction_keys_clear(&keys)
	if e != nil {
		return .Invalid_State
	}
	if packet_keys_set_aes(&h.zero_rtt_read, keys.key[:], keys.iv[:], keys.hp[:], keys.secret[:], false) != .None {
		return .Invalid_State
	}
	h.zero_rtt_read.zero_rtt = true
	h.have_zero_rtt = true
	return .None
}

handshake_discard_zero_rtt :: proc(h: ^Handshake) {
	if h != nil {
		packet_keys_clear(&h.zero_rtt_write)
		packet_keys_clear(&h.zero_rtt_read)
		h.have_zero_rtt = false
	}
}

handshake_zero_rtt_header_protection_apply :: proc(h: ^Handshake, packet: []u8) -> Protection_Error {
	if h == nil || h.failed || h.role != .Client || !h.have_zero_rtt {
		return .Invalid_Keys
	}
	return header_protection_apply(packet, &h.zero_rtt_write, .Zero_RTT)
}

handshake_zero_rtt_header_protection_remove :: proc(h: ^Handshake, packet: []u8) -> Protection_Error {
	if h == nil || h.failed || h.role != .Server || !h.have_zero_rtt {
		return .Invalid_Keys
	}
	return header_protection_remove(packet, &h.zero_rtt_read, .Zero_RTT)
}

handshake_zero_rtt_payload_seal :: proc(h: ^Handshake, dst, header, plain: []u8, pn: u64) -> (int, Protection_Error) {
	if h == nil || h.failed || h.role != .Client || !h.have_zero_rtt {
		return 0, .Invalid_Keys
	}
	return payload_seal(dst, header, plain, &h.zero_rtt_write, pn)
}

handshake_zero_rtt_payload_open :: proc(h: ^Handshake, dst, header, cipher: []u8, pn: u64) -> (int, Protection_Error) {
	if h == nil || h.failed || h.role != .Server || !h.have_zero_rtt {
		return 0, .Invalid_Keys
	}
	return payload_open(dst, header, cipher, &h.zero_rtt_read, pn)
}

handshake_remember_ticket :: proc(
	h: ^Handshake,
	message: []u8,
	session: ^tls.Session,
	scope: tls.Quic_Session_Scope,
	now: time.Time,
) -> tls.Error {
	if h == nil || h.failed || !h.peer_authenticated || !h.have_resumption_master {
		return tls.General_Error.Invalid_Config
	}
	return tls.quic_session_remember(session, h.resumption_master, message, scope, now)
}
