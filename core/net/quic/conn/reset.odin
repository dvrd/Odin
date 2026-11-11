package conn
import "core:crypto"
import "core:net/quic"
import "core:net/quic/harness"
import "core:time"

@(private)
reset_now :: proc() -> i64 {return time.to_unix_nanoseconds(time.now()) / i64(time.Millisecond)}
@(private)
migration_release_local :: proc(c: ^Connection, entry: ^CID_Entry) {
	if c.migration.reset_secrets != nil && entry.reset_lease.held {
		_ = quic.reset_cid_release(c.migration.reset_secrets, &entry.reset_lease, reset_now())
	}
}
@(private)
migration_release_secrets :: proc(c: ^Connection) {
	for &entry in c.migration.local {migration_release_local(c, &entry)}
}

was_stateless_reset :: proc(c: ^Connection) -> bool {return c != nil && c.stateless_reset}
@(private)
reset_terminal :: proc(c: ^Connection) {
	cancel(c); harness.destroy(&c.model); crypto.zero_explicit(&c.migration, size_of(c.migration))
	crypto.zero_explicit(&c.send_mem, size_of(c.send_mem))
	crypto.zero_explicit(&c.recv_mem, size_of(c.recv_mem))
	crypto.zero_explicit(&c.crypto_mem, size_of(c.crypto_mem))
	crypto.zero_explicit(&c.udp_hold, size_of(c.udp_hold))
	crypto.zero_explicit(&c.tx, size_of(c.tx))
	crypto.zero_explicit(&c.material.shared, size_of(c.material.shared)); c.stateless_reset = true
}
@(private)
discard_reset :: proc(c: ^Connection, packet: []u8) -> Error {
	if observe_unrouted_reset(c, packet) {
		return .Stateless_Reset
	}; return .Discarded
}

// Unknown CID prefixes are normal in stateless resets. Authentication is tried
// with copied read keys first: valid packets never trigger suffix matching and
// an unknown-CID key update must not change the live read generation.
observe_unrouted_reset :: proc(c: ^Connection, packet: []u8) -> bool {
	if c == nil ||
	   !c.initialized ||
	   c.phase != .Established ||
	   !c.hs.have_one_rtt ||
	   len(packet) < 21 ||
	   len(packet) > MAX_DATAGRAM ||
	   packet[0] & 0xc0 != 0x40 {
		return false
	}
	tokens: [CID_SLOTS][16]u8; n := peer_reset_tokens(c, tokens[:]); if n == 0 {
		return false
	}
	if reset_packet_authenticated(c, packet) {
		return false
	}
	matched := 0
	for i in 0 ..< n {matched |= crypto.compare_constant_time(packet[len(packet) - 16:], tokens[i][:])}
	crypto.zero_explicit(&tokens, size_of(tokens))
	if matched != 0 {
		reset_terminal(c); return true
	}; return false
}
@(private)
reset_packet_authenticated :: proc(c: ^Connection, packet: []u8) -> bool {
	keys := c.hs.one_rtt_read; defer quic.packet_keys_clear(&keys)
	buf: [MAX_DATAGRAM]u8; copy(buf[:], packet); raw := buf[:len(packet)]
	if quic.header_protection_remove(raw, &keys, .One_RTT, c.local_cid_len) != .None {
		return false
	}
	view, consumed, e := quic.packet_decode_v1(raw, c.local_cid_len)
	if e != .None || consumed != len(raw) || view.kind != .One_RTT {
		return false
	}
	fields, fe := quic.unprotected_fields_decode(view, raw); if fe != .None {
		return false
	}
	pn, pe := quic.handshake_reconstruct_pn(
		&c.hs,
		.One_RTT,
		u64(fields.packet_number),
		fields.packet_number_length * 8,
	); if pe != .None {
		return false
	}
	end := fields_header_end(raw, c.local_cid_len); if end <= 0 || end >= len(raw) {
		return false
	}
	plain: [MAX_DATAGRAM]u8; defer crypto.zero_explicit(&plain, size_of(plain))
	_, oe := quic.payload_open(plain[:], raw[:end], raw[end:], &keys, pn)
	return oe == .None || oe == .Invalid_Header && fields.reserved_bits != 0
}
