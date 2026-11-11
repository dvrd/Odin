// QUIC v1 connection. Recovery, flow control, congestion and anti-amplification
// are the harness model. This package owns UDP, packet protection and stream
// bytes. 0-RTT stays refused unless a caller opts in elsewhere. This connection
// does not enable it. There is no replay policy on this path.
//
// Not implemented: migration and path validation, version negotiation (unknown
// versions and Version Negotiation packets are discarded), Retry, connection-ID
// retirement, preferred address, ECN, coalesced packets, multipath, and
// retransmission of a lost stream offset. The harness has no stream-offset
// replay; loss sends a PTO probe. CRYPTO is resent from offset zero because
// identical overlap is idempotent. Anti-amplification stays on until a
// Handshake packet is accepted. A UDP send is not a peer acknowledgment.
// Two connections on the sim are not an independent peer. Linux is not run
// from this tree.
//
// Do not copy a Connection after init. The harness borrows its packet tables.
// Caller-owned datagram buffers are borrowed only for the call that uses them.
package conn

import "core:bytes"
import "core:crypto"
import "core:crypto/tls"
import "core:crypto/x509"
import "core:net/quic"
import "core:net/quic/harness"
import "core:time"

STREAMS :: 32
STREAM_BYTES :: 256
PACKETS :: 64
CRYPTO_BYTES :: 2048
MAX_DATAGRAM :: harness.K_MAX_DATAGRAM
CID_CAP :: 20

Error :: enum {
	None,
	Invalid,
	Capacity,
	Flow_Control,
	Congestion,
	Anti_Amplification,
	Closed,
	Protocol,
	Cancelled,
	Failed,
	Handshake,
	Allocation,
	Not_Ready,
	Truncated,
	Pending,
	Partial,
	Discarded,
}

Phase :: enum {
	Handshake,
	Established,
	Draining,
	Closed,
	Failed,
}

Material :: struct {
	shared:                                          [32]u8,
	client_hello, server_hello, server_flight, params: []u8,
	server_name:                                     string,
	roots:                                           []^x509.Certificate,
	now:                                             time.Time,
}

Config :: struct {
	role:                     quic.Role,
	local_cid, peer_cid:      []u8,
	material:                 Material,
	limits:                   harness.Limits,
	max_datagram:             int,
	// Pad 1-RTT packets to max_datagram. Handshake packets stay natural size,
	// except Initial datagrams, which stay at the 1200-byte floor.
	full_size:                bool,
}

Timer :: struct {
	armed: bool,
	at:    i64,
	kind:  harness.Timer_Kind,
	space: harness.Space,
}

Buf :: struct {
	used:        bool,
	id:          u64,
	n:           int,
	// Bytes accepted by the harness. A freed stream reports offset 0; this does not.
	sent:        int,
	fin:         bool,
	fin_sent:    bool,
	reset:       bool,
	reset_sent:  bool,
	recv_n:      int,
	read_n:      int,
	recv_fin:    bool,
	recv_reset:  bool,
	reset_final: u64,
	stop:        bool,
}

Connection :: struct {
	initialized:             bool,
	role:                    quic.Role,
	phase:                   Phase,
	reason:                  string,
	full_size:               bool,
	max_datagram:            int,
	material:                Material,
	shared:                  [32]u8,
	hs:                      quic.Handshake,
	model:                   harness.Model,
	initial_pkts:            [PACKETS]harness.Packet,
	handshake_pkts:          [PACKETS]harness.Packet,
	app_pkts:                [PACKETS]harness.Packet,
	model_streams:           [STREAMS]harness.Stream,
	crypto_mem:              [3][CRYPTO_BYTES]u8,
	send_mem:                [STREAMS][STREAM_BYTES]u8,
	recv_mem:                [STREAMS][STREAM_BYTES]u8,
	bufs:                    [STREAMS]Buf,
	local_cid, peer_cid:     [CID_CAP]u8,
	local_cid_len:           int,
	peer_cid_len:            int,
	expected_finished:       [tls.FINISHED_MESSAGE_SIZE]u8,
	ch_off, sh_off:          int,
	flight_off, fin_off:     int,
	server_keys:             bool,
	accepted:                bool,
	authed:                  bool,
	finished_marked:         bool,
	got_handshake:           bool,
	got_finished:            bool,
	seen_done:               bool,
	done_sent:               bool,
	noted_send:              bool,
	noted_recv:              bool,
	want_close:              bool,
	close_sent:              bool,
	cancelled:               bool,
	force_probe:             bool,
	draining_until:          i64,
	pings:                   int,
	update_from:             u64,
	await_update:            bool,
	udp_hold:                [MAX_DATAGRAM]u8,
	udp_hold_len:            int,
}

init :: proc(c: ^Connection, cfg: Config) -> Error {
	if c == nil || c.initialized {
		return .Invalid
	}
	c^ = {}
	if cfg.role != .Client && cfg.role != .Server {
		return .Invalid
	}
	if len(cfg.local_cid) > CID_CAP || len(cfg.peer_cid) > CID_CAP {
		return .Invalid
	}
	max_datagram := cfg.max_datagram
	if max_datagram == 0 {
		max_datagram = harness.K_MIN_INITIAL_DATAGRAM
	}
	if max_datagram < harness.K_MIN_INITIAL_DATAGRAM || max_datagram > MAX_DATAGRAM {
		return .Invalid
	}
	if len(cfg.material.client_hello) == 0 || len(cfg.material.server_hello) == 0 || len(cfg.material.server_flight) == 0 {
		return .Invalid
	}
	if len(cfg.material.client_hello) > CRYPTO_BYTES || len(cfg.material.server_hello) > CRYPTO_BYTES || len(cfg.material.server_flight) > CRYPTO_BYTES {
		return .Capacity
	}
	c.role = cfg.role
	c.phase = .Handshake
	c.full_size = cfg.full_size
	c.max_datagram = max_datagram
	c.material = cfg.material
	c.shared = cfg.material.shared
	c.local_cid_len = len(cfg.local_cid)
	c.peer_cid_len = len(cfg.peer_cid)
	copy(c.local_cid[:], cfg.local_cid)
	copy(c.peer_cid[:], cfg.peer_cid)
	if quic.handshake_init(&c.hs, cfg.role, []string{"h3"}, c.crypto_mem[0][:], c.crypto_mem[1][:], c.crypto_mem[2][:]) != .None {
		c.reason = "handshake init"
		return .Handshake
	}
	// Initial secrets are derived from the client's original Destination CID.
	original := cfg.peer_cid if cfg.role == .Client else cfg.local_cid
	if _, se := quic.handshake_install_initial(&c.hs, original); se != .None {
		quic.handshake_fail(&c.hs)
		c.reason = "initial keys"
		return .Handshake
	}
	hrole := harness.Role.Client if cfg.role == .Client else harness.Role.Server
	if err := harness.init(
		&c.model,
		hrole,
		cfg.local_cid,
		cfg.peer_cid,
		c.initial_pkts[:],
		c.handshake_pkts[:],
		c.app_pkts[:],
		c.model_streams[:],
		max_datagram,
	); err != .None {
		quic.handshake_fail(&c.hs)
		c.reason = "harness init"
		return map_harness(err)
	}
	if err := harness.configure(&c.model, cfg.limits); err != .None {
		harness.destroy(&c.model)
		quic.handshake_fail(&c.hs)
		c.reason = "limits"
		return map_harness(err)
	}
	c.initialized = true
	return .None
}

destroy :: proc(c: ^Connection) {
	if c == nil {
		return
	}
	if c.initialized {
		harness.destroy(&c.model)
	}
	quic.handshake_fail(&c.hs)
	crypto.zero_explicit(&c.shared, size_of(c.shared))
	crypto.zero_explicit(&c.expected_finished, size_of(c.expected_finished))
	crypto.zero_explicit(&c.material.shared, size_of(c.material.shared))
	c^ = {}
}

established :: proc(c: ^Connection) -> bool {
	return c != nil && c.initialized && c.phase == .Established
}

stats :: proc(c: ^Connection) -> harness.Stats {
	if c == nil || !c.initialized {
		return {}
	}
	return harness.stats(&c.model)
}

pending_ack :: proc(c: ^Connection, space: harness.Space) -> (u64, u64, bool) {
	if c == nil || !c.initialized {
		return 0, 0, false
	}
	return harness.pending_ack(&c.model, space)
}

inject_allocation_failure :: proc(c: ^Connection, count: int) -> Error {
	if c == nil || !c.initialized {
		return .Invalid
	}
	return map_harness(harness.inject_allocation_failure(&c.model, count))
}

refuse_zero_rtt :: proc(c: ^Connection) -> Error {
	if c == nil || !c.initialized {
		return .Invalid
	}
	if quic.handshake_install_zero_rtt(&c.hs, nil) != .Zero_RTT_Disabled {
		return .Handshake
	}
	return .None
}

update_keys :: proc(c: ^Connection) -> Error {
	if c == nil || !c.initialized || c.phase != .Established {
		return .Not_Ready
	}
	if quic.handshake_advance_one_rtt(&c.hs) != .None {
		return .Handshake
	}
	c.update_from = c.model.spaces[int(harness.Space.Application)].next_send
	c.await_update = true
	return .None
}

queue_ping :: proc(c: ^Connection) -> Error {
	if c == nil || !c.initialized || c.cancelled {
		return .Invalid
	}
	if c.phase != .Established {
		return .Not_Ready
	}
	if c.pings == max(int) {
		return .Capacity
	}
	c.pings += 1
	return .None
}

write :: proc(c: ^Connection, id: u64, data: []u8, fin: bool) -> (int, Error) {
	if e := usable(c); e != .None {
		return 0, e
	}
	if !our_stream(c, id) {
		return 0, .Protocol
	}
	buf, err := take_buf(c, id, true)
	if err != .None {
		return 0, err
	}
	if buf.reset || buf.fin || buf.stop {
		return 0, .Protocol
	}
	if len(data) > STREAM_BYTES - buf.n {
		return 0, .Capacity
	}
	if !flow_fits(c, buf, len(data)) {
		return 0, .Flow_Control
	}
	copy(c.send_mem[buf_index(c, buf)][buf.n:], data)
	buf.n += len(data)
	if fin {
		buf.fin = true
	}
	return len(data), .None
}

read :: proc(c: ^Connection, id: u64, dst: []u8) -> (int, bool, Error) {
	if c == nil || !c.initialized {
		return 0, false, .Invalid
	}
	if c.cancelled {
		return 0, false, .Cancelled
	}
	if c.phase == .Failed {
		return 0, false, .Failed
	}
	buf := find_buf(c, id)
	if buf == nil {
		return 0, false, .None
	}
	if buf.recv_reset {
		return 0, false, .Protocol
	}
	n := buf.recv_n - buf.read_n
	if n > len(dst) {
		n = len(dst)
	}
	if n < 0 {
		return 0, false, .Protocol
	}
	idx := buf_index(c, buf)
	copy(dst[:n], c.recv_mem[idx][buf.read_n:buf.read_n + n])
	if n > 0 {
		if harness.consume_recv(&c.model, id, n) != .None {
			return 0, false, .Protocol
		}
		buf.read_n += n
	}
	fin := buf.recv_fin && buf.read_n == buf.recv_n
	return n, fin, .None
}

reset_stream :: proc(c: ^Connection, id: u64) -> Error {
	if e := usable(c); e != .None {
		return e
	}
	buf, err := take_buf(c, id, true)
	if err != .None {
		return err
	}
	if buf.fin_sent || buf.reset {
		return .Protocol
	}
	buf.reset = true
	buf.reset_final = u64(buf.n)
	return .None
}

close :: proc(c: ^Connection) -> Error {
	if c == nil || !c.initialized {
		return .Invalid
	}
	if c.cancelled || c.phase == .Failed {
		return .Failed if c.phase == .Failed else .Cancelled
	}
	if c.phase == .Closed || c.phase == .Draining {
		return .Closed
	}
	c.want_close = true
	return .None
}

cancel :: proc(c: ^Connection) {
	if c == nil || !c.initialized {
		return
	}
	c.cancelled = true
	c.phase = .Closed
	c.model.closed = true
	c.udp_hold_len = 0
	quic.handshake_fail(&c.hs)
	crypto.zero_explicit(&c.shared, size_of(c.shared))
	for &buf in c.bufs {
		buf = {}
	}
}

timer :: proc(c: ^Connection, now: i64) -> Timer {
	if c == nil || !c.initialized || c.cancelled || c.phase == .Closed || c.phase == .Failed {
		return {}
	}
	if c.phase == .Draining {
		return {armed = now < c.draining_until, at = c.draining_until}
	}
	got := harness.loss_detection_timer(&c.model, now)
	return {armed = got.armed, at = got.at, kind = got.kind, space = got.space}
}

on_timeout :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error) {
	if c == nil || !c.initialized {
		return 0, .Invalid
	}
	if c.cancelled {
		return 0, .Cancelled
	}
	if c.phase == .Failed {
		return 0, .Failed
	}
	if c.phase == .Closed {
		return 0, .Closed
	}
	if c.phase == .Draining {
		if now >= c.draining_until {
			c.phase = .Closed
		}
		return 0, .None
	}
	due := harness.loss_detection_timer(&c.model, now)
	lost: [PACKETS]u64
	_, _, err := harness.on_timeout(&c.model, now, lost[:])
	if err == .Invalid_Input || err == .Invalid_State {
		return 0, .Not_Ready
	}
	if err != .None {
		return 0, map_harness(err)
	}
	rewind(c, due.space)
	c.force_probe = true
	return pump(c, now, dst)
}

ingest :: proc(c: ^Connection, now: i64, path: u32, datagram: []u8) -> Error {
	if c == nil || !c.initialized {
		return .Invalid
	}
	if c.cancelled {
		return .Cancelled
	}
	if c.phase == .Failed {
		return .Failed
	}
	if c.phase == .Closed {
		return .Closed
	}
	if now < 0 || len(datagram) == 0 || len(datagram) > MAX_DATAGRAM {
		return .Invalid
	}
	if c.phase == .Draining {
		note_unparsed(c, path, len(datagram))
		return .None
	}
	inv, ierr := quic.invariant_decode(datagram, c.local_cid_len)
	if ierr != .None {
		return .Protocol
	}
	if !cid_equal(c.local_cid[:c.local_cid_len], inv.destination_id) {
		return .Discarded
	}
	if inv.long_header && (inv.version == 0 || inv.version != 1) {
		note_unparsed(c, path, len(datagram))
		c.reason = "version negotiation not implemented" if inv.version == 0 else c.reason
		return .Discarded
	}
	view, consumed, derr := quic.packet_decode_v1(datagram, c.local_cid_len)
	if derr != .None {
		note_unparsed(c, path, len(datagram))
		return .Discarded
	}
	if consumed != len(datagram) || view.kind == .Retry || view.kind == .Version_Negotiation || view.kind == .Zero_RTT {
		note_unparsed(c, path, len(datagram))
		return .Discarded
	}
	level := level_of(view.kind)
	packet: [MAX_DATAGRAM]u8
	copy(packet[:], datagram)
	if quic.handshake_header_protection_remove(&c.hs, packet[:consumed], level, c.local_cid_len) != .None {
		note_unparsed(c, path, len(datagram))
		c.reason = "header protection"
		return .None
	}
	fields, ferr := quic.unprotected_fields_decode(view_from(packet[:consumed], c.local_cid_len), packet[:consumed])
	if ferr != .None {
		note_unparsed(c, path, len(datagram))
		return .None
	}
	space := space_of(level)
	sp := c.model.spaces[int(space)]
	full, pok := harness.pn_decode(sp.has_largest_recv, sp.largest_recv, u64(fields.packet_number), fields.packet_number_length * 8)
	hf, he := quic.handshake_reconstruct_pn(&c.hs, level, u64(fields.packet_number), fields.packet_number_length * 8)
	if !pok || he != .None || hf != full {
		note_unparsed(c, path, len(datagram))
		c.reason = "packet number"
		return .None
	}
	header_end := fields_header_end(packet[:consumed], c.local_cid_len)
	if header_end <= 0 || header_end >= consumed {
		return .Protocol
	}
	plain: [MAX_DATAGRAM]u8
	pn, oerr := quic.handshake_payload_open(&c.hs, plain[:], packet[:header_end], packet[header_end:consumed], level, full)
	if oerr != .None {
		note_unparsed(c, path, len(datagram))
		c.reason = "decrypt"
		return .None
	}
	parsed, ok := parse_frames(plain[:pn])
	if !ok {
		fail(c, "frame")
		return .Protocol
	}
	if parsed.stream && !stream_fits_recv(c, parsed) {
		fail(c, "stream buffer")
		return .Capacity
	}
	dup := already_received(sp, full)
	req := shadow_from_parsed(parsed)
	shadow: [MAX_DATAGRAM]u8
	if len(datagram) > len(shadow) || !shadow_packet(c, shadow[:len(datagram)], space, fields.packet_number_length, u64(fields.packet_number), req, parsed.stream_off) {
		fail(c, "shadow")
		return .Protocol
	}
	if err := harness.receive(&c.model, now, path, shadow[:len(datagram)]); err != .None && err != .Closed {
		if err == .Discarded {
			return .None
		}
		fail(c, "harness receive")
		return map_harness(err)
	} else if err == .Closed {
		enter_drain(c, now)
	}
	if !dup {
		if e := apply_parsed(c, level, parsed); e != .None {
			return e
		}
		quic.handshake_note_authenticated_pn(&c.hs, level, full)
		if level == .Handshake && c.role == .Server && !c.noted_recv {
			if quic.handshake_note_handshake_packet(&c.hs, false) == .None {
				c.noted_recv = true
			}
		}
	}
	if c.hs.one_rtt_read.update_pending {
		_ = quic.packet_keys_confirm_update(&c.hs.one_rtt_read)
	}
	if c.await_update {
		app := c.model.spaces[int(harness.Space.Application)]
		if app.has_largest_acked && app.largest_acked >= c.update_from {
			if quic.handshake_confirm_one_rtt(&c.hs) == .None {
				c.await_update = false
			}
		}
	}
	if e := advance_crypto(c); e != .None {
		return e
	}
	if c.model.handshake_confirmed && c.phase == .Handshake {
		c.phase = .Established
	}
	if c.model.closed && c.phase != .Draining && c.phase != .Closed {
		enter_drain(c, now)
	}
	return .None
}

pump :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error) {
	if c == nil || !c.initialized {
		return 0, .Invalid
	}
	if c.cancelled {
		return 0, .Cancelled
	}
	if c.phase == .Failed {
		return 0, .Failed
	}
	if c.phase == .Closed || c.model.closed && c.close_sent {
		return 0, .Closed
	}
	if c.phase == .Draining || c.model.closed {
		if c.phase != .Draining {
			enter_drain(c, now)
		}
		return 0, .None
	}
	if c.want_close && !c.close_sent {
		return send_close(c, now, dst)
	}
	if c.role == .Client && !c.accepted {
		return send_crypto(c, now, dst, .Initial, c.material.client_hello, &c.ch_off)
	}
	if c.role == .Server && c.server_keys && c.sh_off < len(c.material.server_hello) {
		return send_crypto(c, now, dst, .Initial, c.material.server_hello, &c.sh_off)
	}
	if c.role == .Server && c.server_keys && c.sh_off >= len(c.material.server_hello) && c.flight_off < len(c.material.server_flight) {
		return send_crypto(c, now, dst, .Handshake, c.material.server_flight, &c.flight_off)
	}
	if c.role == .Client && c.authed && c.fin_off < c.hs.client_finished_len {
		return send_crypto(c, now, dst, .Handshake, c.hs.client_finished[:c.hs.client_finished_len], &c.fin_off)
	}
	// A PTO with nothing left to rewind still has to send an ack-eliciting probe.
	// Before confirmation that probe is Initial (1200 bytes) or Handshake.
	if c.force_probe && !c.model.handshake_confirmed {
		n, err := send_probe(c, now, dst)
		if err != .None || n > 0 {
			return n, err
		}
	}
	if c.phase == .Established || c.model.handshake_confirmed {
		if c.role == .Server && !c.done_sent {
			return send_done(c, now, dst)
		}
		if n, err, sent := send_stream_progress(c, now, dst); sent {
			return n, err
		}
		if c.pings > 0 || c.force_probe {
			return send_ping(c, now, dst)
		}
	}
	if n, err, sent := send_ack_only(c, now, dst); sent {
		return n, err
	}
	return 0, .None
}

@(private)
usable :: proc(c: ^Connection) -> Error {
	if c == nil || !c.initialized {
		return .Invalid
	}
	if c.cancelled {
		return .Cancelled
	}
	if c.phase == .Failed {
		return .Failed
	}
	if c.phase == .Closed || c.phase == .Draining {
		return .Closed
	}
	return .None
}

@(private)
fail :: proc(c: ^Connection, reason: string) {
	c.phase = .Failed
	c.reason = reason
	c.model.closed = true
}

@(private)
our_stream :: proc(c: ^Connection, id: u64) -> bool {
	want: u64 = 0 if c.role == .Client else 1
	return id % 4 == want
}

@(private)
buf_index :: proc(c: ^Connection, buf: ^Buf) -> int {
	return int((uintptr(buf) - uintptr(&c.bufs[0])) / size_of(Buf))
}

@(private)
find_buf :: proc(c: ^Connection, id: u64) -> ^Buf {
	for &buf in c.bufs {
		if buf.used && buf.id == id {
			return &buf
		}
	}
	return nil
}

@(private)
take_buf :: proc(c: ^Connection, id: u64, create: bool) -> (^Buf, Error) {
	if buf := find_buf(c, id); buf != nil {
		return buf, .None
	}
	if !create {
		return nil, .Invalid
	}
	if id != c.model.next_send_stream && find_model_stream(c, id) < 0 {
		return nil, .Protocol
	}
	for &buf in c.bufs {
		if !buf.used {
			buf = {}
			buf.used = true
			buf.id = id
			return &buf, .None
		}
	}
	return nil, .Capacity
}

@(private)
find_model_stream :: proc(c: ^Connection, id: u64) -> int {
	for s, i in c.model.streams {
		if s.active && s.id == id {
			return i
		}
	}
	return -1
}

@(private)
stream_next :: proc(c: ^Connection, id: u64) -> u64 {
	i := find_model_stream(c, id)
	if i < 0 {
		return 0
	}
	return c.model.streams[i].next_offset
}

@(private)
flow_fits :: proc(c: ^Connection, buf: ^Buf, n: int) -> bool {
	if n < 0 {
		return false
	}
	end := u64(buf.n + n)
	if end > c.model.max_stream_data_send {
		return false
	}
	unsent := u64(0)
	for other in c.bufs {
		if !other.used || other.reset {
			continue
		}
		off := u64(other.sent)
		if u64(other.n) > off {
			unsent += u64(other.n) - off
		}
	}
	if buf.reset {
		return true
	}
	return c.model.data_sent + unsent + u64(n) <= c.model.max_data
}

@(private)
map_harness :: proc(err: harness.Error) -> Error {
	switch err {
	case .None:
		return .None
	case .Capacity:
		return .Capacity
	case .Flow_Control:
		return .Flow_Control
	case .Congestion_Limited:
		return .Congestion
	case .Anti_Amplification:
		return .Anti_Amplification
	case .Closed:
		return .Closed
	case .Allocation:
		return .Allocation
	case .Discarded:
		return .Discarded
	case .Invalid_State, .Invalid_Input, .Datagram_Too_Small, .Protocol, .Destination_Undersized, .Overlap:
		return .Protocol
	}
	return .Protocol
}

@(private)
level_of :: proc(kind: quic.Packet_Kind) -> quic.Encryption_Level {
	switch kind {
	case .Initial:
		return .Initial
	case .Handshake:
		return .Handshake
	case .One_RTT, .Zero_RTT:
		return .One_RTT
	case .Retry, .Version_Negotiation:
		return .Initial
	}
	return .Initial
}

@(private)
space_of :: proc(level: quic.Encryption_Level) -> harness.Space {
	switch level {
	case .Initial:
		return .Initial
	case .Handshake:
		return .Handshake
	case .One_RTT:
		return .Application
	}
	return .Initial
}

@(private)
cid_equal :: proc(a, b: []u8) -> bool {
	return len(a) == len(b) && bytes.equal(a, b)
}

@(private)
note_unparsed :: proc(c: ^Connection, path: u32, n: int) {
	m := &c.model
	if !m.has_path || path != m.path {
		m.has_path = true
		m.path = path
		m.address_validated = false
		m.path_received = 0
		m.path_sent = 0
	}
	if n < 0 || m.path_received > max(int) - n {
		return
	}
	m.path_received += n
}

@(private)
enter_drain :: proc(c: ^Connection, now: i64) {
	if c.phase == .Closed || c.phase == .Failed {
		return
	}
	c.phase = .Draining
	base := c.model.smoothed_rtt
	varied := c.model.rttvar * 4
	if varied < c.model.granularity {
		varied = c.model.granularity
	}
	if base > max(i64) - varied {
		base = max(i64) / 4
	} else {
		base += varied
	}
	if base < 1 {
		base = 1
	}
	if base > max(i64) / 3 {
		base = max(i64) / 3
	}
	until := now + 3 * base
	if c.draining_until == 0 || until < c.draining_until {
		c.draining_until = until
	}
}

@(private)
rewind :: proc(c: ^Connection, space: harness.Space) {
	switch space {
	case .Initial:
		if c.role == .Client && !c.accepted {
			c.ch_off = 0
		}
		if c.role == .Server && !c.got_handshake {
			c.sh_off = 0
		}
	case .Handshake:
		if c.role == .Server && !c.got_finished {
			c.flight_off = 0
		}
		if c.role == .Client && !c.seen_done {
			c.fin_off = 0
		}
	case .Application:
	}
}

@(private)
prefix_ok :: proc(buf, expect: []u8) -> bool {
	return len(buf) >= len(expect) && bytes.equal(buf[:len(expect)], expect)
}

@(private)
advance_crypto :: proc(c: ^Connection) -> Error {
	if c.role == .Server && !c.server_keys {
		got, err := quic.handshake_crypto_bytes(&c.hs, .Initial)
		if err == .None && prefix_ok(got, c.material.client_hello) {
			if e := install_server_keys(c); e != .None {
				return e
			}
		}
	}
	if c.role == .Client && !c.accepted {
		got, err := quic.handshake_crypto_bytes(&c.hs, .Initial)
		if err == .None && prefix_ok(got, c.material.server_hello) {
			he := quic.handshake_accept_client_hello(&c.hs, c.shared, c.material.client_hello, c.material.server_hello, c.material.params)
			if he.kind != .None {
				fail(c, "client hello")
				return .Handshake
			}
			if harness.arm_handshake(&c.model) != .None {
				fail(c, "arm")
				return .Handshake
			}
			c.accepted = true
		}
	}
	if c.role == .Client && c.accepted && !c.authed {
		got, err := quic.handshake_crypto_bytes(&c.hs, .Handshake)
		if err == .None && prefix_ok(got, c.material.server_flight) {
			ae := quic.handshake_authenticate_server(
				&c.hs,
				c.material.client_hello,
				c.material.server_hello,
				c.material.server_flight,
				c.material.server_name,
				c.material.roots,
				c.material.now,
				c.material.params,
			)
			if ae.kind != .None {
				fail(c, "authenticate")
				return .Handshake
			}
			c.authed = true
		}
	}
	if c.role == .Server && c.server_keys && !c.got_finished {
		got, err := quic.handshake_crypto_bytes(&c.hs, .Handshake)
		expect := c.expected_finished[:tls.FINISHED_MESSAGE_SIZE]
		if err == .None && prefix_ok(got, expect) {
			if harness.confirm_handshake(&c.model) != .None {
				fail(c, "confirm")
				return .Handshake
			}
			c.got_finished = true
			if c.phase == .Handshake {
				c.phase = .Established
			}
		}
	}
	return .None
}

@(private)
install_server_keys :: proc(c: ^Connection) -> Error {
	shared := c.shared
	defer crypto.zero_explicit(&shared, size_of(shared))
	hs, he := tls.quic_handshake_secrets(shared, c.material.client_hello, c.material.server_hello, c.material.params)
	defer tls.quic_handshake_keys_clear(&hs)
	if he.kind != .None {
		fail(c, "server handshake secrets")
		return .Handshake
	}
	if quic.packet_keys_set_aes(&c.hs.handshake_write, hs.server.key[:], hs.server.iv[:], hs.server.hp[:], hs.server.secret[:], false) != .None ||
	   quic.packet_keys_set_aes(&c.hs.handshake_read, hs.client.key[:], hs.client.iv[:], hs.client.hp[:], hs.client.secret[:], false) != .None {
		fail(c, "server handshake keys")
		return .Handshake
	}
	c.hs.handshake_secret = hs.handshake_secret
	c.hs.have_handshake = true
	c.hs.local_parameters = c.material.params
	app, finished, ae := tls.quic_application_secrets(
		hs.handshake_secret,
		c.material.client_hello,
		c.material.server_hello,
		c.material.server_flight,
		c.material.server_name,
		c.material.roots,
		c.material.now,
		c.material.params,
		c.material.params,
	)
	defer tls.quic_application_keys_clear(&app)
	defer crypto.zero_explicit(&finished, size_of(finished))
	if ae.kind != .None {
		fail(c, "server application secrets")
		return .Handshake
	}
	if quic.packet_keys_set_aes(&c.hs.one_rtt_write, app.server.key[:], app.server.iv[:], app.server.hp[:], app.server.secret[:], true) != .None ||
	   quic.packet_keys_set_aes(&c.hs.one_rtt_read, app.client.key[:], app.client.iv[:], app.client.hp[:], app.client.secret[:], true) != .None {
		fail(c, "server application keys")
		return .Handshake
	}
	c.expected_finished = finished
	c.hs.have_one_rtt = true
	c.hs.peer_authenticated = true
	c.hs.handshake_complete = true
	if harness.arm_handshake(&c.model) != .None {
		fail(c, "server arm")
		return .Handshake
	}
	c.server_keys = true
	return .None
}

@(private)
shadow_from_parsed :: proc(parsed: Parsed) -> harness.Emit {
	req: harness.Emit
	req.attach_ack = parsed.ack
	req.ack_largest = parsed.ack_largest
	req.ack_smallest = parsed.ack_smallest
	req.ping = parsed.ping || parsed.crypto || parsed.handshake_done
	req.stream = parsed.stream
	req.stream_id = parsed.stream_id
	req.stream_len = len(parsed.stream_data)
	req.fin = parsed.fin
	req.reset = parsed.reset
	if parsed.reset {
		req.stream_id = parsed.reset_id
		req.reset_final = parsed.reset_final
	}
	req.stop_sending = parsed.stop
	if parsed.stop {
		req.stream_id = parsed.stop_id
	}
	req.max_data = parsed.max_data
	req.max_data_value = parsed.max_data_v
	req.connection_close = parsed.close
	req.handshake_confirmed = parsed.handshake_done
	return req
}

@(private)
stream_fits_recv :: proc(c: ^Connection, parsed: Parsed) -> bool {
	buf := find_buf(c, parsed.stream_id)
	have := 0
	if buf != nil {
		have = buf.recv_n
	}
	if u64(have) != parsed.stream_off {
		return true
	}
	return len(parsed.stream_data) <= STREAM_BYTES - have
}

@(private)
apply_parsed :: proc(c: ^Connection, level: quic.Encryption_Level, parsed: Parsed) -> Error {
	if parsed.crypto {
		if quic.handshake_ingest_crypto(&c.hs, level, parsed.crypto_off, parsed.crypto_data) != .None {
			fail(c, "crypto")
			return .Handshake
		}
	}
	if parsed.stream {
		buf, err := take_recv(c, parsed.stream_id)
		if err != .None {
			fail(c, "recv stream")
			return err
		}
		if u64(buf.recv_n) == parsed.stream_off {
			idx := buf_index(c, buf)
			copy(c.recv_mem[idx][buf.recv_n:], parsed.stream_data)
			buf.recv_n += len(parsed.stream_data)
		}
		if parsed.fin {
			buf.recv_fin = true
		}
	}
	if parsed.reset {
		buf, err := take_recv(c, parsed.reset_id)
		if err != .None {
			fail(c, "reset stream")
			return err
		}
		buf.recv_reset = true
		buf.reset_final = parsed.reset_final
	}
	if parsed.stop {
		if buf := find_buf(c, parsed.stop_id); buf != nil {
			buf.stop = true
			buf.reset = true
			buf.reset_final = stream_next(c, parsed.stop_id)
		}
	}
	if parsed.handshake_done {
		c.seen_done = true
	}
	if parsed.close {
		c.reason = "peer close"
	}
	return .None
}

@(private)
take_recv :: proc(c: ^Connection, id: u64) -> (^Buf, Error) {
	if buf := find_buf(c, id); buf != nil {
		return buf, .None
	}
	for &buf in c.bufs {
		if !buf.used {
			buf = {}
			buf.used = true
			buf.id = id
			return &buf, .None
		}
	}
	return nil, .Capacity
}

@(private)
view_from :: proc(packet: []u8, dcid: int) -> quic.Packet_View {
	view, _, _ := quic.packet_decode_v1(packet, dcid)
	return view
}

@(private)
fields_header_end :: proc(packet: []u8, dcid: int) -> int {
	view, _, err := quic.packet_decode_v1(packet, dcid)
	if err != .None {
		return 0
	}
	fields, ferr := quic.unprotected_fields_decode(view, packet)
	if ferr != .None {
		return 0
	}
	return view.packet_number_offset + fields.packet_number_length
}

@(private)
send_crypto :: proc(c: ^Connection, now: i64, dst: []u8, level: quic.Encryption_Level, data: []u8, off: ^int) -> (int, Error) {
	if off^ > len(data) {
		return 0, .Protocol
	}
	if off^ == len(data) {
		return 0, .None
	}
	chunk := len(data) - off^
	if chunk > c.max_datagram / 2 {
		chunk = c.max_datagram / 2
	}
	space := space_of(level)
	req := harness.Emit {
		space = space,
		ping = true,
		more_data = off^ + chunk < len(data),
		probe = c.force_probe,
	}
	attach_ack(c, &req, space)
	frame: [MAX_DATAGRAM]u8
	at := 0
	aok: bool
	at, aok = encode_ack_if(frame[:], at, req)
	if !aok {
		return 0, .Protocol
	}
	cok: bool
	at, cok = encode_crypto(frame[:], at, u64(off^), data[off^:off^ + chunk])
	if !cok {
		return 0, .Protocol
	}
	n, err := seal_and_emit(c, now, dst, req, frame[:at], 0)
	if err != .None {
		return 0, err
	}
	off^ += chunk
	c.force_probe = false
	if level == .Handshake && c.role == .Client && !c.noted_send {
		if quic.handshake_note_handshake_packet(&c.hs, true) == .None {
			c.noted_send = true
		}
	}
	if level == .Handshake && c.role == .Client && off^ == len(data) && !c.finished_marked {
		if quic.handshake_note_finished_sent(&c.hs) == .None {
			c.finished_marked = true
		}
	}
	if level == .Handshake && c.role == .Server {
		c.got_handshake = true
	}
	return n, .None
}

@(private)
send_done :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error) {
	req := harness.Emit {
		space = .Application,
		handshake_confirmed = true,
		probe = c.force_probe,
	}
	attach_ack(c, &req, .Application)
	frame: [64]u8
	at, ok := encode_ack_if(frame[:], 0, req)
	if !ok {
		return 0, .Protocol
	}
	at, ok = encode_done(frame[:], at)
	if !ok {
		return 0, .Protocol
	}
	n, err := seal_and_emit(c, now, dst, req, frame[:at], 0)
	if err != .None {
		return 0, err
	}
	c.done_sent = true
	c.force_probe = false
	c.seen_done = true
	return n, .None
}

@(private)
send_probe :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error) {
	if !c.model.spaces[int(harness.Space.Initial)].discarded {
		return send_ping_in(c, now, dst, .Initial)
	}
	if c.model.handshake_armed && !c.model.spaces[int(harness.Space.Handshake)].discarded {
		return send_ping_in(c, now, dst, .Handshake)
	}
	return 0, .None
}

@(private)
send_ping :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error) {
	return send_ping_in(c, now, dst, .Application)
}

@(private)
send_ping_in :: proc(c: ^Connection, now: i64, dst: []u8, space: harness.Space) -> (int, Error) {
	req := harness.Emit {
		space = space,
		ping = true,
		more_data = c.pings > 1,
		probe = c.force_probe,
	}
	attach_ack(c, &req, space)
	frame: [64]u8
	at, ok := encode_ack_if(frame[:], 0, req)
	if !ok {
		return 0, .Protocol
	}
	at, ok = encode_ping(frame[:], at)
	if !ok {
		return 0, .Protocol
	}
	n, err := seal_and_emit(c, now, dst, req, frame[:at], 0)
	if err != .None {
		return 0, err
	}
	if c.pings > 0 {
		c.pings -= 1
	}
	c.force_probe = false
	return n, .None
}

@(private)
send_close :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error) {
	space := harness.Space.Initial
	if c.model.handshake_confirmed {
		space = .Application
	} else if c.model.handshake_armed {
		space = .Handshake
	}
	req := harness.Emit {
		space = space,
		connection_close = true,
	}
	frame: [32]u8
	at, ok := encode_close(frame[:], 0)
	if !ok {
		return 0, .Protocol
	}
	n, err := seal_and_emit(c, now, dst, req, frame[:at], 0)
	if err != .None {
		return 0, err
	}
	c.close_sent = true
	enter_drain(c, now)
	return n, .None
}

@(private)
send_ack_only :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error, bool) {
	spaces := [?]harness.Space{.Application, .Handshake, .Initial}
	for space in spaces {
		if c.model.spaces[int(space)].discarded {
			continue
		}
		lo, hi, ready := harness.pending_ack(&c.model, space)
		if !ready {
			continue
		}
		if space == .Application && !c.model.handshake_confirmed {
			continue
		}
		req := harness.Emit {
			space = space,
			attach_ack = true,
			ack_largest = hi,
			ack_smallest = lo,
		}
		frame: [64]u8
		at, ok := encode_ack(frame[:], 0, hi, lo)
		if !ok {
			return 0, .Protocol, true
		}
		n, err := seal_and_emit(c, now, dst, req, frame[:at], 0)
		return n, err, true
	}
	return 0, .None, false
}

@(private)
send_stream_progress :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error, bool) {
	if !c.model.handshake_confirmed {
		return 0, .None, false
	}
	for &buf in c.bufs {
		if !buf.used {
			continue
		}
		if buf.reset && !buf.reset_sent {
			req := harness.Emit {
				space = .Application,
				reset = true,
				stream_id = buf.id,
				reset_final = buf.reset_final,
				probe = c.force_probe,
			}
			if u64(buf.n) > buf.reset_final {
				req.reset_final = u64(buf.n)
			}
			attach_ack(c, &req, .Application)
			frame: [64]u8
			at, ok := encode_ack_if(frame[:], 0, req)
			if !ok {
				return 0, .Protocol, true
			}
			at, ok = encode_reset(frame[:], at, buf.id, req.reset_final)
			if !ok {
				return 0, .Protocol, true
			}
			n, err := seal_and_emit(c, now, dst, req, frame[:at], 0)
			if err != .None {
				return 0, err, true
			}
			buf.reset_sent = true
			c.force_probe = false
			return n, .None, true
		}
		if buf.reset || buf.stop || buf.fin_sent {
			continue
		}
		off := u64(buf.sent)
		if u64(buf.n) < off {
			return 0, .Protocol, true
		}
		left := buf.n - int(off)
		want_fin := buf.fin && !buf.fin_sent
		if left == 0 && !want_fin {
			continue
		}
		chunk := left
		if chunk > STREAM_BYTES {
			chunk = STREAM_BYTES
		}
		if chunk > c.max_datagram / 2 {
			chunk = c.max_datagram / 2
		}
		fin := want_fin && chunk == left
		idx := buf_index(c, &buf)
		req := harness.Emit {
			space = .Application,
			stream = true,
			stream_id = buf.id,
			stream_len = chunk,
			fin = fin,
			more_data = !fin && (left > chunk || c.pings > 0),
			probe = c.force_probe,
		}
		attach_ack(c, &req, .Application)
		frame: [MAX_DATAGRAM]u8
		at, ok := encode_ack_if(frame[:], 0, req)
		if !ok {
			return 0, .Protocol, true
		}
		at, ok = encode_stream(frame[:], at, buf.id, off, c.send_mem[idx][int(off):int(off) + chunk], fin)
		if !ok {
			return 0, .Protocol, true
		}
		n, err := seal_and_emit(c, now, dst, req, frame[:at], off)
		if err != .None {
			return 0, err, true
		}
		buf.sent += chunk
		if fin {
			buf.fin_sent = true
		}
		c.force_probe = false
		return n, .None, true
	}
	return 0, .None, false
}

@(private)
attach_ack :: proc(c: ^Connection, req: ^harness.Emit, space: harness.Space) {
	lo, hi, ready := harness.pending_ack(&c.model, space)
	if !ready || c.model.spaces[int(space)].discarded {
		return
	}
	req.attach_ack = true
	req.ack_smallest = lo
	req.ack_largest = hi
}

@(private)
encode_ack_if :: proc(dst: []u8, at: int, req: harness.Emit) -> (int, bool) {
	if !req.attach_ack {
		return at, true
	}
	return encode_ack(dst, at, req.ack_largest, req.ack_smallest)
}

@(private)
seal_and_emit :: proc(c: ^Connection, now: i64, dst: []u8, req: harness.Emit, content: []u8, stream_off: u64) -> (int, Error) {
	if c.model.spaces[int(req.space)].discarded {
		return 0, .Discarded
	}
	natural, pn_len, trunc, ok := harness_natural(c, req)
	if !ok {
		c.reason = "datagram size"
		return 0, .Protocol
	}
	structured := structured_size(req)
	min_plain := len(content)
	if min_plain < 4 {
		min_plain = 4
	}
	if min_plain + 16 < structured {
		min_plain = structured - 16
	}
	goal := natural
	if req.space == .Application && c.full_size && c.max_datagram > goal {
		goal = c.max_datagram
	}
	if goal > c.max_datagram {
		goal = c.max_datagram
	}
	total := 0
	header := 0
	plain_len := min_plain
	fitted := false
	for _ in 0 ..< 6 {
		header = send_header_len(c, req.space, pn_len, plain_len)
		if header <= 0 || header > max(int) - 16 {
			c.reason = "header length"
			return 0, .Protocol
		}
		overhead := header + 16
		if goal < overhead + min_plain {
			goal = overhead + min_plain
			if goal > c.max_datagram {
				return 0, .Capacity
			}
		}
		next := goal - overhead
		if next < min_plain {
			c.reason = "datagram size"
			return 0, .Protocol
		}
		total = overhead + next
		if next == plain_len && total == goal {
			fitted = true
			break
		}
		plain_len = next
	}
	if !fitted || total != goal || total > c.max_datagram || total > len(dst) || total > MAX_DATAGRAM {
		if total > c.max_datagram || total > len(dst) || total > MAX_DATAGRAM {
			return 0, .Capacity
		}
		c.reason = "datagram size"
		return 0, .Protocol
	}
	plain: [MAX_DATAGRAM]u8
	packet: [MAX_DATAGRAM]u8
	copy(plain[:len(content)], content)
	for i in len(content) ..< plain_len {
		plain[i] = 0
	}
	level := quic.Encryption_Level.Initial
	full := c.model.spaces[int(req.space)].next_send
	if req.space == .Handshake {
		level = .Handshake
	} else if req.space == .Application {
		level = .One_RTT
	}
	if req.space == .Application {
		hn, _, herr := quic.short_header_encode_v1(packet[:], {
			destination_id = c.peer_cid[:c.peer_cid_len],
			packet_number = u32(trunc),
			packet_number_length = pn_len,
			key_phase = c.hs.one_rtt_write.phase != 0,
		})
		if herr != .None || hn != header {
			c.reason = "short header"
			return 0, .Protocol
		}
	} else {
		kind := quic.Packet_Kind.Initial
		if req.space == .Handshake {
			kind = .Handshake
		}
		hn, _, herr := quic.long_header_encode_v1(packet[:], {
			kind = kind,
			destination_id = c.peer_cid[:c.peer_cid_len],
			source_id = c.local_cid[:c.local_cid_len],
			packet_number = u32(trunc),
			packet_number_length = pn_len,
			ciphertext_length = u64(plain_len + 16),
		})
		if herr != .None || hn != header {
			c.reason = "long header"
			return 0, .Protocol
		}
	}
	sealed, serr := quic.handshake_payload_seal(&c.hs, packet[header:], packet[:header], plain[:plain_len], level, full)
	if serr != .None || sealed != plain_len + 16 {
		return 0, .Handshake
	}
	if quic.handshake_header_protection_apply(&c.hs, packet[:total], level, c.peer_cid_len) != .None {
		return 0, .Handshake
	}
	sent := req
	sent.bytes = total
	discard: [MAX_DATAGRAM]u8
	n, err := harness.emit(&c.model, now, discard[:], sent)
	if err != .None {
		c.reason = "harness emit"
		return 0, map_harness(err)
	}
	if n != total {
		fail(c, "size")
		return 0, .Protocol
	}
	copy(dst[:total], packet[:total])
	_ = stream_off
	return total, .None
}

@(private)
send_header_len :: proc(c: ^Connection, space: harness.Space, pn_len, plain_len: int) -> int {
	if space == .Application && c.model.handshake_confirmed {
		return 1 + c.peer_cid_len + pn_len
	}
	n, ok := long_header_len(c, space, pn_len, plain_len + 16)
	if !ok {
		return 0
	}
	return n
}
