package conn
import "core:crypto"
import "core:net"
import "core:net/quic/idle"
import quic ".."
import "../harness"

Early_State :: struct {
	active, confirmed, accepted, pumping: bool,
	first_pn, rejected_end:               u64,
	original:                             [CID_CAP]u8,
	original_n:                           int,
	retire_at:                            i64,
	incoming, endpoint:                   net.Endpoint,
	controls:                             [EARLY_CONTROL_CAP]Early_Control,
	control_n:                            int,
}

early :: proc(c: ^Connection) -> bool {
	return c != nil && c.initialized && c.early_state.active && !c.early_state.confirmed
}

// Copies only early keys; the wire TLS driver continues to own its independent
// handshake. Provisional transport bytes/stream state move nowhere on confirm.
adopt_early :: proc(
	c: ^Connection,
	owner: ^quic.Handshake,
	cfg: Adopt_Config,
	original_destination_id: []u8 = nil,
) -> Error {
	if c == nil ||
	   owner == nil ||
	   owner.failed ||
	   !owner.have_zero_rtt ||
	   owner.role != cfg.role ||
	   len(original_destination_id) > CID_CAP {
		return .Invalid
	}
	if cfg.role == .Client && !owner.zero_rtt_write.initialized ||
	   cfg.role == .Server && !owner.zero_rtt_read.initialized {
		return .Invalid
	}
	provisional := quic.Handshake {
		role                = cfg.role,
		have_one_rtt        = true,
		handshake_complete  = true,
		peer_authenticated  = true,
		have_zero_rtt       = true,
		zero_rtt_write      = owner.zero_rtt_write,
		zero_rtt_read       = owner.zero_rtt_read,
		handshake_discarded = true,
	}
	e := adopt_established(c, &provisional, cfg)
	if e != .None {
		quic.handshake_fail(&provisional)
		return e
	}
	c.early_state = {
		active     = true,
		first_pn   = cfg.next_send_pn,
		original_n = len(original_destination_id),
	}
	copy(c.early_state.original[:], original_destination_id)
	c.authed = false
	c.done_sent = true
	c.seen_done = false
	return .None
}

early_update_peer_id :: proc(c: ^Connection, id: []u8) -> Error {
	if !early(c) || len(id) > CID_CAP {
		return .Invalid
	}
	c.peer_cid = {}
	copy(c.peer_cid[:], id)
	c.peer_cid_len = len(id)
	c.model.peer_cid = {}
	copy(c.model.peer_cid[:], id)
	c.model.peer_cid_len = len(id)
	return .None
}

// accepted=false preserves client bytes for normal 1RTT retransmission at
// the same STREAM offsets. Packet numbers never reset, including after Retry.
confirm_early :: proc(
	c: ^Connection,
	owner: ^quic.Handshake,
	cfg: Adopt_Config,
	accepted: bool,
	now: i64,
	endpoint: net.Endpoint = {},
) -> Error {
	if !early(c) ||
	   owner == nil ||
	   owner.failed ||
	   !owner.have_one_rtt ||
	   !owner.handshake_complete ||
	   !owner.peer_authenticated ||
	   owner.role != c.role ||
	   now < 0 {
		return .Invalid
	}
	if len(cfg.local_cid) > CID_CAP || len(cfg.peer_cid) > CID_CAP || cfg.next_send_pn >= u64(1) << 62 {
		return .Invalid
	}
	if !accepted && c.role == .Server {
		return .Invalid
	}
	if !accepted {
		c.early_state.rejected_end = c.model.spaces[2].next_send
		_ = harness.reject_early_packets(&c.model)
		for &sent in c.tx {sent = {}}
		retransmit_unacknowledged(c)
	}
	early_read := c.hs.zero_rtt_read
	quic.handshake_fail(&c.hs)
	c.hs = owner^
	owner^ = {}
	if accepted && c.role == .Server {
		c.hs.zero_rtt_read = early_read
		c.hs.have_zero_rtt = true
	} else {
		crypto.zero_explicit(&early_read, size_of(early_read))
		quic.handshake_discard_zero_rtt(&c.hs)
	}
	c.early_state.endpoint = endpoint
	if endpoint.address == nil {
		c.early_state.endpoint = c.early_state.incoming
	}
	c.early_state.confirmed = true
	c.early_state.accepted = accepted
	c.early_state.retire_at = harness.early_key_discard_at(&c.model, now)
	c.authed = true
	c.got_finished = true
	c.finished_marked = true
	c.server_keys = true
	c.accepted = true
	c.done_sent = c.role == .Client
	c.seen_done = c.role == .Server || c.hs.handshake_discarded
	c.local_cid = {}
	c.peer_cid = {}
	copy(c.local_cid[:], cfg.local_cid)
	copy(c.peer_cid[:], cfg.peer_cid)
	c.local_cid_len = len(cfg.local_cid)
	c.peer_cid_len = len(cfg.peer_cid)
	c.model.local_cid = c.local_cid
	c.model.peer_cid = c.peer_cid
	c.model.local_cid_len = c.local_cid_len
	c.model.peer_cid_len = c.peer_cid_len
	if c.seen_done {
		c.fin_off = c.hs.client_finished_len
	}
	c.model.spaces[2].next_send = max(c.model.spaces[2].next_send, cfg.next_send_pn)
	if c.model.spaces[2].has_largest_recv {
		c.hs.largest_pn[2] = c.model.spaces[2].largest_recv
		c.hs.have_largest[2] = true
	}
	if c.role == .Client && !c.hs.handshake_discarded {
		c.model.handshake_armed = true
		c.model.spaces[1].discarded = false
		c.model.spaces[1].next_send = cfg.next_handshake_send_pn
	}
	if cfg.directional_limits {
		c.directional_limits = true
		c.model.max_data = cfg.peer_max_data
		c.peer_bidi_local = cfg.peer_bidi_local
		c.peer_bidi_remote = cfg.peer_bidi_remote
		c.peer_uni = cfg.peer_uni
		c.peer_bidi_streams = cfg.peer_bidi_streams
		c.peer_uni_streams = cfg.peer_uni_streams
	}
	return .None
}

@(private)
early_tick :: proc(c: ^Connection, now: i64) {
	if c.early_state.confirmed && c.hs.have_zero_rtt && now >= c.early_state.retire_at {
		quic.handshake_discard_zero_rtt(&c.hs)
	}
	if e := early_flush_control(c); e != .None {
		fail(c, "early control")
	}
}

@(private)
early_ack_valid :: proc(c: ^Connection, p: Parsed) -> bool {
	state := c.early_state
	if !state.confirmed || state.accepted || state.rejected_end <= state.first_pn || !p.ack {
		return true
	}
	for i in 0 ..< p.ack_n {
		interval := p.ack_ranges[i]
		if interval[0] < state.rejected_end && interval[1] >= state.first_pn {
			return false
		}
	}
	return true
}

@(private)
early_pump :: proc(c: ^Connection, now: i64, dst: []u8) -> (int, Error) {
	if c.role == .Server {
		return 0, .None
	}
	c.early_state.pumping = true
	defer c.early_state.pumping = false
	// 0RTT cannot acknowledge packets or carry post-handshake CRYPTO/control.
	c.model.ack_pending[2] = false
	if n, e, sent := send_stream_progress(c, now, dst); sent {
		return n, e
	}
	return 0, .None
}

@(private)
early_seal_and_emit :: proc(
	c: ^Connection,
	now: i64,
	dst: []u8,
	request: harness.Emit,
	content: []u8,
) -> (
	int,
	Error,
) {
	if !early(c) || c.role != .Client || request.space != .Application || request.attach_ack {
		return 0, .Protocol
	}
	space := c.model.spaces[2]
	pn_len, truncated, pe := harness.pn_wire_length(space.next_send, space.has_largest_acked, space.largest_acked)
	if pe != .None {
		return 0, map_harness(pe)
	}
	plain_n := max(4, len(content))
	header_n := 7 + c.local_cid_len + c.peer_cid_len + 2 + pn_len
	total := header_n + plain_n + 16
	if total > c.max_datagram || total > len(dst) {
		return 0, .Capacity
	}
	plain: [MAX_DATAGRAM]u8
	copy(plain[:], content)
	packet: [MAX_DATAGRAM]u8
	hn, _, he := quic.long_header_encode_v1(
		packet[:],
		{
			kind = .Zero_RTT,
			destination_id = c.peer_cid[:c.peer_cid_len],
			source_id = c.local_cid[:c.local_cid_len],
			packet_number = u32(truncated),
			packet_number_length = pn_len,
			ciphertext_length = u64(plain_n + 16),
			length_width = 2,
		},
	)
	if he != .None || hn != header_n {
		return 0, .Protocol
	}
	n, e := quic.handshake_zero_rtt_payload_seal(&c.hs, packet[hn:], packet[:hn], plain[:plain_n], space.next_send)
	if e != .None || n != plain_n + 16 {
		return 0, .Handshake
	}
	if quic.handshake_zero_rtt_header_protection_apply(&c.hs, packet[:total]) != .None {
		return 0, .Handshake
	}
	req := request
	req.bytes = total
	discard: [MAX_DATAGRAM]u8
	written, err := harness.emit(&c.model, now, discard[:], req)
	if err != .None {
		return 0, map_harness(err)
	}
	if written != total {
		return 0, .Protocol
	}
	c.output_eliciting = false
	for p in c.model.packets[2] {
		if p.active && p.number == space.next_send {
			c.output_eliciting = p.ack_eliciting
			break
		}
	}
	copy(dst, packet[:total])
	return total, .None
}

@(private)
early_ingest :: proc(c: ^Connection, now: i64, path: u32, datagram: []u8) -> Error {
	if c.role != .Server || !c.hs.have_zero_rtt || c.early_state.confirmed && !c.early_state.accepted {
		return .Discarded
	}
	early_tick(c, now)
	if c.phase == .Failed {
		return .Protocol
	}
	if !c.hs.have_zero_rtt {
		return .Discarded
	}
	view, size, e := quic.packet_decode_v1(datagram, c.local_cid_len)
	if e != .None || view.kind != .Zero_RTT || size != len(datagram) || size > MAX_DATAGRAM {
		c.reason = "early packet shape"
		return .Discarded
	}
	destination := view.invariant.destination_id
	if !accepts_destination_id(c, destination) &&
	   string(destination) != string(c.early_state.original[:c.early_state.original_n]) {
		c.reason = "early destination"
		return .Discarded
	}
	packet: [MAX_DATAGRAM]u8
	copy(packet[:], datagram)
	if quic.handshake_zero_rtt_header_protection_remove(&c.hs, packet[:size]) != .None {
		c.reason = "early header protection"
		return .Discarded
	}
	decoded, _, de := quic.packet_decode_v1(packet[:size], c.local_cid_len)
	if de != .None {
		return .Discarded
	}
	fields, fe := quic.unprotected_fields_decode(decoded, packet[:size])
	if fe != .None {
		return .Discarded
	}
	sp := c.model.spaces[2]
	full, valid := harness.pn_decode(
		sp.has_largest_recv,
		sp.largest_recv,
		u64(fields.packet_number),
		fields.packet_number_length * 8,
	); if !valid {
		return .Discarded
	}
	header := fields_header_end(packet[:size], c.local_cid_len)
	if header <= 0 || header >= size {
		return .Discarded
	}
	plain: [MAX_DATAGRAM]u8
	n, oe := quic.handshake_zero_rtt_payload_open(&c.hs, plain[:], packet[:header], packet[header:size], full)
	if oe == .Invalid_Header {
		fail(c, "early reserved bits")
		return .Protocol
	}
	if oe != .None {
		c.reason = "early decrypt"
		return .Discarded
	}
	parsed, ok := parse_frames(plain[:n])
	for i in 0 ..< parsed.path_n {
		if parsed.paths[i].response {
			ok = false
		}
	}
	if n == 0 || !ok || parsed.new_token || parsed.ack || parsed.crypto || parsed.handshake_done {
		fail(c, "0RTT frame")
		return .Protocol
	}
	duplicate := already_received(sp, full)
	recv_blocks := 0
	for i in 0 ..< parsed.stream_n {
		stream := parsed.streams[i]
		if !stream_fits_recv(
			c,
			{stream_id = stream.id, stream_off = stream.offset, stream_data = stream.data},
			&recv_blocks,
		) {
			return .Capacity
		}
	}
	req := shadow_from_parsed(parsed)
	req.stream = false
	req.reset = false
	req.stop_sending = false
	req.max_data = false
	req.attach_ack = false
	req.ping =
		parsed.ping ||
		parsed.control_eliciting ||
		parsed.stream ||
		parsed.reset ||
		parsed.stop ||
		parsed.max_data ||
		parsed.max_stream_data ||
		parsed.max_streams_bidi ||
		parsed.max_streams_uni
	shadow: [MAX_DATAGRAM]u8
	if !shadow_packet(c, shadow[:size], .Application, fields.packet_number_length, u64(fields.packet_number), req, 0) {
		return .Protocol
	}
	model_path := path
	if c.migration.enabled {
		model_path = c.model.path
	}
	if re := harness.receive(&c.model, now, model_path, shadow[:size]); re != .None {
		return map_harness(re)
	}
	if !duplicate {
		if re := early_defer_control(c, parsed, destination); re != .None {
			fail(c, "early control capacity")
			return re
		}
		ecn_received(c, 2)
		payload := parsed
		payload.path_challenge = false
		if re := apply_parsed(c, .One_RTT, payload); re != .None {
			return re
		}
		quic.handshake_note_authenticated_pn(&c.hs, .One_RTT, full)
		idle.received(&c.idle, now)
	}
	return .None
}

// Metadata belongs to this authenticated datagram only. 0RTT replay never
// validates or switches a path; late packets use the already validated endpoint.
ingest_early_ecn :: proc(
	c: ^Connection,
	now: i64,
	from: net.Endpoint,
	datagram: []u8,
	mark: net.ECN_Codepoint,
	valid: bool,
) -> Error {
	if c == nil {
		return .Invalid
	}
	c.early_state.incoming = from
	if c.migration.enabled {
		if from != c.migration.paths[c.migration.active].endpoint {
			return .Discarded
		}
		return ingest_from_ecn(c, now, from, datagram, mark, valid)
	}
	c.ecn.incoming = mark
	c.ecn.incoming_valid = valid
	defer c.ecn.incoming_valid = false
	return ingest(c, now, 0, datagram)
}

// Routing hint only; packet authentication and endpoint policy remain mandatory.
accepts_zero_rtt_destination :: proc(c: ^Connection, id: []u8) -> bool {
	if c == nil ||
	   !c.initialized ||
	   c.role != .Server ||
	   !c.hs.have_zero_rtt ||
	   !c.hs.zero_rtt_read.initialized ||
	   !c.early_state.active ||
	   c.early_state.confirmed && !c.early_state.accepted {
		return false
	}
	return accepts_destination_id(c, id) || string(id) == string(c.early_state.original[:c.early_state.original_n])
}
