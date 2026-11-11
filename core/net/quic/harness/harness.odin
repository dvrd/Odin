// Deterministic QUIC harness model. Not the production connection API and not
// TLS or AEAD. core:net/quic/sim can host it. Ticks are explicit; the default
// tick is one millisecond so RFC 9002 constants apply directly. Storage is the
// caller's fixed packet and stream tables (at most 64 packets in each number
// space and 32 streams). Datagram bytes are not retained.
package harness

import "core:bytes"
import "core:mem"

K_PACKET_THRESHOLD :: 3
K_TIME_NUM :: 9
K_TIME_DEN :: 8
K_GRANULARITY_MS :: i64(1)
K_INITIAL_RTT_MS :: i64(333)
K_PERSISTENT_CONGESTION_THRESHOLD :: 3
K_MAX_ACK_DELAY_MS :: i64(25)
K_ANTI_AMPLIFICATION :: 3
K_MIN_INITIAL_DATAGRAM :: 1200
K_INITIAL_WINDOW_PACKETS :: 10
K_MINIMUM_WINDOW_PACKETS :: 2
K_INITIAL_WINDOW_BYTE_CAP :: 14720
K_MAX_PACKETS_PER_SPACE :: 64
K_MAX_STREAMS :: 32
K_MAX_DATAGRAM :: 4096
K_RECV_WINDOW :: 64

// Linux has no independent QUIC peer in this tree. The Darwin-vs-Linux gate
// must not treat a loopback of this model as that peer.
LINUX_PEER_UNSUPPORTED :: true

Error :: enum {
	None,
	Invalid_State,
	Invalid_Input,
	Capacity,
	Allocation,
	Congestion_Limited,
	Flow_Control,
	Anti_Amplification,
	Datagram_Too_Small,
	Discarded,
	Closed,
	Protocol,
	Destination_Undersized,
	Overlap,
}

Role :: enum u8 {
	Client,
	Server,
}
Space :: enum u8 {
	Initial,
	Handshake,
	Application,
}
Send_State :: enum u8 {
	Empty,
	Send,
	Data_Sent,
	Reset_Sent,
	Data_Recvd,
	Reset_Recvd,
}
Recv_State :: enum u8 {
	Empty,
	Recv,
	Size_Known,
	Data_Recvd,
	Reset_Recvd,
}

Packet :: struct {
 path_epoch:u64, path:u32, ecn_mark:u8,
	active:        bool,
	number:        u64,
	sent_at:       i64,
	sent_bytes:    int,
	ack_eliciting: bool,
	in_flight:     bool,
	zero_rtt:      bool,
	stream_slot:   int,
	stream_bytes:  int,
	retires_reset: bool,
}
Stream :: struct {
	active:                       bool,
	id:                           u64,
	send:                         Send_State,
	recv:                         Recv_State,
	max_send:                     u64,
	next_offset:                  u64,
	acked:                        u64,
	fin_sent:                     bool,
	recv_max:                     u64,
	recv_got:                     u64,
	recv_final:                   u64,
	recv_fin:                     bool,
	retained:                     int,
	send_retained, recv_retained: int,
	recv_highest:                 u64,
	fin_acked:                    bool,
	externally_owned:             bool,
	// Absolute receive bytes released by the local application. Directional
	// retention stays separate when both halves of a bidi stream are live.
	consumed:                     u64,
}
Space_State :: struct {
	discarded:             bool,
	next_send:             u64,
	largest_acked:         u64,
	has_largest_acked:     bool,
	largest_recv:          u64,
	has_largest_recv:      bool,
	last_ack_eliciting_at: i64,
	ack_eliciting_flight:  int,
	loss_at:               i64,
	has_loss_at:           bool,
	recv_base:             u64,
	recv_bits:             u64,
	has_recv:              bool,
}

// Noncopyable after init: packet and stream slices borrow caller storage.
Model :: struct {
 path_epoch:u64,
	initialized:              bool,
	role:                     Role,
	local_cid, peer_cid:      [20]u8,
	local_cid_len:            int,
	peer_cid_len:             int,
	max_datagram_size:        int,
	granularity:              i64,
	max_ack_delay:            i64,
	packets:                  [3][]Packet,
	streams:                  []Stream,
	spaces:                   [3]Space_State,
	latest_rtt:               i64,
	smoothed_rtt:             i64,
	rttvar:                   i64,
	min_rtt:                  i64,
	first_rtt_sample:         i64,
	has_first_rtt:            bool,
	handshake_confirmed:      bool,
	handshake_armed:          bool,
	peer_validated_us:        bool,
	pto_count:                int,
	congestion_window:        int,
	bytes_in_flight:          int,
	ssthresh:                 i64,
	in_recovery:              bool,
	recovery_start:           i64,
	app_limited:              bool,
	flow_limited:             bool,
	max_data:                 u64,
	data_sent:                u64,
	recv_max_data:            u64,
	recv_data:                u64,
	max_streams_send:         u64,
	max_streams_recv:         u64,
	max_stream_data_send:     u64,
	max_stream_data_recv:     u64,
	next_send_stream:         u64,
	next_recv_stream:         u64,
	path:                     u32,
	has_path:                 bool,
	address_validated:        bool,
	path_received, path_sent: int,
	closed:                   bool,
	retained:                 int,
	live_packets:             int,
	live_streams:             int,
	peak_packets:             int,
	peak_streams:             int,
	peak_retained:            int,
	allocation_failures:      int,
	ecn_ce:                   [3]u64,
	has_ecn:                  [3]bool,
	ack_pending:              [3]bool,
}

Limits :: struct {
	max_data, max_stream_data, max_streams:                u64,
	recv_max_data, recv_max_stream_data, recv_max_streams: u64,
}
Stats :: struct {
	live_packets, live_streams, retained:          int,
	peak_packets, peak_streams, peak_retained:     int,
	bytes_in_flight, congestion_window:            int,
	path_received, path_sent:                      int,
	address_validated, closed:                     bool,
	pto_count:                                     int,
	app_limited, in_recovery, handshake_confirmed: bool,
	smoothed_rtt, rttvar, latest_rtt:              i64,
}
Emit :: struct {
	space:               Space,
	bytes:               int,
	probe:               bool,
	zero_rtt:            bool,
	more_data:           bool,
	ping:                bool,
	padding:             bool,
	attach_ack:          bool,
	ack_largest:         u64,
	ack_smallest:        u64,
	ack_delay:           i64,
	ack_ecn:             bool,
	ack_ecn_ce:          u64,
	stream:              bool,
	stream_id:           u64,
	stream_len:          int,
	fin:                 bool,
	reset:               bool,
	reset_final:         u64,
	stop_sending:        bool,
	max_data:            bool,
	max_data_value:      u64,
	connection_close:    bool,
	handshake_confirmed: bool,
}
Timer_Kind :: enum u8 {
	None,
	Loss,
	Probe,
	Anti_Deadlock_Initial,
	Anti_Deadlock_Handshake,
}
Timer :: struct {
	armed: bool,
	at:    i64,
	space: Space,
	kind:  Timer_Kind,
}

init :: proc(
	m: ^Model,
	role: Role,
	local_cid, peer_cid: []u8,
	initial_packets, handshake_packets, application_packets: []Packet,
	streams: []Stream,
	max_datagram_size: int,
) -> Error {
	if m == nil || m.initialized {
		return .Invalid_State
	}
	if len(local_cid) > 20 ||
	   len(peer_cid) > 20 ||
	   max_datagram_size < K_MIN_INITIAL_DATAGRAM ||
	   max_datagram_size > K_MAX_DATAGRAM {
		return .Invalid_Input
	}
	if len(initial_packets) == 0 ||
	   len(initial_packets) > K_MAX_PACKETS_PER_SPACE ||
	   len(handshake_packets) == 0 ||
	   len(handshake_packets) > K_MAX_PACKETS_PER_SPACE ||
	   len(application_packets) == 0 ||
	   len(application_packets) > K_MAX_PACKETS_PER_SPACE ||
	   len(streams) > K_MAX_STREAMS {
		return .Capacity
	}
	owner := (cast([^]u8)m)[:size_of(Model)]
	tables := [4][]u8 {
		mem.slice_to_bytes(initial_packets),
		mem.slice_to_bytes(handshake_packets),
		mem.slice_to_bytes(application_packets),
		mem.slice_to_bytes(streams),
	}
	for t, i in tables {
		if bytes.alias(owner, t) {
			return .Overlap
		}
		for u in tables[i + 1:] {
			if bytes.alias(t, u) {
				return .Overlap
			}
		}
	}
	for &p in initial_packets {p = {}; p.stream_slot = -1}
	for &p in handshake_packets {p = {}; p.stream_slot = -1}
	for &p in application_packets {p = {}; p.stream_slot = -1}
	for &s in streams {s = {}}
	cwnd := initial_window(max_datagram_size)
	if cwnd <= 0 {
		return .Invalid_Input
	}
	m^ = {
		initialized       = true,
		role              = role,
		local_cid_len     = len(local_cid),
		peer_cid_len      = len(peer_cid),
		max_datagram_size = max_datagram_size,
		granularity       = K_GRANULARITY_MS,
		max_ack_delay     = K_MAX_ACK_DELAY_MS,
		smoothed_rtt      = K_INITIAL_RTT_MS,
		rttvar            = K_INITIAL_RTT_MS / 2,
		ssthresh          = -1,
		congestion_window = cwnd,
		next_send_stream  = 0 if role == .Client else 1,
		next_recv_stream  = 1 if role == .Client else 0,
	}
	copy(m.local_cid[:], local_cid)
	copy(m.peer_cid[:], peer_cid)
	m.packets[0] = initial_packets
	m.packets[1] = handshake_packets
	m.packets[2] = application_packets
	m.streams = streams
	return .None
}

destroy :: proc(m: ^Model) {
	if m == nil {
		return
	}
	if m.initialized {
		release_all(m)
	}
	m^ = {}
}

inject_allocation_failure :: proc(m: ^Model, count: int) -> Error {
	if m == nil || !m.initialized || count < 0 {
		return .Invalid_State
	}
	if count > max(int) - m.allocation_failures {
		return .Invalid_Input
	}
	m.allocation_failures += count
	return .None
}

stats :: proc(m: ^Model) -> Stats {
	return {
		live_packets = m.live_packets,
		live_streams = m.live_streams,
		retained = m.retained,
		peak_packets = m.peak_packets,
		peak_streams = m.peak_streams,
		peak_retained = m.peak_retained,
		bytes_in_flight = m.bytes_in_flight,
		congestion_window = m.congestion_window,
		path_received = m.path_received,
		path_sent = m.path_sent,
		address_validated = m.address_validated,
		closed = m.closed,
		pto_count = m.pto_count,
		app_limited = m.app_limited,
		in_recovery = m.in_recovery,
		handshake_confirmed = m.handshake_confirmed,
		smoothed_rtt = m.smoothed_rtt,
		rttvar = m.rttvar,
		latest_rtt = m.latest_rtt,
	}
}

audit :: proc(m: ^Model) -> bool {
	if m == nil || !m.initialized {
		return false
	}
	if m.retained < 0 || m.live_packets < 0 || m.live_streams < 0 || m.bytes_in_flight < 0 {
		return false
	}
	if m.peak_packets < m.live_packets ||
	   m.peak_streams < m.live_streams ||
	   m.peak_retained < m.retained {
		return false
	}
	if m.live_packets > K_MAX_PACKETS_PER_SPACE * 3 || m.live_streams > len(m.streams) {
		return false
	}
	live, retained, streams := 0, 0, 0
	for space in 0 ..< 3 {
		if len(m.packets[space]) > K_MAX_PACKETS_PER_SPACE {
			return false
		}
		for p in m.packets[space] {
			if p.active {
				live += 1
				if p.sent_bytes < 0 || p.stream_bytes < 0 || p.stream_slot < -1 {
					return false
				}
			}
		}
	}
	for s in m.streams {
		if s.active {
			streams += 1
			if s.retained < 0 {
				return false
			}
			retained += s.retained
		}
	}
	return live == m.live_packets && streams == m.live_streams && retained == m.retained
}

// RFC 9002 §7.2. min(10 * max_datagram_size, max(14720, 2 * max_datagram_size)).
initial_window :: proc(max_datagram_size: int) -> int {
	if max_datagram_size <= 0 || max_datagram_size > max(int) / K_INITIAL_WINDOW_PACKETS {
		return 0
	}
	ten := K_INITIAL_WINDOW_PACKETS * max_datagram_size
	twice := K_MINIMUM_WINDOW_PACKETS * max_datagram_size
	limit := K_INITIAL_WINDOW_BYTE_CAP
	if twice > limit {
		limit = twice
	}
	if ten < limit {
		return ten
	}
	return limit
}

minimum_window :: proc(max_datagram_size: int) -> int {
	if max_datagram_size <= 0 || max_datagram_size > max(int) / K_MINIMUM_WINDOW_PACKETS {
		return 0
	}
	return K_MINIMUM_WINDOW_PACKETS * max_datagram_size
}

// Pseudocode order: rttvar = kInitialRtt/2, then smoothed + max(4*rttvar, 1ms).
// Real-valued 4*(333/2) is 666 and the RFC text calls 999 ms "1 second".
// Integer milliseconds follow the assignment order and yield 997.
initial_handshake_pto :: proc() -> i64 {
	rttvar := K_INITIAL_RTT_MS / 2
	varied := 4 * rttvar
	if varied < K_GRANULARITY_MS {
		varied = K_GRANULARITY_MS
	}
	return K_INITIAL_RTT_MS + varied
}

// RFC 9002 §7.6.3 published arithmetic, in the example's own time units.
persistent_congestion_example :: proc() -> (period, duration: int, persistent: bool) {
	period = 8 - 1
	duration = 2 * K_PERSISTENT_CONGESTION_THRESHOLD
	persistent = period > duration
	return
}

self_check :: proc() -> bool {
	n, trunc, err := pn_wire_length(0xac5c02, true, 0xabe8b3)
	if err != .None || n != 2 || trunc != 0x5c02 {
		return false
	}
	n, trunc, err = pn_wire_length(0xace8fe, true, 0xabe8b3)
	if err != .None || n != 3 || trunc != 0xace8fe {
		return false
	}
	full, ok := pn_decode(true, 0xa82f30ea, 0x9b32, 16)
	if !ok || full != 0xa82f9b32 {
		return false
	}
	if initial_window(1200) != 12000 ||
	   minimum_window(1200) != 2400 ||
	   initial_window(2000) != 14720 {
		return false
	}
	period, duration, persistent := persistent_congestion_example()
	if period != 7 || duration != 6 || !persistent || initial_handshake_pto() != 997 {
		return false
	}
	return(
		K_PACKET_THRESHOLD == 3 &&
		K_MAX_ACK_DELAY_MS == 25 &&
		K_ANTI_AMPLIFICATION == 3 &&
		LINUX_PEER_UNSUPPORTED \
	)
}

// peer_compared is always false: Linux is unsupported and this process is not a peer.
// harness_ok is false only when the local RFC vectors do not match.
darwin_vs_linux_gate :: proc() -> (peer_compared, harness_ok: bool) {
	peer_compared = false
	harness_ok = self_check()
	return
}
