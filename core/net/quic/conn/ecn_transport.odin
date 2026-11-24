package conn
import "core:net"
import ecn "core:net/quic/ecn"
import "core:net/quic/harness"

ECN_Transport :: struct {
	sender:           ecn.Sender,
	received:         [3]ecn.Counts,
	receive_valid:    [3]bool,
	incoming, output: net.ECN_Codepoint,
	incoming_valid:   bool,
	started:          i64,
}

ecn_enable :: proc(c: ^Connection, enabled: bool, now: i64 = 0) {
	if c != nil {
		ecn.init(&c.ecn.sender, enabled)
		c.ecn.started = now
	}
}

output_ecn :: proc(c: ^Connection) -> net.ECN_Codepoint {
	if c == nil {
		return .Not_ECT
	}
	return c.ecn.output
}

ingest_from_ecn :: proc(
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
	c.ecn.incoming = mark
	c.ecn.incoming_valid = valid
	defer c.ecn.incoming_valid = false
	return ingest_from(c, now, from, datagram)
}

@(private)
ecn_received :: proc(c: ^Connection, space: int) {
	if c.ecn.incoming_valid {
		ecn.receive(&c.ecn.received[space], c.ecn.incoming, true)
		c.ecn.receive_valid[space] = true
	}
}

@(private)
ecn_ack :: proc(c: ^Connection, now: i64, space: int, p: Parsed) {
	if !p.ack {
		return
	}
	newly: ecn.Counts
	largest_sent: i64 = -1
	epoch := c.model.path_epoch
	for packet in c.model.packets[space] {
		if !packet.active || !acked_number(p, packet.number) {
			continue
		}
		if packet.path_epoch == epoch && packet.path == c.model.path {
			ecn.receive(&newly, net.ECN_Codepoint(packet.ecn_mark), true)
		}
		if packet.number == p.ack_largest && packet.path_epoch == epoch && packet.path == c.model.path {
			largest_sent = packet.sent_at
		}
	}
	feedback := ecn.validate(&c.ecn.sender, space, p.ack_largest, newly, p.ack_ecn, p.ecn_counts)
	if feedback.congestion && largest_sent >= 0 {
		harness.ecn_congestion(&c.model, now, largest_sent)
	}
}

@(private)
encode_transport_ack :: proc(
	c: ^Connection,
	dst: []u8,
	start: int,
	space: int,
	largest, smallest: u64,
) -> (
	int,
	bool,
) {
	at, ok := encode_ack(dst, start, largest, smallest)
	if !ok || !c.ecn.receive_valid[space] {
		return at, ok
	}
	dst[start] = 0x03
	counts := c.ecn.received[space]
	values := [3]u64{counts.ect0, counts.ect1, counts.ce}
	for value in values {
		at, ok = put_varint(dst, at, value)
		if !ok {
			return at, false
		}
	}
	return at, true
}
