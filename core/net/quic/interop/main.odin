// Independent QUIC v1 server for an already-installed OpenSSL s_client -quic.
// 0-RTT is refused. This is one handshake, not the connection migration surface.
package main

import "core:crypto"
import "core:crypto/tls"
import credentials "core:crypto/tls/credentials"
import credential_store "core:crypto/tls/credentials/store"
import "core:fmt"
import "core:net"
import "core:net/quic"
import "core:os"
import "core:time"

CAP :: 16384
PN_LEN :: 2
SCID_LEN :: 8

Level :: enum {
	Initial,
	Handshake,
	Application,
}

State :: struct {
	hs:                 quic.Handshake,
	owner:              tls.Server_Handshake,
	store:              ^credential_store.Store,
	initial_mem:        [3][64]u8,
	odcid:              [20]u8,
	odcid_len:          int,
	scid:               [SCID_LEN]u8,
	client_scid:        [20]u8,
	client_scid_len:    int,
	installed:          bool,
	have_handshake:     bool,
	have_app:           bool,
	await_finished:     bool,
	complete:           bool,
	done_sent:          bool,
	validated:          bool,
	recv:               [3][CAP]u8,
	recv_n:             [3]int,
	fed:                [3]int,
	send:               [3][CAP]u8,
	send_n:             [3]int,
	send_at:            [3]int,
	ack:                [3]u64,
	have_ack:           [3]bool,
	next_pn:            [3]u64,
	largest_recv:       [3]u64,
	have_largest:       [3]bool,
	bytes_in, bytes_out: int,
	reason:             string,
}

main :: proc() {
	state := new(State)
	defer free(state)
	if !load_credential(state) {
		fail(state)
	}
	defer {
		tls.server_handshake_destroy(&state.owner)
		quic.handshake_fail(&state.hs)
		if state.store != nil {
			credential_store.destroy(&state.store)
		}
	}
	if quic.handshake_init(
		&state.hs,
		.Server,
		[]string{"h3"},
		state.initial_mem[0][:],
		state.initial_mem[1][:],
		state.initial_mem[2][:],
	) != .None {
		state.reason = "handshake init"
		fail(state)
	}
	crypto.rand_bytes(state.scid[:])
	socket, serr := net.make_unbound_udp_socket(.IP4)
	if serr != nil {
		state.reason = "socket"
		fail(state)
	}
	defer net.close(socket)
	if net.bind(socket, {net.IP4_Loopback, 0}) != .None {
		state.reason = "bind"
		fail(state)
	}
	if net.set_option(socket, .Receive_Timeout, 50 * time.Millisecond) != nil {
		state.reason = "timeout"
		fail(state)
	}
	bound, berr := net.bound_endpoint(socket)
	if berr != .None {
		state.reason = "bound endpoint"
		fail(state)
	}
	fmt.printf("quic-listen 127.0.0.1:%d\n", bound.port)
	os.flush(os.stdout)
	deadline := time.now()
	deadline = time.time_add(deadline, 8 * time.Second)
	last_send: time.Time
	buf: [4096]u8
	for time.diff(time.now(), deadline) > 0 {
		if state.complete && state.done_sent {
			fmt.println("quic-handshake-complete")
			os.flush(os.stdout)
			return
		}
		n, from, rerr := net.recv_udp(socket, buf[:])
		if rerr == .Timeout {
			if state.installed && time.diff(last_send, time.now()) > 200 * time.Millisecond {
				if !state.validated {
					state.send_at[0] = 0
					state.send_at[1] = 0
				}
				if send_flight(state, socket, from) {
					last_send = time.now()
				}
			}
			continue
		}
		if rerr != nil || n <= 0 {
			continue
		}
		state.bytes_in += n
		if ingest(state, buf[:n]) {
			if send_flight(state, socket, from) {
				last_send = time.now()
			}
		} else if state.reason != "" {
			fail(state)
		}
	}
	state.reason = "deadline"
	fail(state)
}

load_credential :: proc(state: ^State) -> bool {
	chain := #load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048-valid.pem")
	key := #load("../../../../tests/core/crypto/tls/credentials/testdata/rsa2048.pem")
	cred, ce := credentials.create(chain, key, {}, context.allocator)
	if ce != .None {
		state.reason = "credential"
		return false
	}
	store, se := credential_store.create({}, context.allocator)
	if se.kind != .None {
		credentials.destroy(&cred)
		state.reason = "credential store"
		return false
	}
	state.store = store
	re := credential_store.replace(store, &cred)
	if re.kind != .None {
		credentials.destroy(&cred)
		state.reason = "credential publish"
		return false
	}
	e := tls.server_handshake_init(&state.owner, tls.SERVER_HANDSHAKE_DEFAULT_CONFIG, context.allocator)
	if e != .None {
		state.reason = "server handshake"
		return false
	}
	return true
}

fail :: proc(state: ^State) {
	fmt.eprintf("quic-handshake-failed %s\n", state.reason)
	os.exit(1)
}

ingest :: proc(state: ^State, datagram: []u8) -> bool {
	at := 0
	progress := false
	for at < len(datagram) {
		view, consumed, err := quic.packet_decode_v1(datagram[at:])
		if err == .Unsupported_Version {
			send_version_negotiation(state, datagram[at:])
			return false
		}
		if err != .None || consumed <= 0 {
			break
		}
		packet := datagram[at:][:consumed]
		at += consumed
		if view.kind == .Initial {
			if !open_initial(state, packet) {
				return false
			}
			progress = true
		} else if view.kind == .Handshake {
			if !state.have_handshake {
				continue
			}
			if !open_protected(state, packet, .Handshake, 0) {
				return false
			}
			state.validated = true
			progress = true
		} else if view.kind == .One_RTT {
			if !state.have_app {
				continue
			}
			if !open_protected(state, packet, .Application, SCID_LEN) {
				return false
			}
			progress = true
		}
	}
	return progress
}

send_version_negotiation :: proc(state: ^State, packet: []u8) {
	inv, err := quic.invariant_decode(packet)
	if err != .None || !inv.long_header {
		return
	}
	dst: [128]u8
	versions := []u32{1}
	n, e := quic.version_negotiation_encode(dst[:], inv.source_id, inv.destination_id, versions)
	if e != .None {
		return
	}
	_ = n
	state.reason = "version negotiation sent"
}

open_initial :: proc(state: ^State, packet: []u8) -> bool {
	view, consumed, err := quic.packet_decode_v1(packet)
	if err != .None || view.kind != .Initial || consumed != len(packet) {
		state.reason = "initial decode"
		return false
	}
	if !state.installed {
		if len(view.invariant.destination_id) > len(state.odcid) || len(view.invariant.source_id) > len(state.client_scid) {
			state.reason = "cid length"
			return false
		}
		state.odcid_len = copy(state.odcid[:], view.invariant.destination_id)
		state.client_scid_len = copy(state.client_scid[:], view.invariant.source_id)
		pe, se := quic.handshake_install_initial(&state.hs, state.odcid[:state.odcid_len])
		if pe != .None || se != .None {
			state.reason = "initial keys"
			return false
		}
		state.installed = true
	}
	local: [4096]u8
	if len(packet) > len(local) {
		state.reason = "initial size"
		return false
	}
	copy(local[:len(packet)], packet)
	if quic.handshake_header_protection_remove(&state.hs, local[:len(packet)], .Initial) != .None {
		state.reason = "initial header"
		return false
	}
	opened, _, oerr := quic.packet_decode_v1(local[:len(packet)])
	if oerr != .None {
		state.reason = "initial reopen"
		return false
	}
	fields, ferr := quic.unprotected_fields_decode(opened, local[:len(packet)])
	if ferr != .None {
		state.reason = "initial fields"
		return false
	}
	full, rerr := quic.handshake_reconstruct_pn(&state.hs, .Initial, u64(fields.packet_number), fields.packet_number_length * 8)
	if rerr != .None {
		state.reason = "initial pn"
		return false
	}
	header_n := opened.packet_number_offset + fields.packet_number_length
	plain: [4096]u8
	pn, perr := quic.handshake_payload_open(
		&state.hs,
		plain[:],
		local[:header_n],
		local[header_n:len(packet)],
		.Initial,
		full,
	)
	if perr != .None {
		state.reason = "initial open"
		return false
	}
	quic.handshake_note_authenticated_pn(&state.hs, .Initial, full)
	note_ack(state, .Initial, full)
	fmt.eprintf("initial pn=%d plain=%d dcid=%d scid=%d\n", full, pn, state.odcid_len, state.client_scid_len)
	return take_crypto(state, .Initial, plain[:pn])
}

open_protected :: proc(state: ^State, packet: []u8, level: Level, dcid_len: int) -> bool {
	local: [4096]u8
	if len(packet) > len(local) {
		state.reason = "packet size"
		return false
	}
	copy(local[:len(packet)], packet)
	qlevel := quic_level(level)
	kind := quic.Packet_Kind.Handshake
	if level == .Application {
		kind = .One_RTT
	}
	if quic.handshake_header_protection_remove(&state.hs, local[:len(packet)], qlevel, dcid_len) != .None {
		state.reason = "header protection"
		return false
	}
	pn_offset := 0
	pn_len := 0
	if level == .Application {
		pn_offset = 1 + dcid_len
		if pn_offset >= len(packet) {
			state.reason = "short header"
			return false
		}
		pn_len = int(local[0] & 3) + 1
	} else {
		opened, _, oerr := quic.packet_decode_v1(local[:len(packet)])
		if oerr != .None || opened.kind != kind {
			state.reason = "handshake decode"
			return false
		}
		fields, ferr := quic.unprotected_fields_decode(opened, local[:len(packet)])
		if ferr != .None {
			state.reason = "handshake fields"
			return false
		}
		pn_offset = opened.packet_number_offset
		pn_len = fields.packet_number_length
	}
	if pn_offset + pn_len > len(packet) {
		state.reason = "pn bounds"
		return false
	}
	truncated: u64
	for b in local[pn_offset:pn_offset + pn_len] {
		truncated = (truncated << 8) | u64(b)
	}
	full, rerr := quic.handshake_reconstruct_pn(&state.hs, qlevel, truncated, pn_len * 8)
	if rerr != .None {
		state.reason = "pn"
		return false
	}
	plain: [4096]u8
	n, perr := quic.handshake_payload_open(
		&state.hs,
		plain[:],
		local[:pn_offset + pn_len],
		local[pn_offset + pn_len:len(packet)],
		qlevel,
		full,
	)
	if perr != .None {
		state.reason = "payload open"
		return false
	}
	quic.handshake_note_authenticated_pn(&state.hs, qlevel, full)
	note_ack(state, level, full)
	return take_crypto(state, level, plain[:n])
}

note_ack :: proc(state: ^State, level: Level, pn: u64) {
	i := int(level)
	if !state.have_ack[i] || pn > state.ack[i] {
		state.ack[i] = pn
		state.have_ack[i] = true
	}
	if !state.have_largest[i] || pn > state.largest_recv[i] {
		state.largest_recv[i] = pn
		state.have_largest[i] = true
	}
}

take_crypto :: proc(state: ^State, level: Level, plain: []u8) -> bool {
	at := 0
	for at < len(plain) {
		if plain[at] == 0 {
			at += 1
			continue
		}
		id, n, err := quic.varint_decode(plain[at:])
		if err != .None {
			state.reason = "frame"
			return false
		}
		at += n
		if id == 0x01 {
			continue
		}
		if id == 0x02 || id == 0x03 {
			used := skip_ack(plain[at:], id == 0x03)
			if used < 0 {
				state.reason = "ack"
				return false
			}
			at += used
			continue
		}
		if id == 0x06 {
			offset, on, oerr := quic.varint_decode(plain[at:])
			if oerr != .None {
				state.reason = "crypto offset"
				return false
			}
			at += on
			length, ln, lerr := quic.varint_decode(plain[at:])
			if lerr != .None {
				state.reason = "crypto length"
				return false
			}
			at += ln
			if length > u64(len(plain) - at) || int(offset) > CAP || int(offset) + int(length) > CAP {
				state.reason = "crypto bounds"
				return false
			}
			chunk := plain[at:at + int(length)]
			fmt.eprintf("crypto level=%v off=%d n=%d first=%x\n", level, offset, len(chunk), chunk[0] if len(chunk) > 0 else 0)
			if !write_recv(state, level, int(offset), chunk) {
				return false
			}
			at += int(length)
			continue
		}
		if id == 0x1c || id == 0x1d {
			state.reason = "peer close"
			return false
		}
		state.reason = "unsupported frame"
		return false
	}
	return feed(state, level)
}

write_recv :: proc(state: ^State, level: Level, offset: int, data: []u8) -> bool {
	i := int(level)
	if offset > state.recv_n[i] {
		state.reason = "crypto gap"
		return false
	}
	for b, k in data {
		at := offset + k
		if at < state.recv_n[i] && state.recv[i][at] != b {
			state.reason = "crypto overlap"
			return false
		}
		state.recv[i][at] = b
	}
	end := offset + len(data)
	if end > state.recv_n[i] {
		state.recv_n[i] = end
	}
	return true
}

feed :: proc(state: ^State, level: Level) -> bool {
	i := int(level)
	for state.fed[i] < state.recv_n[i] {
		slice := state.recv[i][state.fed[i]:state.recv_n[i]]
		if state.await_finished {
			if level != .Handshake {
				return true
			}
			if len(slice) > 36 {
				slice = slice[:36]
			}
		}
		consumed, status, err := tls.server_handshake_feed(&state.owner, tls_level(level), slice)
		if err != .None {
			state.reason = "tls feed"
			fmt.eprintf("tls feed %v\n", err)
			return false
		}
		state.fed[i] += consumed
		if status == .Need_Event_Drain || status == .Await_Flight {
			if !drain(state) {
				return false
			}
			if consumed == 0 && status == .Await_Flight {
				return true
			}
			continue
		}
		if status == .Need_Input || status == .Await_Client_Finished {
			if status == .Await_Client_Finished {
				state.await_finished = true
			}
			if consumed == 0 {
				return true
			}
			continue
		}
		if status == .Terminal {
			state.reason = "tls terminal"
			return false
		}
		if consumed == 0 {
			return true
		}
	}
	return true
}

drain :: proc(state: ^State) -> bool {
	for {
		event, err := tls.server_handshake_peek(&state.owner)
		if err != .None {
			state.reason = "tls peek"
			return false
		}
		#partial switch event.kind {
		case .None:
			return true
		case .Peer_Parameters:
			params: [128]u8
			n := transport_parameters(params[:], state.odcid[:state.odcid_len], state.scid[:])
			se := tls.server_handshake_select_parameters(&state.owner, event.id, {
				mode = .QUIC,
				alpn_protocols = []string{"h3"},
				quic_transport_parameters = params[:n],
			})
			if se != .None {
				state.reason = "parameters"
				fmt.eprintf("parameters %v\n", se)
				return false
			}
			fe := tls.server_handshake_start_flight(&state.owner, state.store, time.now())
			if fe != .None {
				state.reason = "flight"
				fmt.eprintf("flight %v\n", fe)
				return false
			}
		case .Handshake_Bytes:
			fmt.eprintf("tx level=%v n=%d first=%x\n", event.level, len(event.bytes), event.bytes[0] if len(event.bytes) > 0 else 0)
			if !queue_send(state, level_from_tls(event.level), event.bytes) {
				return false
			}
			if tls.server_handshake_accept(&state.owner, event.id) != .None {
				state.reason = "accept bytes"
				return false
			}
		case .Traffic_Secret:
			if !install_secret(state, event) {
				return false
			}
			if tls.server_handshake_accept(&state.owner, event.id) != .None {
				state.reason = "accept secret"
				return false
			}
		case .Complete:
			state.complete = true
			state.hs.handshake_complete = true
			state.hs.have_one_rtt = true
			if tls.server_handshake_accept(&state.owner, event.id) != .None {
				state.reason = "accept complete"
				return false
			}
		case .Fatal:
			state.reason = "tls fatal"
			fmt.eprintf("tls fatal %v\n", event.error)
			return false
		}
	}
}

install_secret :: proc(state: ^State, event: tls.Server_Handshake_Event) -> bool {
	if len(event.secret) != 32 {
		state.reason = "secret length"
		return false
	}
	secret: [32]u8
	copy(secret[:], event.secret)
	defer crypto.zero_explicit(&secret, size_of(secret))
	qlevel := tls.Quic_Secret_Level.Handshake
	if event.level == .Application {
		qlevel = .Application
	}
	keys, err := tls.quic_packet_keys_derive(secret, qlevel)
	defer tls.quic_direction_keys_clear(&keys)
	if err.kind != .None {
		state.reason = "quic keys"
		return false
	}
	send := event.direction == .Write
	dest := &state.hs.handshake_write if send else &state.hs.handshake_read
	one_rtt := event.level == .Application
	if one_rtt {
		dest = &state.hs.one_rtt_write if send else &state.hs.one_rtt_read
	}
	if quic.packet_keys_set_aes(dest, keys.key[:], keys.iv[:], keys.hp[:], keys.secret[:], one_rtt) != .None {
		state.reason = "install keys"
		return false
	}
	if event.level == .Handshake {
		state.have_handshake = true
		state.hs.have_handshake = true
	}
	if one_rtt {
		state.have_app = true
		state.hs.have_one_rtt = true
	}
	return true
}

queue_send :: proc(state: ^State, level: Level, bytes: []u8) -> bool {
	i := int(level)
	if state.send_n[i] > CAP - len(bytes) {
		state.reason = "send cap"
		return false
	}
	copy(state.send[i][state.send_n[i]:], bytes)
	state.send_n[i] += len(bytes)
	return true
}

send_flight :: proc(state: ^State, socket: net.UDP_Socket, to: net.Endpoint) -> bool {
	if !state.installed || to.address == nil {
		return false
	}
	// Until a Handshake packet arrives, this flight is unacknowledged.
	if !state.validated {
		state.send_at[0] = 0
		state.send_at[1] = 0
	}
	budget := max(int) if state.validated else state.bytes_in * 3 - state.bytes_out
	if budget < 1200 {
		return false
	}
	sent := false
	if state.send_at[0] < state.send_n[0] || state.have_ack[0] {
		datagram: [1200]u8
		n := seal_initial(state, datagram[:])
		if n < 0 {
			fail(state)
		}
		if send_datagram(state, socket, to, datagram[:n], &budget) {
			sent = true
		}
	}
	for state.have_handshake && budget > 64 && (state.send_at[1] < state.send_n[1] || state.have_ack[1]) {
		datagram: [1200]u8
		n := seal_handshake(state, datagram[:], min(budget, 1200))
		if n < 0 {
			fail(state)
		}
		if n == 0 || !send_datagram(state, socket, to, datagram[:n], &budget) {
			break
		}
		sent = true
		if state.send_at[1] >= state.send_n[1] {
			break
		}
	}
	if state.complete && state.have_app && !state.done_sent && budget > 64 {
		datagram: [1200]u8
		n := seal_done(state, datagram[:])
		if n > 0 && send_datagram(state, socket, to, datagram[:n], &budget) {
			state.done_sent = true
			sent = true
		}
	}
	return sent
}

// One packet per datagram. OpenSSL's QUIC reader reported a 1500-byte prefix
// of a larger coalesced datagram and never decrypted the Handshake flight.
send_datagram :: proc(state: ^State, socket: net.UDP_Socket, to: net.Endpoint, payload: []u8, budget: ^int) -> bool {
	if len(payload) == 0 || len(payload) > 1200 || len(payload) > budget^ {
		return false
	}
	wrote, werr := net.send_udp(socket, payload, to)
	if werr != nil || wrote != len(payload) {
		state.reason = "send"
		fail(state)
	}
	state.bytes_out += wrote
	budget^ -= wrote
	fmt.eprintf("sent %d in=%d out=%d init=%d/%d hs=%d/%d keys=%v\n", wrote, state.bytes_in, state.bytes_out, state.send_at[0], state.send_n[0], state.send_at[1], state.send_n[1], state.have_handshake)
	return true
}

seal_initial :: proc(state: ^State, dst: []u8) -> int {
	frames: [1400]u8
	fn := 0
	if state.have_ack[0] {
		fn += write_ack(frames[fn:], state.ack[0])
	}
	room := 256
	chunk := min(room, state.send_n[0] - state.send_at[0])
	if chunk > 0 {
		fn += write_crypto(frames[fn:], u64(state.send_at[0]), state.send[0][state.send_at[0]:state.send_at[0] + chunk])
	}
	target := 1200
	if len(dst) < target {
		state.reason = "initial dst"
		return -1
	}
	n := seal_long(state, dst[:target], .Initial, frames[:fn], target)
	if n != target {
		state.reason = "initial seal"
		return -1
	}
	state.send_at[0] += chunk
	state.next_pn[0] += 1
	return n
}

seal_handshake :: proc(state: ^State, dst: []u8, budget: int) -> int {
	frames: [1200]u8
	fn := 0
	if state.have_ack[1] {
		fn += write_ack(frames[fn:], state.ack[1])
		state.have_ack[1] = false
	}
	chunk := min(900, state.send_n[1] - state.send_at[1])
	if chunk > 0 {
		fn += write_crypto(frames[fn:], u64(state.send_at[1]), state.send[1][state.send_at[1]:state.send_at[1] + chunk])
	}
	if fn == 0 {
		return 0
	}
	n := seal_long(state, dst, .Handshake, frames[:fn], 0)
	if n < 0 {
		state.reason = "handshake seal"
		return -1
	}
	if n > budget || n > 1200 {
		return 0
	}
	state.send_at[1] += chunk
	state.next_pn[1] += 1
	return n
}

seal_done :: proc(state: ^State, dst: []u8) -> int {
	frames := [2]u8{0x1e, 0x00}
	plain := frames[:]
	pn := state.next_pn[2]
	packet: [128]u8
	header, _, err := quic.short_header_encode_v1(packet[:], {
		destination_id = state.client_scid[:state.client_scid_len],
		packet_number = u32(pn),
		packet_number_length = PN_LEN,
	})
	if err != .None {
		state.reason = "done header"
		return -1
	}
	state.hs.handshake_complete = true
	sealed, serr := quic.handshake_payload_seal(&state.hs, packet[header:], packet[:header], plain, .One_RTT, pn)
	if serr != .None {
		state.reason = "done seal"
		return -1
	}
	total := header + sealed
	if quic.handshake_header_protection_apply(&state.hs, packet[:total], .One_RTT, state.client_scid_len) != .None {
		state.reason = "done hp"
		return -1
	}
	if total > len(dst) {
		return -1
	}
	copy(dst, packet[:total])
	state.next_pn[2] += 1
	return total
}

seal_long :: proc(state: ^State, dst: []u8, kind: quic.Packet_Kind, frames: []u8, target: int) -> int {
	level := quic.Encryption_Level.Initial
	pn := state.next_pn[0]
	if kind == .Handshake {
		level = .Handshake
		pn = state.next_pn[1]
	}
	dcid_len := state.client_scid_len
	// Long header, version, both CID lengths, CIDs, packet number. Initial also
	// has an empty token varint. The length varint is added below.
	header_len := 7 + dcid_len + SCID_LEN + PN_LEN
	if kind == .Initial {
		header_len += 1
	}
	plain_len := len(frames)
	if target > 0 {
		length_width := 2
		header_len += length_width
		plain_len = target - header_len - 16
		if plain_len < len(frames) {
			state.reason = "pad"
			return -1
		}
	} else {
		length_value := u64(PN_LEN + plain_len + 16)
		width := 1
		if length_value >= 64 {
			width = 2
		}
		header_len += width
	}
	total := header_len + plain_len + 16
	if target > 0 && total != target {
		state.reason = "size"
		return -1
	}
	if total > len(dst) {
		state.reason = "dst"
		return -1
	}
	plain: [2048]u8
	if plain_len > len(plain) {
		state.reason = "plain"
		return -1
	}
	copy(plain[:len(frames)], frames)
	packet: [4096]u8
	hn, _, herr := quic.long_header_encode_v1(packet[:], {
		kind = kind,
		destination_id = state.client_scid[:dcid_len],
		source_id = state.scid[:],
		packet_number = u32(pn),
		packet_number_length = PN_LEN,
		ciphertext_length = u64(plain_len + 16),
	})
	if herr != .None || hn != header_len {
		fmt.eprintf("header %v want %d got %d\n", herr, header_len, hn)
		state.reason = "long header"
		return -1
	}
	sealed, serr := quic.handshake_payload_seal(&state.hs, packet[hn:], packet[:hn], plain[:plain_len], level, pn)
	if serr != .None || sealed != plain_len + 16 {
		fmt.eprintf("seal %v\n", serr)
		state.reason = "seal"
		return -1
	}
	if quic.handshake_header_protection_apply(&state.hs, packet[:total], level, dcid_len) != .None {
		state.reason = "hp"
		return -1
	}
	copy(dst[:total], packet[:total])
	return total
}

write_ack :: proc(dst: []u8, largest: u64) -> int {
	dst[0] = 0x02
	at := 1
	n, _ := quic.varint_encode(dst[at:], largest)
	at += n
	n, _ = quic.varint_encode(dst[at:], 0)
	at += n
	n, _ = quic.varint_encode(dst[at:], 0)
	at += n
	n, _ = quic.varint_encode(dst[at:], 0)
	at += n
	return at
}

write_crypto :: proc(dst: []u8, offset: u64, data: []u8) -> int {
	dst[0] = 0x06
	at := 1
	n, _ := quic.varint_encode(dst[at:], offset)
	at += n
	n, _ = quic.varint_encode(dst[at:], u64(len(data)))
	at += n
	copy(dst[at:], data)
	return at + len(data)
}

read_varint :: proc(src: []u8, at: ^int) -> bool {
	_, n, err := quic.varint_decode(src[at^:])
	if err != .None {
		return false
	}
	at^ += n
	return true
}

skip_ack :: proc(src: []u8, ecn: bool) -> int {
	at := 0
	if !read_varint(src, &at) || !read_varint(src, &at) {
		return -1
	}
	count, n, err := quic.varint_decode(src[at:])
	if err != .None {
		return -1
	}
	at += n
	if !read_varint(src, &at) {
		return -1
	}
	for _ in 0 ..< int(count) {
		if !read_varint(src, &at) || !read_varint(src, &at) {
			return -1
		}
	}
	if ecn {
		if !read_varint(src, &at) || !read_varint(src, &at) || !read_varint(src, &at) {
			return -1
		}
	}
	return at
}

put_param :: proc(dst: []u8, at: ^int, id: u64, value: []u8) {
	n, _ := quic.varint_encode(dst[at^:], id)
	at^ += n
	n, _ = quic.varint_encode(dst[at^:], u64(len(value)))
	at^ += n
	copy(dst[at^:], value)
	at^ += len(value)
}

put_param_int :: proc(dst: []u8, at: ^int, id, value: u64) {
	tmp: [8]u8
	n, _ := quic.varint_encode(tmp[:], value)
	put_param(dst, at, id, tmp[:n])
}

transport_parameters :: proc(dst, odcid, scid: []u8) -> int {
	at := 0
	put_param(dst, &at, 0x00, odcid)
	put_param_int(dst, &at, 0x01, 30_000)
	put_param_int(dst, &at, 0x04, 1 << 20)
	put_param_int(dst, &at, 0x05, 1 << 20)
	put_param_int(dst, &at, 0x06, 1 << 20)
	put_param_int(dst, &at, 0x07, 1 << 20)
	put_param_int(dst, &at, 0x08, 16)
	put_param_int(dst, &at, 0x09, 16)
	// 0x0c disable_active_migration is empty. 0x0f is initial_source_connection_id.
	put_param(dst, &at, 0x0c, nil)
	put_param(dst, &at, 0x0f, scid)
	return at
}

quic_level :: proc(level: Level) -> quic.Encryption_Level {
	switch level {
	case .Initial:
		return .Initial
	case .Handshake:
		return .Handshake
	case .Application:
		return .One_RTT
	}
	return .Initial
}

tls_level :: proc(level: Level) -> tls.Server_Handshake_Level {
	switch level {
	case .Initial:
		return .Initial
	case .Handshake:
		return .Handshake
	case .Application:
		return .Application
	}
	return .Initial
}

level_from_tls :: proc(level: tls.Server_Handshake_Level) -> Level {
	switch level {
	case .Initial:
		return .Initial
	case .Handshake:
		return .Handshake
	case .Application:
		return .Application
	}
	return .Initial
}
