package quic

import "core:crypto"
import "core:crypto/aes"
import "core:crypto/tls"
import "core:crypto/x509"
import "core:time"
import "core:mem"
import credential_store "core:crypto/tls/credentials/store"

// Client and server are the QUIC roles. 0-RTT is not a level. It is installed
// only by handshake_install_zero_rtt when the caller passes a replay-safe policy.
Role :: enum {
	Client,
	Server,
}
Encryption_Level :: enum {
	Initial,
	Handshake,
	One_RTT,
}
Session_Error :: enum {
	None,
	Invalid_State,
	Invalid_ALPN,
	Discarded,
	Zero_RTT_Disabled,
	Unauthenticated,
}

// Bounded CRYPTO buffers are caller-owned. Failure and level changes zero
// keys. 1-RTT open/seal waits until the client Finished is marked sent.
Handshake :: struct {
	role:                 Role,
	failed:               bool,
	peer_authenticated:   bool,
	handshake_complete:   bool,
	initial_discarded:    bool,
	handshake_discarded:  bool,
	have_initial:         bool,
	have_handshake:       bool,
	have_one_rtt:         bool,
	initial:              Initial_Key_Pair,
	handshake_read:       Packet_Keys,
	handshake_write:      Packet_Keys,
	one_rtt_read:         Packet_Keys,
	one_rtt_write:        Packet_Keys,
	zero_rtt_write:       Packet_Keys,
	have_zero_rtt:        bool,
	handshake_secret:     [32]u8,
	client_finished:      [tls.FINISHED_MESSAGE_SIZE]u8,
	client_finished_len:  int,
	// Owned only for a mutual-auth flight; the legacy Finished stays inline.
	client_auth_flight: []u8,
	client_auth_allocator: mem.Allocator,
	crypto:               [3]Crypto_Reassembly,
	largest_pn:           [3]u64,
	have_largest:         [3]bool,
	local_parameters:     []u8,
}

handshake_init :: proc(
	h: ^Handshake,
	role: Role,
	alpn: []string,
	initial_crypto, handshake_crypto, one_rtt_crypto: []u8,
) -> Session_Error {
	if h == nil {
		return .Invalid_State
	}
	handshake_release_client_flight(h)
	h^ = {}
	h.failed = true
	if role != .Client && role != .Server {
		return .Invalid_State
	}
	if tls.alpn_transport_offers(.QUIC, alpn) != .None {
		return .Invalid_ALPN
	}
	if crypto_reassembly_init(&h.crypto[0], initial_crypto) != .None ||
	   crypto_reassembly_init(&h.crypto[1], handshake_crypto) != .None ||
	   crypto_reassembly_init(&h.crypto[2], one_rtt_crypto) != .None {
		return .Invalid_State
	}
	h.role = role
	h.failed = false
	return .None
}

handshake_fail :: proc(h: ^Handshake) {
	if h == nil {
		return
	}
	initial_key_pair_clear(&h.initial)
	packet_keys_clear(&h.handshake_read)
	packet_keys_clear(&h.handshake_write)
	packet_keys_clear(&h.one_rtt_read)
	packet_keys_clear(&h.one_rtt_write)
	packet_keys_clear(&h.zero_rtt_write)
	h.have_zero_rtt = false
	crypto.zero_explicit(&h.handshake_secret, size_of(h.handshake_secret))
	handshake_release_client_flight(h)
	crypto.zero_explicit(&h.client_finished, size_of(h.client_finished))
	h.client_finished_len = 0
	for i in 0 ..< 3 {
		crypto_reassembly_discard(&h.crypto[i])
	}
	h.have_initial = false
	h.have_handshake = false
	h.have_one_rtt = false
	h.peer_authenticated = false
	h.handshake_complete = false
	h.initial_discarded = true
	h.handshake_discarded = true
	h.largest_pn = {}
	h.have_largest = {}
	h.local_parameters = nil
	h.failed = true
}

// Does not derive or retain the early secret unless policy is set. A nil policy
// is the default and returns Zero_RTT_Disabled without installing keys.
// early_secret is HKDF-Extract(0, PSK). client_hello must be the offered hello.
handshake_install_zero_rtt :: proc(
	h: ^Handshake,
	early_secret: []u8,
	policy: ^tls.Early_Data_Policy = nil,
	client_hello: []u8 = nil,
) -> Session_Error {
	if h == nil || h.failed {
		return .Discarded
	}
	if policy == nil || policy.allow == nil {
		return .Zero_RTT_Disabled
	}
	if h.have_zero_rtt || len(early_secret) != 32 || len(client_hello) == 0 {
		return .Invalid_State
	}
	secret: [32]u8
	copy(secret[:], early_secret)
	defer crypto.zero_explicit(&secret, size_of(secret))
	keys, err := tls.quic_early_packet_keys(secret, policy, client_hello)
	defer tls.quic_direction_keys_clear(&keys)
	if err.kind != .None {
		return .Zero_RTT_Disabled
	}
	if packet_keys_set_aes(&h.zero_rtt_write, keys.key[:], keys.iv[:], keys.hp[:], keys.secret[:], false) != .None {
		packet_keys_clear(&h.zero_rtt_write)
		return .Invalid_State
	}
	h.have_zero_rtt = true
	return .None
}

handshake_install_initial :: proc(h: ^Handshake, original_destination_id: []u8) -> (Protection_Error, Session_Error) {
	if h == nil || h.failed {
		return .Invalid_Keys, .Discarded
	}
	if h.initial_discarded || h.have_initial {
		return .Invalid_Keys, .Invalid_State
	}
	pair, e := initial_keys_derive_v1(original_destination_id)
	defer initial_key_pair_clear(&pair)
	if e != .None {
		return e, .None
	}
	h.initial = pair
	h.have_initial = true
	return .None, .None
}

// Client only. A transcript or ALPN failure discards every key and CRYPTO buffer.
handshake_accept_client_hello :: proc(
	h: ^Handshake,
	shared_secret: [32]u8,
	client_hello, server_hello, local_parameters: []u8,
) -> tls.Quic_Secret_Error {
	shared := shared_secret
	defer crypto.zero_explicit(&shared, size_of(shared))
	if h == nil || h.role != .Client || h.failed || h.have_handshake {
		return {kind = .Invalid_Input}
	}
	keys, e := tls.quic_handshake_secrets(shared, client_hello, server_hello, local_parameters)
	defer tls.quic_handshake_keys_clear(&keys)
	if e.kind != .None {
		handshake_fail(h)
		return e
	}
	if packet_keys_set_aes(&h.handshake_write, keys.client.key[:], keys.client.iv[:], keys.client.hp[:], keys.client.secret[:], false) != .None ||
	   packet_keys_set_aes(&h.handshake_read, keys.server.key[:], keys.server.iv[:], keys.server.hp[:], keys.server.secret[:], false) != .None {
		handshake_fail(h)
		return {kind = .Derivation_Failed}
	}
	h.handshake_secret = keys.handshake_secret
	h.local_parameters = local_parameters
	h.have_handshake = true
	return {}
}

// Existing TLS certificate, hostname, signature and Finished checks. Mismatched
// transport parameters fail before those checks and still discard handshake state.
handshake_authenticate_server :: proc(
	h: ^Handshake,
	client_hello, server_hello, handshake_messages: []u8,
	server_name: string,
	roots: []^x509.Certificate,
	now: time.Time,
	peer_parameters: []u8,
	identity:^credential_store.Store=nil,
	allocator:mem.Allocator=context.allocator,
	identity_lease:^credential_store.Lease=nil,
) -> tls.Quic_Secret_Error {
	if h == nil || h.role != .Client || h.failed || !h.have_handshake || h.peer_authenticated {
		return {kind = .Invalid_Input}
	}
	keys, finished, e := tls.quic_application_secrets_mutual(
		h.handshake_secret,
		client_hello,
		server_hello,
		handshake_messages,
		server_name,
		roots,
		now,
		h.local_parameters,
		peer_parameters,identity,allocator,identity_lease,
	)
	defer tls.quic_application_keys_clear(&keys)
	retained:=false
	defer if !retained && raw_data(finished)!=nil {crypto.zero_explicit(raw_data(finished),len(finished));delete(finished,allocator)}
	if e.kind != .None {
		handshake_fail(h)
		return e
	}
	if packet_keys_set_aes(&h.one_rtt_write, keys.client.key[:], keys.client.iv[:], keys.client.hp[:], keys.client.secret[:], true) != .None ||
	   packet_keys_set_aes(&h.one_rtt_read, keys.server.key[:], keys.server.iv[:], keys.server.hp[:], keys.server.secret[:], true) != .None {
		handshake_fail(h)
		return {kind = .Derivation_Failed}
	}
	if len(finished)==tls.FINISHED_MESSAGE_SIZE {copy(h.client_finished[:],finished)} else {
		h.client_auth_flight=finished;h.client_auth_allocator=allocator;retained=true
	}
	h.client_finished_len = len(finished)
	h.have_one_rtt = true
	h.peer_authenticated = true
	return {}
}

handshake_client_finished :: proc(h: ^Handshake) -> ([]u8, Session_Error) {
	if h == nil || h.failed || !h.peer_authenticated || h.client_finished_len < tls.FINISHED_MESSAGE_SIZE {
		return nil, .Unauthenticated
	}
	if h.client_finished_len>tls.FINISHED_MESSAGE_SIZE {
		if len(h.client_auth_flight)!=h.client_finished_len {return nil,.Unauthenticated}
		return h.client_auth_flight,.None
	}
	return h.client_finished[:h.client_finished_len], .None
}

// Client has sent its Finished. 1-RTT packets stay refused until this call.
handshake_note_finished_sent :: proc(h: ^Handshake) -> Session_Error {
	if h == nil || h.failed {
		return .Discarded
	}
	if h.role != .Client || !h.peer_authenticated || h.client_finished_len < tls.FINISHED_MESSAGE_SIZE {
		return .Unauthenticated
	}
	h.handshake_complete = true
	return .None
}

// RFC 9001 section 4.9.1. Client drops Initial keys when it first sends Handshake.
// Server drops them when it first successfully processes Handshake.
handshake_note_handshake_packet :: proc(h: ^Handshake, sent: bool) -> Session_Error {
	if h == nil || h.failed {
		return .Discarded
	}
	drop := (h.role == .Client && sent) || (h.role == .Server && !sent)
	if !drop {
		return .None
	}
	return handshake_discard_initial(h)
}

handshake_discard_initial :: proc(h: ^Handshake) -> Session_Error {
	if h == nil || h.failed {
		return .Discarded
	}
	initial_key_pair_clear(&h.initial)
	crypto_reassembly_discard(&h.crypto[int(Encryption_Level.Initial)])
	h.have_initial = false
	h.initial_discarded = true
	h.largest_pn[int(Encryption_Level.Initial)] = 0
	h.have_largest[int(Encryption_Level.Initial)] = false
	return .None
}

handshake_discard_handshake_keys :: proc(h: ^Handshake) -> Session_Error {
	if h == nil || h.failed {
		return .Discarded
	}
	packet_keys_clear(&h.handshake_read)
	packet_keys_clear(&h.handshake_write)
	crypto.zero_explicit(&h.handshake_secret, size_of(h.handshake_secret))
	crypto_reassembly_discard(&h.crypto[int(Encryption_Level.Handshake)])
	h.have_handshake = false
	h.handshake_discarded = true
	h.largest_pn[int(Encryption_Level.Handshake)] = 0
	h.have_largest[int(Encryption_Level.Handshake)] = false
	h.local_parameters = nil
	if len(h.client_auth_flight)>0 {handshake_release_client_flight(h);h.client_finished_len=0}
	return .None
}

@(private)
handshake_release_client_flight :: proc(h:^Handshake) {
 if h==nil {return}
 if raw_data(h.client_auth_flight)!=nil {crypto.zero_explicit(raw_data(h.client_auth_flight),len(h.client_auth_flight));delete(h.client_auth_flight,h.client_auth_allocator)}
 h.client_auth_flight=nil;h.client_auth_allocator={}
}

// Sender advances the 1-RTT write secret one phase. The read generation changes
// only when a peer packet opens under the next key and IV.
handshake_advance_one_rtt :: proc(h: ^Handshake) -> Session_Error {
	if e := handshake_one_rtt_ready(h); e != .None {
		return e
	}
	if packet_keys_advance(&h.one_rtt_write) != .None {
		return .Invalid_State
	}
	return .None
}

handshake_confirm_one_rtt :: proc(h: ^Handshake) -> Session_Error {
	if e := handshake_one_rtt_ready(h); e != .None {
		return e
	}
	if packet_keys_confirm_update(&h.one_rtt_write) != .None {
		return .Invalid_State
	}
	return .None
}

@(private)
handshake_one_rtt_ready :: proc(h: ^Handshake) -> Session_Error {
	if h == nil || h.failed {
		return .Discarded
	}
	if h.role != .Client && h.role != .Server {
		return .Invalid_State
	}
	if !h.handshake_complete {
		return .Unauthenticated
	}
	if !h.have_one_rtt {
		return .Invalid_State
	}
	return .None
}

// Handshake keys are dropped only once the handshake is confirmed.
handshake_confirm :: proc(h: ^Handshake) -> Session_Error {
	if h == nil || h.failed {
		return .Discarded
	}
	if !h.handshake_complete {
		return .Unauthenticated
	}
	return handshake_discard_handshake_keys(h)
}

handshake_ingest_crypto :: proc(
	h: ^Handshake,
	level: Encryption_Level,
	offset: u64,
	data: []u8,
) -> Crypto_Error {
	if h == nil || h.failed {
		return .Discarded
	}
	if level == .Initial && h.initial_discarded || level == .Handshake && h.handshake_discarded {
		return .Discarded
	}
	e := crypto_reassembly_write(&h.crypto[int(level)], offset, data)
	if e == .Cap_Overflow || e == .Overlap_Mismatch || e == .Span_Exhausted {
		handshake_fail(h)
	}
	return e
}

// Records a packet number only after AEAD success. Reconstruction uses that
// space's largest; before any success the expected number is 0.
handshake_note_authenticated_pn :: proc(
	h: ^Handshake,
	level: Encryption_Level,
	full: u64,
) -> Protection_Error {
	if h == nil || h.failed {
		return .Invalid_Keys
	}
	if full > MAX_VARINT {
		return .Invalid_Packet_Number
	}
	i := int(level)
	if !h.have_largest[i] || full > h.largest_pn[i] {
		h.largest_pn[i] = full
		h.have_largest[i] = true
	}
	return .None
}

handshake_reconstruct_pn :: proc(
	h: ^Handshake,
	level: Encryption_Level,
	truncated: u64,
	pn_nbits: int,
) -> (
	u64,
	Protection_Error,
) {
	if h == nil || h.failed {
		return 0, .Invalid_Keys
	}
	i := int(level)
	return packet_number_reconstruct(h.have_largest[i], h.largest_pn[i], truncated, pn_nbits)
}

handshake_crypto_bytes :: proc(h: ^Handshake, level: Encryption_Level) -> ([]u8, Crypto_Error) {
	if h == nil || h.failed {
		return nil, .Discarded
	}
	return crypto_reassembly_bytes(&h.crypto[int(level)])
}

handshake_payload_seal :: proc(
	h: ^Handshake,
	dst, header, plaintext: []u8,
	level: Encryption_Level,
	full_packet_number: u64,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> (
	int,
	Protection_Error,
) {
	keys, e := handshake_direction_keys(h, level, true)
	if e != .None {
		return 0, e
	}
	if level == .Initial {
		return initial_payload_seal(dst, header, plaintext, keys.initial, full_packet_number, implementation)
	}
	return payload_seal(dst, header, plaintext, keys.packet, full_packet_number, implementation)
}

handshake_payload_open :: proc(
	h: ^Handshake,
	dst, header, ciphertext_and_tag: []u8,
	level: Encryption_Level,
	full_packet_number: u64,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> (
	int,
	Protection_Error,
) {
	keys, e := handshake_direction_keys(h, level, false)
	if e != .None {
		return 0, e
	}
	if level == .Initial {
		return initial_payload_open(dst, header, ciphertext_and_tag, keys.initial, full_packet_number, implementation)
	}
	return payload_open(dst, header, ciphertext_and_tag, keys.packet, full_packet_number, implementation)
}

handshake_header_protection_apply :: proc(
	h: ^Handshake,
	packet: []u8,
	level: Encryption_Level,
	destination_id_len: int = 0,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> Protection_Error {
	return handshake_header_protection(h, packet, level, destination_id_len, false, implementation)
}

handshake_header_protection_remove :: proc(
	h: ^Handshake,
	packet: []u8,
	level: Encryption_Level,
	destination_id_len: int = 0,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> Protection_Error {
	return handshake_header_protection(h, packet, level, destination_id_len, true, implementation)
}

@(private)
Direction_Keys :: struct {
	initial: ^Initial_Keys,
	packet:  ^Packet_Keys,
}

@(private)
handshake_direction_keys :: proc(
	h: ^Handshake,
	level: Encryption_Level,
	send: bool,
) -> (
	Direction_Keys,
	Protection_Error,
) {
	if h == nil || h.failed {
		return {}, .Invalid_Keys
	}
	if level == .One_RTT && !h.handshake_complete {
		return {}, .Unauthenticated
	}
	switch level {
	case .Initial:
		if !h.have_initial || h.initial_discarded {
			return {}, .Invalid_Keys
		}
		keys := &h.initial.client
		if (h.role == .Client) != send {
			keys = &h.initial.server
		}
		return {initial = keys}, .None
	case .Handshake:
		if !h.have_handshake || h.handshake_discarded {
			return {}, .Invalid_Keys
		}
		keys := &h.handshake_write
		if !send {
			keys = &h.handshake_read
		}
		return {packet = keys}, .None
	case .One_RTT:
		if !h.have_one_rtt {
			return {}, .Invalid_Keys
		}
		keys := &h.one_rtt_write
		if !send {
			keys = &h.one_rtt_read
		}
		return {packet = keys}, .None
	}
	return {}, .Invalid_Header
}

@(private)
handshake_header_protection :: proc(
	h: ^Handshake,
	packet: []u8,
	level: Encryption_Level,
	destination_id_len: int,
	remove: bool,
	implementation: aes.Implementation,
) -> Protection_Error {
	keys, e := handshake_direction_keys(h, level, !remove)
	if e != .None {
		return e
	}
	if level == .Initial {
		if remove {
			return initial_header_protection_remove(packet, keys.initial, implementation)
		}
		return initial_header_protection_apply(packet, keys.initial, implementation)
	}
	kind: Packet_Kind = .Handshake
	if level == .One_RTT {
		kind = .One_RTT
	}
	if remove {
		return header_protection_remove(packet, keys.packet, kind, destination_id_len, implementation)
	}
	return header_protection_apply(packet, keys.packet, kind, destination_id_len, implementation)
}
