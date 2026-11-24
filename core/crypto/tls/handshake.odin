package tls

import "core:crypto"
import "core:crypto/hash"
import "core:mem"
import transport "core:net"
import "core:net"
import "core:time"

// Authenticated handshake orchestration

MAX_SERVER_FLIGHT_SIZE :: 1 << 20

Handshake_Error_Kind :: enum {
	None,
	Invalid_State,
	Client_Hello_Failed,
	Server_Hello_Failed,
	Key_Derivation_Failed,
	Server_Flight_Read_Failed,
	Server_Flight_Oversized,
	Unexpected_Handshake_Message,
	Malformed_Message,
	Unsupported_Extension,
	Client_Authentication_Unsupported,
	Authentication_Failed,
	Finished_Failed,
	Finished_Write_Failed,
	Deadline_Failed,
	Allocation_Failed,
	Invalid_ALPN,
	Early_Data_Disabled,
}

Handshake_Error :: struct {
	kind:           Handshake_Error_Kind,
	client_hello:   Client_Hello_Send_Error,
	server_hello:   Server_Hello_Read_Error,
	keys:           Handshake_Keys_Error,
	record:         Handshake_Record_Read_Error,
	authentication: Authentication_Error,
	finished:       Finished_Error,
	protection:     Record_Protection_Error,
	transport:      transport.Connection_Error,
	message_type:   u8,
	allocation:     mem.Allocator_Error,
	// Socket facade only: an extension of EncryptedExtensions overran the
	// message, which upstream's client answers with an unprotected alert.
	plaintext_alert: bool,
	// Socket facade only: the alert upstream's client names for a failure
	// of its own checks, where the kind does not say. Zero is none.
	upstream_alert: Alert_Description,
}

// Authenticate the server, verify Finished, then send our Finished before
// allowing application bytes. Repeated successful calls perform no I/O.
// Certificate authentication is unchanged. An offered session may resume with
// psk_dhe_ke. Early data is refused unless Config.early_data is set. That
// policy is not installed as 0-RTT keys on this path.
@(private)
engine_handshake :: proc(conn: ^Conn) -> Handshake_Error {
	return handshake_until_internal(conn, {})
}

// Authenticates within the earlier of the configured handshake budget and the
// caller's absolute deadline. Zero preserves handshake's existing behavior.
// Synchronous callbacks cannot be interrupted; expiry is checked on return.
@(private)
engine_handshake_until :: proc(conn: ^Conn, deadline: time.Time) -> Handshake_Error {
	effective := deadline
	// Preserve one effective absolute cutoff, including for callbacks which
	// return success after the earlier configured handshake budget elapsed.
	if deadline != (time.Time{}) && conn != nil {
		timeout := conn.config.handshake_timeout
		if timeout == 0 {timeout = 10 * time.Second}
		now := time.now()
		if time.diff(now, deadline) > timeout {effective = time.time_add(now, timeout)}
	}
	error := handshake_until_internal(conn, effective)
	if error.kind != .None {return error}
	return handshake_until_check(conn, effective)
}

@(private)
handshake_until_internal :: proc(conn: ^Conn, deadline: time.Time) -> Handshake_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Established do return {}

	if conn.phase == .Failed {
		if conn.handshake_error.kind != .None {
			return conn.handshake_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Handshake_Pending {
		return {kind = .Invalid_State}
	}

	deadlines_set, deadline_error := handshake_deadline_start_until(conn, deadline)
	if deadline_error.kind != .None do return deadline_error

	defer {
		handshake_alert_flush(conn)
		if deadlines_set {
			transport.set_deadline(conn.transport, {})
		}
	}
	if error := handshake_until_check(conn, deadline); error.kind != .None {return error}
	if hello_error := handshake_hello_exchange(conn); hello_error.kind != .None {
		return hello_error
	}
	if conn.tls12.negotiated {
		return tls12_client_establish(conn)
	}
	// A stable bounded allocation keeps borrowed DER valid while parsing and
	// verifying the entire certificate chain. It is released before returning.
	flight_storage, allocation_error := make([]u8, MAX_SERVER_FLIGHT_SIZE)
	if allocation_error != nil {
		return handshake_fail(conn, {kind = .Allocation_Failed, allocation = allocation_error})
	}
	defer delete(flight_storage)
	if error := handshake_until_check(conn, deadline); error.kind != .None {return error}
	flight, flight_error := handshake_server_flight_read(conn, flight_storage)
	if flight_error.kind != .None do return flight_error
	if verify_error := engine_handshake_server_flight_verify(conn, flight); verify_error.kind != .None {
		return verify_error
	}

	if error := handshake_until_check(conn, deadline); error.kind != .None {
		return error
	}

	if finish_error := handshake_client_finished_send(conn); finish_error.kind != .None {
		return finish_error
	}

	if error := handshake_until_check(conn, deadline); error.kind != .None {
		return error
	}

	activation_error := handshake_application_activate(conn, deadlines_set)
	if activation_error.kind == .None {
		deadlines_set = false
	}
	return activation_error
}

@(private)
handshake_deadline_start :: proc(conn: ^Conn) -> (bool, Handshake_Error) {
	return handshake_deadline_start_until(conn, {})
}

@(private)
handshake_deadline_start_until :: proc(conn: ^Conn, deadline: time.Time) -> (bool, Handshake_Error) {
	deadlines_set := false
	if conn.transport.set_read_deadline != nil && conn.transport.set_write_deadline != nil {
		timeout := conn.config.handshake_timeout
		if timeout == 0 do timeout = 10 * time.Second

		now := time.now()
		selected := deadline
		if deadline == (time.Time{}) {
			// Only the legacy path establishes a relative deadline here.
			selected = time.time_add(now, timeout)
		} else if time.diff(now, deadline) <= 0 {
			return false, handshake_fail(conn, {kind = .Deadline_Failed, transport = {kind = .Timeout}})
		}
		if err := transport.set_deadline(conn.transport, selected);
		   err.kind != .None {
			transport.set_deadline(conn.transport, {})
			return false, handshake_fail(conn, {kind = .Deadline_Failed, transport = err})
		}

		if deadline != (time.Time{}) && time.diff(time.now(), selected) <= 0 {
			transport.set_deadline(conn.transport, {})
			return false, handshake_fail(conn, {kind = .Deadline_Failed, transport = {kind = .Timeout}})
		}
		deadlines_set = true
	} else if conn.config.handshake_timeout > 0 || deadline != (time.Time{}) {
		return false, handshake_fail(
			conn,
			{kind = .Deadline_Failed, transport = {kind = .Deadline_Unsupported}},
		)
	}

	return deadlines_set, {}
}

@(private)
handshake_hello_exchange :: proc(conn: ^Conn) -> Handshake_Error {
	if err := client_hello_send(conn); err.kind != .None {
		return handshake_fail(conn, {kind = .Client_Hello_Failed, client_hello = err})
	}

	if err := server_hello_read(conn); err.kind != .None {
		return handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
	}

	if conn.phase == .Hello_Retry_Received {
		if err := client_hello_retry_send(conn); err.kind != .None {
			return handshake_fail(conn, {kind = .Client_Hello_Failed, client_hello = err})
		}

		if err := server_hello_read(conn); err.kind != .None {
			return handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
		}
	}

	if conn.tls12.negotiated {
		return {}
	}

	if err := client_handshake_keys_init(conn); err.kind != .None {
		return handshake_fail(conn, {kind = .Key_Derivation_Failed, keys = err})
	}

	return {}
}

@(private)
handshake_server_flight_read :: proc(
	conn: ^Conn,
	flight_storage: []u8,
) -> (
	[]u8,
	Handshake_Error,
) {
	storage: [MAX_CIPHERTEXT_SIZE]u8
	size := 0
	for conn.phase == .Handshake_Keys_Ready {
		content, err := handshake_record_read(conn, storage[:])
		if err.kind != .None {
			return nil, handshake_fail(conn, {kind = .Server_Flight_Read_Failed, record = err})
		}

		if len(content) > len(flight_storage) - size {
			return nil, handshake_fail(conn, {kind = .Server_Flight_Oversized})
		}

		copy(flight_storage[size:], content)
		size += len(content)
	}
	if conn.phase != .Server_Finished_Received {
		return nil, handshake_fail(conn, {kind = .Invalid_State})
	}

	return flight_storage[:size], {}
}

// Authenticates the complete server flight against the handshake secrets of
// conn. On success the transcript through server Finished is retained for the
// client's flight and for the application secrets.
@(private)
engine_handshake_server_flight_verify :: proc(conn: ^Conn, flight: []u8) -> Handshake_Error {
	transcript: Handshake_Transcript
	handshake_hello_transcript(conn, &transcript)

	at := 0
	encrypted_extensions, message_err := handshake_next_message(flight, &at, .Encrypted_Extensions)
	if message_err.kind != .None {
		return handshake_fail(conn, message_err)
	}

	if conn.upstream_client {
		if check_error := socket_encrypted_extensions_check(encrypted_extensions, conn.config.server_name, conn.config.alpn_protocols); check_error.kind != .None {
			return handshake_fail(conn, check_error)
		}
	}

	allow_early := conn.early_offered && conn.config.early_data != nil && conn.config.early_data.allow != nil
	selected, early_accepted, extension_error := encrypted_extensions_decode(
		encrypted_extensions,
		conn.config.server_name,
		conn.config.alpn_protocols,
		allow_early,
	)
	if extension_error.kind != .None {
		return handshake_fail(conn, extension_error)
	}

	transcript_update(&transcript, encrypted_extensions)
	if at < len(flight) && flight[at] == u8(Handshake_Type.Certificate_Request) {
		request, e := handshake_next_message(flight, &at, .Certificate_Request)
		if e.kind != .None {
			return handshake_fail(conn, e)
		}

		if conn.upstream_client {
			// Upstream answers any well-formed request with no certificate.
			if e = socket_certificate_request_check(request); e.kind != .None {
				return handshake_fail(conn, e)
			}
			conn.client_auth_requested = true
		} else if e = client_auth_request_decode(conn, request); e.kind != .None {
			return handshake_fail(conn, e)
		}

		transcript_update(&transcript, request)
	}
	// Abbreviate only when the PSK is still bound to this hostname and the peer
	// omitted certificates. A certificate still takes the existing checks.
	// Finished-only is not accepted for a full handshake.
	bound_session := conn.offered_session
	if bound_session == nil {
		bound_session = conn.config.session
	}
	abbreviate := conn.psk_selected && session_offerable(bound_session, conn.config.server_name, time.now())
	if abbreviate && string(selected) != string(bound_session.alpn[:bound_session.alpn_len]) {
		return handshake_fail(conn, {kind = .Malformed_Message})
	}

	if !(abbreviate && at < len(flight) && flight[at] == u8(Handshake_Type.Finished)) {
		if cert_error := handshake_flight_certificates_verify(conn, flight, &at, &transcript); cert_error.kind != .None {
			return cert_error
		}
	}

	if finished_error := handshake_flight_finished_verify(conn, flight, &at, &transcript); finished_error.kind != .None {
		return finished_error
	}

	// The flight buffer is released by the async driver before Finished is sent.
	// Retain a bounded owned copy, still hidden until authentication completes.
	copy(conn.alpn_selected[:], selected)
	conn.alpn_selected_size = len(selected)
	conn.server_finished_transcript = transcript
	conn.application_transcript = transcript
	conn.have_server_finished_transcript = true
	if conn.early_offered {
		conn.early_accepted = early_accepted
		conn.early_rejected = !early_accepted
	}
	return {}
}

// Hash of the suite over message_hash/HRR (after a retry), ClientHello and
// ServerHello: the transcript the handshake traffic secrets are bound to.
@(private)
handshake_hello_transcript :: proc(conn: ^Conn, transcript: ^Handshake_Transcript) {
	transcript_init(transcript, cipher_suite_hash(conn.server_parameters.cipher_suite))
	transcript_update(transcript, conn.retry_transcript[:conn.retry_transcript_size])
	transcript_update(transcript, handshake_effective_client_hello(conn))
	transcript_update(transcript, conn.server_hello[:conn.server_hello_size])
}

@(private)
handshake_flight_certificates_verify :: proc(
	conn: ^Conn,
	flight: []u8,
	at: ^int,
	transcript: ^Handshake_Transcript,
) -> Handshake_Error {
	certificate, certificate_message_err := handshake_next_message(flight, at, .Certificate)
	if certificate_message_err.kind != .None {
		return handshake_fail(conn, certificate_message_err)
	}

	certs, auth_err := engine_server_certificates_parse(certificate)
	if auth_err.kind != .None {
		return handshake_fail(conn, {kind = .Authentication_Failed, authentication = auth_err})
	}

	defer server_certificates_destroy(&certs)
	if !conn.config.unsafe_skip_verify {
		// Upstream's client verifies the chain for the name exactly as given.
		err: Authentication_Error
		if conn.upstream_client {
			err = verify_server_chain(&certs, conn.config.server_name, conn.config.root_cas, time.now())
		} else {
			err = engine_verify_server_certificates(&certs, conn.config.server_name, conn.config.root_cas, time.now())
		}
		if err.kind != .None {
			return handshake_fail(conn, {kind = .Authentication_Failed, authentication = err})
		}
	}

	transcript_update(transcript, certificate)
	return handshake_flight_signature_verify(conn, &certs, flight, at, transcript)
}

@(private)
handshake_flight_signature_verify :: proc(
	conn: ^Conn,
	certs: ^Server_Certificates,
	flight: []u8,
	at: ^int,
	transcript: ^Handshake_Transcript,
) -> Handshake_Error {
	certificate_verify, verify_message_err := handshake_next_message(
		flight,
		at,
		.Certificate_Verify,
	)
	if verify_message_err.kind != .None {
		return handshake_fail(conn, verify_message_err)
	}

	digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
	digest := transcript_hash(transcript, digest_storage[:])
	schemes := client_offer_signature_schemes(conn.config.offer)
	if err := verify_certificate_signature(certs, certificate_verify, digest, true, schemes);
	   err.kind != .None {
		return handshake_fail(
			conn,
			{kind = .Authentication_Failed, authentication = err, message_type = u8(Handshake_Type.Certificate_Verify)},
		)
	}

	transcript_update(transcript, certificate_verify)
	return {}
}

@(private)
handshake_flight_finished_verify :: proc(
	conn: ^Conn,
	flight: []u8,
	at: ^int,
	transcript: ^Handshake_Transcript,
) -> Handshake_Error {
	finished_message, finished_message_err := handshake_next_message(flight, at, .Finished)
	if finished_message_err.kind != .None {
		return handshake_fail(conn, finished_message_err)
	}

	if at^ != len(flight) {
		return handshake_fail(conn, {kind = .Unexpected_Handshake_Message})
	}

	if conn.secrets.hash == .Invalid {
		return handshake_fail(conn, {kind = .Invalid_State})
	}

	if len(finished_message) != 4 + hash.DIGEST_SIZES[conn.secrets.hash] {
		return handshake_fail(conn, {kind = .Finished_Failed, finished = .Invalid_Length})
	}

	if !verify_connection_finished(&conn.secrets, transcript, finished_message[4:], true) {
		return handshake_fail(conn, {kind = .Finished_Failed, finished = .Verification_Failed})
	}

	transcript_update(transcript, finished_message)
	return {}
}

// Seals the client Finished over the transcript through the server Finished
// and any client authentication flight. The digest through this Finished is
// kept for the resumption master secret.
@(private)
handshake_client_finished_encode :: proc(
	conn: ^Conn,
	wire: []u8,
) -> (
	int,
	Handshake_Error,
) {
	if !conn.have_server_finished_transcript {
		return 0, handshake_fail(conn, {kind = .Invalid_State})
	}

	storage: [MAX_FINISHED_MESSAGE_SIZE]u8
	defer crypto.zero_explicit(&storage, size_of(storage))

	digest_size := hash.DIGEST_SIZES[conn.secrets.hash]
	client_finished := storage[:4 + digest_size]
	finished_header_encode(client_finished, digest_size)
	derive_connection_finished(&conn.secrets, &conn.server_finished_transcript, client_finished[4:], true)

	through_finished := conn.server_finished_transcript
	transcript_update(&through_finished, client_finished)
	transcript_hash(&through_finished, conn.client_finished_hash[:])
	conn.have_client_finished_hash = true

	written, protection_err := engine_record_seal(
		&conn.handshake_send,
		wire,
		.Handshake,
		client_finished,
	)
	if protection_err != .None {
		return 0, handshake_fail(
			conn,
			{kind = .Finished_Write_Failed, protection = protection_err},
		)
	}

	return written, {}
}

@(private)
handshake_client_finished_send :: proc(conn: ^Conn) -> Handshake_Error {
	if e := client_auth_prepare(conn, context.allocator); e.kind != .None {
		return handshake_fail(conn, e)
	}

	wire: [RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE]u8
	if size := handshake_ccs_encode(conn, wire[:]); size > 0 {
		if _, write_error := transport.write_all(conn.transport, wire[:size]); write_error.kind != .None {
			return handshake_fail(conn, {kind = .Finished_Write_Failed, transport = write_error})
		}
	}

	for conn.client_auth_offset < len(conn.client_auth_flight) {
		at := conn.client_auth_offset
		end := min(len(conn.client_auth_flight), at + MAX_PLAINTEXT_SIZE)
		n, e := engine_record_seal(&conn.handshake_send, wire[:], .Handshake, conn.client_auth_flight[at:end])
		if e != .None {
			return handshake_fail(conn, {kind = .Finished_Write_Failed, protection = e})
		}

		if _, write_error := transport.write_all(conn.transport, wire[:n]); write_error.kind != .None {
			return handshake_fail(conn, {kind = .Finished_Write_Failed, transport = write_error})
		}

		conn.client_auth_offset = end
	}

	written, err := handshake_client_finished_encode(conn, wire[:])
	if err.kind != .None {
		return err
	}

	_, send_err := transport.write_all(conn.transport, wire[:written])
	if send_err.kind != .None {
		return handshake_fail(conn, {kind = .Finished_Write_Failed, transport = send_err})
	}

	return {}
}

// Switches to the application traffic secrets once the client Finished left
// under the handshake keys: upstream's finished_connection_secrets takes the
// schedule to the master secret over the transcript through server Finished.
@(private)
handshake_application_activate :: proc(
	conn: ^Conn,
	deadlines_set: bool,
) -> Handshake_Error {
	if !conn.have_server_finished_transcript {
		return handshake_fail(conn, {kind = .Invalid_State})
	}

	if deadlines_set {
		if err := transport.set_deadline(conn.transport, {}); err.kind != .None {
			return handshake_fail(conn, {kind = .Deadline_Failed, transport = err})
		}
	}

	finished_connection_secrets(&conn.secrets, &conn.keys, &conn.application_transcript)
	resumption_capture(conn)

	resumption_master: []u8
	if conn.have_resumption_master {
		resumption_master = conn.resumption_master[:hash.DIGEST_SIZES[conn.keys.hash]]
	}
	application_init(&conn.application, &conn.secrets, resumption_master)
	handshake_keys_clear(conn)
	conn.phase = .Established
	conn.handshake_complete = true
	return {}
}

@(private)
handshake_sni_offered :: proc(server_name: string) -> bool {
	return net.parse_address(server_name) == nil
}

@(private)
handshake_fail :: proc(conn: ^Conn, err: Handshake_Error) -> Handshake_Error {
	handshake_alert_stage(conn, err)
	conn.phase = .Failed
	alpn_clear(conn)
	conn.handshake_error = err
	conn.offered_session = nil
	conn.early_offered = false
	conn.early_accepted = false
	conn.early_rejected = false
	conn.early_effect_done = false
	handshake_keys_clear(conn)
	application_clear(&conn.application)
	return err
}

// Size of a sealed or plaintext alert record.
HANDSHAKE_ALERT_WIRE_SIZE :: RECORD_HEADER_SIZE + 2 + 1 + GCM_TAG_SIZE

// The Upstream offer tells the peer why the handshake failed, as upstream's
// client does: the fatal alert of the first failure is sealed here, while
// the handshake keys still exist (plaintext before them), and the driver
// writes it out. The Compatible offer sends no alert.
@(private)
handshake_alert_stage :: proc(conn: ^Conn, err: Handshake_Error) {
	if conn.alert_staged || conn.config.offer != .Upstream {
		return
	}
	conn.alert_staged = true

	description, plaintext, send := socket_handshake_alert(err)
	if !send {
		return
	}

	content := [2]u8{u8(alert_to_level(description)), u8(description)}
	if conn.handshake_send.initialized && !plaintext {
		size, seal_error := engine_record_seal(&conn.handshake_send, conn.alert_wire[:], .Alert, content[:])
		if seal_error == .None {
			conn.alert_size = size
		}
		return
	}

	header := record_header_encode({content_type = .Alert, legacy_version = LEGACY_TLS_1_2, length = len(content)})
	copy(conn.alert_wire[:], header[:])
	copy(conn.alert_wire[RECORD_HEADER_SIZE:], content[:])
	conn.alert_size = RECORD_HEADER_SIZE + len(content)
}

// Best effort: the handshake has already failed.
@(private)
handshake_alert_flush :: proc(conn: ^Conn) {
	if conn.alert_size == 0 {
		return
	}

	transport.write_all(conn.transport, conn.alert_wire[:conn.alert_size])
	conn.alert_size = 0
}

// ChangeCipherSpec of the Upstream offer's middlebox compatibility mode: sent
// once, immediately before the client's encrypted flight.
@(private)
CHANGE_CIPHER_SPEC_RECORD :: [RECORD_HEADER_SIZE + 1]u8{u8(TLS_Content_Type.Change_Cipher_Spec), 3, 3, 0, 1, 1}

// Writes the compatibility ChangeCipherSpec to dst when the offer of conn
// owes one; returns the bytes written.
@(private)
handshake_ccs_encode :: proc(conn: ^Conn, dst: []u8) -> int {
	if conn.config.offer != .Upstream || conn.ccs_sent {
		return 0
	}

	conn.ccs_sent = true
	record := CHANGE_CIPHER_SPEC_RECORD
	return copy(dst, record[:])
}

// Upstream's client accepts no ChangeCipherSpec before the ServerHello and a
// single one after it; the engine otherwise tolerates
// MAX_IGNORED_CHANGE_CIPHER_SPECS at either point.
@(private)
handshake_ccs_refused :: proc(conn: ^Conn) -> bool {
	if !conn.upstream_client {
		return false
	}

	if conn.phase != .Handshake_Keys_Ready || conn.ccs_received > 0 {
		return true
	}

	conn.ccs_received += 1
	return false
}

@(private)
handshake_next_message :: proc(
	flight: []u8,
	at: ^int,
	expected: Handshake_Type,
) -> (
	[]u8,
	Handshake_Error,
) {
	if at^ > len(flight) - 4 {
		return nil, {kind = .Malformed_Message}
	}

	kind := flight[at^]
	if kind == cast(u8)Handshake_Type.Certificate_Request && expected != .Certificate_Request {
		return nil, {kind = .Client_Authentication_Unsupported, message_type = kind}
	}

	if kind != cast(u8)expected {
		return nil, {kind = .Unexpected_Handshake_Message, message_type = kind}
	}

	size := 4 + handshake_body_size(flight[at^:])
	if size > len(flight) - at^ {
		return nil, {kind = .Malformed_Message}
	}

	message := flight[at^:][:size]
	at^ += size
	return message, {}
}

// Legacy no-ALPN validation keeps its exported signature and rejects unsolicited
// protocol selections. The shared decoder also handles configured offers.
@(private)
engine_encrypted_extensions_validate :: proc(message: []u8, server_name: string) -> Handshake_Error {
	_, _, error := encrypted_extensions_decode(message, server_name, nil, false)
	return error
}

@(private)
encrypted_extensions_decode :: proc(
	message: []u8,
	server_name: string,
	offers: []string,
	allow_early: bool,
) -> (
	selected: []u8,
	early_accepted: bool,
	error: Handshake_Error,
) {
	if len(message) < 6 {
		return nil, false, {kind = .Malformed_Message}
	}

	extensions_size := cast(int)message[4] << 8 | cast(int)message[5]
	if extensions_size != len(message) - 6 {
		return nil, false, {kind = .Malformed_Message}
	}

	at := 6
	name_seen, groups_seen, alpn_seen, early_seen: bool
	for at < len(message) {
		if len(message) - at < 4 {
			return nil, false, {kind = .Malformed_Message}
		}

		kind := cast(u16)message[at] << 8 | cast(u16)message[at + 1]
		size := cast(int)message[at + 2] << 8 | cast(int)message[at + 3]
		at += 4
		if size > len(message) - at {
			return nil, false, {kind = .Malformed_Message}
		}

		switch kind {
		case cast(u16)Extension_Type.Server_Name:
			if name_seen || size != 0 || !handshake_sni_offered(server_name) {
				return nil, false, {kind = .Malformed_Message}
			}

			name_seen = true
		case cast(u16)Extension_Type.Supported_Groups:
			if groups_seen || size < 4 || size % 2 != 0 {
				return nil, false, {kind = .Malformed_Message}
			}

			list_size := cast(int)message[at] << 8 | cast(int)message[at + 1]
			if list_size != size - 2 {
				return nil, false, {kind = .Malformed_Message}
			}

			groups_seen = true
		case cast(u16)Extension_Type.Application_Layer_Protocol_Negotiation:
			if alpn_seen {return nil, false, {kind = .Malformed_Message}}
			alpn_seen = true
			selected, error = alpn_selection_decode(message[at:at + size], offers)
			if error.kind != .None {return nil, false, error}
		case 42:
			if early_seen || size != 0 {
				return nil, false, {kind = .Malformed_Message}
			}
			early_seen = true
			if !allow_early {
				return nil, false, {kind = .Early_Data_Disabled}
			}
		case:
			return nil, false, {kind = .Unsupported_Extension}
		}
		at += size
	}
	return selected, early_seen, {}
}

// Initial ClientHello exchange

Client_Hello_Send_Error_Kind :: enum {
	None,
	Invalid_State,
	Entropy_Unavailable,
	Encode_Failed,
	Invalid_Retry,
	Write_Failed,
}

Client_Hello_Send_Error :: struct {
	kind:      Client_Hello_Send_Error_Kind,
	encode:    Client_Hello_Error,
	retry:     Server_Hello_Error,
	transport: transport.Connection_Error,
	written:   int,
}

// First step of the handshake, not a completed TLS connection. A successful
// call leaves the connection awaiting ServerHello. Errors are terminal and
// cached: retrying must never send a second or partially repeated ClientHello.
@(private)
engine_client_hello_prepare :: proc(conn: ^Conn) -> Client_Hello_Send_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.client_hello_error.kind != .None {
			return conn.client_hello_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Handshake_Pending {
		return {kind = .Invalid_State}
	}

	when !crypto.HAS_RAND_BYTES {
		return client_hello_fail(conn, {kind = .Entropy_Unavailable})
	}
	hello := Client_Hello {
		server_name = conn.config.server_name,
		alpn_protocols = conn.config.alpn_protocols,
	}
	crypto.rand_bytes(hello.random[:])
	conn.tls12.client_random = hello.random

	// Upstream's hello carries a random legacy session id.
	conn.legacy_session_id_size = 0
	if conn.config.offer == .Upstream {
		crypto.rand_bytes(conn.legacy_session_id[:])
		conn.legacy_session_id_size = len(conn.legacy_session_id)
	}

	clear_ephemeral_keys(&conn.ephemeral)
	if !init_ephemeral_keys(&conn.ephemeral, config_groups(&conn.config)) {
		return client_hello_fail(conn, {kind = .Entropy_Unavailable})
	}
	// One flight offers TLS 1.3 and the two TLS 1.2 AES-GCM suites. The
	// TLS 1.3-only encoder stays available for tests and is not this path.
	conn.psk_offered = false
	conn.psk_selected = false
	conn.offered_session = nil
	conn.early_offered = false
	conn.early_accepted = false
	conn.early_rejected = false
	conn.early_effect_done = false
	size, encode_err := client_hello_offer_encode(conn, &hello)
	if encode_err != .None {
		return client_hello_fail(conn, {kind = .Encode_Failed, encode = encode_err})
	}
	if chosen := session_resume_candidate(conn, time.now()); chosen != nil {
		// Opt-in is the policy. Resumption alone does not install 0-RTT keys.
		early := conn.config.early_data != nil && conn.config.early_data.allow != nil &&
			chosen.saw_early_data && chosen.early_data_max > 0
		bound, offered := resumption_client_hello_offer(conn.client_hello[:], size, chosen, time.now(), early)
		if !offered {
			return client_hello_fail(conn, {kind = .Encode_Failed, encode = .Destination_Undersized})
		}
		size = bound
		conn.psk_offered = true
		conn.offered_session = chosen
		conn.early_offered = early
 } else if conn.config.remember_tickets {
  // Advertise psk_dhe_ke on the initial full handshake too; independent
  // servers otherwise correctly decline to issue any resumption tickets.
  layout,valid:=client_hello_layout_decode(conn.client_hello[:size]);if !valid||size+6>len(conn.client_hello) {return client_hello_fail(conn,{kind=.Encode_Failed,encode=.Destination_Undersized})}
  at:=size;resumption_put_u16(conn.client_hello[:],&at,EXTENSION_PSK_MODES);resumption_put_u16(conn.client_hello[:],&at,2);conn.client_hello[at],conn.client_hello[at+1]=1,PSK_DHE_KE;size=at+2
  retry_put_u24(conn.client_hello[:],1,size-4);retry_put_u16(conn.client_hello[:],layout.extensions_length_offset,u16(layout.extensions_size+6))
 }

 conn.client_hello_size = size

	return {}
}

// Encodes the first flight of the configured offer from the fresh ephemeral
// keys of conn.
@(private)
client_hello_offer_encode :: proc(conn: ^Conn, hello: ^Client_Hello) -> (int, Client_Hello_Error) {
	if conn.config.offer == .Upstream {
		return upstream_client_hello_encode(
			conn.client_hello[:],
			hello^,
			config_cipher_suites(&conn.config),
			&conn.ephemeral,
			handshake_session_id(conn),
			conn.upstream_client,
		)
	}

	client_key_share_bytes(&conn.ephemeral, .X25519, hello.x25519_public_key[:])
	return compatible_client_hello_encode(conn.client_hello[:], hello^)
}

// The legacy session id the ClientHello of conn carried.
@(private)
handshake_session_id :: proc(conn: ^Conn) -> []u8 {
	return conn.legacy_session_id[:conn.legacy_session_id_size]
}

// The largest ServerHello the offer of conn can be answered with.
@(private)
server_hello_cap :: proc(conn: ^Conn) -> int {
	if conn.config.offer == .Upstream {
		return MAX_UPSTREAM_SERVER_HELLO_SIZE
	}
	return MAX_SERVER_HELLO_SIZE
}

// Reassembly storage for one ServerHello or HelloRetryRequest of the offer.
@(private)
server_hello_storage_size :: proc(conn: ^Conn) -> int {
	return max(MAX_HELLO_RETRY_REQUEST_SIZE, server_hello_cap(conn))
}

@(private)
client_hello_send :: proc(conn: ^Conn) -> Client_Hello_Send_Error {
	if err := engine_client_hello_prepare(conn); err.kind != .None do return err
	size := conn.client_hello_size

	// Initial ClientHello may use legacy record version 0x0301. The inner
	// ClientHello uses 0x0303 and offers TLS 1.3, then TLS 1.2.
	header := record_header_encode(
		{content_type = .Handshake, legacy_version = LEGACY_TLS_1_0, length = cast(u16)size},
	)
	wire: [RECORD_HEADER_SIZE + MAX_CLIENT_HELLO_SIZE]u8
	copy(wire[:RECORD_HEADER_SIZE], header[:])
	copy(wire[RECORD_HEADER_SIZE:], conn.client_hello[:size])
	written, write_err := transport.write_all(conn.transport, wire[:RECORD_HEADER_SIZE + size])
	if write_err.kind != .None {
		return client_hello_fail(
			conn,
			{kind = .Write_Failed, transport = write_err, written = written},
		)
	}

	conn.phase = .Awaiting_Server_Hello
	return {}
}

@(private)
client_hello_fail :: proc(conn: ^Conn, err: Client_Hello_Send_Error) -> Client_Hello_Send_Error {
	conn.phase = .Failed
	alpn_clear(conn)
	conn.client_hello_error = err
	conn.offered_session = nil
	conn.early_offered = false
	conn.early_accepted = false
	conn.early_rejected = false
	conn.early_effect_done = false
	clear_ephemeral_keys(&conn.ephemeral)
	return err
}

// ServerHello exchange

// Resource limit for compatibility records that make no handshake progress.
@(private)
MAX_IGNORED_CHANGE_CIPHER_SPECS :: 16

Server_Hello_Read_Error_Kind :: enum {
	None,
	Invalid_State,
	Record_Read_Failed,
	Peer_Alert,
	Invalid_Change_Cipher_Spec,
	Too_Many_Change_Cipher_Specs,
	Interleaved_Record,
	Message_Oversized,
	Record_Boundary_Violation,
	Invalid_Server_Hello,
	Invalid_Key_Share,
}

Server_Hello_Read_Error :: struct {
	kind:              Server_Hello_Read_Error_Kind,
	record:            Record_Read_Error,
	decode:            Server_Hello_Error,
	// Preserve the peer's wire alert, including descriptions unknown to us.
	alert_level:       u8,
	alert_description: u8,
}

// Reassembles exactly one ServerHello, retaining its handshake bytes for the
// transcript. It must end at a record boundary because encryption keys change
// immediately afterwards (RFC 8446 section 5.1). No encrypted bytes are read.
// Failure is terminal; close this connection. One bounded cookie-only retry
// can instead transition to Hello_Retry_Received without discarding the key.
@(private)
server_hello_read :: proc(conn: ^Conn) -> Server_Hello_Read_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.server_hello_error.kind != .None {
			return conn.server_hello_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Awaiting_Server_Hello {
		return {kind = .Invalid_State}
	}

	storage: [MAX_SERVER_HELLO_MESSAGE_SIZE]u8
	message := storage[:server_hello_storage_size(conn)]
	received, read_error := server_hello_message_read(conn, message)
	if read_error.kind != .None do return server_hello_fail(conn, read_error)
	if hello_is_retry(message[:received]) {
		return server_hello_retry_accept(conn, message[:received])
	}
	// Only the Compatible offer carries the TLS 1.2 suites.
	if conn.config.offer == .Compatible && tls12_server_hello_selected(message[:received]) {
		return tls12_server_hello_accept(conn, message[:received])
	}
	if conn.tls12.prefix != nil {
		return server_hello_fail(conn, {kind = .Record_Boundary_Violation})
	}
	return server_hello_accept(conn, message[:received])
}

@(private)
server_hello_message_append :: proc(
	message, body: []u8,
	received: ^int,
	cap: int = MAX_SERVER_HELLO_SIZE,
) -> (
	bool,
	Server_Hello_Read_Error,
) {
	if len(body) > len(message) - received^ {
		return false, {kind = .Message_Oversized}
	}

	copy(message[received^:], body)
	received^ += len(body)
	if message[0] != cast(u8)Handshake_Type.Server_Hello {
		return false, {kind = .Invalid_Server_Hello, decode = .Unexpected_Handshake_Type}
	}

	if received^ < 4 do return false, {}

	expected := 4 + handshake_body_size(message[:received^])
	if expected > len(message) {
		return false, {kind = .Message_Oversized}
	}

	if received^ >= 38 &&
	   !hello_is_retry(message[:received^]) &&
	   expected > cap {
		return false, {kind = .Message_Oversized}
	}

	if received^ > expected {
		return false, {kind = .Record_Boundary_Violation}
	}

	if received^ < expected do return false, {}

	return true, {}
}

@(private)
server_hello_ccs_validate :: proc(body: []u8, ignored_ccs: ^int) -> Server_Hello_Read_Error {
	if body[0] != 1 {
		return {kind = .Invalid_Change_Cipher_Spec}
	}

	ignored_ccs^ += 1
	if ignored_ccs^ > MAX_IGNORED_CHANGE_CIPHER_SPECS {
		return {kind = .Too_Many_Change_Cipher_Specs}
	}

	return {}
}

// TLS 1.3 still rejects a ServerHello that shares its record with later
// handshake bytes. TLS 1.2 keeps that tail for the certificate flight. The
// 90-byte cap applies once the suite is TLS 1.3; a retry may be larger.
@(private)
server_hello_message_limit :: proc(
	message: []u8,
	received: int,
	cap: int = MAX_SERVER_HELLO_SIZE,
) -> (
	int,
	Server_Hello_Read_Error,
) {
	if received < 4 do return len(message), {}
	if received >= 39 && int(message[38]) > 32 {
		return 0, {kind = .Invalid_Server_Hello, decode = .Session_ID_Mismatch}
	}
	limit := len(message)
	if received >= 38 && !hello_is_retry(message[:received]) {
		// Until the suite is read, either version's cap may apply.
		limit = max(TLS12_MAX_SERVER_HELLO_SIZE, cap)
		if cipher, ok := tls12_server_hello_cipher(message[:received]); ok &&
		   cipher != TLS12_ECDHE_RSA_AES128_GCM_SHA256 &&
		   cipher != TLS12_ECDHE_ECDSA_AES128_GCM_SHA256 {
			limit = cap
		} else if ok {
			limit = TLS12_MAX_SERVER_HELLO_SIZE
		}
	}
	expected := 4 + handshake_body_size(message)
	if expected > limit || expected > len(message) {
		return 0, {kind = .Message_Oversized}
	}
	return expected, {}
}

@(private)
server_hello_consume :: proc(
	message, body: []u8,
	received: ^int,
	cap: int = MAX_SERVER_HELLO_SIZE,
) -> (
	complete: bool,
	consumed: int,
	error: Server_Hello_Read_Error,
) {
	for consumed < len(body) {
		expected := len(message)
		if received^ >= 4 {
			var_expected, limit_error := server_hello_message_limit(message, received^, cap)
			if limit_error.kind != .None do return false, consumed, limit_error
			expected = var_expected
			if received^ == expected do return true, consumed, {}
			if received^ > expected do return false, consumed, {kind = .Record_Boundary_Violation}
		}
		goal := 4
		if received^ >= 4 do goal = expected
		// Classify the suite before accepting a large body. HelloRetryRequest
		// is recognizable from its random, which sits in the first 38 bytes.
		if received^ < 38 && goal > 38 do goal = 38
		n := min(goal - received^, len(body) - consumed)
		if n <= 0 do return false, consumed, {kind = .Invalid_Server_Hello}
		copy(message[received^:], body[consumed:][:n])
		received^ += n
		consumed += n
	}
	if received^ >= 4 {
		expected, limit_error := server_hello_message_limit(message, received^, cap)
		if limit_error.kind != .None do return false, consumed, limit_error
		if received^ == expected do return true, consumed, {}
	}
	return false, consumed, {}
}

@(private)
server_hello_message_read :: proc(conn: ^Conn, message: []u8) -> (int, Server_Hello_Read_Error) {
	storage: [MAX_PLAINTEXT_SIZE]u8
	received, ignored_ccs: int
	for {
		header, body, err := record_read_plaintext(conn.transport, storage[:])
		if err.kind != .None {
			return 0, {kind = .Record_Read_Failed, record = err}
		}

		if header.content_type != .Handshake && received > 0 {
			return 0, {kind = .Interleaved_Record}
		}

		#partial switch header.content_type {
		case .Alert:
			return 0, {kind = .Peer_Alert, alert_level = body[0], alert_description = body[1]}
		case .Change_Cipher_Spec:
			if handshake_ccs_refused(conn) {
				return 0, {kind = .Too_Many_Change_Cipher_Specs}
			}

			if ccs_error := server_hello_ccs_validate(body, &ignored_ccs); ccs_error.kind != .None do return 0, ccs_error
			continue
		case .Handshake:
			complete, consumed, append_error := server_hello_consume(message, body, &received, server_hello_cap(conn))
			if append_error.kind != .None do return 0, append_error
			if !complete do continue
			if consumed < len(body) {
				if hello_is_retry(message[:received]) || !tls12_server_hello_selected(message[:received]) {
					return 0, {kind = .Record_Boundary_Violation}
				}
				tail := body[consumed:]
				copied, allocation_error := make([]u8, len(tail))
				if allocation_error != nil {
					return 0, {kind = .Message_Oversized}
				}
				copy(copied, tail)
				conn.tls12.prefix = copied
				conn.tls12.prefix_allocator = context.allocator
			}
		}
		break
	}
	return received, {}
}

@(private)
server_hello_retry_accept :: proc(conn: ^Conn, message: []u8) -> Server_Hello_Read_Error {
	// Upstream's client sends every key share and treats a retry as an error.
	if conn.upstream_client {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = .Hello_Retry_Unsupported})
	}

	if conn.retry_transcript_size != 0 {
		return server_hello_fail(
			conn,
			{kind = .Invalid_Server_Hello, decode = .Repeated_Hello_Retry},
		)
	}

	cookie, cookie_error := hello_retry_request_decode(message, config_cipher_suites(&conn.config), handshake_session_id(conn))
	if cookie_error != .None {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = cookie_error})
	}

	if err := client_hello_retry_prepare(conn, message, cookie); err != .None {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = err})
	}

	conn.phase = .Hello_Retry_Received
	return {}
}

@(private)
server_hello_accept :: proc(conn: ^Conn, message: []u8) -> Server_Hello_Read_Error {
	received := len(message)
	copy(conn.server_hello[:], message[:received])
	parameters, decode_err := server_hello_decode_offered(
		conn.server_hello[:received],
		config_cipher_suites(&conn.config),
		config_groups(&conn.config),
		conn.psk_offered,
		handshake_session_id(conn),
	)
	defer crypto.zero_explicit(&parameters, size_of(parameters))
	if decode_err != .None {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = decode_err})
	}

	algorithm := CIPHER_SUITE_HASH[parameters.cipher_suite]

	// RFC 8446 section 4.1.4: the suite of a retry binds the ServerHello.
	if conn.retry_transcript_size != 0 && algorithm != client_hello_retry_hash(conn.retry_transcript[conn.retry_message_hash_size:conn.retry_transcript_size]) {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = .Unoffered_Cipher})
	}

	// Sessions hold SHA-256 PSKs: a PSK may only be selected with its hash.
	if parameters.psk_selected && algorithm != .SHA256 {
		return server_hello_fail(conn, {kind = .Invalid_Server_Hello, decode = .Unoffered_Cipher})
	}

	// Upstream's schedule from the early secret through the key exchange.
	// RFC 8446 section 7.4.2: a low-order or malformed share fails here.
	schedule_init(&conn.keys, algorithm, handshake_selected_psk(conn, parameters.psk_selected))
	agreed := update_handshake_keys_ephemeral(
		&conn.keys,
		&conn.ephemeral,
		parameters.group,
		parameters.key_share[:parameters.key_share_size],
	)
	clear_ephemeral_keys(&conn.ephemeral)
	if !agreed {
		return server_hello_fail(conn, {kind = .Invalid_Key_Share})
	}

	conn.server_hello_size = received
	conn.server_parameters = parameters
	conn.psk_selected = parameters.psk_selected
	conn.phase = .Server_Hello_Received
	return {}
}

// The PSK of the session the server selected, or nil when none was selected
// or its session is gone (key installation reports that).
@(private)
handshake_selected_psk :: proc(conn: ^Conn, selected: bool) -> []u8 {
	if !selected {
		return nil
	}

	bound_session := conn.offered_session
	if bound_session == nil {
		bound_session = conn.config.session
	}

	if bound_session == nil || !bound_session.usable {
		return nil
	}
	return bound_session.psk[:]
}

@(private)
server_hello_fail :: proc(conn: ^Conn, err: Server_Hello_Read_Error) -> Server_Hello_Read_Error {
	conn.phase = .Failed
	alpn_clear(conn)
	conn.server_hello_error = err
	clear_ephemeral_keys(&conn.ephemeral)
	clear_handshake_keys(&conn.keys)
	return err
}

// Handshake key installation and cleanup

Handshake_Keys_Error_Kind :: enum {
	None,
	Invalid_State,
	Derivation_Failed,
}

Handshake_Keys_Error :: struct {
	kind:  Handshake_Keys_Error_Kind,
	cause: Key_Schedule_Error,
}

// Install independent send/receive keys, each starting at sequence zero.
// This transition happens once; calling it again must never reset nonces.
// These keys encrypt the remaining handshake, not authenticated application I/O.
@(private)
client_handshake_keys_init :: proc(conn: ^Conn) -> Handshake_Keys_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.handshake_keys_error.kind != .None {
			return conn.handshake_keys_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Server_Hello_Received {
		return {kind = .Invalid_State}
	}

	if conn.client_hello_size < 0 ||
	   conn.client_hello_size > len(conn.client_hello) ||
	   conn.server_hello_size < 0 ||
	   conn.server_hello_size > len(conn.server_hello) ||
	   conn.retry_client_hello_size < 0 ||
	   conn.retry_client_hello_size > len(conn.retry_client_hello) ||
	   conn.retry_transcript_size < 0 ||
	   conn.retry_transcript_size > len(conn.retry_transcript) {
		return {kind = .Invalid_State}
	}

	// Handshake secrets only. 0-RTT packet keys are not installed here.
	if conn.psk_selected && handshake_selected_psk(conn, true) == nil {
		conn.phase = .Failed
		alpn_clear(conn)
		conn.offered_session = nil
		conn.handshake_keys_error = {kind = .Derivation_Failed, cause = .Invalid_Secret_Length}
		handshake_keys_clear(conn)
		return conn.handshake_keys_error
	}

	if err := client_handshake_schedule_check(conn); err != .None {
		conn.phase = .Failed
		alpn_clear(conn)
		conn.handshake_keys_error = {
			kind  = .Derivation_Failed,
			cause = err,
		}
		handshake_keys_clear(conn)
		return conn.handshake_keys_error
	}

	client_handshake_secrets_install(conn)
	conn.phase = .Handshake_Keys_Ready
	return {}
}

@(private)
client_handshake_schedule_check :: proc(conn: ^Conn) -> Key_Schedule_Error {
	if !schedule_message_valid(handshake_effective_client_hello(conn), .Client_Hello) {
		return .Invalid_Client_Hello
	}

	if !schedule_message_valid(conn.server_hello[:conn.server_hello_size], .Server_Hello) {
		return .Invalid_Server_Hello
	}

	if !cipher_suite_known(conn.server_parameters.cipher_suite) {
		return .Invalid_Server_Hello
	}

	// ServerHello acceptance left the handshake secret of the suite's hash.
	if conn.keys.hash != CIPHER_SUITE_HASH[conn.server_parameters.cipher_suite] {
		return .Invalid_Shared_Secret
	}

	return .None
}

// Continues upstream's schedule from the handshake secret that ServerHello
// acceptance left in conn.keys: both handshake traffic secrets over the
// stored hello messages and their AEAD state, which move into the record
// protections.
@(private)
client_handshake_secrets_install :: proc(conn: ^Conn) {
	suite := conn.server_parameters.cipher_suite

	transcript: Handshake_Transcript
	handshake_hello_transcript(conn, &transcript)
	// The key log names the connection by the ClientHello random.
	logger := conn.config.unsafe_secret_logger
	client_random: []u8
	if logger != nil {
		client_random = conn.client_hello[CLIENT_HELLO_RANDOM_OFFSET:][:RANDOM_SIZE]
	}
	init_connection_secrets(&conn.secrets, &conn.keys, &transcript, CIPHER_SUITE_AEAD[suite], true, context.allocator, client_random, logger)

	record_protection_init(&conn.handshake_send, &conn.secrets.client_aead)
	record_protection_init(&conn.handshake_receive, &conn.secrets.server_aead)
}

@(private)
handshake_keys_clear :: proc(conn: ^Conn) {
 client_auth_clear(conn)
	clear_ephemeral_keys(&conn.ephemeral)
	clear_handshake_keys(&conn.keys)
	clear_connection_secrets(&conn.secrets)
	crypto.zero_explicit(&conn.resumption_master, size_of(conn.resumption_master))
	conn.have_resumption_master = false
	crypto.zero_explicit(&conn.server_finished_transcript, size_of(conn.server_finished_transcript))
	crypto.zero_explicit(&conn.application_transcript, size_of(conn.application_transcript))
	conn.have_server_finished_transcript = false
	crypto.zero_explicit(&conn.client_finished_hash, size_of(conn.client_finished_hash))
	conn.have_client_finished_hash = false
	record_protection_clear(&conn.handshake_send)
	record_protection_clear(&conn.handshake_receive)
	tls12_client_clear(conn)
	system_roots_release(conn)
}

@(private)
handshake_effective_client_hello :: proc(conn: ^Conn) -> []u8 {
	if conn.retry_client_hello_size > 0 {
		return conn.retry_client_hello[:conn.retry_client_hello_size]
	}

	return conn.client_hello[:conn.client_hello_size]
}

// HelloRetryRequest handling

// Resource policy: accept cookie-only retries up to 1024 cookie bytes. Our
// fixed X25519 share rules out any legitimate HRR key_share selection.
MAX_RETRY_COOKIE_SIZE :: 1024
MAX_HELLO_RETRY_REQUEST_SIZE :: 44 + LEGACY_SESSION_ID_SIZE + 6 + 6 + MAX_RETRY_COOKIE_SIZE
MAX_RETRY_TRANSCRIPT_SIZE :: MAX_MESSAGE_HASH_SIZE + MAX_HELLO_RETRY_REQUEST_SIZE
MAX_RETRY_CLIENT_HELLO_SIZE :: MAX_CLIENT_HELLO_SIZE + 6 + MAX_RETRY_COOKIE_SIZE
// Reassembly storage for a ServerHello of any offer or a HelloRetryRequest.
MAX_SERVER_HELLO_MESSAGE_SIZE :: max(MAX_HELLO_RETRY_REQUEST_SIZE, MAX_UPSTREAM_SERVER_HELLO_SIZE)
@(private)
RETRY_COOKIE_EXTENSION :: cast(u16)44

// RFC 8446 sections 4.1.4, 4.2.2, 4.2.8. Cookie bytes borrow wire. For our
// fixed offer, any key_share HRR is invalid: X25519 was already shared, and
// every other group was not offered. A retry must make a real change, so a
// cookie is required and may not be empty.
@(private)
hello_retry_request_decode :: proc(
	wire: []u8,
	suites: []Cipher_Suite = COMPATIBLE_CIPHER_SUITES,
	session_id: []u8 = nil,
) -> (
	cookie: []u8,
	err: Server_Hello_Error,
) {
	if len(wire) < 44 + len(session_id) {
		return nil, .Truncated
	}

	if wire[0] != cast(u8)Handshake_Type.Server_Hello {
		return nil, .Unexpected_Handshake_Type
	}

	if handshake_body_size(wire) + 4 != len(wire) {
		return nil, .Length_Mismatch
	}

	if retry_u16(wire, 4) != cast(u16)LEGACY_TLS_1_2 {
		return nil, .Invalid_Legacy_Version
	}

	if !hello_is_retry(wire) {
		return nil, .Invalid_Hello_Retry_Request
	}

	if !hello_session_echoed(wire, session_id) {
		return nil, .Session_ID_Mismatch
	}

	at := 39 + len(session_id)
	if !cipher_suite_offered(suites, Cipher_Suite(retry_u16(wire, at))) {
		return nil, .Unoffered_Cipher
	}

	if wire[at + 2] != 0 {
		return nil, .Invalid_Compression
	}

	if cast(int)retry_u16(wire, at + 3) != len(wire) - (at + 5) {
		return nil, .Extension_Length_Mismatch
	}

	return hello_retry_extensions_decode(wire, at + 5)
}

@(private)
hello_retry_extensions_decode :: proc(wire: []u8, extensions_at: int = 44) -> (cookie: []u8, err: Server_Hello_Error) {
	version_seen, cookie_seen: bool
	at := extensions_at
	for at < len(wire) {
		if len(wire) - at < 4 do return nil, .Truncated

		kind, size := retry_u16(wire, at), cast(int)retry_u16(wire, at + 2)
		at += 4
		if size > len(wire) - at do return nil, .Truncated

		switch kind {
		case cast(u16)Extension_Type.Supported_Versions:
			if version_seen {
				return nil, .Duplicate_Extension
			}

			version_seen = true
			if size != 2 {
				return nil, .Extension_Length_Mismatch
			}

			if retry_u16(wire, at) != VERSION_TLS_1_3 {
				return nil, .Unsupported_Version
			}

		case RETRY_COOKIE_EXTENSION:
			if cookie_seen {
				return nil, .Duplicate_Extension
			}

			cookie_seen = true
			if size < 3 || cast(int)retry_u16(wire, at) != size - 2 {
				return nil, .Invalid_Retry_Cookie
			}

			if size - 2 > MAX_RETRY_COOKIE_SIZE {
				return nil, .Retry_Cookie_Oversized
			}

			cookie = wire[at + 2:at + size]
		case cast(u16)Extension_Type.Key_Share:
			return nil, .Invalid_Retry_Group
		case:
			return nil, .Unsupported_Extension
		}
		at += size
	}
	if !version_seen {
		return nil, .Missing_Supported_Versions
	}

	if !cookie_seen do return nil, .Missing_Retry_Cookie

	return cookie, .None
}

// Sending is separate from receiving so the full handshake can drive a clear
// Hello_Retry_Received -> Awaiting_Server_Hello transition. The original
// ClientHello and ephemeral key are retained; cookie retries reuse both.
@(private)
client_hello_retry_send :: proc(conn: ^Conn) -> Client_Hello_Send_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.client_hello_error.kind != .None {
			return conn.client_hello_error
		}

		return {kind = .Invalid_State}
	}

	if conn.phase != .Hello_Retry_Received {
		return {kind = .Invalid_State}
	}

	if conn.retry_client_hello_size < 47 ||
	   conn.retry_client_hello_size > MAX_RETRY_CLIENT_HELLO_SIZE ||
	   conn.retry_transcript_size < 36 {
		return client_hello_fail(
			conn,
			{kind = .Invalid_Retry, retry = .Invalid_Retry_Client_Hello},
		)
	}

	size := conn.retry_client_hello_size
	header := record_header_encode(
		{content_type = .Handshake, legacy_version = LEGACY_TLS_1_2, length = cast(u16)size},
	)
	wire: [RECORD_HEADER_SIZE + MAX_RETRY_CLIENT_HELLO_SIZE]u8
	copy(wire[:RECORD_HEADER_SIZE], header[:])
	copy(wire[RECORD_HEADER_SIZE:], conn.retry_client_hello[:size])
	written, err := transport.write_all(conn.transport, wire[:RECORD_HEADER_SIZE + size])
	if err.kind != .None {
		return client_hello_fail(conn, {kind = .Write_Failed, transport = err, written = written})
	}

	conn.phase = .Awaiting_Server_Hello
	return {}
}

@(private)
hello_is_retry :: proc(wire: []u8) -> bool {
	if len(wire) < 38 do return false

	for value, i in HELLO_RETRY_REQUEST_RANDOM {
		if wire[6 + i] != value do return false
	}
	return true
}

// Prepare CH2 and the transcript prefix atomically after validating HRR.
// RFC 8446 section 4.4.1 replaces CH1 with message_hash(Hash(CH1)).
@(private)
client_hello_retry_prepare :: proc(conn: ^Conn, retry: []u8, cookie: []u8) -> Server_Hello_Error {
	if conn == nil do return .Invalid_Retry_Client_Hello
	if conn.retry_transcript_size != 0 {
		return .Repeated_Hello_Retry
	}

	size := conn.client_hello_size
	if size < 47 || size > len(conn.client_hello) {
		return .Invalid_Retry_Client_Hello
	}
	first := conn.client_hello[:size]
	layout, valid := client_hello_layout_decode(first)
	if !valid || layout.session_size != conn.legacy_session_id_size || layout.has_cookie {
		return .Invalid_Retry_Client_Hello
	}
	if len(cookie) == 0 || len(cookie) > MAX_RETRY_COOKIE_SIZE {
		return .Invalid_Retry_Cookie
	}
	if len(retry) > MAX_HELLO_RETRY_REQUEST_SIZE {
		return .Retry_Cookie_Oversized
	}

	// The retry must name a suite this ClientHello offered.
	if !client_hello_layout_has_cipher(first, layout, u16(client_hello_retry_suite(retry))) {
		return .Invalid_Retry_Client_Hello
	}

	new_size := size + 6 + len(cookie)
	extensions_size := layout.extensions_size + 6 + len(cookie)
	if new_size > len(conn.retry_client_hello) || extensions_size > 65535 ||
	   MAX_MESSAGE_HASH_SIZE + len(retry) > len(conn.retry_transcript) ||
	   !client_hello_retry_inputs_disjoint(conn, retry, cookie, new_size) {
		return .Invalid_Retry_Client_Hello
	}
	if resumption_extension_offset(first, EXTENSION_PRE_SHARED_KEY) >= 0 {
		return resumption_retry_prepare(conn, first, retry, cookie, layout)
	}
	copy(conn.retry_client_hello[:], first)
	retry_put_u24(conn.retry_client_hello[:], 1, new_size - 4)
	retry_put_u16(conn.retry_client_hello[:], layout.extensions_length_offset, u16(extensions_size))
	retry_put_u16(conn.retry_client_hello[:], size, RETRY_COOKIE_EXTENSION)
	retry_put_u16(conn.retry_client_hello[:], size + 2, u16(2 + len(cookie)))
	retry_put_u16(conn.retry_client_hello[:], size + 4, u16(len(cookie)))
	copy(conn.retry_client_hello[size + 6:], cookie)
	conn.retry_client_hello_size = new_size

	client_hello_retry_transcript_prepare(conn, first, retry)
	return .None
}

// The suite a decoded retry names, after its legacy session id echo. A retry
// too short to name one counts as TLS_AES_128_GCM_SHA256, the suite of every
// offer, so this step stays total; the retry decoder rejects such input.
@(private)
client_hello_retry_suite :: proc(retry: []u8) -> Cipher_Suite {
	if len(retry) < 39 || len(retry) < 41 + int(retry[38]) {
		return .TLS_AES_128_GCM_SHA256
	}
	return Cipher_Suite(retry_u16(retry, 39 + int(retry[38])))
}

// The hash of message_hash is the hash of the suite the retry names.
@(private)
client_hello_retry_hash :: proc(retry: []u8) -> hash.Algorithm {
	return cipher_suite_hash(client_hello_retry_suite(retry))
}

@(private)
cipher_suite_known :: proc(suite: Cipher_Suite) -> bool {
	return suite >= min(Cipher_Suite) && suite <= max(Cipher_Suite)
}

// Transcript hash of suite. A value that names no TLS 1.3 suite (nothing
// negotiated yet) maps to SHA-256 so callers stay total.
@(private)
cipher_suite_hash :: proc(suite: Cipher_Suite) -> hash.Algorithm {
	if !cipher_suite_known(suite) {
		return .SHA256
	}
	return CIPHER_SUITE_HASH[suite]
}

@(private)
client_hello_retry_transcript_prepare :: proc(conn: ^Conn, first, retry: []u8) {
	t: Handshake_Transcript
	transcript_init(&t, client_hello_retry_hash(retry))
	transcript_update(&t, first)

	digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
	digest := transcript_hash(&t, digest_storage[:])
	message := transcript_message_hash_encode(conn.retry_transcript[:], digest)
	copy(conn.retry_transcript[len(message):], retry)
	conn.retry_message_hash_size = len(message)
	conn.retry_transcript_size = len(message) + len(retry)
}

@(private)
retry_u16 :: proc(data: []u8, at: int) -> u16 {
	return cast(u16)data[at] << 8 | cast(u16)data[at + 1]
}

@(private)
retry_put_u16 :: proc(data: []u8, at: int, value: u16) {
	data[at], data[at + 1] = cast(u8)(value >> 8), cast(u8)value
}

@(private)
retry_put_u24 :: proc(data: []u8, at, value: int) {
	data[at], data[at + 1], data[at + 2] =
		cast(u8)(value >> 16), cast(u8)(value >> 8), cast(u8)value
}

// Encrypted handshake records and message boundaries

Handshake_Record_Read_Error_Kind :: enum {
	None,
	Invalid_State,
	Destination_Undersized,
	Header_Read_Failed,
	Invalid_Header,
	Body_Read_Failed,
	Unexpected_Content_Type,
	Invalid_Change_Cipher_Spec,
	Too_Many_Change_Cipher_Specs,
	Interleaved_Record,
	Record_Boundary_Violation,
	Decryption_Failed,
	Peer_Alert,
}

Handshake_Record_Read_Error :: struct {
	kind:              Handshake_Record_Read_Error_Kind,
	transport:         transport.Connection_Error,
	record:            Record_Error,
	protection:        Record_Protection_Error,
	received:          int,
	alert_level:       u8,
	alert_description: u8,
	// Unexpected_Content_Type: the outer type of the offending record, or
	// Application_Data when the type inside a protected record was wrong.
	content_type:      TLS_Content_Type,
}

// Reads and authenticates one encrypted handshake record. Returned bytes
// borrow dst and may contain multiple handshake messages or a message fragment.
// Their certificate and Finished authentication is handled by later stages.
// Undersized buffers consume nothing; all other operational failures are
// terminal and cached. The caller still owns closing the failed connection.
@(private)
handshake_record_read :: proc(
	conn: ^Conn,
	dst: []u8,
) -> (
	body: []u8,
	err: Handshake_Record_Read_Error,
) {
	if conn == nil do return nil, {kind = .Invalid_State}

	if conn.phase == .Failed {
		if conn.handshake_record_error.kind != .None {
			return nil, conn.handshake_record_error
		}

		return nil, {kind = .Invalid_State}
	}

	if conn.phase != .Handshake_Keys_Ready {
		return nil, {kind = .Invalid_State}
	}

	if len(dst) < MAX_CIPHERTEXT_SIZE {
		return nil, {kind = .Destination_Undersized}
	}

	wire: [RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE]u8
	ignored_ccs: int
	for {
		header, wire_error := handshake_record_wire_read(conn, wire[:])
		if wire_error.kind != .None do return handshake_record_fail(conn, wire_error)

		if header.content_type == .Change_Cipher_Spec {
			if handshake_ccs_refused(conn) {
				return handshake_record_fail(conn, {kind = .Too_Many_Change_Cipher_Specs})
			}

			if wire[RECORD_HEADER_SIZE] != 1 {
				return handshake_record_fail(conn, {kind = .Invalid_Change_Cipher_Spec})
			}

			ignored_ccs += 1
			if ignored_ccs > MAX_IGNORED_CHANGE_CIPHER_SPECS {
				return handshake_record_fail(conn, {kind = .Too_Many_Change_Cipher_Specs})
			}

			continue
		}

		return handshake_record_decrypt(conn, dst, wire[:], header)
	}
}

@(private)
handshake_record_header_validate :: proc(
	conn: ^Conn,
	header: Record_Header,
) -> Handshake_Record_Read_Error {
	if header.content_type == .Change_Cipher_Spec {
		if conn.server_handshake_header_used > 0 || conn.server_handshake_remaining > 0 {
			return {kind = .Interleaved_Record}
		}

		if header.length != 1 {
			return {kind = .Invalid_Change_Cipher_Spec, record = .Invalid_Change_Cipher_Spec_Length}
		}
	} else if header.content_type != .Application_Data {
		return {kind = .Unexpected_Content_Type, content_type = header.content_type}
	}

	if cast(int)header.length > MAX_CIPHERTEXT_SIZE {
		return {kind = .Invalid_Header, record = .Record_Oversized}
	}

	return {}
}

@(private)
handshake_record_wire_read :: proc(
	conn: ^Conn,
	wire: []u8,
) -> (
	Record_Header,
	Handshake_Record_Read_Error,
) {
	count, header_err := transport.read_exact(conn.transport, wire[:RECORD_HEADER_SIZE])
	if header_err.kind != .None {
		return {}, {kind = .Header_Read_Failed, transport = header_err, received = count}
	}

	header_bytes: [RECORD_HEADER_SIZE]u8
	copy(header_bytes[:], wire[:RECORD_HEADER_SIZE])
	header, decode_err := record_header_decode(header_bytes)
	if decode_err != .None {
		return {}, {kind = .Invalid_Header, record = decode_err}
	}

	if validation_error := handshake_record_header_validate(conn, header); validation_error.kind != .None do return {}, validation_error
	body_count, body_err := transport.read_exact(
		conn.transport,
		wire[RECORD_HEADER_SIZE:][:cast(int)header.length],
	)
	if body_err.kind != .None {
		return {}, {kind = .Body_Read_Failed, transport = body_err, received = body_count}
	}

	return header, {}
}

@(private)
handshake_record_decrypt :: proc(
	conn: ^Conn,
	dst, wire: []u8,
	header: Record_Header,
) -> (
	[]u8,
	Handshake_Record_Read_Error,
) {
	content_type, content, protection_err := engine_record_open(
		&conn.handshake_receive,
		dst,
		wire[:RECORD_HEADER_SIZE + cast(int)header.length],
	)
	if protection_err != .None {
		return handshake_record_fail(
			conn,
			{kind = .Decryption_Failed, protection = protection_err},
		)
	}

	if content_type == .Alert {
		alert := Handshake_Record_Read_Error {
			kind              = .Peer_Alert,
			alert_level       = content[0],
			alert_description = content[1],
		}
		crypto.zero_explicit(raw_data(content), len(content))
		return handshake_record_fail(conn, alert)
	}

	if content_type != .Handshake {
		crypto.zero_explicit(raw_data(content), len(content))
		return handshake_record_fail(conn, {kind = .Unexpected_Content_Type, content_type = .Application_Data})
	}

	if !handshake_record_track(conn, content) {
		crypto.zero_explicit(raw_data(content), len(content))
		return handshake_record_fail(conn, {kind = .Record_Boundary_Violation})
	}

	return content, {}
}

// Track message boundaries without buffering certificate-sized messages. This
// keeps compatibility records out of fragmented messages, and ensures messages
// that precede a key change finish at the end of their record (RFC 8446 5.1).
@(private)
handshake_record_track :: proc(conn: ^Conn, content: []u8) -> bool {
	at := 0
	for at < len(content) {
		if conn.server_handshake_remaining > 0 {
			count := min(conn.server_handshake_remaining, len(content) - at)
			conn.server_handshake_remaining -= count
			at += count
			if conn.server_handshake_remaining > 0 {
				return true
			}

			if conn.server_handshake_type == cast(u8)Handshake_Type.Finished ||
			   conn.server_handshake_type == cast(u8)Handshake_Type.Key_Update {
				if at != len(content) do return false
			}

			if conn.server_handshake_type == cast(u8)Handshake_Type.Finished {
				conn.phase = .Server_Finished_Received
			}

			continue
		}

		count := min(4 - conn.server_handshake_header_used, len(content) - at)
		copy(
			conn.server_handshake_header[conn.server_handshake_header_used:],
			content[at:][:count],
		)
		conn.server_handshake_header_used += count
		at += count
		if conn.server_handshake_header_used < 4 {
			return true
		}

		conn.server_handshake_type = conn.server_handshake_header[0]
		conn.server_handshake_remaining = handshake_body_size(conn.server_handshake_header[:])
		conn.server_handshake_header_used = 0
		if conn.server_handshake_remaining == 0 &&
		   (conn.server_handshake_type == cast(u8)Handshake_Type.Finished ||
				   conn.server_handshake_type == cast(u8)Handshake_Type.Key_Update) &&
		   at != len(content) {
			return false
		}

		if conn.server_handshake_remaining == 0 &&
		   conn.server_handshake_type == cast(u8)Handshake_Type.Finished {
			conn.phase = .Server_Finished_Received
		}
	}
	return true
}

@(private)
handshake_record_fail :: proc(
	conn: ^Conn,
	err: Handshake_Record_Read_Error,
) -> (
	[]u8,
	Handshake_Record_Read_Error,
) {
	handshake_alert_stage(conn, {kind = .Server_Flight_Read_Failed, record = err})
	conn.phase = .Failed
	alpn_clear(conn)
	conn.handshake_record_error = err
	handshake_keys_clear(conn)
	return nil, err
}


// Asynchronous handshake operations

@(private)
async_handshake_fail :: proc(conn: ^Async_Conn, error: Handshake_Error) {
	p := &conn.protocol
	handshake_alert_stage(p, error)
	if p.alert_size > 0 && !conn.tx.pending && !conn.tx_done {
		size := copy(conn.tx_wire[:], p.alert_wire[:p.alert_size])
		p.alert_size = 0
		async_send_start(conn, .Alert, size, conn.handshake_deadline)
	}

	conn.protocol.handshake_error = error
	async_terminal(conn, {kind = .Protocol_Failed}, {kind = .Handshake_Failed, handshake = error})
}

@(private)
async_hello_send :: proc(conn: ^Async_Conn, retry: bool) {
	message := conn.protocol.client_hello[:conn.protocol.client_hello_size]
	version := LEGACY_TLS_1_0
	kind := Async_Send_Kind.Hello
	if retry {
		message = conn.protocol.retry_client_hello[:conn.protocol.retry_client_hello_size]
		version, kind = LEGACY_TLS_1_2, .Retry
	}
	header := record_header_encode(
		{content_type = .Handshake, legacy_version = version, length = u16(len(message))},
	)
	copy(conn.tx_wire[:], header[:])
	copy(conn.tx_wire[RECORD_HEADER_SIZE:], message)
	async_send_start(conn, kind, RECORD_HEADER_SIZE + len(message), conn.handshake_deadline)
}

@(private)
async_handshake_drive :: proc(conn: ^Async_Conn) {
	if conn.tx.pending || conn.tx_done do return
	p := &conn.protocol
	if p.phase == .Handshake_Pending {
		if err := engine_client_hello_prepare(p); err.kind != .None {
			async_handshake_fail(conn, {kind = .Client_Hello_Failed, client_hello = err}); return
		}
		async_hello_send(conn, false)
		return
	}
	if p.phase == .Hello_Retry_Received {
		async_hello_send(conn, true)
		return
	}
	if p.phase == .Server_Finished_Received {
		if !conn.finishing {
			if err := engine_handshake_server_flight_verify(p, conn.flight[:conn.flight_used]); err.kind != .None {
				async_handshake_fail(conn, err)
				return
			}

			if e := client_auth_prepare(p, conn.allocator); e.kind != .None {
				async_handshake_fail(conn, e)
				return
			}

			crypto.zero_explicit(raw_data(conn.flight), len(conn.flight))
			delete(conn.flight, conn.allocator)
			conn.flight = nil
			conn.finishing = true
		}

		if p.client_auth_offset < len(p.client_auth_flight) {
			at := p.client_auth_offset
			end := min(len(p.client_auth_flight), at + MAX_PLAINTEXT_SIZE)
			prefix := handshake_ccs_encode(p, conn.tx_wire[:])
			n, e := engine_record_seal(&p.handshake_send, conn.tx_wire[prefix:], .Handshake, p.client_auth_flight[at:end])
			if e != .None {
				async_handshake_fail(conn, {kind = .Finished_Write_Failed, protection = e})
				return
			}

			p.client_auth_offset = end
			async_send_start(conn, .Client_Auth, prefix + n, conn.handshake_deadline)
			return
		}

		prefix := handshake_ccs_encode(p, conn.tx_wire[:])
		size, e := handshake_client_finished_encode(p, conn.tx_wire[prefix:])
		if e.kind != .None {
			async_handshake_fail(conn, e)
			return
		}

		async_send_start(conn, .Finished, prefix + size, conn.handshake_deadline)
		return
	}
	if p.phase != .Awaiting_Server_Hello && p.phase != .Handshake_Keys_Ready {
		async_handshake_fail(conn, {kind = .Invalid_State}); return
	}
	header, ready := async_receive_record(conn, conn.handshake_deadline)
	if !ready do return
	body := conn.rx_wire[RECORD_HEADER_SIZE:conn.rx_expected]
	if p.phase == .Awaiting_Server_Hello {
		if err := record_header_validate_plaintext(header); err != .None {
			async_handshake_fail(
				conn,
				{
					kind = .Server_Hello_Failed,
					server_hello = {
						kind = .Record_Read_Failed,
						record = {kind = .Invalid_Header, record = err},
					},
				},
			); return
		}
		if header.content_type != .Handshake && conn.hello_used > 0 {
			async_handshake_fail(
				conn,
				{kind = .Server_Hello_Failed, server_hello = {kind = .Interleaved_Record}},
			); return
		}
		#partial switch header.content_type {
		case .Change_Cipher_Spec:
			if handshake_ccs_refused(p) {
				async_handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = {kind = .Too_Many_Change_Cipher_Specs}})
				return
			}

			if err := server_hello_ccs_validate(body, &conn.ignored_ccs); err.kind != .None {
				async_handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
				return
			}
		case .Alert:
			async_handshake_fail(
				conn,
				{
					kind = .Server_Hello_Failed,
					server_hello = {
						kind = .Peer_Alert,
						alert_level = body[0],
						alert_description = body[1],
					},
				},
			); return
		case .Handshake:
			complete, append_error := server_hello_message_append(
				conn.hello[:server_hello_storage_size(p)],
				body,
				&conn.hello_used,
				server_hello_cap(p),
			)
			if append_error.kind != .None {
				async_handshake_fail(
					conn,
					{kind = .Server_Hello_Failed, server_hello = append_error},
				)
				return
			}
			if complete {
				message := conn.hello[:conn.hello_used]
				err :=
					server_hello_retry_accept(p, message) if \
						hello_is_retry(message) else \
						server_hello_accept(p, message)
				if err.kind != .None {
					async_handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
					return
				}
				conn.hello_used = 0
				if p.phase == .Server_Hello_Received {
					if key_error := client_handshake_keys_init(p); key_error.kind != .None {
						async_handshake_fail(
							conn,
							{kind = .Key_Derivation_Failed, keys = key_error},
						)
						return
					}
					allocation_error: mem.Allocator_Error
					conn.flight, allocation_error = make([]u8, 4096, conn.allocator)
					if allocation_error != nil {
						async_handshake_fail(
							conn,
							{kind = .Allocation_Failed, allocation = allocation_error},
						)
						return
					}
				}
			}
		}
	} else {
		if err := handshake_record_header_validate(p, header); err.kind != .None {
			async_handshake_fail(conn, {kind = .Server_Flight_Read_Failed, record = err})
			return
		}
		if header.content_type == .Change_Cipher_Spec {
			if handshake_ccs_refused(p) {
				async_handshake_fail(conn, {kind = .Server_Flight_Read_Failed, record = {kind = .Too_Many_Change_Cipher_Specs}})
				return
			}

			if err := server_hello_ccs_validate(body, &conn.ignored_ccs); err.kind != .None {
				async_handshake_fail(conn, {kind = .Server_Hello_Failed, server_hello = err})
				return
			}
		} else {
			content, err := handshake_record_decrypt(
				p,
				conn.rx_plain[:],
				conn.rx_wire[:conn.rx_expected],
				header,
			)
			if err.kind != .None {
				async_handshake_fail(conn, {kind = .Server_Flight_Read_Failed, record = err})
				return
			}
			needed := conn.flight_used + len(content)
			if needed > MAX_SERVER_FLIGHT_SIZE {
				async_handshake_fail(conn, {kind = .Server_Flight_Oversized})
				return
			}
			if needed > len(conn.flight) {
				storage, allocation_error := make(
					[]u8,
					min(MAX_SERVER_FLIGHT_SIZE, max(needed, 2 * len(conn.flight))),
					conn.allocator,
				)
				if allocation_error != nil {
					async_handshake_fail(
						conn,
						{kind = .Allocation_Failed, allocation = allocation_error},
					)
					return
				}
				copy(storage, conn.flight[:conn.flight_used])
				crypto.zero_explicit(raw_data(conn.flight), len(conn.flight))
				delete(conn.flight, conn.allocator)
				conn.flight = storage
			}
			copy(conn.flight[conn.flight_used:], content)
			conn.flight_used += len(content)
		}
	}
	async_record_consumed(conn)
	async_queue(conn)
}

@(private)
handshake_until_check :: proc(conn: ^Conn, deadline: time.Time) -> Handshake_Error {
	if deadline != (time.Time{}) && time.diff(time.now(), deadline) <= 0 {
		conn.handshake_complete = false
		return handshake_fail(conn, {kind = .Deadline_Failed, transport = {kind = .Timeout}})
	}
	return {}
}
