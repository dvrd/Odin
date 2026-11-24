package tls

import "core:crypto/hash"
import "core:crypto/x509"
import "core:io"
import "core:mem"
import "core:time"
import credential_store "credentials/store"

/*
What a QUIC transport needs of TLS, behind the package's `Error`: the packet
keys of each level, and the pieces of the handshake that QUIC carries in its own
CRYPTO frames in place of records.
*/

// quic_handshake_secrets derives the Handshake packet keys from the hellos.
@(require_results)
quic_handshake_secrets :: proc(
	shared_secret: [32]u8,
	client_hello,
	server_hello,
	local_parameters: []u8,
	session: ^Session = nil,
	early_allowed: bool = false,
) -> (Quic_Handshake_Keys, Error) {
	r0, failure := engine_quic_handshake_secrets(shared_secret, client_hello, server_hello, local_parameters, session, early_allowed)
	return r0, quic_secret_error(failure)
}

// quic_application_secrets authenticates the server's flight and derives the 1-RTT packet keys.
@(require_results)
quic_application_secrets :: proc(
	handshake_secret: [32]u8,
	client_hello,
	server_hello,
	handshake_messages: []u8,
	server_name: string,
	roots: []^x509.Certificate,
	now: time.Time,
	local_parameters,
	peer_parameters: []u8,
) -> (Quic_Application_Keys, [FINISHED_MESSAGE_SIZE]u8, Error) {
	r0, r1, failure := engine_quic_application_secrets(handshake_secret, client_hello, server_hello, handshake_messages, server_name, roots, now, local_parameters, peer_parameters)
	return r0, r1, quic_secret_error(failure)
}

// quic_application_secrets_mutual is `quic_application_secrets` for a server that asks for a client certificate.
@(require_results)
quic_application_secrets_mutual :: proc(
	handshake_secret: [32]u8,
	client_hello,
	server_hello,
	handshake_messages: []u8,
	server_name: string,
	roots: []^x509.Certificate,
	now: time.Time,
	local_parameters,
	peer_parameters: []u8,
	identity: ^credential_store.Store,
	allocator: mem.Allocator,
	identity_lease: ^credential_store.Lease = nil,
	session: ^Session = nil,
	early_allowed: bool = false,
) -> (Quic_Application_Keys, []u8, Error) {
	r0, r1, failure := engine_quic_application_secrets_mutual(handshake_secret, client_hello, server_hello, handshake_messages, server_name, roots, now, local_parameters, peer_parameters, identity, allocator, identity_lease, session, early_allowed)
	return r0, r1, quic_secret_error(failure)
}

// quic_early_packet_keys derives the 0-RTT packet keys of a resumed session.
@(require_results)
quic_early_packet_keys :: proc(
	early_secret: [32]u8,
	policy: ^Early_Data_Policy = nil,
	client_hello: []u8 = nil,
) -> (Quic_Direction_Keys, Error) {
	r0, failure := engine_quic_early_packet_keys(early_secret, policy, client_hello)
	return r0, quic_secret_error(failure)
}

// quic_packet_keys_derive derives the packet keys of one direction from its traffic secret.
@(require_results)
quic_packet_keys_derive :: proc(traffic_secret: [32]u8, level: Quic_Secret_Level) -> (Quic_Direction_Keys, Error) {
	r0, failure := engine_quic_packet_keys_derive(traffic_secret, level)
	return r0, quic_secret_error(failure)
}

// quic_client_hello_offer adds a session's resumption offer to a ClientHello.
@(require_results)
quic_client_hello_offer :: proc(
	dst: []u8,
	hello_len: int,
	session: ^Session,
	scope: Quic_Session_Scope,
	now: time.Time,
	early: bool = false,
) -> (int, Error) {
	r0, failure := engine_quic_client_hello_offer(dst, hello_len, session, scope, now, early)
	return r0, quic_secret_error(failure)
}

// quic_session_remember stores a NewSessionTicket for a later resumption.
@(require_results)
quic_session_remember :: proc(
	session: ^Session,
	master: [32]u8,
	message: []u8,
	scope: Quic_Session_Scope,
	now: time.Time,
) -> Error {
	return quic_secret_error(engine_quic_session_remember(session, master, message, scope, now))
}

// hkdf_expand_label is HKDF-Expand-Label of RFC 8446, section 7.1.
@(require_results)
hkdf_expand_label :: proc(
	secret: []u8,
	label: string,
	label_context: []u8,
	dst: []u8,
	algorithm: hash.Algorithm = .SHA256,
) -> Error {
	return key_schedule_error(engine_hkdf_expand_label(secret, label, label_context, dst, algorithm))
}

// finished_verify checks a Finished message against the transcript.
@(require_results)
finished_verify :: proc(message: []u8, traffic_secret: [32]u8, transcript_hash: [32]u8) -> Error {
	return finished_error(engine_finished_verify(message, traffic_secret, transcript_hash))
}

// server_hello_decode parses a ServerHello.
@(require_results)
server_hello_decode :: proc(wire: []u8, allow_psk: bool = false) -> (Server_Hello, Error) {
	r0, failure := engine_server_hello_decode(wire, allow_psk)
	return r0, socket_server_hello_decode_error(failure)
}

// client_hello_encode writes a ClientHello into `dst`.
@(require_results)
client_hello_encode :: proc(dst: []u8, hello: Client_Hello) -> (int, Error) {
	r0, failure := engine_client_hello_encode(dst, hello)
	return r0, client_hello_encode_error(failure)
}

// client_hello_prepare builds the ClientHello of `conn` without sending it.
@(require_results)
client_hello_prepare :: proc(conn: ^Conn) -> Error {
	return client_hello_send_error(engine_client_hello_prepare(conn))
}

// server_certificates_parse parses a Certificate message.
@(require_results)
server_certificates_parse :: proc(message: []u8) -> (Server_Certificates, Error) {
	r0, failure := engine_server_certificates_parse(message)
	return r0, authentication_error(failure)
}

// verify_server_certificates verifies a parsed chain for `server_name` against `roots`.
@(require_results)
verify_server_certificates :: proc(
	certs: ^Server_Certificates,
	server_name: string,
	roots: []^x509.Certificate,
	now: time.Time,
) -> Error {
	return authentication_error(engine_verify_server_certificates(certs, server_name, roots, now))
}

// verify_server_certificate_signature checks a CertificateVerify message against the transcript.
@(require_results)
verify_server_certificate_signature :: proc(
	certs: ^Server_Certificates,
	message: []u8,
	transcript_hash: [32]u8,
) -> Error {
	return authentication_error(engine_verify_server_certificate_signature(certs, message, transcript_hash))
}

// handshake_server_flight_verify authenticates the server's flight for `conn`.
@(require_results)
handshake_server_flight_verify :: proc(conn: ^Conn, flight: []u8) -> Error {
	return handshake_error(engine_handshake_server_flight_verify(conn, flight))
}

// encrypted_extensions_validate checks an EncryptedExtensions message.
@(require_results)
encrypted_extensions_validate :: proc(message: []u8, server_name: string) -> Error {
	return handshake_error(engine_encrypted_extensions_validate(message, server_name))
}

// record_open decrypts one record.
@(require_results)
record_open :: proc(state: ^Record_Protection, dst: []u8, wire: []u8) -> (TLS_Content_Type, []u8, Error) {
	r0, r1, failure := engine_record_open(state, dst, wire)
	return r0, r1, record_protection_error(failure)
}

// record_seal encrypts one record.
@(require_results)
record_seal :: proc(
	state: ^Record_Protection,
	dst: []u8,
	content_type: TLS_Content_Type,
	body: []u8,
) -> (int, Error) {
	r0, failure := engine_record_seal(state, dst, content_type, body)
	return r0, record_protection_error(failure)
}

// alpn_transport_offers reports whether a list of protocols suits a transport.
@(require_results)
alpn_transport_offers :: proc(transport: ALPN_Transport, protocols: []string) -> Error {
	return client_error(engine_alpn_transport_offers(transport, protocols))
}

@(private, require_results)
quic_secret_error :: proc(failure: Quic_Secret_Error) -> Error {
	switch failure.kind {
	case .None:
		return nil
	case .Invalid_Input, .Invalid_ALPN:
		return General_Error.Invalid_Config
	case .Early_Data_Disabled:
		return General_Error.Early_Data_Rejected
	case .Transcript_Mismatch:
		return Protocol_Error.Illegal_Parameter
	case .Parameters_Missing:
		return Protocol_Error.Missing_Extension
	case .Parameters_Oversized:
		return General_Error.Limit_Exceeded
	case .Malformed:
		return Protocol_Error.Decode_Error
	case .Unsupported:
		return Protocol_Error.Handshake_Failure
	case .Authentication_Failed:
		return failed(socket_authentication_error(failure.authentication))
	case .Finished_Failed:
		return Protocol_Error.Decrypt_Error
	case .Derivation_Failed:
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
key_schedule_error :: proc(failure: Key_Schedule_Error) -> Error {
	if failure == .None {
		return nil
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
finished_error :: proc(failure: Finished_Error) -> Error {
	switch failure {
	case .None:
		return nil
	case .Unexpected_Handshake_Type:
		return Protocol_Error.Unexpected_Message
	case .Verification_Failed:
		return Protocol_Error.Decrypt_Error
	case .Destination_Undersized:
		return io.Error.Short_Buffer
	case .Invalid_Length:
		return Protocol_Error.Decode_Error
	}
	return Protocol_Error.Internal_Error
}

@(private, require_results)
client_hello_encode_error :: proc(failure: Client_Hello_Error) -> Error {
	#partial switch failure {
	case .None:
		return nil
	case .Invalid_Server_Name:
		return General_Error.Invalid_SNI_Hostname
	case .Destination_Undersized:
		return io.Error.Short_Buffer
	}
	return General_Error.Invalid_Config
}

// The Socket's mappers are written for failures; these also take none.
@(private, require_results)
client_hello_send_error :: proc(failure: Client_Hello_Send_Error) -> Error {
	if failure.kind == .None {
		return nil
	}
	return socket_client_hello_error(failure)
}

@(private, require_results)
authentication_error :: proc(failure: Authentication_Error) -> Error {
	if failure.kind == .None {
		return nil
	}
	return socket_authentication_error(failure)
}

@(private, require_results)
record_protection_error :: proc(failure: Record_Protection_Error) -> Error {
	if failure == .None {
		return nil
	}
	return socket_protection_error(failure, .Decode_Error)
}
