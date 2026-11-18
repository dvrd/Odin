package tls

import "core:crypto"
import "core:crypto/sha2"
import "core:crypto/x509"
import "core:time"
import "core:mem"
import credential_store "credentials/store"

// QUIC packet protection consumes TLS traffic secrets. It is not a TLS record
// and it does not change the TCP handshake. 0-RTT is not a level here.
Quic_Secret_Level :: enum {
	Handshake,
	Application,
}
Quic_Secret_Kind :: enum {
	None,
	Invalid_Input,
	Early_Data_Disabled,
	Invalid_ALPN,
	Transcript_Mismatch,
	Parameters_Missing,
	Parameters_Oversized,
	Malformed,
	Unsupported,
	Derivation_Failed,
	Authentication_Failed,
	Finished_Failed,
}
Quic_Secret_Error :: struct {
	kind:           Quic_Secret_Kind,
	authentication: Authentication_Error,
	schedule:       Key_Schedule_Error,
	hello:          Server_Hello_Error,
	finished:       Finished_Error,
}
// AES-128-GCM lengths only, matching the native TLS profile. Caller erases.
Quic_Direction_Keys :: struct {
	secret: [32]u8,
	key:    [16]u8,
	iv:     [12]u8,
	hp:     [16]u8,
}
Quic_Handshake_Keys :: struct {
	client, server:    Quic_Direction_Keys,
	handshake_secret:  [32]u8,
}
Quic_Application_Keys :: struct {
	client, server: Quic_Direction_Keys,
 resumption_master:[32]u8,
 early_accepted:bool,
}

@(private)
QUIC_EXTENSION_EARLY_DATA :: u16(42)
@(private)
QUIC_EXTENSION_PARAMETERS :: u16(57)

quic_direction_keys_clear :: proc(keys: ^Quic_Direction_Keys) {
	if keys != nil {
		crypto.zero_explicit(keys, size_of(Quic_Direction_Keys))
	}
}
quic_handshake_keys_clear :: proc(keys: ^Quic_Handshake_Keys) {
	if keys != nil {
		crypto.zero_explicit(keys, size_of(Quic_Handshake_Keys))
	}
}
quic_application_keys_clear :: proc(keys: ^Quic_Application_Keys) {
	if keys != nil {
		crypto.zero_explicit(keys, size_of(Quic_Application_Keys))
	}
}

// RFC 9001 section 5.1. Level selects handshake versus application secrets.
// Early data is not a level here. quic_early_packet_keys derives it only when
// the caller passes a replay-safe policy and a ClientHello that offered it.
quic_packet_keys_derive :: proc(
	traffic_secret: [32]u8,
	level: Quic_Secret_Level,
) -> (
	keys: Quic_Direction_Keys,
	err: Quic_Secret_Error,
) {
	secret := traffic_secret
	defer crypto.zero_explicit(&secret, size_of(secret))
	// Local, not the named result: the deferred wipe runs after the return copy.
	local: Quic_Direction_Keys
	defer quic_direction_keys_clear(&local)
	switch level {
	case .Handshake, .Application:
	}
	local.secret = secret
	schedule := quic_expand_aead(&local)
	if schedule != .None {
		return {}, {kind = .Derivation_Failed, schedule = schedule}
	}
	return local, {}
}

// early_secret is HKDF-Extract(0, PSK), not the resumption PSK and not packet
// keys. A nil policy, or a ClientHello that did not offer early_data, refuses
// 0-RTT and produces no key bytes. The secret is erased either way.
quic_early_packet_keys :: proc(
	early_secret: [32]u8,
	policy: ^Early_Data_Policy = nil,
	client_hello: []u8 = nil,
) -> (
	keys: Quic_Direction_Keys,
	err: Quic_Secret_Error,
) {
	secret := early_secret
	defer crypto.zero_explicit(&secret, size_of(secret))
	if policy == nil || policy.allow == nil || len(client_hello) == 0 ||
	   resumption_extension_offset(client_hello, EXTENSION_EARLY_DATA) < 0 {
		return {}, {kind = .Early_Data_Disabled}
	}
	if !schedule_message_valid(client_hello, .Client_Hello) {
		return {}, {kind = .Malformed}
	}
	local: Quic_Direction_Keys
	defer quic_direction_keys_clear(&local)
	hash := quic_hash(client_hello)
	defer crypto.zero_explicit(&hash, size_of(hash))
	schedule_expand(.SHA256, secret[:], "c e traffic", hash[:], local.secret[:])
	if schedule := quic_expand_aead(&local); schedule != .None {
		return {}, {kind = .Derivation_Failed, schedule = schedule}
	}
	return local, {}
}

// Handshake keys from CH||SH. local_parameters must be the exact
// quic_transport_parameters extension payload inside client_hello.
// Certificate and Finished checks are not done here; these keys are unauthenticated.
quic_handshake_secrets :: proc(
	shared_secret: [32]u8,
	client_hello, server_hello, local_parameters: []u8,
 session:^Session=nil,early_allowed:bool=false,
) -> (
	keys: Quic_Handshake_Keys,
	err: Quic_Secret_Error,
) {
	shared := shared_secret
	defer crypto.zero_explicit(&shared, size_of(shared))
	local: Quic_Handshake_Keys
	defer quic_handshake_keys_clear(&local)
	if len(local_parameters) > SERVER_QUIC_PARAMETERS_CAP {
		return {}, {kind = .Parameters_Oversized}
	}
	if e := quic_client_hello_policy(client_hello, local_parameters,early_allowed); e.kind != .None {
		return {}, e
	}
	hello, hello_error := server_hello_decode(server_hello,session!=nil)
 defer crypto.zero_explicit(&hello,size_of(hello))
	if hello_error != .None {
		kind: Quic_Secret_Kind = .Malformed
		if hello_error == .Hello_Retry_Unsupported || hello_error == .Unsupported_Extension {
			kind = .Unsupported
		}
		return {}, {kind = kind, hello = hello_error}
	}
	psk:[]u8;if hello.psk_selected {if session==nil||!session.usable {return {},{kind=.Invalid_Input}};psk=session.psk[:]}
	secrets, schedule := handshake_secrets_derive(shared, client_hello, server_hello,nil,psk)
	defer crypto.zero_explicit(&secrets, size_of(secrets))
	if schedule != .None {
		return {}, {kind = .Derivation_Failed, schedule = schedule}
	}
	local.handshake_secret = secrets.handshake_secret
	client, client_error := quic_packet_keys_derive(secrets.client_traffic_secret, .Handshake)
	defer quic_direction_keys_clear(&client)
	if client_error.kind != .None {
		return {}, client_error
	}
	server, server_error := quic_packet_keys_derive(secrets.server_traffic_secret, .Handshake)
	defer quic_direction_keys_clear(&server)
	if server_error.kind != .None {
		return {}, server_error
	}
	local.client = client
	local.server = server
	return local, {}
}

// Server authentication uses the existing certificate, signature and Finished
// checks. peer_parameters must equal the extension inside EncryptedExtensions.
// Success also returns the client Finished message (handshake keys, not 1-RTT).
quic_application_secrets :: proc(
	handshake_secret: [32]u8,
	client_hello, server_hello, handshake_messages: []u8,
	server_name: string,
	roots: []^x509.Certificate,
	now: time.Time,
	local_parameters, peer_parameters: []u8,
) -> (
	keys: Quic_Application_Keys,
	client_finished: [FINISHED_MESSAGE_SIZE]u8,
	err: Quic_Secret_Error,
) {
	secret := handshake_secret
	defer crypto.zero_explicit(&secret, size_of(secret))
	local: Quic_Application_Keys
	finished_message: [FINISHED_MESSAGE_SIZE]u8
	defer quic_application_keys_clear(&local)
	defer crypto.zero_explicit(&finished_message, size_of(finished_message))
	if crypto.is_zero_constant_time(secret[:]) == 1 {
		return {}, {}, {kind = .Derivation_Failed}
	}
	if len(local_parameters) > SERVER_QUIC_PARAMETERS_CAP || len(peer_parameters) > SERVER_QUIC_PARAMETERS_CAP {
		return {}, {}, {kind = .Parameters_Oversized}
	}
	if e := quic_client_hello_policy(client_hello, local_parameters); e.kind != .None {
		return {}, {}, e
	}
	messages: [4][]u8
	if !quic_split_messages(handshake_messages, messages[:]) {
		return {}, {}, {kind = .Malformed}
	}
	if messages[0][0] != u8(Handshake_Type.Encrypted_Extensions) ||
	   messages[1][0] != u8(Handshake_Type.Certificate) ||
	   messages[2][0] != u8(Handshake_Type.Certificate_Verify) ||
	   messages[3][0] != u8(Handshake_Type.Finished) {
		return {}, {}, {kind = .Unsupported}
	}
	if e := quic_encrypted_extensions_policy(messages[0], peer_parameters); e.kind != .None {
		return {}, {}, e
	}
	certs, auth := server_certificates_parse(messages[1])
	defer server_certificates_destroy(&certs)
	if auth.kind != .None {
		return {}, {}, {kind = .Authentication_Failed, authentication = auth}
	}
	auth = verify_server_certificates(&certs, server_name, roots, now)
	if auth.kind != .None {
		return {}, {}, {kind = .Authentication_Failed, authentication = auth}
	}
	through_certificate := quic_hash(client_hello, server_hello, messages[0], messages[1])
	auth = verify_server_certificate_signature(&certs, messages[2], through_certificate)
	crypto.zero_explicit(&through_certificate, size_of(through_certificate))
	if auth.kind != .None {
		return {}, {}, {kind = .Authentication_Failed, authentication = auth}
	}
	through_verify := quic_hash(client_hello, server_hello, messages[0], messages[1], messages[2])
	server_traffic := quic_server_traffic(secret, client_hello, server_hello)
	defer crypto.zero_explicit(&server_traffic, size_of(server_traffic))
	finished := finished_verify(messages[3], server_traffic, through_verify)
	crypto.zero_explicit(&through_verify, size_of(through_verify))
	if finished != .None {
		return {}, {}, {kind = .Finished_Failed, finished = finished}
	}
	through_server_finished := quic_hash(
		client_hello,
		server_hello,
		messages[0],
		messages[1],
		messages[2],
		messages[3],
	)
	defer crypto.zero_explicit(&through_server_finished, size_of(through_server_finished))
	client_traffic := quic_client_traffic(secret, client_hello, server_hello)
	defer crypto.zero_explicit(&client_traffic, size_of(client_traffic))
	n, finished_error := finished_encode(finished_message[:], client_traffic, through_server_finished)
	if finished_error != .None || n != FINISHED_MESSAGE_SIZE {
		return {}, {}, {kind = .Finished_Failed, finished = finished_error}
	}
	application := application_secrets_derive(secret, through_server_finished)
	defer crypto.zero_explicit(&application, size_of(application))
	client, client_error := quic_packet_keys_derive(application.client_traffic_secret, .Application)
	defer quic_direction_keys_clear(&client)
	if client_error.kind != .None {
		return {}, {}, client_error
	}
	server, server_error := quic_packet_keys_derive(application.server_traffic_secret, .Application)
	defer quic_direction_keys_clear(&server)
	if server_error.kind != .None {
		return {}, {}, server_error
	}
	local.client = client
	local.server = server
	return local, finished_message, {}
}

@(private)
quic_expand_aead :: proc(keys: ^Quic_Direction_Keys) -> Key_Schedule_Error {
	if e := hkdf_expand_label(keys.secret[:], "quic key", nil, keys.key[:]); e != .None {
		return e
	}
	if e := hkdf_expand_label(keys.secret[:], "quic iv", nil, keys.iv[:]); e != .None {
		return e
	}
	return hkdf_expand_label(keys.secret[:], "quic hp", nil, keys.hp[:])
}

@(private)
quic_server_traffic :: proc(handshake_secret: [32]u8, client_hello, server_hello: []u8) -> [32]u8 {
	return quic_traffic(handshake_secret, "s hs traffic", client_hello, server_hello)
}

@(private)
quic_client_traffic :: proc(handshake_secret: [32]u8, client_hello, server_hello: []u8) -> [32]u8 {
	return quic_traffic(handshake_secret, "c hs traffic", client_hello, server_hello)
}

@(private)
quic_traffic :: proc(handshake_secret: [32]u8, label: string, client_hello, server_hello: []u8) -> [32]u8 {
	hash := quic_hash(client_hello, server_hello)
	defer crypto.zero_explicit(&hash, size_of(hash))
	secret := handshake_secret
	defer crypto.zero_explicit(&secret, size_of(secret))
	out: [32]u8
	schedule_expand(.SHA256, secret[:], label, hash[:], out[:])
	return out
}

@(private)
quic_hash :: proc(parts: ..[]u8) -> [32]u8 {
	t: sha2.Context_256
	sha2.init_256(&t)
	for part in parts {
		sha2.update(&t, part)
	}
	out: [32]u8
	sha2.final(&t, out[:])
	return out
}

@(private)
quic_client_hello_policy :: proc(message, parameters: []u8,allow_early:bool=false) -> Quic_Secret_Error {
	at, end, e := quic_client_hello_extensions(message)
	if e.kind != .None {
		return e
	}
	return quic_scan_extensions(message[at:end], parameters, true,allow_early)
}

@(private)
quic_encrypted_extensions_policy :: proc(message, parameters: []u8,allow_early:bool=false) -> Quic_Secret_Error {
	if len(message) < 6 || message[0] != u8(Handshake_Type.Encrypted_Extensions) {
		return {kind = .Malformed}
	}
	if handshake_body_size(message) + 4 != len(message) {
		return {kind = .Malformed}
	}
	ext_len := int(hello_u16(message, 4))
	if ext_len != len(message) - 6 {
		return {kind = .Malformed}
	}
	return quic_scan_extensions(message[6:], parameters, false,allow_early)
}

@(private)
quic_client_hello_extensions :: proc(message: []u8) -> (at, end: int, err: Quic_Secret_Error) {
	if len(message) < 4 || message[0] != u8(Handshake_Type.Client_Hello) {
		return 0, 0, {kind = .Malformed}
	}
	if handshake_body_size(message) + 4 != len(message) {
		return 0, 0, {kind = .Malformed}
	}
	at = 4
	if len(message) - at < 35 {
		return 0, 0, {kind = .Malformed}
	}
	at += 34 // legacy_version + random
	sid := int(message[at])
	at += 1
	if sid > len(message) - at {
		return 0, 0, {kind = .Malformed}
	}
	at += sid
	if len(message) - at < 2 {
		return 0, 0, {kind = .Malformed}
	}
	cs := int(hello_u16(message, at))
	at += 2
	if cs > len(message) - at {
		return 0, 0, {kind = .Malformed}
	}
	at += cs
	if len(message) - at < 1 {
		return 0, 0, {kind = .Malformed}
	}
	comp := int(message[at])
	at += 1
	if comp > len(message) - at {
		return 0, 0, {kind = .Malformed}
	}
	at += comp
	if len(message) - at < 2 {
		return 0, 0, {kind = .Malformed}
	}
	ext := int(hello_u16(message, at))
	at += 2
	if ext != len(message) - at {
		return 0, 0, {kind = .Malformed}
	}
	return at, len(message), {}
}

@(private)
quic_scan_extensions :: proc(data, parameters: []u8, offer: bool,allow_early:bool=false) -> Quic_Secret_Error {
	seen: [32]u16
	seen_n := 0
	have_alpn, have_parameters := false, false
	at := 0
	for at < len(data) {
		if len(data) - at < 4 {
			return {kind = .Malformed}
		}
		kind := hello_u16(data, at)
		size := int(hello_u16(data, at + 2))
		at += 4
		if size > len(data) - at {
			return {kind = .Malformed}
		}
		if seen_n == len(seen) {
			return {kind = .Malformed}
		}
		for previous in seen[:seen_n] {
			if previous == kind {
				return {kind = .Malformed}
			}
		}
		seen[seen_n] = kind
		seen_n += 1
		payload := data[at:at + size]
		at += size
		switch kind {
		case QUIC_EXTENSION_EARLY_DATA:
   if !allow_early||size!=0 {return {kind=.Early_Data_Disabled}}
		case QUIC_EXTENSION_PARAMETERS:
			if size > SERVER_QUIC_PARAMETERS_CAP {
				return {kind = .Parameters_Oversized}
			}
			if len(payload) != len(parameters) ||
			   (len(payload) > 0 && crypto.compare_constant_time(payload, parameters) != 1) {
				return {kind = .Transcript_Mismatch}
			}
			have_parameters = true
		case u16(Extension_Type.Application_Layer_Protocol_Negotiation):
			if kind := quic_alpn_exact_h3(payload, offer); kind != .None {
				return {kind = kind}
			}
			have_alpn = true
		}
	}
	if !have_parameters {
		return {kind = .Parameters_Missing}
	}
	if !have_alpn {
		return {kind = .Invalid_ALPN}
	}
	return {}
}

@(private)
quic_alpn_exact_h3 :: proc(payload: []u8, offer: bool) -> Quic_Secret_Kind {
	if len(payload) < 2 {
		return .Malformed
	}
	list := int(hello_u16(payload, 0))
	if list != len(payload) - 2 {
		return .Malformed
	}
	names: [1]string
	count := 0
	at := 2
	for at < len(payload) {
		n := int(payload[at])
		at += 1
		if n == 0 || n > len(payload) - at {
			return .Malformed
		}
		if count == len(names) {
			return .Invalid_ALPN
		}
		names[count] = string(payload[at:at + n])
		count += 1
		at += n
	}
	if at != len(payload) {
		return .Malformed
	}
	if alpn_transport_offers(.QUIC, names[:count]) != .None {
		return .Invalid_ALPN
	}
	if !offer && (count != 1 || names[0] != ALPN_H3) {
		return .Invalid_ALPN
	}
	return .None
}

@(private)
quic_split_messages :: proc(src: []u8, dst: [][]u8) -> bool {
	at := 0
	for _, i in dst {
		if len(src) - at < 4 {
			return false
		}
		n := handshake_body_size(src[at:]) + 4
		if n < 4 || n > len(src) - at {
			return false
		}
		dst[i] = src[at:at + n]
		at += n
	}
	return at == len(src)
}

// Authenticates the complete QUIC server flight, including an optional initial
// CertificateRequest. Returns an allocator-owned client Certificate/Verify/
// Finished flight. Application keys still derive at server Finished; client
// Finished authenticates the additional client-authentication messages. No TLS
// records are produced. The caller must retain/retransmit every returned byte
// before declaring Finished sent, then erase/free it after handshake retirement.
quic_application_secrets_mutual :: proc(
 handshake_secret:[32]u8,client_hello,server_hello,handshake_messages:[]u8,
 server_name:string,roots:[]^x509.Certificate,now:time.Time,
 local_parameters,peer_parameters:[]u8,identity:^credential_store.Store,
 allocator:mem.Allocator,identity_lease:^credential_store.Lease=nil,
 session:^Session=nil,early_allowed:bool=false,
)->(keys:Quic_Application_Keys,client_flight:[]u8,err:Quic_Secret_Error) {
 secret:=handshake_secret;defer crypto.zero_explicit(&secret,size_of(secret))
 if crypto.is_zero_constant_time(secret[:])==1 {return {},nil,{kind=.Derivation_Failed}}
 if len(local_parameters)>SERVER_QUIC_PARAMETERS_CAP||len(peer_parameters)>SERVER_QUIC_PARAMETERS_CAP {return {},nil,{kind=.Parameters_Oversized}}
 if e:=quic_client_hello_policy(client_hello,local_parameters,early_allowed);e.kind!=.None {return {},nil,e}
 messages:[5][]u8;count,at:=0,0
 for at<len(handshake_messages) {
  if count==len(messages)||len(handshake_messages)-at<4 {return {},nil,{kind=.Malformed}}
  n:=4+handshake_body_size(handshake_messages[at:]);if n>len(handshake_messages)-at {return {},nil,{kind=.Malformed}}
  messages[count]=handshake_messages[at:at+n];count+=1;at+=n
 }
 hello,hello_error:=server_hello_decode(server_hello,session!=nil);defer crypto.zero_explicit(&hello,size_of(hello))
 if hello_error!=.None {return {},nil,{kind=.Malformed}}
 resumed:=hello.psk_selected&&session!=nil&&session.usable
 if count<2||messages[0][0]!=8||resumed&&count!=2||!resumed&&count<4 {return {},nil,{kind=.Malformed}}
 if e:=quic_encrypted_extensions_policy(messages[0],peer_parameters,early_allowed);e.kind!=.None {return {},nil,e}
 transcript:Handshake_Transcript;transcript_init(&transcript);defer crypto.zero_explicit(&transcript,size_of(transcript))
 transcript_update(&transcript,client_hello);transcript_update(&transcript,server_hello);transcript_update(&transcript,messages[0])
 requested:=count==5;cert_at:=1
 schemes:[32]u16;scheme_count:=0
 if !resumed {
 if requested {
  request:=messages[1]
  parsed,e:=client_certificate_request_schemes(request);if e.kind!=.None {return {},nil,{kind=.Malformed}}
  schemes=parsed.schemes;scheme_count=parsed.count;transcript_update(&transcript,request);cert_at=2
 }
 if messages[cert_at][0]!=11||messages[cert_at+1][0]!=15||messages[cert_at+2][0]!=20 {return {},nil,{kind=.Unsupported}}
 previous:=context.allocator;context.allocator=allocator;defer context.allocator=previous
 certs,ae:=server_certificates_parse(messages[cert_at]);defer server_certificates_destroy(&certs)
 if ae.kind!=.None {return {},nil,{kind=.Authentication_Failed,authentication=ae}}
 if ae=verify_server_certificates(&certs,server_name,roots,now);ae.kind!=.None {return {},nil,{kind=.Authentication_Failed,authentication=ae}}
 transcript_update(&transcript,messages[cert_at])
 if ae=verify_server_certificate_signature(&certs,messages[cert_at+1],transcript_snapshot(&transcript));ae.kind!=.None {return {},nil,{kind=.Authentication_Failed,authentication=ae}}
 transcript_update(&transcript,messages[cert_at+1])
 }
 finished_at:=cert_at+2;if resumed {finished_at=1}
 if messages[finished_at][0]!=20 {return {},nil,{kind=.Malformed}}
 server_traffic:=quic_server_traffic(secret,client_hello,server_hello);defer crypto.zero_explicit(&server_traffic,size_of(server_traffic))
 if e:=finished_verify(messages[finished_at],server_traffic,transcript_snapshot(&transcript));e!=.None {return {},nil,{kind=.Finished_Failed,finished=e}}
 transcript_update(&transcript,messages[finished_at])
 application:=application_secrets_derive(secret,transcript_snapshot(&transcript));defer crypto.zero_explicit(&application,size_of(application))
 local:Quic_Application_Keys;defer quic_application_keys_clear(&local)
 client,ce:=quic_packet_keys_derive(application.client_traffic_secret,.Application);defer quic_direction_keys_clear(&client);if ce.kind!=.None {return {},nil,ce}
 server,se:=quic_packet_keys_derive(application.server_traffic_secret,.Application);defer quic_direction_keys_clear(&server);if se.kind!=.None {return {},nil,se}
 local={client=client,server=server}
 auth:[]u8
 if requested {
  wire,e:=client_authentication_flight(identity,schemes[:scheme_count],&transcript,allocator,identity_lease)
  if e.kind!=.None {return {},nil,{kind=.Authentication_Failed,authentication=e.authentication}}
  auth=wire
 }
 defer if raw_data(auth)!=nil {crypto.zero_explicit(raw_data(auth),len(auth));delete(auth,allocator)}
 flight,e:=make([]u8,len(auth)+FINISHED_MESSAGE_SIZE,allocator);if e!=nil {return {},nil,{kind=.Derivation_Failed}}
 copy(flight,auth)
 client_traffic:=quic_client_traffic(secret,client_hello,server_hello);defer crypto.zero_explicit(&client_traffic,size_of(client_traffic))
 n,fe:=finished_encode(flight[len(auth):],client_traffic,transcript_snapshot(&transcript))
 if fe!=.None||n!=FINISHED_MESSAGE_SIZE {crypto.zero_explicit(raw_data(flight),len(flight));delete(flight,allocator);return {},nil,{kind=.Finished_Failed,finished=fe}}
 transcript_update(&transcript,flight[len(auth):]);hash:=transcript_snapshot(&transcript)
 schedule_expand(.SHA256, application.master_secret[:],"res master",hash[:],local.resumption_master[:])
 local.early_accepted=quic_ee_has_early(messages[0])
 if local.early_accepted&&!resumed {crypto.zero_explicit(raw_data(flight),len(flight));delete(flight,allocator);return {},nil,{kind=.Malformed}}
 return local,flight,{}
}

@(private)
quic_ee_has_early :: proc(message:[]u8)->bool {
 if len(message)<6 {return false};at:=6
 for at+4<=len(message) {kind:=hello_u16(message,at);n:=int(hello_u16(message,at+2));at+=4;if n>len(message)-at {return false};if kind==42 {return n==0};at+=n};return false
}
