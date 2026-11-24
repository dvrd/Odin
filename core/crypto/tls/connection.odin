package tls

import "core:crypto"
import "core:crypto/x509"
import credential_store "credentials/store"
import "core:mem"
import trans "core:net"
import "core:net"
import "core:os"
import "core:time"

// Connection configuration and state

// Borrowed, immutable configuration. The name, roots, and certificates must
// outlive Conn. Use Root_Pool to load a platform PEM bundle; keep the pool alive.
Config :: struct {
	server_name:       string,
	root_cas:          []^x509.Certificate,
	// Zero uses ten seconds. Negative durations are invalid.
	// On wrapped transports this temporarily replaces, then clears deadlines.
	// A custom transport without deadline callbacks must bound its own I/O;
	// explicitly requesting a nonzero timeout requires callback support.
	handshake_timeout: time.Duration,
	// Ordered opaque names, borrowed and immutable through the full handshake
	// (including async completion). Zero offers preserve legacy behavior.
	alpn_protocols: []string,
	// Nil keeps a full handshake. Tickets are validated and discarded unless
	// remember_tickets stores one into this borrowed session and, when set,
	// into session_cache. The cache is caller-owned, bounded, and isolated by
	// server name. 0-RTT stays off unless early_data is set. Certificate checks
	// are unchanged when the server sends a certificate or does not select the PSK.
	session:          ^Session,
	session_cache:    ^Session_Cache,
	remember_tickets: bool,
	// Nil refuses early data. A policy is the only opt-in, and its allow
	// procedure must accept only replay-safe methods. It is borrowed for the
	// handshake and must not apply application effects itself.
	early_data: ^Early_Data_Policy,
	// Optional immutable identity store, borrowed through handshake completion.
	client_credentials: ^credential_store.Store,
	// Optional generation pinned by an origin pool, borrowed through handshake.
	client_credential_lease: ^credential_store.Lease,
	// The first flight and the answers accepted for it. The zero value keeps
	// the TLS_AES_128_GCM_SHA256/X25519 offer with the TLS 1.2 fallback.
	offer: Client_Offer,
	// Internal, for this package's tests and harnesses: Cipher_Suite and
	// Named_Group are private to the package, as upstream declares them.
	// Upstream offer only: restrict it to these suites (in this order) or to
	// these groups, each sent with its key share. Nil keeps upstream's lists.
	_cipher_suites: []Cipher_Suite,
	_groups: []Named_Group,
	// Debugging options that destroy security, as upstream's client_handshake
	// takes them: the certificate chain is parsed but not verified (the
	// CertificateVerify signature still is), and the traffic secrets are
	// written in NSS key log format to a file the connection then closes.
	unsafe_skip_verify: bool,
	unsafe_secret_logger: ^os.File,
	// An empty root_cas stays empty instead of loading the platform anchors:
	// verification then fails for want of an authority.
	no_system_roots: bool,
}

@(private)
Client_Error :: enum {
	None,
	Nil_Connection,
	Already_Initialized,
	Invalid_Transport,
	Missing_Server_Name,
	Invalid_Server_Name,
	Missing_Trust_Roots,
	Invalid_Trust_Root,
	Invalid_Timeout,
	Invalid_ALPN,
	Invalid_Client_Credentials,
	Invalid_Offer,
}

Conn_Phase :: enum {
	Uninitialized,
	Handshake_Pending,
	Awaiting_Server_Hello,
	Hello_Retry_Received,
	Server_Hello_Received,
	Handshake_Keys_Ready,
	Server_Finished_Received, // Received, not yet verified/authenticated.
	Established,
	Failed,
	Closed,
}

// Caller-owned; do not copy or mutate an initialized Conn.
// A full handshake must succeed before application I/O is exposed.
Conn :: struct {
	transport:                    trans.Connection,
	// The asynchronous driver queues control writes instead of blocking.
	defer_key_updates:            bool,
	// Set by the Socket facade: the engine then accepts and refuses exactly
	// what upstream's client does (see socket.odin).
	upstream_client:              bool,
	// Socket facade only: the send direction ended with an alert, after
	// which upstream's sender is gone and close says nothing more.
	send_ended:                   bool,
	config:                       Config,
	phase:                        Conn_Phase,
	// Internal handshake material. Only the handshake message (no record
	// header) participates in transcript authentication.
	client_hello:                 [MAX_CLIENT_HELLO_SIZE]u8,
	client_hello_size:            int,
	// The ClientHello's legacy session id: random for the Upstream offer
	// (middlebox compatibility), empty for the Compatible offer. The server
	// must echo it.
	legacy_session_id:            [LEGACY_SESSION_ID_SIZE]u8,
	legacy_session_id_size:       int,
	// The Upstream offer's compatibility ChangeCipherSpec records.
	ccs_sent:                     bool,
	ccs_received:                 int,
	// The fatal alert of a failed handshake, until the driver writes it.
	alert_wire:                   [HANDSHAKE_ALERT_WIRE_SIZE]u8,
	alert_size:                   int,
	alert_staged:                 bool,
	// One private key per offered group, until ServerHello selects one.
	ephemeral:                    Ephemeral_Keys,
	client_hello_error:           Client_Hello_Send_Error,
	server_hello:                 [MAX_UPSTREAM_SERVER_HELLO_SIZE]u8,
	server_hello_size:            int,
	server_parameters:            Server_Hello,
	server_hello_error:           Server_Hello_Read_Error,
	// Upstream's schedule state: the stage secret, then the traffic secrets
	// of the negotiated suite. Record keys live in the protections below.
	keys:                         Handshake_Keys,
	secrets:                      Connection_Secrets,
	handshake_send:               Record_Protection,
	handshake_receive:            Record_Protection,
	handshake_keys_error:         Handshake_Keys_Error,
	handshake_record_error:       Handshake_Record_Read_Error,
	// Framing only; message semantics and peer authentication follow later.
	server_handshake_header:      [4]u8,
	server_handshake_header_used: int,
	server_handshake_remaining:   int,
	server_handshake_type:        u8,
	application:                  Application_State,
	handshake_error:              Handshake_Error,
	handshake_complete:           bool,
	// Owns the negotiated name; exposed only by authenticated connection_state.
	alpn_selected:                [MAX_ALPN_PROTOCOL_SIZE]u8,
	alpn_selected_size:           int,
	// Used only by dial; client may wrap any caller-supplied transport.
	tcp:                          trans.TCP_Connection,
	retry_transcript:             [MAX_RETRY_TRANSCRIPT_SIZE]u8,
	retry_transcript_size:        int,
	// Size of the message_hash prefix; the HelloRetryRequest follows it.
	retry_message_hash_size:      int,
	retry_client_hello:           [MAX_RETRY_CLIENT_HELLO_SIZE]u8,
	retry_client_hello_size:      int,
	// Owned only when the caller supplied no roots. Explicit roots are the
	// sole trust set for that connection.
	system_roots:                 ^Root_Pool,
	system_roots_allocator:       mem.Allocator,
	tls12:                        TLS12_Client,
	psk_offered:                  bool,
	psk_selected:                 bool,
	// Borrowed from session or session_cache for this handshake. Not owned.
	offered_session:              ^Session,
 session_identity:[32]u8,
 session_roots_identity:[32]u8,
 session_identity_present,session_identity_valid:bool,
	early_offered:                bool,
	early_accepted:               bool,
	early_rejected:               bool,
	early_effect_done:            bool,
	resumption_master:            [MAX_TRANSCRIPT_HASH_SIZE]u8,
	have_resumption_master:       bool,
	// Through server Finished; a requested client flight is appended to it.
	server_finished_transcript:   Handshake_Transcript,
	have_server_finished_transcript: bool,
	// Through server Finished only: the application secrets' transcript.
	application_transcript:       Handshake_Transcript,
	// Digest through client Finished, for the resumption master secret.
	client_finished_hash:         [MAX_TRANSCRIPT_HASH_SIZE]u8,
	have_client_finished_hash:    bool,
	client_auth_requested: bool,
	client_auth_used: bool,
	client_auth_schemes: [32]u16,
	client_auth_scheme_count: int,
	// The certificate_request_context to echo. Only a Socket accepts one in
	// the handshake, as upstream's client does.
	client_auth_context: [255]u8,
	client_auth_context_size: int,
	client_auth_flight: []u8,
	client_auth_offset: int,
	client_auth_allocator: mem.Allocator,
}

@(private)
engine_config_validate :: proc(config: Config) -> Client_Error {
 if config.client_credential_lease!=nil {
  if config.client_credentials==nil {return .Invalid_Client_Credentials}
  if _,e:=credential_store.lease_generation(config.client_credentials,config.client_credential_lease^);e.kind!=.None {return .Invalid_Client_Credentials}
 }
	if config.handshake_timeout < 0 {
		return .Invalid_Timeout
	}

	if len(config.server_name) == 0 {
		return .Missing_Server_Name
	}

	if !server_name_valid(config.server_name) {
		return .Invalid_Server_Name
	}

	// A nil slice is omitted trust and fails before any dial. A non-nil empty
	// slice asks for platform anchors. Verification is never skipped.
	if raw_data(config.root_cas) == nil && !config_roots_optional(config) {
		return .Missing_Trust_Roots
	}
	for root in config.root_cas {
		if root == nil do return .Invalid_Trust_Root
	}
	if _, valid := alpn_protocols_size(config.alpn_protocols); !valid {return .Invalid_ALPN}
	if !config_offer_valid(config) {
		return .Invalid_Offer
	}
	return .None
}

// Like Go's tls.Client, wrapping performs no network I/O.
// Ownership of the transport transfers only on success. On failure the caller
// retains it. A closed Conn cannot be reinitialized accidentally.
@(private)
engine_client :: proc(conn: ^Conn, underlying: trans.Connection, config: Config) -> Client_Error {
	if conn == nil do return .Nil_Connection

	if conn.phase != .Uninitialized {
		return .Already_Initialized
	}

	if !trans.connection_valid(underlying) do return .Invalid_Transport

	settings, roots, roots_allocator, trust_error := client_trust(config)
	if trust_error != .None {
		return trust_error
	}
	// h3 is not a TCP record offer. Reject before any handshake write.
	if err := alpn_tcp_rejects_h3(settings.alpn_protocols); err != .None {
		system_roots_release_pool(roots, roots_allocator)
		return err
	}

	conn^ = {
		transport = underlying,
		config    = settings,
		phase     = .Handshake_Pending,
	}
	conn.system_roots = roots
	conn.system_roots_allocator = roots_allocator
	return .None
}

// Whether the configuration may leave root_cas empty.
@(private)
config_roots_optional :: proc(config: Config) -> bool {
	return config.unsafe_skip_verify || config.no_system_roots
}

// Loads Darwin/Unix system anchors for a non-nil empty root list.
// A nil list is omitted trust. An explicit slice is not combined with the system store.
@(private)
client_trust :: proc(
	config: Config,
) -> (
	settings: Config,
	roots: ^Root_Pool,
	roots_allocator: mem.Allocator,
	err: Client_Error,
) {
	settings = config
	if len(settings.root_cas) == 0 && !config_roots_optional(config) {
		if raw_data(settings.root_cas) == nil {
			return {}, nil, {}, .Missing_Trust_Roots
		}
		roots_allocator = context.allocator
		allocated, allocation_error := new(Root_Pool, roots_allocator)
		if allocation_error != nil || allocated == nil {
			return {}, nil, {}, .Missing_Trust_Roots
		}
		loaded := engine_root_pool_load_system(allocated)
		if loaded.kind != .None || allocated.count == 0 {
			root_pool_destroy(allocated)
			free(allocated, roots_allocator)
			return {}, nil, {}, .Missing_Trust_Roots
		}
		settings.root_cas = allocated.roots[:allocated.count]
		roots = allocated
	}
	if validate_error := engine_config_validate(settings); validate_error != .None {
		system_roots_release_pool(roots, roots_allocator)
		return {}, nil, {}, validate_error
	}
	return settings, roots, roots_allocator, .None
}

@(private)
system_roots_release_pool :: proc(pool: ^Root_Pool, allocator: mem.Allocator) {
	if pool == nil do return
	root_pool_destroy(pool)
	free(pool, allocator)
}

@(private)
system_roots_release :: proc(conn: ^Conn) {
	if conn == nil || conn.system_roots == nil do return
	// root_cas borrows the pool. Drop that view before the bytes are freed.
	conn.config.root_cas = nil
	pool := conn.system_roots
	allocator := conn.system_roots_allocator
	conn.system_roots = nil
	conn.system_roots_allocator = {}
	system_roots_release_pool(pool, allocator)
}

// Connection establishment and inspection

@(private)
Dial_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	TCP_Dial_Failed,
	Handshake_Failed,
}

@(private)
Dial_Error :: struct {
	kind:      Dial_Error_Kind,
	config:    Client_Error,
	network:   net.Network_Error,
	handshake: Handshake_Error,
}

// Like Go's tls.Dial, this opens TCP and authenticates TLS before returning.
// An empty server_name is inferred from host. DNS/TCP connection establishment
// uses core:net's dial behavior; handshake_timeout bounds the TLS phase only.
// conn must stay at the same address until closed and must not be copied.
@(private)
engine_dial :: proc(conn: ^Conn, host: string, port: int, config: Config) -> Dial_Error {
	if conn == nil || conn.phase != .Uninitialized {
		return {kind = .Invalid_State}
	}

	settings := config
	if settings.server_name == "" {
		settings.server_name = host
	}

	if err := engine_config_validate(settings); err != .None {
		return {kind = .Invalid_Config, config = err}
	}
	// Before any TCP socket. QUIC's h3 token never enters this record stack.
	if err := alpn_tcp_rejects_h3(settings.alpn_protocols); err != .None {
		return {kind = .Invalid_Config, config = err}
	}

	socket, dial_err := net.dial_tcp(host, port)
	if dial_err != nil {
		return {kind = .TCP_Dial_Failed, network = dial_err}
	}

	// client overwrites Conn, so install the socket after wrapping its stable
	// embedded adapter address. No transport I/O happens inside client.
	underlying := trans.tcp_connection(&conn.tcp)
	if err := engine_client(conn, underlying, settings); err != .None {
		net.close(socket)
		return {kind = .Invalid_Config, config = err}
	}

	conn.tcp = {
		socket = socket,
	}
	if err := engine_handshake(conn); err.kind != .None {
		engine_close(conn)
		return {kind = .Handshake_Failed, handshake = err}
	}

	return {}
}

Connection_State :: struct {
	handshake_complete: bool,
	version:            u16,
	cipher_suite:       Cipher_Suite,
	server_name:        string,
	// Borrows fixed Conn storage until failure/close; empty before authentication
	// and when the server omits ALPN. Does not borrow the server flight.
	negotiated_protocol: string,
	peer_identity: Peer_Identity,
	resumed:bool,
}

connection_state :: proc(conn: ^Conn) -> Connection_State {
	if conn == nil do return {}

	protocol: string
	if conn.phase == .Established && conn.handshake_complete {
		protocol = string(conn.alpn_selected[:conn.alpn_selected_size])
	}
	return {
		handshake_complete = conn.handshake_complete,
		resumed=conn.handshake_complete&&conn.psk_selected,
		version = conn.server_parameters.version,
		cipher_suite = conn.server_parameters.cipher_suite,
		server_name = conn.config.server_name,
		negotiated_protocol = protocol,
	}
}

// Connection deadlines

// Zero clears a deadline. Like read/write, callers must serialize these
// operations; this client does not yet support concurrent connection access.
@(private)
engine_set_read_deadline :: proc(conn: ^Conn, deadline: time.Time) -> trans.Connection_Error {
	if conn == nil || conn.phase == .Uninitialized {
		return {kind = .Invalid_Connection}
	}

	if conn.phase == .Closed do return {kind = .Closed}

	return trans.set_read_deadline(conn.transport, deadline)
}

@(private)
engine_set_write_deadline :: proc(conn: ^Conn, deadline: time.Time) -> trans.Connection_Error {
	if conn == nil || conn.phase == .Uninitialized {
		return {kind = .Invalid_Connection}
	}

	if conn.phase == .Closed do return {kind = .Closed}

	return trans.set_write_deadline(conn.transport, deadline)
}

@(private)
engine_set_deadline :: proc(conn: ^Conn, deadline: time.Time) -> trans.Connection_Error {
	if conn == nil || conn.phase == .Uninitialized {
		return {kind = .Invalid_Connection}
	}

	if conn.phase == .Closed do return {kind = .Closed}

	return trans.set_deadline(conn.transport, deadline)
}

// Immediate connection shutdown

// Releases a connection without sending close_notify. Use after protocol/I/O
// failure when a graceful write cannot safely complete within a deadline.
@(private)
engine_abort :: proc(conn: ^Conn) -> IO_Error {
	if conn == nil || conn.phase == .Uninitialized {
		return {kind = .Invalid_State}
	}

	if conn.phase == .Closed do return {}

	conn.phase = .Closed
	alpn_clear(conn)
	application_clear(&conn.application)
	handshake_keys_clear(conn)
	if err := conn.transport.close(conn.transport.data); err.kind != .None {
		return {kind = .Transport_Close_Failed, transport = err}
	}

	return {}
}


// Asynchronous connection operations

// Caller-owned until callback, which is always deferred. A zero deadline in
// async_handshake uses Config.handshake_timeout (ten seconds by default).
Async_Handshake_Operation :: struct {
	callback:  proc(op: ^Async_Handshake_Operation),
	user_data: rawptr,
	pending:   bool,
	err:       net.Connection_Error,
	result:    Handshake_Error,
}

// Owned by the executor's thread. Do not copy; retain at a stable address until
// async close completes. Config and trust roots borrow caller storage. The
// executor, transport and allocator must outlive all callbacks. Complete the
// explicit handshake before submitting application reads or writes.
Async_Conn :: struct {
	protocol:                                                          Conn,
	transport:                                                         net.Async_Connection,
	executor:                                                          net.Async_Executor,
	allocator:                                                         mem.Allocator,
	initialized, queued, closing, transport_closing, transport_closed: bool,
	notify_allowed, notify_sent:                                       bool,
	failure:                                                           net.Connection_Error,
	io_error:                                                          IO_Error,
	close_error:                                                       net.Connection_Error,
	handshake_op:                                                      ^Async_Handshake_Operation,
	handshake_deadline:                                                time.Time,
	flight:                                                            []u8,
	flight_used:                                                       int,
	hello:                                                             [MAX_SERVER_HELLO_MESSAGE_SIZE]u8,
	hello_used, ignored_ccs:                                           int,
	finishing:                                                         bool,
	read_op, write_op, close_op:                                       ^net.Async_Operation,
	read_buffer, write_buffer:                                         []u8,
	read_deadline, write_deadline:                                     time.Time,
	read_cancel, write_cancel:                                         bool,
	rx, tx, shutdown:                                                  net.Async_Operation,
	rx_wire:                                                           [RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE]u8,
	rx_plain:                                                          [MAX_CIPHERTEXT_SIZE]u8,
	rx_used, rx_expected:                                              int,
	rx_error:                                                          net.Connection_Error,
	tx_wire:                                                           [RECORD_HEADER_SIZE + MAX_CIPHERTEXT_SIZE]u8,
	tx_size, tx_plain_count:                                           int,
	tx_kind:                                                           Async_Send_Kind,
	tx_done:                                                           bool,
}

// Shares the authenticated state view without exposing the async driver's
// embedded protocol or borrowing its transient server-flight allocation.
async_connection_state :: proc(conn: ^Async_Conn) -> Connection_State {
	if conn == nil {return {}}
	return connection_state(&conn.protocol)
}

Async_Send_Kind :: enum {
	None,
	Hello,
	Retry,
	Finished,
	Client_Auth,
	Data,
	Key_Update,
	Notify,
	Alert,
}

// Wraps without I/O. Success transfers transport ownership; failure leaves it
// with the caller. Roots and allocator are explicit, as in the blocking client.
@(private)
engine_async_client :: proc(
	conn: ^Async_Conn,
	underlying: net.Async_Connection,
	executor: net.Async_Executor,
	config: Config,
	allocator := context.allocator,
) -> Client_Error {
	if conn == nil do return .Nil_Connection
	if conn.initialized do return .Already_Initialized
	if underlying.submit == nil || underlying.cancel == nil || executor.schedule == nil do return .Invalid_Transport
	settings, roots, _, trust_error := client_trust(config)
	if trust_error != .None do return trust_error
	if err := alpn_tcp_rejects_h3(settings.alpn_protocols); err != .None {
		system_roots_release_pool(roots, context.allocator)
		return err
	}
	conn^ = {
		initialized = true,
		transport = underlying,
		executor = executor,
		allocator = allocator,
		protocol = {
			config = settings,
			phase = .Handshake_Pending,
			defer_key_updates = true,
			system_roots = roots,
			system_roots_allocator = context.allocator,
		},
	}
	conn.rx = {
		callback  = async_receive_done,
		user_data = conn,
	}
	conn.tx = {
		callback  = async_send_done,
		user_data = conn,
	}
	conn.shutdown = {
		callback  = async_shutdown_done,
		user_data = conn,
	}
	return .None
}

// The handshake occupies its own operation. Read/write submissions are rejected
// until it succeeds. Cancellation is terminal for a partially exchanged handshake.
@(private)
engine_async_handshake :: proc(
	conn: ^Async_Conn,
	op: ^Async_Handshake_Operation,
	deadline := time.Time{},
) -> net.Connection_Error {
	if conn == nil || !conn.initialized do return {kind = .Invalid_Connection}
	if op == nil || op.callback == nil do return {kind = .Invalid_Operation}
	if conn.closing || conn.transport_closed do return {kind = .Closed}
	if op.pending || conn.handshake_op != nil do return {kind = .Operation_Pending}
	if conn.protocol.phase != .Handshake_Pending && conn.protocol.phase != .Established do return {kind = .Protocol_Failed}
	op.pending, op.err, op.result = true, {}, {}
	conn.handshake_op = op
	timeout := conn.protocol.config.handshake_timeout
	if timeout == 0 do timeout = 10 * time.Second
	conn.handshake_deadline = time.time_add(time.now(), timeout)
	if deadline != (time.Time{}) && time.diff(deadline, conn.handshake_deadline) > 0 do conn.handshake_deadline = deadline
	async_queue(conn)
	return {}
}

@(private)
engine_async_cancel_handshake :: proc(conn: ^Async_Conn) -> net.Connection_Error {
	if conn == nil || !conn.initialized do return {kind = .Invalid_Connection}
	if conn.handshake_op == nil || conn.protocol.phase == .Established do return {}
	async_terminal(conn, {kind = .Cancelled}, {})
	return {}
}

// Exposes the same application byte-stream contract as asynchronous TCP.
// Handshake/authentication errors remain available in async_failure.
async_connection :: proc(conn: ^Async_Conn) -> net.Async_Connection {
	if conn == nil || !conn.initialized do return {}
	return {data = conn, submit = async_submit, cancel = async_cancel}
}

@(private)
engine_async_failure :: proc(conn: ^Async_Conn) -> IO_Error {
	if conn == nil do return {kind = .Invalid_State}
	return conn.io_error
}

@(private)
async_submit :: proc(
	data: rawptr,
	op: ^net.Async_Operation,
	kind: net.Async_Operation_Kind,
	buffer: []u8,
	deadline: time.Time,
) -> net.Connection_Error {
	conn := cast(^Async_Conn)data
	if conn.closing || conn.transport_closed && kind != .Close do return {kind = .Closed}
	if kind != .Close {
		if conn.failure.kind != .None do return conn.failure
		if conn.protocol.phase != .Established do return {kind = .Invalid_Connection}
	}
	switch kind {
	case .Read:
		if conn.read_op != nil do return {kind = .Operation_Pending}
		conn.read_op, conn.read_buffer, conn.read_deadline, conn.read_cancel =
			op, buffer, deadline, false
	case .Write:
		if conn.write_op != nil do return {kind = .Operation_Pending}
		conn.write_op, conn.write_buffer, conn.write_deadline, conn.write_cancel =
			op, buffer, deadline, false
	case .Close:
		conn.close_op = op
		conn.closing = true
		// An interrupted TLS write can leave a partial record on the wire.
		// Only idle, healthy writers can safely send close_notify.
		conn.notify_allowed =
			conn.protocol.phase == .Established &&
			conn.failure.kind == .None &&
			!conn.tx.pending &&
			!conn.tx_done
	}
	op.kind, op.pending, op.result, op._owner = kind, true, {}, conn
	async_queue(conn)
	return {}
}

@(private)
async_cancel :: proc(data: rawptr, op: ^net.Async_Operation) -> net.Connection_Error {
	conn := cast(^Async_Conn)data
	if !op.pending do return {}
	if op._owner != conn || op.kind == .Close do return {kind = .Invalid_Operation}
	if op == conn.read_op {
		conn.read_cancel = true
		if conn.rx.pending do net.async_cancel(conn.transport, &conn.rx)
	} else if op == conn.write_op {
		conn.write_cancel = true
		if conn.tx.pending && conn.tx_kind == .Data do net.async_cancel(conn.transport, &conn.tx)
	} else {
		return {kind = .Invalid_Operation}
	}
	async_queue(conn)
	return {}
}

@(private)
async_queue :: proc(conn: ^Async_Conn) {
	if !conn.queued {
		conn.queued = true
		conn.executor.schedule(conn.executor.data, async_pump, conn)
	}
}

@(private)
async_pump :: proc(data: rawptr) {
	conn := cast(^Async_Conn)data
	conn.queued = false
	allocator := context.allocator
	context.allocator = conn.allocator
	defer context.allocator = allocator
	if conn.tx_done {
		conn.tx_done = false
		async_send_process(conn)
	}
	if conn.closing || conn.failure.kind != .None {
		async_shutdown_drive(conn)
		return // close callback can free conn
	}
	if conn.protocol.phase != .Established {
		if conn.handshake_op != nil do async_handshake_drive(conn)
	} else {
		if conn.handshake_op != nil do async_handshake_complete(conn, {})
		if !conn.closing && conn.failure.kind == .None do async_application_drive(conn)
	}
}

@(private)
async_terminal :: proc(conn: ^Async_Conn, error: net.Connection_Error, details: IO_Error) {
	if conn.failure.kind == .None {
		conn.failure = error
		conn.io_error = details
		if conn.handshake_op != nil && conn.protocol.handshake_error.kind == .None {
			conn.protocol.handshake_error = {
				kind      = .Server_Flight_Read_Failed,
				transport = error,
			}
		}
		conn.protocol.phase = .Failed
		alpn_clear(&conn.protocol)
		crypto.zero_explicit(&conn.protocol.resumption_master, size_of(conn.protocol.resumption_master))
		conn.protocol.have_resumption_master = false
		crypto.zero_explicit(&conn.protocol.server_finished_transcript, size_of(conn.protocol.server_finished_transcript))
		conn.protocol.have_server_finished_transcript = false
	}
	async_queue(conn)
}

@(private)
async_emit :: proc(
	conn: ^Async_Conn,
	kind: net.Async_Operation_Kind,
	error: net.Connection_Error,
) {
	op := conn.read_op if kind == .Read else conn.write_op
	if op == nil do return
	if kind == .Read {
		conn.read_op = nil; conn.read_buffer = nil
	} else {
		conn.write_op = nil; conn.write_buffer = nil
	}
	op.result.err, op.pending, op._owner = error, false, nil
	op.callback(op)
}

@(private)
async_handshake_complete :: proc(conn: ^Async_Conn, error: net.Connection_Error) {
	op := conn.handshake_op
	if op == nil do return
	conn.handshake_op = nil
	op.pending, op.err, op.result = false, error, conn.protocol.handshake_error
	op.callback(op)
}

@(private)
async_shutdown_drive :: proc(conn: ^Async_Conn) {
	if conn.rx.pending do net.async_cancel(conn.transport, &conn.rx)
	if conn.tx.pending {
		if conn.tx_kind != .Notify && conn.tx_kind != .Alert {
			net.async_cancel(conn.transport, &conn.tx)
		}
		return
	}
	if conn.rx.pending do return
	error := conn.failure
	if conn.closing do error = {
		kind = .Closed,
	}
	async_handshake_complete(conn, error)
	async_emit(conn, .Read, error)
	async_emit(conn, .Write, error)
	if conn.closing && conn.notify_allowed && !conn.notify_sent && conn.failure.kind == .None {
		size, seal_error := engine_record_seal(
			&conn.protocol.application.send,
			conn.tx_wire[:],
			.Alert,
			[]u8{1, 0},
		)
		conn.notify_allowed = false
		if seal_error == .None {
			async_send_start(conn, .Notify, size, time.time_add(time.now(), time.Second))
			return
		}
	}
	if !conn.transport_closing {
		conn.transport_closing = true
		close_error := net.async_close(conn.transport, &conn.shutdown)
		if close_error.kind != .None {
			conn.close_error = close_error; conn.transport_closed = true
		}
	}
	if !conn.transport_closed || conn.queued do return
	alpn_clear(&conn.protocol)
	application_clear(&conn.protocol.application)
	handshake_keys_clear(&conn.protocol)
	crypto.zero_explicit(&conn.rx_wire, size_of(conn.rx_wire))
	crypto.zero_explicit(&conn.tx_wire, size_of(conn.tx_wire))
	crypto.zero_explicit(&conn.rx_plain, size_of(conn.rx_plain))
	if conn.flight != nil {
		crypto.zero_explicit(raw_data(conn.flight), len(conn.flight))
		delete(conn.flight, conn.allocator); conn.flight = nil
	}
	if conn.close_op != nil {
		op := conn.close_op
		conn.close_op = nil
		conn.protocol.phase = .Closed
		op.pending, op._owner, op.result.err = false, nil, conn.close_error
		op.callback(op)
		// conn and op may have been freed by callback.
	}
}

@(private)
async_shutdown_done :: proc(op: ^net.Async_Operation) {
	conn := cast(^Async_Conn)op.user_data
	conn.transport_closed = true
	if conn.close_error.kind == .None do conn.close_error = op.result.err
	async_queue(conn)
}
