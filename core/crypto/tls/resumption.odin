package tls

import "core:crypto"
import "core:crypto/hash"
import "core:crypto/sha2"
import "core:time"
import credential_store "credentials/store"

// One TLS 1.3 resumption ticket (RFC 8446 §4.6.1 and §7.1). psk_dhe_ke only.
// 0-RTT stays off unless the caller passes Early_Data_Policy. early_data_max is
// the peer's advertisement, not permission to send early data by itself.
SESSION_TICKET_MAX :: 4096
SESSION_NONCE_MAX :: 255
SESSION_CACHE_CAP :: 8
RESUMPTION_BINDER_LEN :: 32
RESUMPTION_BINDERS_TAIL :: 2 + 1 + RESUMPTION_BINDER_LEN

// psk_key_exchange_modes plus one pre_shared_key identity and one SHA-256 binder.
MAX_RESUMPTION_EXTENSION :: 6 + 4 + 2 + 2 + SESSION_TICKET_MAX + 4 + RESUMPTION_BINDERS_TAIL

@(private)
EXTENSION_PRE_SHARED_KEY :: u16(41)
@(private)
EXTENSION_EARLY_DATA :: u16(42)
@(private)
EXTENSION_PSK_MODES :: u16(45)
@(private)
PSK_DHE_KE :: u8(1)

Session :: struct {
	usable:              bool,
	alpn:                [255]u8,
	alpn_len:            int,
	client_identity:     [32]u8,
	roots_identity:      [32]u8,
	is_quic:             bool,
	quic_profile:        [SERVER_EARLY_CONTEXT_MAX]u8,
	quic_profile_len:    int,
	quic_port:           u16,
	quic_local_profile:  [32]u8,
	has_client_identity: bool,
	name:                [MAX_SERVER_NAME_SIZE]u8,
	name_len:            int,
	ticket:              [SESSION_TICKET_MAX]u8,
	ticket_len:          int,
	nonce:               [SESSION_NONCE_MAX]u8,
	nonce_len:           int,
	psk:                 [32]u8,
	age_add:             u32,
	lifetime_sec:        u32,
	received:            time.Time,
	saw_early_data:      bool,
	early_data_max:      u32,
}

// Caller-owned. Slots are copies, so clearing the source session does not
// drop a stored ticket. One live ticket per server name. Expired slots are
// erased on lookup of that name and when a put needs a free slot.
Session_Cache :: struct {
	slots: [SESSION_CACHE_CAP]Session,
	live:  [SESSION_CACHE_CAP]bool,
	order: [SESSION_CACHE_CAP]u64,
	clock: u64,
}

// allow must be non-nil and must return true only for replay-safe methods.
// It must not apply application effects.
Early_Data_Policy :: struct {
	allow: proc(method: string) -> bool,
}

@(private)
Early_Data_Result :: enum {
	None,
	Applied,
	Deferred,
	Refused,
}

session_clear :: proc(session: ^Session) {
	if session != nil {
		crypto.zero_explicit(session, size_of(Session))
	}
}

// Refuses 0-RTT unless policy is set and the session advertised early data.
// The early secret is not retained. A nil policy produces no key bytes.
session_early_keys :: proc(
	session: ^Session,
	policy: ^Early_Data_Policy = nil,
	client_hello: []u8 = nil,
) -> (
	keys: Quic_Direction_Keys,
	err: Quic_Secret_Error,
) {
	if session == nil ||
	   !session.usable ||
	   !session.saw_early_data ||
	   session.early_data_max == 0 ||
	   policy == nil ||
	   policy.allow == nil ||
	   len(client_hello) == 0 {
		return engine_quic_early_packet_keys({})
	}
	secret, ok := session_early_secret(session)
	defer crypto.zero_explicit(&secret, size_of(secret))
	if !ok {
		return engine_quic_early_packet_keys({})
	}
	return engine_quic_early_packet_keys(secret, policy, client_hello)
}

// HKDF-Extract(0, PSK). Not an early traffic secret and not packet keys.
session_early_secret :: proc(session: ^Session) -> (secret: [32]u8, ok: bool) {
	if session == nil || !session.usable {
		return
	}
	psk := session.psk
	defer crypto.zero_explicit(&psk, size_of(psk))

	keys: Handshake_Keys
	defer clear_handshake_keys(&keys)

	schedule_init(&keys, .SHA256, psk[:])
	copy(secret[:], schedule_secret(&keys))
	ok = true
	return
}

session_cache_clear :: proc(cache: ^Session_Cache) {
	if cache == nil {
		return
	}
	for i in 0 ..< SESSION_CACHE_CAP {
		session_clear(&cache.slots[i])
	}
	cache.live = {}
	cache.order = {}
	cache.clock = 0
}

// Copies session into the cache. Same server name replaces that slot. A full
// cache drops the oldest live slot. An already-expired session is refused and
// the cache is left unchanged.
session_cache_put :: proc(cache: ^Session_Cache, session: ^Session) -> bool {
	if cache == nil || session == nil || !session.usable {
		return false
	}
	if session.name_len < 1 ||
	   session.name_len > len(session.name) ||
	   session.ticket_len < 1 ||
	   session.ticket_len > SESSION_TICKET_MAX ||
	   session.lifetime_sec == 0 ||
	   session.lifetime_sec > 7 * 24 * 60 * 60 {
		return false
	}
	name := string(session.name[:session.name_len])
	if !session_offerable(session, name, time.now()) {
		return false
	}
	slot := -1
	oldest := -1
	oldest_order := max(u64)
	for i in 0 ..< SESSION_CACHE_CAP {
		if !cache.live[i] {
			if slot < 0 {
				slot = i
			}
			continue
		}
		same :=
			cache.slots[i].name_len == session.name_len &&
			string(cache.slots[i].name[:cache.slots[i].name_len]) == name
		if same {
			slot = i
			break
		}
		if !session_offerable(&cache.slots[i], string(cache.slots[i].name[:cache.slots[i].name_len]), time.now()) {
			session_clear(&cache.slots[i])
			cache.live[i] = false
			cache.order[i] = 0
			if slot < 0 {
				slot = i
			}
			continue
		}
		if cache.order[i] < oldest_order {
			oldest_order = cache.order[i]
			oldest = i
		}
	}
	if slot < 0 {
		slot = oldest
	}
	if slot < 0 {
		return false
	}
	if cache.live[slot] {
		session_clear(&cache.slots[slot])
	}
	cache.slots[slot] = session^
	cache.live[slot] = true
	if cache.clock < max(u64) {
		cache.clock += 1
	}
	cache.order[slot] = cache.clock
	return true
}

// Returns the slot for server_name only. An expired ticket for that name is
// erased. Another name's ticket is left in place.
session_cache_lookup :: proc(cache: ^Session_Cache, server_name: string, now: time.Time) -> ^Session {
	if cache == nil || len(server_name) == 0 || len(server_name) > MAX_SERVER_NAME_SIZE {
		return nil
	}
	for i in 0 ..< SESSION_CACHE_CAP {
		if !cache.live[i] {
			continue
		}
		slot := &cache.slots[i]
		same := slot.name_len == len(server_name) && string(slot.name[:slot.name_len]) == server_name
		if !same {
			continue
		}
		if !session_offerable(slot, server_name, now) {
			session_clear(slot)
			cache.live[i] = false
			cache.order[i] = 0
			return nil
		}
		return slot
	}
	return nil
}

@(private)
session_offerable :: proc(session: ^Session, server_name: string, now: time.Time) -> bool {
	if session == nil ||
	   !session.usable ||
	   session.ticket_len < 1 ||
	   session.ticket_len > SESSION_TICKET_MAX ||
	   session.name_len < 1 ||
	   session.name_len > len(session.name) ||
	   session.alpn_len < 0 ||
	   session.alpn_len > len(session.alpn) {
		return false
	}
	if session.lifetime_sec == 0 || session.lifetime_sec > 7 * 24 * 60 * 60 {
		return false
	}
	if session.name_len != len(server_name) || string(session.name[:session.name_len]) != server_name {
		return false
	}
	age := time.diff(session.received, now)
	if age < 0 {
		return false
	}
	if i64(age) >= i64(session.lifetime_sec) * i64(time.Second) {
		return false
	}
	return true
}

// message is a full NewSessionTicket handshake message, including its header.
// An oversized ticket or a bad name leaves session unchanged. Early data in the
// ticket is recorded and then refused by session_early_keys.
session_remember :: proc(
	session: ^Session,
	resumption_master: [32]u8,
	message: []u8,
	server_name: string,
	now: time.Time,
) -> bool {
	if session == nil || len(server_name) == 0 || len(server_name) > len(session.name) {
		return false
	}
	if len(message) < 4 || message[0] != NEW_SESSION_TICKET_TYPE {
		return false
	}
	if handshake_body_size(message) + 4 != len(message) || !application_ticket_valid(message[4:]) {
		return false
	}
	body := message[4:]
	lifetime := u32(body[0]) << 24 | u32(body[1]) << 16 | u32(body[2]) << 8 | u32(body[3])
	if lifetime == 0 || lifetime > 7 * 24 * 60 * 60 {
		return false
	}
	age_add := u32(body[4]) << 24 | u32(body[5]) << 16 | u32(body[6]) << 8 | u32(body[7])
	nonce_len := int(body[8])
	if nonce_len > SESSION_NONCE_MAX {
		return false
	}
	nonce := body[9:][:nonce_len]
	at := 9 + nonce_len
	ticket_len := int(body[at]) << 8 | int(body[at + 1])
	at += 2
	if ticket_len < 1 || ticket_len > SESSION_TICKET_MAX || ticket_len > len(body) - at {
		return false
	}
	ticket := body[at:][:ticket_len]
	at += ticket_len
	if len(body) - at < 2 {
		return false
	}
	ext_len := int(body[at]) << 8 | int(body[at + 1])
	at += 2
	if ext_len != len(body) - at {
		return false
	}
	saw_early := false
	early_max: u32
	ext_end := at + ext_len
	for at < ext_end {
		if ext_end - at < 4 {
			return false
		}
		kind := int(body[at]) << 8 | int(body[at + 1])
		size := int(body[at + 2]) << 8 | int(body[at + 3])
		at += 4
		if size > ext_end - at {
			return false
		}
		if kind == int(EXTENSION_EARLY_DATA) {
			if size != 4 {
				return false
			}
			saw_early = true
			early_max = u32(body[at]) << 24 | u32(body[at + 1]) << 16 | u32(body[at + 2]) << 8 | u32(body[at + 3])
		}
		at += size
	}
	psk := session_psk(resumption_master, nonce)
	defer crypto.zero_explicit(&psk, size_of(psk))
	next := Session {
		usable         = true,
		name_len       = len(server_name),
		ticket_len     = ticket_len,
		nonce_len      = nonce_len,
		psk            = psk,
		age_add        = age_add,
		lifetime_sec   = lifetime,
		received       = now,
		saw_early_data = saw_early,
		early_data_max = early_max,
	}
	copy(next.name[:], server_name)
	copy(next.ticket[:], ticket)
	copy(next.nonce[:], nonce)
	session_clear(session)
	session^ = next
	crypto.zero_explicit(&next, size_of(next))
	return true
}

@(private)
session_psk :: proc(master: [32]u8, nonce: []u8) -> (psk: [32]u8) {
	secret := master
	defer crypto.zero_explicit(&secret, size_of(secret))
	schedule_expand(.SHA256, secret[:], "resumption", nonce, psk[:])
	return
}

@(private)
session_obfuscated_age :: proc(session: ^Session, now: time.Time) -> u32 {
	age := time.diff(session.received, now)
	if age < 0 {
		age = 0
	}
	ms := i64(age) / i64(time.Millisecond)
	if ms < 0 {
		ms = 0
	}
	if ms > 0xffffffff {
		ms = 0xffffffff
	}
	return u32((u64(ms) + u64(session.age_add)) & 0xffffffff)
}

// Append psk_dhe_ke and pre_shared_key. early appends an empty early_data
// extension before pre_shared_key, which stays last. Lengths count the binder,
// which is then written over the truncated ClientHello.
@(private)
resumption_client_hello_offer :: proc(
	dst: []u8,
	hello_len: int,
	session: ^Session,
	now: time.Time,
	early: bool = false,
) -> (
	written: int,
	ok: bool,
) {
	if session == nil || hello_len < 47 || hello_len > len(dst) {
		return hello_len, false
	}
	layout, valid := client_hello_layout_decode(dst[:hello_len])
	if !valid {
		return hello_len, false
	}
	if resumption_extension_offset(dst[:hello_len], EXTENSION_PRE_SHARED_KEY) >= 0 ||
	   resumption_extension_offset(dst[:hello_len], EXTENSION_EARLY_DATA) >= 0 ||
	   resumption_extension_offset(dst[:hello_len], EXTENSION_PSK_MODES) >= 0 {
		return hello_len, false
	}
	add := 6 + 4 + 2 + 2 + session.ticket_len + 4 + RESUMPTION_BINDERS_TAIL
	if early {
		add += 4
	}
	if hello_len + add > len(dst) || layout.extensions_size + add > 65535 {
		return hello_len, false
	}
	at := hello_len
	resumption_put_u16(dst, &at, EXTENSION_PSK_MODES)
	resumption_put_u16(dst, &at, 2)
	dst[at] = 1
	at += 1
	dst[at] = PSK_DHE_KE
	at += 1
	if early {
		resumption_put_u16(dst, &at, EXTENSION_EARLY_DATA)
		resumption_put_u16(dst, &at, 0)
	}
	identities := 2 + session.ticket_len + 4
	payload := 2 + identities + RESUMPTION_BINDERS_TAIL
	resumption_put_u16(dst, &at, EXTENSION_PRE_SHARED_KEY)
	resumption_put_u16(dst, &at, u16(payload))
	resumption_put_u16(dst, &at, u16(identities))
	resumption_put_u16(dst, &at, u16(session.ticket_len))
	copy(dst[at:], session.ticket[:session.ticket_len])
	at += session.ticket_len
	age := session_obfuscated_age(session, now)
	dst[at] = u8(age >> 24)
	dst[at + 1] = u8(age >> 16)
	dst[at + 2] = u8(age >> 8)
	dst[at + 3] = u8(age)
	at += 4
	resumption_put_u16(dst, &at, 33)
	dst[at] = RESUMPTION_BINDER_LEN
	at += 1
	for i in 0 ..< RESUMPTION_BINDER_LEN {
		dst[at + i] = 0
	}
	at += RESUMPTION_BINDER_LEN
	if at != hello_len + add {
		return hello_len, false
	}
	body := at - 4
	dst[1] = u8(body >> 16)
	dst[2] = u8(body >> 8)
	dst[3] = u8(body)
	retry_put_u16(dst, layout.extensions_length_offset, u16(layout.extensions_size + add))
	if !resumption_write_binder(dst[:at], session.psk, nil) {
		return hello_len, false
	}
	return at, true
}

// CH2 keeps pre_shared_key last. The binder covers ClientHello1 || HRR || Truncate(CH2).
// HelloRetryRequest rejects 0-RTT, so early_data is removed before the cookie insert.
@(private)
resumption_retry_prepare :: proc(
	conn: ^Conn,
	first, retry, cookie: []u8,
	layout: Client_Hello_Layout,
) -> Server_Hello_Error {
	session := conn.offered_session
	if session == nil || !session.usable {
		session = conn.config.session
	}
	if session == nil || !session.usable {
		return .Invalid_Retry_Client_Hello
	}
	_ = layout
	stripped: [MAX_CLIENT_HELLO_SIZE]u8
	base := first
	if resumption_extension_offset(first, EXTENSION_EARLY_DATA) >= 0 {
		n, stripped_ok := resumption_strip_extension(stripped[:], first, EXTENSION_EARLY_DATA)
		if !stripped_ok {
			return .Invalid_Retry_Client_Hello
		}
		base = stripped[:n]
		conn.early_offered = false
		conn.early_accepted = false
		conn.early_rejected = true
	}
	base_layout, valid := client_hello_layout_decode(base)
	if !valid {
		return .Invalid_Retry_Client_Hello
	}
	psk_at := resumption_last_extension_offset(base)
	if psk_at < 0 || hello_u16(base, psk_at) != EXTENSION_PRE_SHARED_KEY {
		return .Invalid_Retry_Client_Hello
	}
	insert := 6 + len(cookie)
	new_size := len(base) + insert
	tail_n := len(base) - psk_at
	tail: [8 + 2 + SESSION_TICKET_MAX + 4 + RESUMPTION_BINDERS_TAIL]u8
	if tail_n > len(tail) || tail_n < RESUMPTION_BINDERS_TAIL || new_size > len(conn.retry_client_hello) {
		return .Invalid_Retry_Client_Hello
	}
	copy(conn.retry_client_hello[:len(base)], base)
	copy(tail[:tail_n], conn.retry_client_hello[psk_at:][:tail_n])
	at := psk_at
	retry_put_u16(conn.retry_client_hello[:], at, RETRY_COOKIE_EXTENSION)
	retry_put_u16(conn.retry_client_hello[:], at + 2, u16(2 + len(cookie)))
	retry_put_u16(conn.retry_client_hello[:], at + 4, u16(len(cookie)))
	copy(conn.retry_client_hello[at + 6:], cookie)
	copy(conn.retry_client_hello[psk_at + insert:], tail[:tail_n])
	retry_put_u24(conn.retry_client_hello[:], 1, new_size - 4)
	ext := base_layout.extensions_size + insert
	if ext > 65535 {
		return .Invalid_Retry_Client_Hello
	}
	retry_put_u16(conn.retry_client_hello[:], base_layout.extensions_length_offset, u16(ext))
	ch2 := conn.retry_client_hello[:new_size]
	id_len := int(hello_u16(ch2, psk_at + insert + 6))
	age_at := psk_at + insert + 8 + id_len
	if age_at + 4 > new_size - RESUMPTION_BINDERS_TAIL {
		return .Invalid_Retry_Client_Hello
	}
	age := session_obfuscated_age(session, time.now())
	ch2[age_at] = u8(age >> 24)
	ch2[age_at + 1] = u8(age >> 16)
	ch2[age_at + 2] = u8(age >> 8)
	ch2[age_at + 3] = u8(age)
	if !resumption_write_binder(ch2, session.psk, [][]u8{first, retry}) {
		return .Invalid_Retry_Client_Hello
	}
	conn.retry_client_hello_size = new_size
	client_hello_retry_transcript_prepare(conn, first, retry)
	return .None
}

// Writes the PSK binder over the truncated ClientHello (RFC 8446 section
// 4.2.11.2): a Finished MAC keyed from the PSK's early secret. SHA-256 PSKs.
@(private)
resumption_write_binder :: proc(hello: []u8, psk: [32]u8, prefix: [][]u8) -> bool {
	if len(hello) < RESUMPTION_BINDERS_TAIL + 4 {
		return false
	}

	truncated := hello[:len(hello) - RESUMPTION_BINDERS_TAIL]
	t: Handshake_Transcript
	transcript_init(&t)
	for part in prefix {
		transcript_update(&t, part)
	}
	transcript_update(&t, truncated)

	digest := transcript_snapshot(&t)
	key := resumption_binder_key(psk)
	defer crypto.zero_explicit(&key, size_of(key))

	schedule_finished_mac(.SHA256, key[:], digest[:], hello[len(hello) - RESUMPTION_BINDER_LEN:])
	return true
}

@(private)
resumption_binder_key :: proc(psk: [32]u8) -> (key: [32]u8) {
	secret := psk
	defer crypto.zero_explicit(&secret, size_of(secret))

	keys: Handshake_Keys
	defer clear_handshake_keys(&keys)

	schedule_init(&keys, .SHA256, secret[:])
	schedule_derive_secret(&keys, "res binder", keys.zero_hash[:32], key[:])
	return
}

// Derives the resumption master secret once the schedule holds the master
// secret and the digest through client Finished is known.
@(private)
resumption_capture :: proc(conn: ^Conn) {
	// Tickets are scoped to negotiated ALPN and the exact configured client identity.
	if conn == nil || !conn.config.remember_tickets || !conn.have_client_finished_hash {
		return
	}

	if conn.config.session == nil && conn.config.session_cache == nil {
		return
	}

	digest_size := hash.DIGEST_SIZES[conn.keys.hash]
	schedule_derive_secret(
		&conn.keys,
		"res master",
		conn.client_finished_hash[:digest_size],
		conn.resumption_master[:digest_size],
	)
	conn.have_resumption_master = true
}

@(private)
resumption_extension_offset :: proc(wire: []u8, kind: u16) -> int {
	layout, valid := client_hello_layout_decode(wire)
	if !valid {
		return -1
	}
	at := layout.extensions_offset
	end := at + layout.extensions_size
	for at + 4 <= end {
		ext := hello_u16(wire, at)
		size := int(hello_u16(wire, at + 2))
		if at + 4 + size > end {
			return -1
		}
		if ext == kind {
			return at
		}
		at += 4 + size
	}
	return -1
}

@(private)
resumption_last_extension_offset :: proc(wire: []u8) -> int {
	layout, valid := client_hello_layout_decode(wire)
	if !valid {
		return -1
	}
	at := layout.extensions_offset
	end := at + layout.extensions_size
	last := -1
	for at + 4 <= end {
		size := int(hello_u16(wire, at + 2))
		if at + 4 + size > end {
			return -1
		}
		last = at
		at += 4 + size
	}
	if at != end {
		return -1
	}
	return last
}

@(private)
resumption_put_u16 :: proc(dst: []u8, at: ^int, value: u16) {
	dst[at^] = u8(value >> 8)
	dst[at^ + 1] = u8(value)
	at^ += 2
}

@(private)
resumption_strip_extension :: proc(dst, src: []u8, kind: u16) -> (int, bool) {
	layout, valid := client_hello_layout_decode(src)
	if !valid || len(dst) < len(src) {
		return 0, false
	}
	at := resumption_extension_offset(src, kind)
	if at < 0 {
		return 0, false
	}
	size := int(hello_u16(src, at + 2))
	drop := 4 + size
	if at + drop > len(src) || drop > layout.extensions_size || drop > len(src) {
		return 0, false
	}
	n := len(src) - drop
	copy(dst[:at], src[:at])
	copy(dst[at:n], src[at + drop:])
	body := n - 4
	dst[1] = u8(body >> 16)
	dst[2] = u8(body >> 8)
	dst[3] = u8(body)
	retry_put_u16(dst, layout.extensions_length_offset, u16(layout.extensions_size - drop))
	if _, ok := client_hello_layout_decode(dst[:n]); !ok {
		return 0, false
	}
	return n, true
}

@(private)
session_resume_candidate :: proc(conn: ^Conn, now: time.Time) -> ^Session {
	// Scope selection before any PSK is put onto the wire.

	if conn == nil {
		return nil
	}
	conn.session_roots_identity = resumption_roots_identity(conn)
	conn.session_identity, conn.session_identity_present, conn.session_identity_valid = resumption_client_identity(
		conn,
	)
	if session_offerable(conn.config.session, conn.config.server_name, now) &&
	   resumption_scope_matches(conn, conn.config.session) {
		return conn.config.session
	}
	if conn.config.session_cache == nil {
		return nil
	}
	candidate := session_cache_lookup(conn.config.session_cache, conn.config.server_name, now)
	if !resumption_scope_matches(conn, candidate) {
		return nil
	}
	return candidate
}

@(private)
resumption_remember_ticket :: proc(conn: ^Conn, message: []u8) {
	if conn == nil || !conn.config.remember_tickets || !conn.application.have_resumption {
		return
	}

	// A session holds a SHA-256 PSK. A SHA-384 connection remembers no ticket.
	resumption_secret: [32]u8
	defer crypto.zero_explicit(&resumption_secret, size_of(resumption_secret))
	if conn.application.resumption_secret_size != len(resumption_secret) {
		return
	}
	copy(resumption_secret[:], conn.application.resumption_secret[:])

	now := time.now()
	if conn.config.session != nil {
		_ = session_remember(conn.config.session, resumption_secret, message, conn.config.server_name, now)
		resumption_scope_bind(conn, conn.config.session)
		if conn.config.session.usable && conn.config.session_cache != nil {
			_ = session_cache_put(conn.config.session_cache, conn.config.session)
		}
		return
	}
	if conn.config.session_cache == nil {
		return
	}
	temp: Session
	defer session_clear(&temp)
	if session_remember(&temp, resumption_secret, message, conn.config.server_name, now) {
		resumption_scope_bind(conn, &temp)
		_ = session_cache_put(conn.config.session_cache, &temp)
	}
}

@(private)
early_data_usable :: proc(conn: ^Conn, method: string) -> bool {
	return conn != nil &&
		conn.phase != .Failed &&
		conn.phase != .Closed &&
		len(method) > 0 &&
		conn.config.early_data != nil &&
		conn.config.early_data.allow != nil
}

// One application effect for this handshake. Acceptance of a replay-safe method
// applies it. Rejection or a method the policy refuses does not. A later call
// does not apply it again.
@(private)
connection_early_data_apply :: proc(
	conn: ^Conn,
	method: string,
	effect: proc(rawptr),
	user: rawptr,
) -> Early_Data_Result {
	if effect == nil || !early_data_usable(conn, method) {
		return .Refused
	}
	if conn.early_effect_done {
		return .None
	}
	if !conn.early_offered && !conn.early_accepted && !conn.early_rejected {
		return .Refused
	}
	if conn.early_accepted && conn.config.early_data.allow(method) {
		effect(user)
		conn.early_effect_done = true
		return .Applied
	}
	if conn.early_rejected || conn.early_accepted {
		return .Deferred
	}
	return .Refused
}

// Fallback after rejected early data, or after a method the policy refused.
// Does nothing when the effect was already applied, including an accepted
// replay-safe 0-RTT attempt.
@(private)
connection_early_data_fallback :: proc(
	conn: ^Conn,
	method: string,
	effect: proc(rawptr),
	user: rawptr,
) -> Early_Data_Result {
	if effect == nil || !early_data_usable(conn, method) {
		return .Refused
	}
	if conn.early_effect_done {
		return .None
	}
	replay_safe := conn.config.early_data.allow(method)
	if conn.early_accepted && replay_safe {
		return .None
	}
	if !conn.early_rejected && !(conn.early_accepted && !replay_safe) {
		return .Refused
	}
	effect(user)
	conn.early_effect_done = true
	return .Applied
}

@(private)
resumption_client_identity :: proc(conn: ^Conn) -> (fingerprint: [32]u8, present, valid: bool) {
	if conn.config.client_credentials == nil {
		return {}, false, true
	}
	owner := conn.config.client_credentials
	lease: credential_store.Lease
	if conn.config.client_credential_lease != nil {
		lease = conn.config.client_credential_lease^
	} else {
		l, e := credential_store.acquire(owner)
		if e.kind != .None {
			return {}, true, false
		}
		lease = l
		defer _ = credential_store.release(owner, &lease)
		f, fe := credential_store.fingerprint(owner, lease)
		return f, true, fe.kind == .None
	}
	f, fe := credential_store.fingerprint(owner, lease)
	return f, true, fe.kind == .None
}

@(private)
resumption_scope_matches :: proc(conn: ^Conn, session: ^Session) -> bool {
	if session == nil {
		return false
	}
	identity, present, valid := resumption_client_identity(conn)
	if session.roots_identity != resumption_roots_identity(conn) {
		return false
	}
	if !valid || session.has_client_identity != present || present && session.client_identity != identity {
		return false
	}
	if session.alpn_len == 0 {
		return len(conn.config.alpn_protocols) == 0
	}
	for protocol in conn.config.alpn_protocols {
		if protocol == string(session.alpn[:session.alpn_len]) {
			return true
		}
	}
	return false
}

@(private)
resumption_scope_bind :: proc(conn: ^Conn, session: ^Session) {
	if !session.usable {
		return
	}
	identity, present, valid := conn.session_identity, conn.session_identity_present, conn.session_identity_valid
	if !valid && conn.config.client_credentials == nil {
		valid = true
		present = false
		identity = {}
	}
	if !valid {
		session_clear(session)
		return
	}
	session.roots_identity = conn.session_roots_identity
	session.client_identity = identity
	session.has_client_identity = present
	session.alpn_len = copy(session.alpn[:], conn.alpn_selected[:conn.alpn_selected_size])
}

@(private)
resumption_roots_identity :: proc(conn: ^Conn) -> (out: [32]u8) {
	if len(conn.config.root_cas) == 0 {
		return
	}
	hash: sha2.Context_256
	sha2.init_256(&hash)
	for root in conn.config.root_cas {
		if root != nil {
			sha2.update(&hash, root.raw)
		}
	}
	sha2.final(&hash, out[:])
	return
}
