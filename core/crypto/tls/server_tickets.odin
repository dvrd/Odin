package tls

import "core:crypto"
import "core:crypto/aes"
import "core:crypto/sha2"
import "core:sync"
import "core:time"

@(private)
SERVER_TICKET_MAX_LIFETIME :: 7 * 24 * time.Hour

Server_Ticket_Error :: enum {
	None,
	Invalid,
	Closed,
	Entropy,
	Clock,
}

@(private)
Server_Ticket_Key :: struct {
	valid:   bool,
	id:      u64,
	secret:  [32]u8,
	expires: i64,
}

// Stable caller-owned keyring; keep alive through every configured connection.
// Concurrent issue/open/rotation are serialized; no per-ticket cache is retained.
Server_Ticket_Keys :: struct {
	_mutex:                sync.Mutex,
	_initialized, _closed: bool,
	_current, _previous:   Server_Ticket_Key,
	_max_age, _last_now:   i64,
}

Server_Ticket_Config :: struct {
	keys:         ^Server_Ticket_Keys,
	lifetime:     time.Duration,
	policy_epoch: u64,
	early_data:   ^Server_Early_Data_Config,
}

server_ticket_keys_init :: proc(
	keys: ^Server_Ticket_Keys,
	max_lifetime: time.Duration = 24 * time.Hour,
) -> Server_Ticket_Error {
	if keys == nil || max_lifetime < time.Second || max_lifetime > SERVER_TICKET_MAX_LIFETIME {
		return .Invalid
	}
	if !crypto.HAS_RAND_BYTES {
		return .Entropy
	}
	sync.mutex_lock(&keys._mutex)
	defer sync.mutex_unlock(&keys._mutex)
	if keys._initialized {
		return .Invalid
	}
	keys._initialized = true
	keys._max_age = i64(max_lifetime / time.Second)
	keys._current.valid = true
	keys._current.id = 1
	crypto.rand_bytes(keys._current.secret[:])
	keys._last_now = time.to_unix_seconds(time.now())
	return .None
}

// Retain at most one previous key for max_lifetime. A second rotation revokes
// older tickets immediately. Secret keys are always freshly generated.
server_ticket_keys_rotate :: proc(keys: ^Server_Ticket_Keys, now: time.Time) -> Server_Ticket_Error {
	if keys == nil {
		return .Invalid
	}
	if !crypto.HAS_RAND_BYTES {
		return .Entropy
	}
	sync.mutex_lock(&keys._mutex)
	defer sync.mutex_unlock(&keys._mutex)
	if !keys._initialized || keys._closed {
		return .Closed
	}
	sec := time.to_unix_seconds(now)
	if sec < keys._last_now || sec > max(i64) - keys._max_age || keys._current.id == max(u64) {
		return .Clock
	}
	crypto.zero_explicit(&keys._previous, size_of(keys._previous))
	keys._previous = keys._current
	keys._previous.expires = sec + keys._max_age
	keys._current = {
		valid = true,
		id    = keys._previous.id + 1,
	}
	crypto.rand_bytes(keys._current.secret[:])
	keys._last_now = sec
	return .None
}

server_ticket_keys_close :: proc(keys: ^Server_Ticket_Keys) {
	if keys == nil {
		return
	}
	sync.mutex_lock(&keys._mutex)
	defer sync.mutex_unlock(&keys._mutex)
	crypto.zero_explicit(&keys._current, size_of(keys._current))
	crypto.zero_explicit(&keys._previous, size_of(keys._previous))
	keys._closed = true
}

server_ticket_config_valid :: proc(config: ^Server_Ticket_Config) -> bool {
	if config == nil {
		return true
	}
	if !server_early_data_config_valid(config.early_data) ||
	   config.keys == nil ||
	   config.lifetime < time.Second ||
	   config.lifetime > SERVER_TICKET_MAX_LIFETIME {
		return false
	}
	keys := config.keys
	sync.mutex_lock(&keys._mutex)
	defer sync.mutex_unlock(&keys._mutex)
	return keys._initialized && !keys._closed && i64(config.lifetime / time.Second) <= keys._max_age
}

@(private)
TICKET_PLAIN_SIZE :: 8 * 5 + 32 * 6 + 1 + 4 + 2 + SERVER_EARLY_CONTEXT_MAX + 1

@(private)
TICKET_WIRE_SIZE :: 8 + 12 + TICKET_PLAIN_SIZE + 16

@(private)
Server_Ticket_Claims :: struct {
	issued, expires, peer_expires:            i64,
	generation, policy_epoch:                 u64,
	psk, sni, alpn, credential, policy, peer: [32]u8,
	authenticated:                            bool,
	age_add:                                  u32,
	early_context:                            [SERVER_EARLY_CONTEXT_MAX]u8,
	early_context_len:                        int,
	early_capable:                            bool,
}

@(private)
ticket_put64 :: proc(out: []u8, n: u64) {for i in 0 ..< 8 {out[i] = u8(n >> u64(56 - 8 * i))}}

@(private)
ticket_get64 :: proc(input: []u8) -> (n: u64) {for b in input[:8] {n = (n << 8) | u64(b)}; return}

@(private)
ticket_hash :: proc(input: []u8) -> (out: [32]u8) {
	h: sha2.Context_256
	sha2.init_256(&h)
	sha2.update(&h, input)
	sha2.final(&h, out[:])
	return
}

@(private)
server_ticket_crypt :: proc(
	config: ^Server_Ticket_Config,
	claims: ^Server_Ticket_Claims,
	wire: []u8,
	seal: bool,
	now: time.Time,
) -> bool {
	if config == nil || len(wire) != TICKET_WIRE_SIZE {
		return false
	}
	key: Server_Ticket_Key
	defer crypto.zero_explicit(&key, size_of(key))
	keys := config.keys
	sec := time.to_unix_seconds(now)
	sync.mutex_lock(&keys._mutex)
	if !keys._initialized || keys._closed || sec < keys._last_now {
		sync.mutex_unlock(&keys._mutex)
		return false
	}
	keys._last_now = sec
	if seal {
		key = keys._current
	} else {
		id := ticket_get64(wire)
		if keys._current.valid && keys._current.id == id {
			key = keys._current
		}
		if keys._previous.valid && keys._previous.id == id && sec < keys._previous.expires {
			key = keys._previous
		}
	}
	sync.mutex_unlock(&keys._mutex)
	if !key.valid {
		return false
	}
	plain: [TICKET_PLAIN_SIZE]u8
	defer crypto.zero_explicit(&plain, size_of(plain))
	cipher: aes.Context_GCM
	defer crypto.zero_explicit(&cipher, size_of(cipher))
	aes.init_gcm(&cipher, key.secret[:])
	if seal {
		if !crypto.HAS_RAND_BYTES {
			return false
		}
		ticket_put64(wire, key.id)
		crypto.rand_bytes(wire[8:20])
		ticket_put64(plain[:], u64(claims.issued))
		ticket_put64(plain[8:], u64(claims.expires))
		ticket_put64(plain[16:], u64(claims.peer_expires))
		ticket_put64(plain[24:], claims.generation)
		ticket_put64(plain[32:], claims.policy_epoch)
		at := 40
		for bytes in ([]^[32]u8{&claims.psk, &claims.sni, &claims.alpn, &claims.credential, &claims.policy, &claims.peer}) {
			copy(plain[at:], bytes[:])
			at += 32
		}
		plain[at] = 1 if claims.authenticated else 0
		at += 1
		plain[at], plain[at + 1], plain[at + 2], plain[at + 3] =
			u8(claims.age_add >> 24), u8(claims.age_add >> 16), u8(claims.age_add >> 8), u8(claims.age_add)
			at += 4
		plain[at], plain[at + 1] = u8(claims.early_context_len >> 8), u8(claims.early_context_len & 255)
		at += 2
		copy(plain[at:], claims.early_context[:])
		at += SERVER_EARLY_CONTEXT_MAX
		plain[at] = 1 if claims.early_capable else 0
		aes.seal_gcm(
			&cipher,
			wire[20:20 + TICKET_PLAIN_SIZE],
			wire[20 + TICKET_PLAIN_SIZE:],
			wire[8:20],
			wire[:20],
			plain[:],
		); return true
	}
	if !aes.open_gcm(
		&cipher,
		plain[:],
		wire[8:20],
		wire[:20],
		wire[20:20 + TICKET_PLAIN_SIZE],
		wire[20 + TICKET_PLAIN_SIZE:],
	) {
		return false
	}
	claims.issued = i64(ticket_get64(plain[:]))
	claims.expires = i64(ticket_get64(plain[8:]))
	claims.peer_expires = i64(ticket_get64(plain[16:]))
	claims.generation = ticket_get64(plain[24:])
	claims.policy_epoch = ticket_get64(plain[32:])
	at := 40
	for dst in ([]^[32]u8{&claims.psk, &claims.sni, &claims.alpn, &claims.credential, &claims.policy, &claims.peer}) {
		copy(dst[:], plain[at:at + 32])
		at += 32
	}
	claims.authenticated = plain[at] == 1
	at += 1
	claims.age_add = u32(plain[at]) << 24 | u32(plain[at + 1]) << 16 | u32(plain[at + 2]) << 8 | u32(plain[at + 3])
	at += 4
	claims.early_context_len = int(plain[at]) << 8 | int(plain[at + 1])
	at += 2
	if claims.early_context_len > SERVER_EARLY_CONTEXT_MAX {
		return false
	}
	copy(claims.early_context[:], plain[at:at + SERVER_EARLY_CONTEXT_MAX])
	at += SERVER_EARLY_CONTEXT_MAX
	claims.early_capable = plain[at] == 1
	return claims.issued <= sec &&
		sec < claims.expires &&
		claims.expires - claims.issued <= keys._max_age &&
		(!claims.authenticated || sec < claims.peer_expires)
}
