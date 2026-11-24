package quic

import "core:crypto"
import "core:crypto/hmac"
import "core:encoding/endian"
import "core:net"
import "core:sync"

// Retry tokens carry public connection metadata; the MAC authenticates it and
// the exact remote endpoint. Keys are supplied by the application, never fixed.
// A store must stay at a stable address. Do not copy it after initialization.
RETRY_TOKEN_CAP :: 91
RETRY_TOKEN_KEY_BYTES :: 32
RETRY_TOKEN_MAX_AGE :: i64(3600)

Retry_Token_Error :: enum {
	None,
	Invalid,
	Destination_Undersized,
	Authentication,
	Expired,
	Clock,
}

Retry_Claims :: struct {
	original_destination_id:     [20]u8,
	original_destination_id_len: int,
	retry_source_id:             [20]u8,
	retry_source_id_len:         int,
	issued_at:                   i64,
}

@(private)
Retry_Key :: struct {
	present: bool,
	id:      u64,
	secret:  [RETRY_TOKEN_KEY_BYTES]u8,
	expires: i64,
}

Retry_Tokens :: struct {
	_mutex:              sync.Mutex,
	_initialized:        bool,
	_current, _previous: Retry_Key,
	_max_age, _last_now: i64,
}

// now and max_age are Unix seconds. Callers must provide nondecreasing time.
// One previous key is retained for max_age after rotation. Rotating again evicts
// the older key; callers needing uninterrupted validity must space rotations.
retry_tokens_init :: proc(store: ^Retry_Tokens, secret: []u8, key_id: u64, max_age, now: i64) -> Retry_Token_Error {
	if store == nil ||
	   len(secret) != RETRY_TOKEN_KEY_BYTES ||
	   max_age <= 0 ||
	   max_age > RETRY_TOKEN_MAX_AGE ||
	   now < 0 ||
	   now > max(i64) - max_age {
		return .Invalid
	}
	sync.mutex_lock(&store._mutex)
	defer sync.mutex_unlock(&store._mutex)
	if store._initialized {
		return .Invalid
	}
	store._current = {
		present = true,
		id      = key_id,
	}
	copy(store._current.secret[:], secret)
	store._previous = {}
	store._max_age = max_age
	store._last_now = now
	store._initialized = true
	return .None
}

retry_tokens_rotate :: proc(store: ^Retry_Tokens, secret: []u8, key_id: u64, now: i64) -> Retry_Token_Error {
	if store == nil || len(secret) != RETRY_TOKEN_KEY_BYTES {
		return .Invalid
	}
	sync.mutex_lock(&store._mutex)
	defer sync.mutex_unlock(&store._mutex)
	if !store._initialized ||
	   now < 0 ||
	   now > max(i64) - store._max_age ||
	   key_id == store._current.id ||
	   store._previous.present && key_id == store._previous.id {
		return .Invalid
	}
	if now < store._last_now {
		return .Clock
	}
	replacement: [RETRY_TOKEN_KEY_BYTES]u8
	copy(replacement[:], secret)
	defer crypto.zero_explicit(&replacement, size_of(replacement))
	crypto.zero_explicit(&store._previous, size_of(store._previous))
	store._previous = store._current
	store._previous.expires = now + store._max_age
	store._current = {
		present = true,
		id      = key_id,
	}
	copy(store._current.secret[:], replacement[:])
	store._last_now = now
	return .None
}

retry_tokens_destroy :: proc(store: ^Retry_Tokens) {
	if store == nil {
		return
	}
	sync.mutex_lock(&store._mutex)
	defer sync.mutex_unlock(&store._mutex)
	crypto.zero_explicit(&store._current, size_of(store._current))
	crypto.zero_explicit(&store._previous, size_of(store._previous))
	store._initialized = false
	store._max_age = 0
	store._last_now = 0
}

@(private)
retry_endpoint :: proc(dst: []u8, peer: net.Endpoint) -> (int, bool) {
	if len(dst) < 19 || peer.port < 0 || peer.port > 65535 {
		return 0, false
	}
	dst[1] = u8(peer.port >> 8)
	dst[2] = u8(peer.port)
	switch a in peer.address {
	case net.IP4_Address:
		dst[0] = 4
		for b, i in a {dst[3 + i] = b}; return 7, true
	case net.IP6_Address:
		dst[0] = 6
		for word, i in a {dst[3 + i * 2] = u8(word >> 8); dst[4 + i * 2] = u8(word)}
		return 19, true
	}
	return 0, false
}

@(private)
retry_token_mac :: proc(tag: []u8, payload, endpoint, key: []u8) {
	ctx: hmac.Context
	hmac.init(&ctx, .SHA256, key)
	hmac.update(&ctx, transmute([]u8)string("odin/quic/v1/retry-token/v1"))
	hmac.update(&ctx, endpoint)
	hmac.update(&ctx, payload)
	hmac.final(&ctx, tag)
}

retry_token_issue :: proc(
	store: ^Retry_Tokens,
	dst: []u8,
	peer: net.Endpoint,
	original_destination_id, retry_source_id: []u8,
	now: i64,
) -> (
	int,
	Retry_Token_Error,
) {
	endpoint: [19]u8
	en, valid := retry_endpoint(endpoint[:], peer)
	if store == nil ||
	   !valid ||
	   len(original_destination_id) < 8 ||
	   len(original_destination_id) > 20 ||
	   len(retry_source_id) == 0 ||
	   len(retry_source_id) > 20 ||
	   string(original_destination_id) == string(retry_source_id) {
		return 0, .Invalid
	}
	n := 19 + len(original_destination_id) + len(retry_source_id) + 32
	if len(dst) < n {
		return 0, .Destination_Undersized
	}
	key: Retry_Key
	defer crypto.zero_explicit(&key, size_of(key))
	{
		sync.mutex_lock(&store._mutex)
		defer sync.mutex_unlock(&store._mutex)
		if !store._initialized {
			return 0, .Invalid
		}
		if now < store._last_now || now < 0 {
			return 0, .Clock
		}
		store._last_now = now
		key = store._current
	}
	token: [RETRY_TOKEN_CAP]u8
	token[0] = 1
	endian.put_u64(token[1:9], .Big, key.id)
	endian.put_u64(token[9:17], .Big, u64(now))
	token[17] = u8(len(original_destination_id))
	copy(token[18:], original_destination_id)
	at := 18 + len(original_destination_id)
	token[at] = u8(len(retry_source_id))
	at += 1
	at += copy(token[at:], retry_source_id)
	retry_token_mac(token[at:at + 32], token[:at], endpoint[:en], key.secret[:])
	copy(dst[:n], token[:n])
	return n, .None
}

retry_token_open :: proc(
	store: ^Retry_Tokens,
	token: []u8,
	peer: net.Endpoint,
	retry_source_id: []u8,
	now: i64,
) -> (
	Retry_Claims,
	Retry_Token_Error,
) {
	endpoint: [19]u8
	en, valid := retry_endpoint(endpoint[:], peer)
	if store == nil || !valid || len(token) < 60 || len(token) > RETRY_TOKEN_CAP || token[0] != 1 {
		return {}, .Invalid
	}
	original_n := int(token[17])
	at := 18 + original_n
	if original_n < 8 || original_n > 20 || at >= len(token) - 32 {
		return {}, .Invalid
	}
	retry_n := int(token[at])
	at += 1
	if retry_n == 0 || retry_n > 20 || at + retry_n + 32 != len(token) || len(retry_source_id) != retry_n {
		return {}, .Invalid
	}
	key_id, _ := endian.get_u64(token[1:9], .Big)
	issued, _ := endian.get_u64(token[9:17], .Big)
	key: Retry_Key
	defer crypto.zero_explicit(&key, size_of(key))
	age: i64
	{
		sync.mutex_lock(&store._mutex)
		defer sync.mutex_unlock(&store._mutex)
		if !store._initialized {
			return {}, .Invalid
		}
		if now < store._last_now || now < 0 {
			return {}, .Clock
		}
		store._last_now = now
		age = store._max_age
		if key_id == store._current.id {
			key = store._current
		} else if store._previous.present && key_id == store._previous.id && now < store._previous.expires {
			key = store._previous
		} else {
			return {}, .Authentication
		}
	}
	tag: [32]u8
	defer crypto.zero_explicit(&tag, size_of(tag))
	payload_n := len(token) - 32
	retry_token_mac(tag[:], token[:payload_n], endpoint[:en], key.secret[:])
	if crypto.compare_constant_time(tag[:], token[payload_n:]) != 1 ||
	   crypto.compare_constant_time(token[at:at + retry_n], retry_source_id) != 1 {
		return {}, .Authentication
	}
	if issued > u64(now) {
		return {}, .Clock
	}
	if u64(now) - issued >= u64(age) {
		return {}, .Expired
	}
	claims := Retry_Claims {
		issued_at                   = i64(issued),
		original_destination_id_len = original_n,
		retry_source_id_len         = retry_n,
	}
	copy(claims.original_destination_id[:], token[18:18 + original_n])
	copy(claims.retry_source_id[:], token[at:at + retry_n])
	return claims, .None
}

retry_tokens_max_age :: proc(store: ^Retry_Tokens) -> i64 {
	if store == nil {
		return 0
	}
	sync.mutex_lock(&store._mutex)
	defer sync.mutex_unlock(&store._mutex)
	if !store._initialized {
		return 0
	}
	return store._max_age
}
