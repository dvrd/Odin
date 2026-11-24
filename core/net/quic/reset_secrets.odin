package quic
import "core:crypto"
import "core:crypto/hmac"
import "core:net"
import "core:sync"

RESET_CID_LEN :: 16
RESET_LEASES :: 256
RESET_PEERS :: 32

Reset_Error :: enum {
	None,
	Invalid,
	Clock,
	Busy,
	Capacity,
	Unknown_Key,
	Limited,
	Discarded,
}

Reset_Config :: struct {
	retention_ms:                i64,
	burst, per_second:           u32,
	peer_burst, peer_per_second: u32,
}

Reset_CID_Lease :: struct {
	id, generation: u64,
	held:           bool,
	token:          [16]u8,
	owner:          rawptr,
}

@(private)
Reset_Key :: struct {
	present:      bool,
	id:           u16,
	generation:   u64,
	secret:       [32]u8,
	refs:         int,
	retain_until: i64,
}

@(private)
Reset_Lease_Record :: struct {
	used:           bool,
	id, generation: u64,
}

@(private)
Reset_Rate :: struct {
	used:   bool,
	peer:   net.Endpoint,
	tokens: u64,
	at:     i64,
}

Reset_Secrets :: struct {
	_mutex:                        sync.Mutex,
	_initialized:                  bool,
	_config:                       Reset_Config,
	_current, _previous:           Reset_Key,
	_next_generation, _next_lease: u64,
	_leases:                       [RESET_LEASES]Reset_Lease_Record,
	_peers:                        [RESET_PEERS]Reset_Rate,
	_global:                       Reset_Rate,
	_last_now:                     i64,
}

reset_secrets_init :: proc(
	s: ^Reset_Secrets,
	secret: []u8,
	key_id: u16,
	config: Reset_Config,
	now_unix_ms: i64,
) -> Reset_Error {
	cfg := config
	if cfg.retention_ms == 0 {
		cfg.retention_ms = 3_600_000
	}
	if cfg.burst == 0 {
		cfg.burst = 64
	}
	if cfg.per_second == 0 {
		cfg.per_second = 32
	}
	if cfg.peer_burst == 0 {
		cfg.peer_burst = 4
	}
	if cfg.peer_per_second == 0 {
		cfg.peer_per_second = 2
	}
	if s == nil ||
	   len(secret) != 32 ||
	   cfg.retention_ms <= 0 ||
	   cfg.retention_ms > 86_400_000 ||
	   cfg.burst == 0 ||
	   cfg.per_second == 0 ||
	   cfg.peer_burst == 0 ||
	   cfg.peer_per_second == 0 ||
	   now_unix_ms < 0 ||
	   now_unix_ms > max(i64) - cfg.retention_ms {
		return .Invalid
	}
	sync.mutex_lock(&s._mutex)
	defer sync.mutex_unlock(&s._mutex)
	if s._initialized {
		return .Invalid
	}
	s._config = cfg
	s._current = Reset_Key {
		present    = true,
		id         = key_id,
		generation = 1,
	}
	copy(s._current.secret[:], secret)
	s._previous = {}
	s._next_generation = 2
	s._next_lease = 1
	s._leases = {}
	s._peers = {}
	s._global = Reset_Rate {
		used   = true,
		tokens = u64(cfg.burst) * 1000,
		at     = now_unix_ms,
	}
	s._last_now = now_unix_ms
	s._initialized = true
	return .None
}

@(private)
reset_clock :: proc(s: ^Reset_Secrets, now: i64) -> Reset_Error {
	if !s._initialized {
		return .Invalid
	}
	if now < s._last_now || now > max(i64) - s._config.retention_ms {
		return .Clock
	}
	s._last_now = now
	return .None
}

reset_secrets_rotate :: proc(s: ^Reset_Secrets, secret: []u8, key_id: u16, now_unix_ms: i64) -> Reset_Error {
	if s == nil || len(secret) != 32 {
		return .Invalid
	}
	sync.mutex_lock(&s._mutex)
	defer sync.mutex_unlock(&s._mutex)
	if e := reset_clock(s, now_unix_ms); e != .None {
		return e
	}
	if s._next_generation == 0 {
		return .Capacity
	}
	if key_id == s._current.id || s._previous.present && key_id == s._previous.id {
		return .Invalid
	}
	if s._previous.present && (s._previous.refs > 0 || now_unix_ms < s._previous.retain_until) {
		return .Busy
	}
	replacement: [32]u8
	copy(replacement[:], secret)
	defer crypto.zero_explicit(&replacement, size_of(replacement))
	crypto.zero_explicit(&s._previous, size_of(s._previous))
	s._previous = s._current
	s._previous.retain_until = max(s._previous.retain_until, now_unix_ms + s._config.retention_ms)
	s._current = Reset_Key {
		present    = true,
		id         = key_id,
		generation = s._next_generation,
	}
	s._next_generation += 1
	copy(s._current.secret[:], replacement[:])
	return .None
}

reset_secrets_destroy :: proc(s: ^Reset_Secrets) -> Reset_Error {
	if s == nil {
		return .Invalid
	}
	sync.mutex_lock(&s._mutex)
	defer sync.mutex_unlock(&s._mutex)
	if s._current.refs > 0 || s._previous.refs > 0 {
		return .Busy
	}
	crypto.zero_explicit(&s._current, size_of(s._current))
	crypto.zero_explicit(&s._previous, size_of(s._previous))
	crypto.zero_explicit(&s._leases, size_of(s._leases))
	s._initialized = false
	return .None
}

reset_secrets_retention_ms :: proc(s: ^Reset_Secrets) -> i64 {
	if s == nil {
		return 0
	}
	sync.mutex_lock(&s._mutex)
	defer sync.mutex_unlock(&s._mutex)
	if !s._initialized {
		return 0
	}
	return s._config.retention_ms
}

@(private)
reset_key :: proc(s: ^Reset_Secrets, cid: []u8, now: i64) -> ^Reset_Key {
	if len(cid) != RESET_CID_LEN {
		return nil
	}
	id := u16(cid[0]) << 8 | u16(cid[1])
	if s._current.present && s._current.id == id {
		return &s._current
	}
	if s._previous.present && s._previous.id == id && (s._previous.refs > 0 || now <= s._previous.retain_until) {
		return &s._previous
	}
	return nil
}

@(private)
reset_token :: proc(key: ^Reset_Key, cid: []u8) -> [16]u8 {
	h: hmac.Context
	hmac.init(&h, .SHA256, key.secret[:])
	defer crypto.zero_explicit(&h, size_of(h))
	hmac.update(&h, transmute([]u8)string("odin.quic.v1.stateless-reset\x00"))
	hmac.update(&h, []u8{u8(len(cid))})
	hmac.update(&h, cid)
	digest: [32]u8
	hmac.final(&h, digest[:])
	defer crypto.zero_explicit(&digest, size_of(digest))
	token: [16]u8
	copy(token[:], digest[:16])
	return token
}

reset_cid_random :: proc(s: ^Reset_Secrets, dst: []u8, now_unix_ms: i64) -> Reset_Error {
	if s == nil || len(dst) != RESET_CID_LEN {
		return .Invalid
	}
	sync.mutex_lock(&s._mutex)
	defer sync.mutex_unlock(&s._mutex)
	if e := reset_clock(s, now_unix_ms); e != .None {
		return e
	}
	crypto.rand_bytes(dst)
	dst[0] = u8(s._current.id >> 8)
	dst[1] = u8(s._current.id)
	s._current.retain_until = max(s._current.retain_until, now_unix_ms + s._config.retention_ms)
	return .None
}

reset_cid_acquire :: proc(s: ^Reset_Secrets, cid: []u8, now_unix_ms: i64) -> (Reset_CID_Lease, Reset_Error) {
	if s == nil {
		return {}, .Invalid
	}
	sync.mutex_lock(&s._mutex)
	defer sync.mutex_unlock(&s._mutex)
	if e := reset_clock(s, now_unix_ms); e != .None {
		return {}, e
	}
	key := reset_key(s, cid, now_unix_ms)
	if key == nil {
		return {}, .Unknown_Key
	}
	for &record in s._leases {
		if !record.used {
			if s._next_lease == 0 {
				return {}, .Capacity
			}
			record = Reset_Lease_Record {
				used       = true,
				id         = s._next_lease,
				generation = key.generation,
			}
			s._next_lease += 1
			key.refs += 1
			return Reset_CID_Lease {
					owner = s,
					id = record.id,
					generation = record.generation,
					held = true,
					token = reset_token(key, cid),
				},
				.None
		}
	}
	return {}, .Capacity
}

reset_cid_issue :: proc(s: ^Reset_Secrets, dst: []u8, now_unix_ms: i64) -> (Reset_CID_Lease, Reset_Error) {
	if e := reset_cid_random(s, dst, now_unix_ms); e != .None {
		return {}, e
	}
	return reset_cid_acquire(s, dst, now_unix_ms)
}

reset_cid_release :: proc(s: ^Reset_Secrets, lease: ^Reset_CID_Lease, now_unix_ms: i64) -> Reset_Error {
	if s == nil || lease == nil || !lease.held || lease.owner != s {
		return .Invalid
	}
	sync.mutex_lock(&s._mutex)
	defer sync.mutex_unlock(&s._mutex)
	if !s._initialized {
		return .Invalid
	}
	now := min(max(now_unix_ms, s._last_now), max(i64) - s._config.retention_ms)
	s._last_now = now
	for &record in s._leases {
		if record.used && record.id == lease.id && record.generation == lease.generation {
			key: ^Reset_Key
			if record.generation == s._current.generation {
				key = &s._current
			} else if record.generation == s._previous.generation {
				key = &s._previous
			}
			if key == nil || key.refs <= 0 {
				return .Invalid
			}
			key.refs -= 1
			key.retain_until = max(key.retain_until, now + s._config.retention_ms)
			record = {}
			crypto.zero_explicit(lease, size_of(lease^))
			return .None
		}
	}
	return .Invalid
}

@(private)
reset_rate_take :: proc(bucket: ^Reset_Rate, rate, burst: u32, now: i64) -> bool {
	elapsed := u64(now - bucket.at)
	ceiling := u64(burst) * 1000
	// Saturate before multiplying elapsed by rate.
	if elapsed >= ceiling / u64(rate) + 1 {
		bucket.tokens = ceiling
	} else {
		bucket.tokens = min(ceiling, bucket.tokens + elapsed * u64(rate))
	}
	bucket.at = now
	if bucket.tokens < 1000 {
		return false
	}
	bucket.tokens -= 1000
	return true
}

reset_packet :: proc(
	s: ^Reset_Secrets,
	dst, trigger: []u8,
	peer: net.Endpoint,
	now_unix_ms: i64,
) -> (
	int,
	Reset_Error,
) {
	if s == nil || peer.address == nil {
		return 0, .Invalid
	}
	if len(trigger) <= 21 || trigger[0] & 0xc0 != 0x40 || len(dst) < 21 {
		return 0, .Discarded
	}
	cid := trigger[1:1 + RESET_CID_LEN]
	sync.mutex_lock(&s._mutex)
	defer sync.mutex_unlock(&s._mutex)
	if e := reset_clock(s, now_unix_ms); e != .None {
		return 0, e
	}
	key := reset_key(s, cid, now_unix_ms)
	if key == nil {
		return 0, .Unknown_Key
	}
	if !reset_rate_take(&s._global, s._config.per_second, s._config.burst, now_unix_ms) {
		return 0, .Limited
	}
	index := -1
	oldest := 0
	for bucket, i in s._peers {
		if bucket.used && bucket.peer.address == peer.address {
			index = i
			break
		}
		if !bucket.used {
			oldest = i
		} else if s._peers[oldest].used && bucket.at < s._peers[oldest].at {
			oldest = i
		}
	}
	if index < 0 {
		index = oldest
		s._peers[index] = Reset_Rate {
			used   = true,
			peer   = peer,
			tokens = u64(s._config.peer_burst) * 1000,
			at     = now_unix_ms,
		}
	}
	if !reset_rate_take(&s._peers[index], s._config.peer_per_second, s._config.peer_burst, now_unix_ms) {
		return 0, .Limited
	}
	random: [1]u8
	crypto.rand_bytes(random[:])
	limit := min(min(43, len(trigger) - 1), len(dst))
	n := 21 + int(random[0]) % (limit - 20)
	token := reset_token(key, cid)
	crypto.rand_bytes(dst[:n - 16])
	dst[0] = (dst[0] & 0x3f) | 0x40
	copy(dst[n - 16:n], token[:])
	return n, .None
}
