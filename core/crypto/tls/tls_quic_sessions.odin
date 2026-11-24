package tls
import "core:crypto/sha2"
import "core:crypto/x509"
import "core:time"
import credential_store "credentials/store"

Quic_Session_Scope :: struct {
	server_name:        string,
	roots:              []^x509.Certificate,
	identity:           ^credential_store.Store,
	identity_lease:     ^credential_store.Lease,
	profile:            []u8,
	local_profile:      []u8,
	port:               u16,
	roots_identity:     [32]u8,
	has_roots_identity: bool,
}

@(private)
quic_scope_identity :: proc(scope: Quic_Session_Scope) -> (identity: [32]u8, present, valid: bool) {
	if scope.identity == nil {
		return {}, false, scope.identity_lease == nil
	}
	lease: credential_store.Lease
	if scope.identity_lease != nil {
		lease = scope.identity_lease^
	} else {
		l, e := credential_store.acquire(scope.identity)
		if e.kind != .None {
			return {}, true, false
		}
		lease = l
		defer _ = credential_store.release(scope.identity, &lease)
		f, fe := credential_store.fingerprint(scope.identity, lease)
		return f, true, fe.kind == .None
	}
	f, fe := credential_store.fingerprint(scope.identity, lease)
	return f, true, fe.kind == .None
}

@(private)
quic_scope_roots :: proc(scope: Quic_Session_Scope) -> [32]u8 {
	if scope.has_roots_identity {
		return scope.roots_identity
	}
	return quic_roots_identity(scope.roots)
}

// Snapshot by DER value while trust objects are alive. Pools and late ticket
// capture retain this digest, never a borrowed certificate pool.
quic_roots_identity :: proc(roots: []^x509.Certificate) -> (out: [32]u8) {
	if len(roots) == 0 {
		return
	}
	hash: sha2.Context_256
	sha2.init_256(&hash)
	for root in roots {
		if root != nil {
			sha2.update(&hash, root.raw)
		}
	}
	sha2.final(&hash, out[:])
	return
}

quic_session_scope_matches :: proc(session: ^Session, scope: Quic_Session_Scope, now: time.Time) -> bool {
	if !session_offerable(session, scope.server_name, now) ||
	   !session.is_quic ||
	   session.quic_port != scope.port ||
	   session.alpn_len != 2 ||
	   string(session.alpn[:2]) != "h3" ||
	   session.quic_profile_len < 0 ||
	   session.quic_profile_len > len(session.quic_profile) {
		return false
	}
	identity, present, valid := quic_scope_identity(scope)
	return valid &&
		session.has_client_identity == present &&
		(!present || identity == session.client_identity) &&
		session.roots_identity == quic_scope_roots(scope)
}

// Append after QUIC transport parameters; pre_shared_key remains the last
// extension. A nil session advertises psk_dhe_ke for later ticket issuance.
@(private)
engine_quic_client_hello_offer :: proc(
	dst: []u8,
	hello_len: int,
	session: ^Session,
	scope: Quic_Session_Scope,
	now: time.Time,
	early: bool = false,
) -> (
	int,
	Quic_Secret_Error,
) {
	if hello_len < 0 || hello_len > len(dst) {
		return hello_len, {kind = .Invalid_Input}
	}
	if session != nil {
		if !quic_session_scope_matches(session, scope, now) ||
		   early && (!session.saw_early_data || session.early_data_max != max(u32) || session.quic_profile_len == 0) {
			return hello_len, {kind = .Invalid_Input}
		}
		n, ok := resumption_client_hello_offer(dst, hello_len, session, now, early)
		if !ok {
			return hello_len, {kind = .Malformed}
		}
		return n, {}
	}
	layout, valid := client_hello_layout_decode(dst[:hello_len])
	if !valid || hello_len + 6 > len(dst) {
		return hello_len, {kind = .Malformed}
	}
	at := hello_len
	resumption_put_u16(dst, &at, 45)
	resumption_put_u16(dst, &at, 2)
	dst[at], dst[at + 1] = 1, PSK_DHE_KE
	at += 2
	retry_put_u24(dst, 1, at - 4)
	retry_put_u16(dst, layout.extensions_length_offset, u16(layout.extensions_size + 6))
	return at, {}
}

// Caller binds the authenticated peer's remembered transport+HTTP3 settings in
// profile. No 0RTT use is possible without this bounded authenticated context.
@(private)
engine_quic_session_remember :: proc(
	session: ^Session,
	master: [32]u8,
	message: []u8,
	scope: Quic_Session_Scope,
	now: time.Time,
) -> Quic_Secret_Error {
	if len(scope.profile) > SERVER_EARLY_CONTEXT_MAX {
		return {kind = .Parameters_Oversized}
	}
	next: Session
	if !session_remember(&next, master, message, scope.server_name, now) {
		return {kind = .Malformed}
	}
	if next.saw_early_data && next.early_data_max != max(u32) {
		session_clear(&next)
		return {kind = .Malformed}
	}
	identity, present, valid := quic_scope_identity(scope)
	if !valid {
		session_clear(&next)
		return {kind = .Invalid_Input}
	}
	next.is_quic = true
	next.quic_port = scope.port
	next.quic_local_profile = ticket_hash(scope.local_profile)
	next.alpn_len = 2
	copy(next.alpn[:], "h3")
	next.client_identity = identity
	next.has_client_identity = present
	next.roots_identity = quic_scope_roots(scope)
	next.quic_profile_len = copy(next.quic_profile[:], scope.profile)
	session_clear(session)
	session^ = next
	session_clear(&next)
	return {}
}

quic_session_early_scope_matches :: proc(session: ^Session, scope: Quic_Session_Scope, now: time.Time) -> bool {
	return quic_session_scope_matches(session, scope, now) &&
		session.quic_local_profile == ticket_hash(scope.local_profile) &&
		session.saw_early_data &&
		session.early_data_max == max(u32) &&
		session.quic_profile_len > 0
}
