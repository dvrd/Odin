package tls

import "core:crypto/sha2"

// SHA-256 transcript for the current AES-128-GCM profile. Feed exact handshake
// bytes (including headers), once and in order. Framing, message order and HRR
// eligibility belong to the caller. Retains only SHA state and its partial block;
// no input borrows, complete transcript buffer or allocations.
@(private="file")
CLIENT_CERTIFICATE_VERIFY_CONTEXT :: "TLS 1.3, client CertificateVerify"

@(private)
Handshake_Transcript :: sha2.Context_256

@(private)
transcript_init :: proc(t: ^Handshake_Transcript) {
	sha2.init_256(t)
}

@(private)
transcript_update :: proc(t: ^Handshake_Transcript, bytes: []u8) {
	sha2.update(t, bytes)
}

// Snapshot without finalizing the live state. Value copies can stage output or
// branch a transcript without sharing mutable storage.
@(private)
transcript_snapshot :: proc(t: ^Handshake_Transcript) -> (digest: [32]u8) {
	sha2.final(t, digest[:], finalize_clone = true)
	return
}

// RFC 8446 section 4.4.1: replace CH1 by message_hash(Hash(CH1)). Call only
// after hashing the complete CH1 and before hashing the single accepted HRR.
@(private)
transcript_retry :: proc(t: ^Handshake_Transcript) {
	message := transcript_message_hash(transcript_snapshot(t))
	transcript_init(t)
	transcript_update(t, message[:])
}

@(private)
transcript_message_hash :: proc(digest: [32]u8) -> (message: [36]u8) {
	message[0], message[3] = 254, 32
	for value, i in digest do message[4 + i] = value
	return
}

@(private)
transcript_empty_hash :: proc() -> [32]u8 {
	t: Handshake_Transcript
	transcript_init(&t)
	return transcript_snapshot(&t)
}

// The role is the signer, independently of which side consumes this input.
// Ed25519 signs these bytes directly; SHA-256 RSA-PSS signs their digest.
@(private)
certificate_verify_input :: proc(hash: [32]u8, server: bool) -> (signed: [64 + len(SERVER_CERTIFICATE_VERIFY_CONTEXT) + 1 + 32]u8) {
	for i in 0 ..< 64 do signed[i] = 0x20
	label := CLIENT_CERTIFICATE_VERIFY_CONTEXT
	if server do label = SERVER_CERTIFICATE_VERIFY_CONTEXT
	copy(signed[64:], transmute([]u8)label)
	for value, i in hash do signed[len(signed) - 32 + i] = value
	return
}

@(private)
certificate_verify_digest :: proc(hash: [32]u8, server: bool) -> [32]u8 {
	signed := certificate_verify_input(hash, server)
	t: Handshake_Transcript
	transcript_init(&t)
	transcript_update(&t, signed[:])
	return transcript_snapshot(&t)
}
