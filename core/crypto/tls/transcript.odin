package tls

import "core:crypto/hash"

// Transcript hash of the negotiated cipher suite. Feed exact handshake bytes
// (including headers), once and in order. Framing, message order and HRR
// eligibility belong to the caller. Retains only hash state and its partial
// block; no input borrows, complete transcript buffer or allocations.
@(private)
CLIENT_CERTIFICATE_VERIFY_CONTEXT :: "TLS 1.3, client CertificateVerify"

Handshake_Transcript :: hash.Context

// The largest transcript hash and traffic secret of a TLS 1.3 suite (SHA-384).
MAX_TRANSCRIPT_HASH_SIZE :: 48
MAX_MESSAGE_HASH_SIZE :: 4 + MAX_TRANSCRIPT_HASH_SIZE
@(private)
MAX_CERTIFICATE_VERIFY_INPUT_SIZE :: 64 + len(SERVER_CERTIFICATE_VERIFY_CONTEXT) + 1 + MAX_TRANSCRIPT_HASH_SIZE

@(private)
transcript_init :: proc(t: ^Handshake_Transcript, algorithm: hash.Algorithm = .SHA256) {
	hash.init(t, algorithm)
}

@(private)
transcript_update :: proc(t: ^Handshake_Transcript, bytes: []u8) {
	hash.update(t, bytes)
}

// Digest of the bytes fed so far, without finalizing the live state. dst must
// hold the digest of the transcript's algorithm; the result borrows dst.
transcript_hash :: proc(t: ^Handshake_Transcript, dst: []u8) -> []u8 {
	digest := dst[:hash.digest_size(t)]
	hash.final(t, digest, true)
	return digest
}

// SHA-256 transcripts only: the by-value digest of the fixed-size codecs.
@(private)
transcript_snapshot :: proc(t: ^Handshake_Transcript) -> (digest: [32]u8) {
	assert(hash.algorithm(t) == .SHA256, "tls: transcript_snapshot requires a SHA-256 transcript")
	hash.final(t, digest[:], true)
	return
}

// RFC 8446 section 4.4.1: replace CH1 by message_hash(Hash(CH1)). Call only
// after hashing the complete CH1 and before hashing the single accepted HRR.
@(private)
transcript_retry :: proc(t: ^Handshake_Transcript) {
	algorithm := hash.algorithm(t)
	digest_storage: [MAX_TRANSCRIPT_HASH_SIZE]u8
	digest := transcript_hash(t, digest_storage[:])

	message_storage: [MAX_MESSAGE_HASH_SIZE]u8
	message := transcript_message_hash_encode(message_storage[:], digest)

	transcript_init(t, algorithm)
	transcript_update(t, message)
}

// Writes the synthetic message_hash handshake message for digest into dst.
@(private)
transcript_message_hash_encode :: proc(dst: []u8, digest: []u8) -> []u8 {
	dst[0] = u8(Handshake_Type.Message_Hash)
	dst[1] = 0
	dst[2] = 0
	dst[3] = u8(len(digest))
	copy(dst[4:], digest)
	return dst[:4 + len(digest)]
}

@(private)
transcript_message_hash :: proc(digest: [32]u8) -> (message: [36]u8) {
	local := digest
	transcript_message_hash_encode(message[:], local[:])
	return
}

// Hash of the empty string for algorithm; the result borrows dst.
@(private)
transcript_empty_hash_into :: proc(algorithm: hash.Algorithm, dst: []u8) -> []u8 {
	return hash.hash_bytes_to_buffer(algorithm, nil, dst)
}

@(private)
transcript_empty_hash :: proc() -> (digest: [32]u8) {
	transcript_empty_hash_into(.SHA256, digest[:])
	return
}

// The bytes covered by a CertificateVerify signature (RFC 8446 section 4.4.3).
// The role is the signer, independently of which side consumes this input.
// The result borrows dst, which must hold MAX_CERTIFICATE_VERIFY_INPUT_SIZE.
@(private)
certificate_verify_content :: proc(dst: []u8, transcript_hash: []u8, server: bool) -> []u8 {
	for i in 0 ..< 64 {
		dst[i] = 0x20
	}

	label := CLIENT_CERTIFICATE_VERIFY_CONTEXT
	if server {
		label = SERVER_CERTIFICATE_VERIFY_CONTEXT
	}

	at := 64
	at += copy(dst[at:], transmute([]u8)label)
	dst[at] = 0
	at += 1
	at += copy(dst[at:], transcript_hash)
	return dst[:at]
}

// SHA-256 transcript form of certificate_verify_content.
@(private)
certificate_verify_input :: proc(digest: [32]u8, server: bool) -> (signed: [64 + len(SERVER_CERTIFICATE_VERIFY_CONTEXT) + 1 + 32]u8) {
	local := digest
	certificate_verify_content(signed[:], local[:], server)
	return
}

@(private)
certificate_verify_digest :: proc(digest: [32]u8, server: bool) -> (out: [32]u8) {
	signed := certificate_verify_input(digest, server)
	hash.hash_bytes_to_buffer(.SHA256, signed[:], out[:])
	return
}
