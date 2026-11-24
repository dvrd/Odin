package tls

import "core:bytes"
import "core:crypto"
import "core:crypto/hmac"

@(private)
TLS12_FINISHED_SIZE :: 12
@(private)
TLS12_FINISHED_MESSAGE_SIZE :: 4 + TLS12_FINISHED_SIZE
@(private)
TLS12_PRF_MAX_OUTPUT :: 4096

@(private)
TLS12_Schedule_Error :: enum {
	None,
	Invalid_Secret_Length,
	Invalid_Label_Length,
	Seed_Oversized,
	Output_Oversized,
	Overlapping_Buffers,
}

// RFC5246 section5 P_SHA256, with explicit finite inputs and no allocation.
// The label excludes a trailing NUL. Validation writes no destination bytes;
// dst must not alias any input. Empty output is valid. Secret material owned
// by the caller is never modified; intermediate keyed states are erased.
@(private)
tls12_prf_sha256 :: proc(secret: []u8, label: string, seed, dst: []u8) -> TLS12_Schedule_Error {
	if len(secret) < 1 || len(secret) > 512 {return .Invalid_Secret_Length}
	if len(label) < 1 || len(label) > 64 {return .Invalid_Label_Length}
	if len(seed) > 256 {return .Seed_Oversized}
	if len(dst) > TLS12_PRF_MAX_OUTPUT {return .Output_Oversized}
	label_bytes := transmute([]u8)label
	if bytes.alias(dst, secret) || bytes.alias(dst, seed) || bytes.alias(dst, label_bytes) {
		return .Overlapping_Buffers
	}
	a, next, block: [32]u8
	defer crypto.zero_explicit(&a, size_of(a))
	defer crypto.zero_explicit(&next, size_of(next))
	defer crypto.zero_explicit(&block, size_of(block))
	ctx: hmac.Context
	defer hmac.reset(&ctx)
	hmac.init(&ctx, .SHA256, secret)
	hmac.update(&ctx, label_bytes)
	hmac.update(&ctx, seed)
	hmac.final(&ctx, a[:])
	for at := 0; at < len(dst); at += len(block) {
		hmac.init(&ctx, .SHA256, secret)
		hmac.update(&ctx, a[:])
		hmac.update(&ctx, label_bytes)
		hmac.update(&ctx, seed)
		hmac.final(&ctx, block[:])
		copy(dst[at:min(at + len(block), len(dst))], block[:])
		hmac.sum(.SHA256, next[:], a[:], secret)
		a = next
	}
	return .None
}

// session_hash is SHA256(ClientHello through ClientKeyExchange), including
// handshake headers, excluding TLS record/CCS headers (RFC7627 sections3–4).
@(private)
tls12_extended_master_secret :: proc(
	pre_master: []u8,
	session_hash: [32]u8,
) -> (master: [48]u8, error: TLS12_Schedule_Error) {
	hash := session_hash
	error = tls12_prf_sha256(pre_master, "extended master secret", hash[:], master[:])
	return
}

// RFC5288 AES128GCM has no separate MAC keys: two16-byte keys, two4-byte salts.
// Owns key material. Clear after installing both independent record directions.
@(private)
TLS12_Key_Block :: struct {
	client_key, server_key: [16]u8,
	client_iv, server_iv: [4]u8,
}

@(private)
tls12_key_block_clear :: proc(keys: ^TLS12_Key_Block) {
	if keys != nil {crypto.zero_explicit(keys, size_of(keys^))}
}

@(private)
tls12_key_block :: proc(
	master: [48]u8,
	client_random, server_random: [32]u8,
) -> (keys: TLS12_Key_Block) {
	secret := master
	defer crypto.zero_explicit(&secret, size_of(secret))
	seed: [64]u8
	for v, i in server_random {seed[i] = v}; for v, i in client_random {seed[32+i] = v}
	block: [40]u8
	defer crypto.zero_explicit(&block, size_of(block))
	error := tls12_prf_sha256(secret[:], "key expansion", seed[:], block[:])
	assert(error == .None)
	copy(keys.client_key[:], block[:16]); copy(keys.server_key[:], block[16:32])
	copy(keys.client_iv[:], block[32:36]); copy(keys.server_iv[:], block[36:])
	return
}

// RFC5246 section7.4.9. Hash excludes the Finished being computed; the server
// hash includes the client's Finished in a full client-initiated handshake.
@(private)
tls12_finished_verify_data :: proc(
	master: [48]u8,
	transcript_hash: [32]u8,
	server: bool,
) -> (verify_data: [12]u8) {
	secret := master
	defer crypto.zero_explicit(&secret, size_of(secret))
	label := server ? "server finished" : "client finished"
	hash := transcript_hash
	error := tls12_prf_sha256(secret[:], label, hash[:], verify_data[:])
	assert(error == .None)
	return
}

@(private)
tls12_finished_encode :: proc(
	dst: []u8,
	master: [48]u8,
	transcript_hash: [32]u8,
	server: bool,
) -> (written: int, error: Finished_Error) {
	if len(dst) < TLS12_FINISHED_MESSAGE_SIZE {return 0, .Destination_Undersized}
	data := tls12_finished_verify_data(master, transcript_hash, server)
	defer crypto.zero_explicit(&data, size_of(data))
	dst[0], dst[1], dst[2], dst[3] = u8(Handshake_Type.Finished), 0, 0, TLS12_FINISHED_SIZE
	copy(dst[4:TLS12_FINISHED_MESSAGE_SIZE], data[:])
	return TLS12_FINISHED_MESSAGE_SIZE, .None
}

@(private)
tls12_finished_verify :: proc(
	message: []u8,
	master: [48]u8,
	transcript_hash: [32]u8,
	server: bool,
) -> Finished_Error {
	if len(message) != TLS12_FINISHED_MESSAGE_SIZE {return .Invalid_Length}
	if message[0] != u8(Handshake_Type.Finished) {return .Unexpected_Handshake_Type}
	if message[1] != 0 || message[2] != 0 || message[3] != TLS12_FINISHED_SIZE {
		return .Invalid_Length
	}
	expected := tls12_finished_verify_data(master, transcript_hash, server)
	defer crypto.zero_explicit(&expected, size_of(expected))
	if crypto.compare_constant_time(message[4:], expected[:]) != 1 {return .Verification_Failed}
	return .None
}
