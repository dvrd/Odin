package quic

import "core:crypto"
import "core:crypto/aes"

// RFC 9001 section 5.8. v1 fixed key and nonce. Not a traffic secret.
@(private)
RETRY_INTEGRITY_KEY :: [16]u8 {
	0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
}
@(private)
RETRY_INTEGRITY_NONCE :: [12]u8 {
	0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
}
@(private)
RETRY_PSEUDO_CAP :: 2048

// original_destination_id is the DCID of the Initial that triggered this Retry.
// retry_without_tag is the Retry header and token, excluding the 16-byte tag.
retry_integrity_tag :: proc(
	dst_tag, original_destination_id, retry_without_tag: []u8,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> Protection_Error {
	if implementation != .Portable && implementation != .Hardware {
		return .Invalid_Implementation
	}
	if len(original_destination_id) > 20 {
		return .Invalid_Connection_ID
	}
	if len(dst_tag) < 16 {
		return .Destination_Undersized
	}
	pseudo: [RETRY_PSEUDO_CAP]u8
	defer crypto.zero_explicit(&pseudo, size_of(pseudo))
	n := 1 + len(original_destination_id) + len(retry_without_tag)
	if n > len(pseudo) {
		return .Invalid_Length
	}
	pseudo[0] = u8(len(original_destination_id))
	copy(pseudo[1:], original_destination_id)
	copy(pseudo[1 + len(original_destination_id):], retry_without_tag)
	key := RETRY_INTEGRITY_KEY
	nonce := RETRY_INTEGRITY_NONCE
	defer crypto.zero_explicit(&key, size_of(key))
	defer crypto.zero_explicit(&nonce, size_of(nonce))
	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, key[:], implementation)
	defer aes.reset_gcm(&ctx)
	empty: []u8
	aes.seal_gcm(&ctx, empty, dst_tag[:16], nonce[:], pseudo[:n], empty)
	return .None
}

// retry_packet includes its 16-byte tag. Failure leaves no tag copy behind.
retry_integrity_verify :: proc(
	original_destination_id, retry_packet: []u8,
	implementation := aes.DEFAULT_IMPLEMENTATION,
) -> Protection_Error {
	if len(retry_packet) < 16 {
		return .Invalid_Length
	}
	tag: [16]u8
	defer crypto.zero_explicit(&tag, size_of(tag))
	body := retry_packet[:len(retry_packet) - 16]
	if e := retry_integrity_tag(tag[:], original_destination_id, body, implementation); e != .None {
		return e
	}
	if crypto.compare_constant_time(tag[:], retry_packet[len(retry_packet) - 16:]) != 1 {
		return .Authentication_Failed
	}
	return .None
}
