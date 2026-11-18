package tls

import "core:crypto/aes"
import "core:crypto/ecdh"
import "core:crypto/mlkem"

// What a client offers in its first flight. One engine serves both; the
// offer only selects the ClientHello and the answers it accepts.
Client_Offer :: enum u8 {
	// TLS_AES_128_GCM_SHA256 over one X25519 share, with the TLS 1.2 ECDHE
	// AES-128-GCM fallback in the same hello. The zero value: the first
	// flight of every Conn and Async_Conn configured before offers existed.
	Compatible,
	// Upstream's client: its three suites in its hardware-dependent order,
	// a key share for each of SUPPORTED_GROUPS, SIGNATURE_SCHEMES, and
	// TLS 1.3 only. Socket uses this offer.
	Upstream,
}

@(rodata)
COMPATIBLE_CIPHER_SUITES := []Cipher_Suite{.TLS_AES_128_GCM_SHA256}

@(rodata)
COMPATIBLE_GROUPS := []Named_Group{.X25519}

// PKCS#1 is offered for certificate signatures only, never CertificateVerify.
@(rodata)
COMPATIBLE_SIGNATURE_SCHEMES := []Signature_Scheme{.Ecdsa_Secp256r1_Sha256, .Rsa_Pss_Rsae_Sha256, .Ed25519}

// The largest key_share a server returns: the X25519MLKEM768 ciphertext and
// X25519 public key.
MAX_KEY_SHARE_SIZE :: 1088 + 32

client_offer_cipher_suites :: proc(offer: Client_Offer) -> []Cipher_Suite {
	if offer == .Compatible {
		return COMPATIBLE_CIPHER_SUITES
	}

	if aes.is_hardware_accelerated() {
		return CIPHER_SUITES_HW_AES
	}
	return CIPHER_SUITES
}

// The groups offered, each with a key share.
client_offer_groups :: proc(offer: Client_Offer) -> []Named_Group {
	if offer == .Compatible {
		return COMPATIBLE_GROUPS
	}
	return SUPPORTED_GROUPS
}

// The schemes accepted in the server's CertificateVerify.
client_offer_signature_schemes :: proc(offer: Client_Offer) -> []Signature_Scheme {
	if offer == .Compatible {
		return COMPATIBLE_SIGNATURE_SCHEMES
	}
	return SIGNATURE_SCHEMES
}

cipher_suite_offered :: proc(suites: []Cipher_Suite, suite: Cipher_Suite) -> bool {
	for offered in suites {
		if offered == suite {
			return true
		}
	}
	return false
}

named_group_offered :: proc(groups: []Named_Group, group: Named_Group) -> bool {
	for offered in groups {
		if offered == group {
			return true
		}
	}
	return false
}

signature_scheme_offered :: proc(schemes: []Signature_Scheme, scheme: Signature_Scheme) -> bool {
	for offered in schemes {
		if offered == scheme {
			return true
		}
	}
	return false
}

// Size of a group's key_share: the client's share, or the server's answer.
// Zero for a group this package does not implement.
named_group_share_size :: proc(group: Named_Group, server: bool) -> int {
	#partial switch group {
	case .X25519:
		return ecdh.PUBLIC_KEY_SIZES[.X25519]
	case .X448:
		return ecdh.PUBLIC_KEY_SIZES[.X448]
	case .Secp256r1:
		return ecdh.PUBLIC_KEY_SIZES[.SECP256R1]
	case .Secp384r1:
		return ecdh.PUBLIC_KEY_SIZES[.SECP384R1]
	case .X25519MLKEM768:
		if server {
			return mlkem.CIPHERTEXT_SIZES[.ML_KEM_768] + ecdh.PUBLIC_KEY_SIZES[.X25519]
		}
		return mlkem.ENCAPSULATION_KEY_SIZES[.ML_KEM_768] + ecdh.PUBLIC_KEY_SIZES[.X25519]
	}
	return 0
}

// Writes the client's key_share for group from its ephemeral keys; the
// result borrows dst, which must hold named_group_share_size(group, false).
client_key_share_bytes :: proc(keys: ^Ephemeral_Keys, group: Named_Group, dst: []u8) -> []u8 {
	size := named_group_share_size(group, false)
	share := dst[:size]

	#partial switch group {
	case .X25519:
		ecdh.private_key_public_bytes(&keys.x25519_priv, share)
	case .X448:
		ecdh.private_key_public_bytes(&keys.x448_priv, share)
	case .Secp256r1:
		ecdh.private_key_public_bytes(&keys.secp256r1_priv, share)
	case .Secp384r1:
		ecdh.private_key_public_bytes(&keys.secp384r1_priv, share)
	case .X25519MLKEM768:
		kem_size := mlkem.ENCAPSULATION_KEY_SIZES[.ML_KEM_768]
		mlkem.decapsulation_key_encaps_bytes(&keys.pqt_x25519mlkem768_decaps, share[:kem_size])
		ecdh.private_key_public_bytes(&keys.pqt_x25519_priv, share[kem_size:])
	}
	return share
}

// What a server engine is willing to select.
Server_Offer :: enum u8 {
	// TLS_AES_128_GCM_SHA256 over X25519 or P-256: the zero value, and what
	// QUIC hosts need (they derive AES-128-GCM packet keys from 32-byte secrets).
	Compatible,
	// Any of upstream's three suites over any of SUPPORTED_GROUPS.
	Upstream,
}

@(rodata)
COMPATIBLE_SERVER_GROUPS := []Named_Group{.X25519, .Secp256r1}

server_offer_groups :: proc(offer: Server_Offer) -> []Named_Group {
	if offer == .Compatible {
		return COMPATIBLE_SERVER_GROUPS
	}
	return SUPPORTED_GROUPS
}

server_offer_cipher_suites :: proc(offer: Server_Offer) -> []Cipher_Suite {
	if offer == .Compatible {
		return COMPATIBLE_CIPHER_SUITES
	}
	return CIPHER_SUITES
}

// The suites conn offers: the offer's list, or the configured restriction.
config_cipher_suites :: proc(config: ^Config) -> []Cipher_Suite {
	if config.offer == .Upstream && len(config.cipher_suites) > 0 {
		return config.cipher_suites
	}
	return client_offer_cipher_suites(config.offer)
}

config_groups :: proc(config: ^Config) -> []Named_Group {
	if config.offer == .Upstream && len(config.groups) > 0 {
		return config.groups
	}
	return client_offer_groups(config.offer)
}

// A restriction is a duplicate-free subset of upstream's lists, and belongs
// to the Upstream offer: the Compatible first flight is fixed.
config_offer_valid :: proc(config: Config) -> bool {
	if config.offer != .Upstream {
		return len(config.cipher_suites) == 0 && len(config.groups) == 0
	}

	for suite, i in config.cipher_suites {
		if !cipher_suite_offered(CIPHER_SUITES, suite) || cipher_suite_offered(config.cipher_suites[:i], suite) {
			return false
		}
	}

	for group, i in config.groups {
		if !named_group_offered(SUPPORTED_GROUPS, group) || named_group_offered(config.groups[:i], group) {
			return false
		}
	}
	return true
}
