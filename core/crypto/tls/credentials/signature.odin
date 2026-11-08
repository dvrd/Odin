package credentials

import "core:crypto"
import "core:crypto/ecdsa"
import "core:crypto/hash"

// Wire identifiers, deliberately independent of the parent TLS package.
Signature_Scheme :: enum u16 {
	None = 0,
	ECDSA_SECP256R1_SHA256 = 0x0403,
	RSA_PSS_RSAE_SHA256 = 0x0804,
}
signature_scheme :: proc(credential:^Credential) -> Signature_Scheme {
	if credential==nil {return .None}
	return (cast(^Owner)credential).scheme
}

// Hashes message exactly once with SHA256. Scheme must match the admitted key.
// Output is canonical DER for ECDSA, fixed-width PSS for RSA; failure preserves
// out. Immutable concurrent signing uses distinct per-call stack/output storage.
// Hedged native ECDSA requires OS entropy; no deterministic fallback is exposed.
@(require_results)
sign_sha256 :: proc(credential:^Credential, scheme:Signature_Scheme, message,out:[]u8) -> (int,Error) {
	if credential==nil {return 0,.Invalid_Handle}
	owner:=cast(^Owner)credential
	if scheme==.None || scheme!=owner.scheme {return 0,.Unsupported_Signature_Scheme}
	if !crypto.HAS_RAND_BYTES {return 0,.Entropy_Unavailable}
	if scheme==.RSA_PSS_RSAE_SHA256 {
		digest:[32]u8;defer crypto.zero_explicit(&digest,size_of(digest))
		hash.hash_bytes_to_buffer(.SHA256,message,digest[:])
		return sign_digest_pss_sha256(credential,digest,out)
	}
	// Require the maximum encoded size before invoking entropy/signing.
	if len(out)<72 {return 0,.Output_Too_Small}
	if overlaps(raw_data(out),len(out),owner,size_of(Owner)) {return 0,.Output_Aliases_Owner}
	for a in owner.allocations {
		if a.pointer!=nil && overlaps(raw_data(out),len(out),a.pointer,a.size) {return 0,.Output_Aliases_Owner}
	}
	raw:[64]u8;encoded:[72]u8
	defer crypto.zero_explicit(&raw,size_of(raw));defer crypto.zero_explicit(&encoded,size_of(encoded))
	if !ecdsa.sign_raw(&owner.ec,.SHA256,message,raw[:],deterministic=false) {return 0,.Signing_Failed}
	encoded[0]=0x30
	n:=2
	for i in 0..<2 {
		integer:=raw[i*32:(i+1)*32]
		for len(integer)>1 && integer[0]==0 {integer=integer[1:]}
		pad:=1 if integer[0]&0x80!=0 else 0
		encoded[n],encoded[n+1]=2,u8(len(integer)+pad);n+=2
		if pad!=0 {encoded[n]=0;n+=1}
		copy(encoded[n:],integer);n+=len(integer)
	}
	encoded[1]=u8(n-2);copy(out,encoded[:n])
	return n,.None
}
