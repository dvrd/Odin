package credentials

import "core:bytes"
import "core:crypto/ecdsa"
import "core:crypto/rsa"
import "core:crypto/x509"
import "core:encoding/asn1"

@(private)
EC_KEY_OID :: []u8{0x2a,0x86,0x48,0xce,0x3d,2,1}
@(private)
P256_OID :: []u8{0x2a,0x86,0x48,0xce,0x3d,3,1,7}
@(private)
RSA_KEY_OID :: []u8{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1}

// Narrow allocation-free import; caller's unpublished owner is wiped on failure.
// SEC1 requires named P-256 parameters; PKCS8 supplies them in AlgorithmIdentifier.
// If an inner curve/public point is present it must agree, never override policy.
@(private)
parse_credential_key :: proc(owner:^Owner, label:string, der:[]u8) -> Error {
	if label=="RSA PRIVATE KEY" {
		if x509.parse_pkcs1_rsa(&owner.key,der).kind!=.None {return .Malformed_Key}
		return finish_rsa_key(owner)
	}
	if label=="EC PRIVATE KEY" {return parse_ec_key(owner,der,false)}
	if label!="PRIVATE KEY" {return .Unsupported_Key}
	outer:=asn1.Cursor{data=der}
	info,e:=asn1.read_sequence(&outer)
	if e!=.None || asn1.done(&outer)!=.None {return .Malformed_Key}
	version,ve:=asn1.read_i64(&info)
	if ve!=.None || version!=0 {return .Malformed_Key}
	algorithm,ae:=asn1.read_sequence(&info)
	if ae!=.None {return .Malformed_Key}
	oid,oe:=asn1.read_oid(&algorithm)
	if oe!=.None {return .Malformed_Key}
	if bytes.equal(oid,RSA_KEY_OID) {
		if x509.parse_pkcs8_rsa(&owner.key,der).kind!=.None {return .Malformed_Key}
		return finish_rsa_key(owner)
	}
	if !bytes.equal(oid,EC_KEY_OID) {return .Unsupported_Key}
	curve,ce:=asn1.read_oid(&algorithm)
	if ce!=.None || asn1.done(&algorithm)!=.None {return .Malformed_Key}
	if !bytes.equal(curve,P256_OID) {return .Unsupported_Key}
	encoded,ke:=asn1.read_octet_string(&info)
	if ke!=.None || asn1.done(&info)!=.None {return .Malformed_Key}
	return parse_ec_key(owner,encoded,true)
}
@(private)
finish_rsa_key :: proc(owner:^Owner) -> Error {
	modulus:[512]u8
	n:=rsa.private_key_n(&owner.key,modulus[:])
	if n<256 || n>512 || n==256 && modulus[0]<0x80 {return .Unsupported_Key}
	owner.scheme=.RSA_PSS_RSAE_SHA256
	return .None
}
@(private)
parse_ec_key :: proc(owner:^Owner, der:[]u8, outer_p256:bool) -> Error {
	if len(der)>512 {return .Input_Limit}
	outer:=asn1.Cursor{data=der}
	info,e:=asn1.read_sequence(&outer)
	if e!=.None || asn1.done(&outer)!=.None {return .Malformed_Key}
	version,ve:=asn1.read_i64(&info)
	if ve!=.None || version!=1 {return .Malformed_Key}
	scalar,se:=asn1.read_octet_string(&info)
	if se!=.None || len(scalar)!=32 {return .Malformed_Key}
	parameters,present,pe:=asn1.read_explicit(&info,0)
	if pe!=.None {return .Malformed_Key}
	if present {
		oid,oe:=asn1.read_oid(&parameters)
		if oe!=.None || asn1.done(&parameters)!=.None {return .Malformed_Key}
		if !bytes.equal(oid,P256_OID) {return .Unsupported_Key}
	} else if !outer_p256 {return .Unsupported_Key}
	public,has_public,pue:=asn1.read_explicit(&info,1)
	if pue!=.None || asn1.done(&info)!=.None {return .Malformed_Key}
	if !ecdsa.private_key_set_bytes(&owner.ec,.SECP256R1,scalar) {return .Malformed_Key}
	if has_public {
		point,be:=asn1.read_bit_string_octets(&public)
		if be!=.None || asn1.done(&public)!=.None {return .Malformed_Key}
		expected:[65]u8
		ecdsa.private_key_public_bytes(&owner.ec,expected[:])
		// Exact match to the natively derived point also rejects invalid,
		// infinity, compressed, noncanonical or mismatched public points.
		if !bytes.equal(point,expected[:]) {return .Key_Mismatch}
	}
	owner.scheme=.ECDSA_SECP256R1_SHA256
	return .None
}
