package credentials

import "core:crypto/hash"

// Construction-time values, not a signature/trust verdict. Only meaningful for
// RSA_PSS certificates. X509 already checked the parameter DER/trailer field.
Certificate_PSS_Parameters :: struct {
	digest, mgf_digest: hash.Algorithm,
	salt_length: int,
}
certificate_pss_parameters :: proc(credential:^Credential,index:int) -> (Certificate_PSS_Parameters,Error) {
	if credential==nil {return {},.Invalid_Handle}
	owner:=cast(^Owner)credential
	if index<0 || index>=owner.count {return {},.Invalid_Index}
	cert:=&owner.certs[index]
	if cert.signature_algorithm!=.RSA_PSS {return {},.Unsupported_Signature_Scheme}
	return {cert.pss_hash,cert.pss_mgf_hash,cert.pss_salt_len},.None
}
