package x509

import "core:encoding/asn1"
import "core:testing"

@(test)
pss_hash_algorithm_parameters_require_null_or_absent :: proc(t: ^testing.T) {
	for mode in 0 ..< 8 {
		algorithm := [2]asn1.Value{asn1.object_identifier(_OID_HASH_SHA256), asn1.null()}
		if mode == 2 || mode == 5 {
			algorithm[1] = asn1.octet_string(nil)
		}
		if mode == 3 || mode == 6 {
			algorithm[1] = asn1.sequence(nil)
		}
		size := 2
		if mode == 1 || mode == 4 {
			size = 1
		}
		mgf := [2]asn1.Value{asn1.object_identifier(_OID_MGF1), asn1.sequence(algorithm[:size])}
		fields: [1]asn1.Value
		hash_fields := [1]asn1.Value{asn1.sequence(algorithm[:size])}
		mgf_fields := [1]asn1.Value{asn1.sequence(mgf[:])}
		if mode < 4 {
			fields[0] = asn1.context_explicit(0, hash_fields[:])
		} else {
			fields[0] = asn1.context_explicit(1, mgf_fields[:])
		}
		der, e := asn1.marshal(asn1.sequence(fields[:]))
		assert(e == .None)
		defer delete(der)
		cert: Certificate
		error := _parse_pss_params(&cert, der)
		good := mode == 0 || mode == 1 || mode == 4 || mode == 7
		testing.expect_value(t, error, Error.None if good else Error.Malformed)
		if good {
			if mode < 4 {
				testing.expect_value(t, cert.pss_hash, .SHA256)
			} else {
				testing.expect_value(t, cert.pss_mgf_hash, .SHA256)
			}
		}
	}
}
