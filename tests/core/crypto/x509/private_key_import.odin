package test_core_x509

import "core:crypto/rsa"
import "core:crypto/x509"
import "core:testing"
import "core:encoding/asn1"
import "core:crypto"
import "core:bytes"
import "core:mem"

@(test)
rsa_pkcs8_imports_independent_openssl_key :: proc(t: ^testing.T) {
	key:=new(rsa.Private_Key)
	defer free(key)
	defer rsa.private_key_clear(key)
	error:=x509.parse_pkcs8_rsa(key,#load("testdata/import_rsa_openssl_2048.der"))
	testing.expect_value(t,error.kind,.None)
	testing.expect_value(t,rsa.private_key_size(key),256)
	signature:[256]u8
	testing.expect(t,rsa.sign_pkcs1(key,.SHA256,transmute([]u8)string("owned fixture"),signature[:]))
}

trusted_rsa_parts :: proc() -> [8][]u8 {
	outer:=asn1.Cursor{data=#load("testdata/import_rsa_openssl_2048.der")}
	info,ie:=asn1.read_sequence(&outer);assert(ie==.None)
	_,ve:=asn1.read_i64(&info);assert(ve==.None)
	_,ae:=asn1.read_sequence(&info);assert(ae==.None)
	encoded,ee:=asn1.read_octet_string(&info);assert(ee==.None)
	inner:=asn1.Cursor{data=encoded}
	sequence,se:=asn1.read_sequence(&inner);assert(se==.None)
	_,ve=asn1.read_i64(&sequence);assert(ve==.None)
	parts:[8][]u8
	for &part in parts {var_error:asn1.Error;part,var_error=asn1.read_unsigned_integer_bytes(&sequence);assert(var_error==.None)}
	return parts
}

// Construct exact adversarial encodings through the independent DER writer.
// Every returned allocation contains only synthetic test key material.
private_key_variant :: proc(variant:int) -> []u8 {
	parts:=trusted_rsa_parts()
	values:[10]asn1.Value
	values[0]=asn1.integer_raw({0})
	for part,i in parts {values[i+1]=asn1.integer_unsigned(part)}
	count:=9
	large:[513]u8
	for &b in large {b=1}
	switch variant {
	case 1:values[0]=asn1.integer_raw({1}) // PKCS1 multiprime/version1.
	case 2:values[3]=asn1.integer_raw({0,1}) // Nonminimal d.
	case 3:values[3]=asn1.integer_raw({0x80}) // Negative d.
	case 4:values[3]=asn1.integer_raw({0}) // Zero d.
	case 5:values[1]=asn1.integer_unsigned(large[:])
	case 6:values[2]=asn1.integer_unsigned(large[:5])
	case 7:values[4]=asn1.integer_unsigned(large[:261])
	case 8:count=8 // Missing coefficient.
	case 9:values[9]=asn1.integer_raw({1});count=10 // Trailing field.
	case 10:values[4]=asn1.integer_unsigned({1}) // Operationally invalid CRT.
	}
	inner,inner_error:=asn1.marshal(asn1.sequence(values[:count]));assert(inner_error==.None)
	defer delete(inner)
	defer crypto.zero_explicit(raw_data(inner),len(inner))
	oid:=[]u8{0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1}
	if variant==11 {oid[8]=10} // rsaPSS is not rsaEncryption.
	algorithm:=[3]asn1.Value{asn1.object_identifier(oid),asn1.null(),asn1.null()}
	algorithm_count:=2
	if variant==12 {algorithm_count=3}
	if variant==13 {algorithm_count=1} // Absent parameters retain compatibility.
	if variant==14 {algorithm[1]=asn1.integer_raw({0})}
	outer:=[4]asn1.Value{asn1.integer_raw({0}),asn1.sequence(algorithm[:algorithm_count]),asn1.octet_string(inner),asn1.null()}
	outer_count:=3
	if variant==15 {outer[0]=asn1.integer_raw({1})}
	if variant==16 {outer_count=4}
	if variant==18 {outer[2]=asn1.octet_string_wrap({asn1.raw(inner),asn1.null()})}
	if variant==19 {outer_count=2}
	if variant==20 {algorithm[1]=asn1.Value{tag=asn1.universal(.Null),content={1}}}
	if variant==17 {outer[0]=outer[1];outer[1]=outer[2];outer_count=2} // Encrypted-like profile.
	encoded,error:=asn1.marshal(asn1.sequence(outer[:outer_count]));assert(error==.None)
	return encoded
}

@(test)
rsa_pkcs8_malformed_inputs_preserve_existing_key :: proc(t:^testing.T) {
	key:=new(rsa.Private_Key)
	defer free(key)
	defer rsa.private_key_clear(key)
	assert(x509.parse_pkcs8_rsa(key,#load("testdata/import_rsa_openssl_2048.der")).kind==.None)
	before:=make([]u8,size_of(rsa.Private_Key))
	defer delete(before)
	defer crypto.zero_explicit(raw_data(before),len(before))
	copy(before,(cast([^]u8)key)[:size_of(rsa.Private_Key)])
	for variant in 1..=20 {
		if variant==13 {continue}
		encoded:=private_key_variant(variant)
		error:=x509.parse_pkcs8_rsa(key,encoded)
		testing.expect(t,error.kind != .None)
		testing.expect(t,bytes.equal(before,(cast([^]u8)key)[:size_of(rsa.Private_Key)]))
		crypto.zero_explicit(raw_data(encoded),len(encoded));delete(encoded)
	}
	fixture:=#load("testdata/import_rsa_openssl_2048.der")
	for n in 0..<len(fixture) {
		// Every strict prefix must be rejected without consulting native RSA.
		error:=x509.parse_pkcs8_rsa(key,fixture[:n])
		assert(error.kind != .None)
	}
	trailing:=make([]u8,len(fixture)+1)
	defer delete(trailing)
	defer crypto.zero_explicit(raw_data(trailing),len(trailing))
	copy(trailing,fixture)
	testing.expect_value(t,x509.parse_pkcs8_rsa(key,trailing).kind,.Malformed)
	testing.expect(t,bytes.equal(before,(cast([^]u8)key)[:size_of(rsa.Private_Key)]))
}

@(test)
rsa_pkcs8_input_bounds_overlap_and_nil_allocator :: proc(t:^testing.T) {
	key:=new(rsa.Private_Key)
	defer free(key)
	defer rsa.private_key_clear(key)
	oversized:=make([]u8,x509.MAX_RSA_PKCS8_DER_SIZE+1)
	defer delete(oversized)
	testing.expect_value(t,x509.parse_pkcs8_rsa(key,oversized).kind,.Input_Oversized)
	testing.expect_value(t,x509.parse_pkcs8_rsa(key,oversized[:x509.MAX_RSA_PKCS8_DER_SIZE]).kind,.Malformed)
	testing.expect_value(t,x509.parse_pkcs8_rsa(nil,[]u8{1}).kind,.Invalid_Input)
	previous:=context
	defer context=previous
	context.allocator=mem.nil_allocator();context.temp_allocator=mem.nil_allocator()
	assert(x509.parse_pkcs8_rsa(key,#load("testdata/import_rsa_openssl_2048.der")).kind==.None)
	before_n:[512]u8
	n:=rsa.private_key_n(key,before_n[:])
	alias:=(cast([^]u8)key)[:size_of(rsa.Private_Key)]
	assert(x509.parse_pkcs8_rsa(key,alias).kind==.Overlap)
	after_n:[512]u8
	assert(rsa.private_key_n(key,after_n[:])==n && bytes.equal(before_n[:n],after_n[:n]))
}

@(test)
rsa_pkcs8_does_not_retain_der_and_accepts_absent_null :: proc(t:^testing.T) {
	key:=new(rsa.Private_Key)
	defer free(key)
	defer rsa.private_key_clear(key)
	encoded:=private_key_variant(13)
	defer delete(encoded)
	assert(x509.parse_pkcs8_rsa(key,encoded).kind==.None)
	crypto.zero_explicit(raw_data(encoded),len(encoded))
	parts:=trusted_rsa_parts()
	public:rsa.Public_Key
	assert(rsa.public_key_set_bytes(&public,parts[0],parts[1]))
	defer rsa.public_key_clear(&public)
	signature:[256]u8
	message:=transmute([]u8)string("owned import survives input erasure")
	testing.expect(t,rsa.sign_pkcs1(key,.SHA256,message,signature[:]))
	testing.expect(t,rsa.verify_pkcs1(&public,.SHA256,message,signature[:]))
}

@(test)
rsa_pkcs1_entrypoint_shares_transaction_and_borrow_contract :: proc(t:^testing.T) {
	parts:=trusted_rsa_parts()
	fields:[9]asn1.Value
	fields[0]=asn1.integer_raw({0})
	for part,i in parts {fields[i+1]=asn1.integer_unsigned(part)}
	encoded,encode_error:=asn1.marshal(asn1.sequence(fields[:]));assert(encode_error==.None)
	defer delete(encoded)
	defer crypto.zero_explicit(raw_data(encoded),len(encoded))
	key:=new(rsa.Private_Key)
	defer free(key)
	defer rsa.private_key_clear(key)
	previous:=context
	defer context=previous
	context.allocator=mem.nil_allocator();context.temp_allocator=mem.nil_allocator()
	assert(x509.parse_pkcs1_rsa(key,encoded).kind==.None)
	assert(x509.parse_pkcs1_rsa(key,encoded[:len(encoded)-1]).kind != .None)
	crypto.zero_explicit(raw_data(encoded),len(encoded))
	signature:[256]u8
	testing.expect(t,rsa.sign_pkcs1(key,.SHA256,transmute([]u8)string("raw native compatibility"),signature[:]))
	testing.expect_value(t,rsa.private_key_size(key),256)
}
