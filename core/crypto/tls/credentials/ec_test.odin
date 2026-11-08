package credentials

import "core:bytes"
import "core:crypto/ecdsa"
import "core:crypto/hash"
import "core:crypto/rsa"
import "core:encoding/asn1"
import "core:encoding/pem"
import "core:fmt"
import "core:mem"
import "core:slice"
import "core:testing"

ec_cert :: #load("../../../../tests/core/crypto/tls/credentials/testdata/p256-valid.pem")
ec_key :: #load("../../../../tests/core/crypto/tls/credentials/testdata/p256.pem")
ec_sec1 :: #load("../../../../tests/core/crypto/tls/credentials/testdata/p256-sec1.pem")

@(test)
p256_credentials_formats_signatures_and_budgets :: proc(t:^testing.T) {
	for input in ([]string{string(ec_key),string(ec_sec1)}) {
		a:=Audit{backing=context.allocator}
		h,e:=create(ec_cert,transmute([]u8)input,{},audit_allocator(&a));testing.expect_value(t,e,.None);assert(h!=nil)
		testing.expect_value(t,signature_scheme(h),.ECDSA_SECP256R1_SHA256)
		owner:=cast(^Owner)h
		before:=storage_usage(h)
		fmt.printf("P256 credential owner=%d key union=%d native EC=%d retained=%d peak=%d allocations=%d\n",size_of(Owner),size_of(owner.private),size_of(ecdsa.Private_Key),before.retained_bytes,before.peak_bytes,a.calls)
		message:=[]u8{1,2,3,4,5};out:[80]u8
		for &b in out {b=0xa5}
		for i in 0..<8 {
			n:int;se:Error
			{context.allocator=mem.panic_allocator();n,se=sign_sha256(h,.ECDSA_SECP256R1_SHA256,message,out[:])};testing.expect_value(t,se,.None);testing.expect(t,n>=8 && n<=72)
			pub:ecdsa.Public_Key;assert(ecdsa.public_key_set_bytes(&pub,.SECP256R1,owner.certs[0].ec_point))
			testing.expect(t,ecdsa.verify_asn1(&pub,.SHA256,message,out[:n]))
			changed:=[]u8{1,2,3,4,6};testing.expect(t,!ecdsa.verify_asn1(&pub,.SHA256,changed,out[:n]))
			ecdsa.public_key_clear(&pub)
			cursor:=asn1.Cursor{data=out[:n]};seq,qe:=asn1.read_sequence(&cursor);testing.expect_value(t,qe,.None)
			for _ in 0..<2 {value,ie:=asn1.read_unsigned_integer_bytes(&seq);testing.expect_value(t,ie,.None);testing.expect(t,len(value)>0 && len(value)<=32)}
			testing.expect_value(t,asn1.done(&seq),.None);testing.expect_value(t,asn1.done(&cursor),.None)
			for b in out[n:] {testing.expect_value(t,b,u8(0xa5))}
			for &b in out {b=0xa5}
		}
		_,small:=sign_sha256(h,.ECDSA_SECP256R1_SHA256,message,out[:71]);testing.expect_value(t,small,.Output_Too_Small)
		_,wrong:=sign_sha256(h,.RSA_PSS_RSAE_SHA256,message,out[:]);testing.expect_value(t,wrong,.Unsupported_Signature_Scheme)
		_,legacy:=sign_digest_pss_sha256(h,{},out[:]);testing.expect_value(t,legacy,.Unsupported_Key)
		for b in out {testing.expect_value(t,b,u8(0xa5))}
		der,_:=certificate_der(h,0);before_der,_:=slice.clone(der);defer delete(before_der)
		_,alias:=sign_sha256(h,.ECDSA_SECP256R1_SHA256,message,der);testing.expect_value(t,alias,.Output_Aliases_Owner);testing.expect(t,bytes.equal(der,before_der))
		_,oa:=sign_sha256(h,.ECDSA_SECP256R1_SHA256,message,(cast([^]u8)owner)[:size_of(Owner)]);testing.expect_value(t,oa,.Output_Aliases_Owner)
		testing.expect_value(t,storage_usage(h),before)
		attempts:=a.calls;destroy(&h);audit_clean(t,&a)
		for mode in ([]Audit_Mode{.OOM,.Nil_Success,.Undergrant,.Overgrant,.Error_Grant}) {for fail_at in 1..=attempts {
			b:=Audit{backing=context.allocator,mode=mode,fail_at=fail_at}
			bad,be:=create(ec_cert,transmute([]u8)input,{},audit_allocator(&b));testing.expect(t,bad==nil && be==.Allocation_Failed);destroy(&bad);audit_clean(t,&b)
		}}
		exact,xe:=create(ec_cert,transmute([]u8)input,{max_storage_bytes=before.peak_bytes},context.allocator);testing.expect_value(t,xe,.None);destroy(&exact)
		limited,le:=create(ec_cert,transmute([]u8)input,{max_storage_bytes=before.peak_bytes-1},context.allocator);testing.expect(t,limited==nil && le==.Storage_Limit);destroy(&limited)
	}
}

// Build SEC1 framing only; native primitives validate all scalars/points.
ec_test_der :: proc(scalar,point,curve:[]u8,version:=u8(1),duplicate:=false) -> []u8 {
	v:=[1]u8{version}
	fields:[5]asn1.Value
	fields[0]=asn1.integer_raw(v[:]);fields[1]=asn1.octet_string(scalar);n:=2
	curve_value:=[1]asn1.Value{asn1.object_identifier(curve)}
	point_value:=[1]asn1.Value{asn1.bit_string_octets(point)}
	if curve!=nil {fields[n]=asn1.context_explicit(0,curve_value[:]);n+=1}
	if point!=nil {fields[n]=asn1.context_explicit(1,point_value[:]);n+=1}
	if duplicate {fields[n]=asn1.context_explicit(1,point_value[:]);n+=1}
	der,e:=asn1.marshal(asn1.sequence(fields[:n]));assert(e==.None);return der
}

@(test)
p256_key_import_scalar_point_profile_rejections :: proc(t:^testing.T) {
	one:[32]u8;one[31]=1
	key:ecdsa.Private_Key;assert(ecdsa.private_key_set_bytes(&key,.SECP256R1,one[:]));defer ecdsa.private_key_clear(&key)
	public:[65]u8;ecdsa.private_key_public_bytes(&key,public[:])
	order:=[32]u8{0xff,0xff,0xff,0xff,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51}
	for mode in 0..<14 {
		scalar:=one;point:=public;curve:=P256_OID;version:=u8(1);length:=32;point_length:=65
		if mode==0 {scalar={}}
		if mode==1 {scalar=order}
		if mode==2 {for &b in scalar {b=0xff}}
		if mode==3 {length=31}
		if mode==4 {point[0]=0}
		if mode==5 {point[1]~=1}
		if mode==6 {point[0]=2;point_length=33}
		if mode==7 {curve=[]u8{0x2b,0x81,4,0,0x22}}
		if mode==8 {curve=nil}
		if mode==9 {version=2}
		original:=ec_test_der(scalar[:length],point[:point_length],curve,version,mode==10);defer delete(original)
		der:=original
		if mode==11 {appended:=append_copy(der,0);defer delete(appended);der=appended}
		if mode==12 {der[1]=0x80}
		if mode==13 {der=der[:len(der)-1]}
		a:=Audit{backing=context.allocator}
		owner:Owner;cause:=parse_ec_key(&owner,der,false)
		testing.expect(t,cause!=.None,fmt.tprintf("mode%d",mode))
		// Full construction must also reject and erase all unpublished grants.
		text,pe:=pem.encode("EC PRIVATE KEY",der);assert(pe==nil);defer delete(text)
		h,e:=create(ec_cert,text,{},audit_allocator(&a));testing.expect(t,h==nil && e!=.None);destroy(&h);audit_clean(t,&a)
	}
	for c in ([]struct{cert,key:[]u8}{
		{ec_cert,#load("../../../../tests/core/crypto/tls/credentials/testdata/p256-other.pem")},
		{fixture_cert,ec_key},{ec_cert,fixture_key},
		{#load("../../../../tests/core/crypto/tls/credentials/testdata/p384-valid.pem"),#load("../../../../tests/core/crypto/tls/credentials/testdata/p384.pem")},
	}) {
		a:=Audit{backing=context.allocator};h,e:=create(c.cert,c.key,{},audit_allocator(&a));testing.expect(t,h==nil && e!=.None);destroy(&h);audit_clean(t,&a)
	}
	// SEC1 public point may be omitted, but named curve may not.
	der:=ec_test_der(one[:],nil,P256_OID);defer delete(der);owner:Owner
	testing.expect_value(t,parse_ec_key(&owner,der,false),.None)
}

append_copy :: proc(input:[]u8,b:u8) -> []u8 {result:=make([]u8,len(input)+1);copy(result,input);result[len(input)]=b;return result}

@(test)
rsa_typed_message_signing_matches_legacy_digest_contract :: proc(t:^testing.T) {
	h,e:=create(fixture_cert,fixture_key,{},context.allocator);assert(e==.None);defer destroy(&h)
	testing.expect_value(t,signature_scheme(h),.RSA_PSS_RSAE_SHA256)
	out:[512]u8;n,se:=sign_sha256(h,.RSA_PSS_RSAE_SHA256,[]u8{1,2,3},out[:]);testing.expect_value(t,se,.None)
	// Existing RSA verification hashes the message once, not twice.
	digest:[32]u8;hash.hash_bytes_to_buffer(.SHA256,[]u8{1,2,3},digest[:])
	owner:=cast(^Owner)h
	pub:rsa.Public_Key;assert(rsa.public_key_set_bytes(&pub,owner.certs[0].rsa_n,owner.certs[0].rsa_e));defer rsa.public_key_clear(&pub)
	testing.expect(t,rsa.verify_pss(&pub,.SHA256,32,digest[:],out[:n],is_prehashed=true,mgf1_algo=.SHA256))
	testing.expect_value(t,n,256)
	{context.allocator=mem.panic_allocator();_,se:=sign_sha256(h,.RSA_PSS_RSAE_SHA256,[]u8{1,2,3},out[:]);testing.expect_value(t,se,.None)}
}

@(test)
p256_pkcs8_outer_inner_policy_and_exact_der :: proc(t:^testing.T) {
	one:[32]u8;one[31]=1
	key:ecdsa.Private_Key;assert(ecdsa.private_key_set_bytes(&key,.SECP256R1,one[:]));defer ecdsa.private_key_clear(&key)
	public:[65]u8;ecdsa.private_key_public_bytes(&key,public[:])
	for mode in 0..<11 {
		curve:=P256_OID;oid:=EC_KEY_OID;version:=[1]u8{0};inner_version:=u8(1);inner_curve:[]u8
		if mode==1 {version[0]=1}
		if mode==2 {curve=[]u8{0x2b,0x81,4,0,0x22}}
		if mode==3 {oid=RSA_KEY_OID}
		if mode==7 {inner_curve=[]u8{0x2b,0x81,4,0,0x22}}
		if mode==8 {inner_version=2}
		point:=public;if mode==9 {point[64]~=1}
		inner:=ec_test_der(one[:],point[:],inner_curve,inner_version);defer delete(inner)
		algorithm:=[2]asn1.Value{asn1.object_identifier(oid),asn1.object_identifier(curve)}
		if mode==4 {algorithm[1]=asn1.null()}
		algorithm_size:=2;if mode==6 {algorithm_size=1}
		fields:=[4]asn1.Value{asn1.integer_raw(version[:]),asn1.sequence(algorithm[:algorithm_size]),asn1.octet_string(inner),asn1.null()}
		n:=3;if mode==5 {n=4}
		original,e:=asn1.marshal(asn1.sequence(fields[:n]));assert(e==.None);defer delete(original)
		der:=original
		if mode==10 {appended:=append_copy(der,0);defer delete(appended);der=appended}
		text,pe:=pem.encode("PRIVATE KEY",der);assert(pe==nil);defer delete(text)
		a:=Audit{backing=context.allocator};h,ce:=create(ec_cert,text,{},audit_allocator(&a))
		if mode==0 {testing.expect_value(t,ce,.None);testing.expect(t,h!=nil)} else {testing.expect(t,h==nil && ce!=.None,fmt.tprintf("pkcs8 mode%d",mode))}
		destroy(&h);audit_clean(t,&a)
	}
}
