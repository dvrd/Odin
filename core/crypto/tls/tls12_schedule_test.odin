package tls
import "core:bytes"
import "core:crypto"
import "core:encoding/hex"
import "core:mem"
import "core:testing"

tls12_test_bytes :: proc(text: string) -> []u8 {
 data,err:=hex.decode(transmute([]u8)text);assert(err==nil);return data
}
tls12_test_array :: proc($N:int,text:string) -> (out:[N]u8) {
 data:=tls12_test_bytes(text);defer delete(data);assert(len(data)==N);copy(out[:],data);return
}

// Published SHA256 PRF vector, Botan official corpus (origin IETF TLS list):
// https://github.com/randombit/botan/blob/master/src/tests/data/kdf/tls_prf.vec
@(test)
tls12_prf_published_vector :: proc(t:^testing.T) {
 secret:=tls12_test_bytes("9bbe436ba940f017b17652849a71db35");defer delete(secret)
 seed:=tls12_test_bytes("a0ba9f936cda311827a6f796ffd5198c");defer delete(seed)
 expected:=tls12_test_bytes("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66");defer delete(expected)
 context.allocator=mem.nil_allocator();context.temp_allocator=mem.nil_allocator()
 out:[100]u8
 testing.expect_value(t,tls12_prf_sha256(secret,"test label",seed,out[:]),.None)
 testing.expect(t,bytes.equal(out[:],expected))
 for n in 0..=100 {
  prefix:[100]u8
  testing.expect_value(t,tls12_prf_sha256(secret,"test label",seed,prefix[:n]),.None)
  testing.expect(t,bytes.equal(prefix[:n],expected[:n]))
 }
}

// Independent Python stdlib HMAC reference: evidence/tls12-primitives/reference.py.
@(test)
tls12_schedule_reference :: proc(t:^testing.T) {
 secret:=tls12_test_array(32,"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
 client:=tls12_test_array(32,"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
 server:=tls12_test_array(32,"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
 digest:=tls12_test_array(32,"145e3a23a8405718b35fb1aee0be9b06b0f18cb5815d611a416a0972907ffbc4")
 expected_master:=tls12_test_array(48,"518bc65fd30dabe86349152f98435c94d907b50c92a931c5a2f9e3a4d90f3439f2726c763fb1a40aec90b8bc60173f7c")
 expected_ems:=tls12_test_array(48,"e8157b0a4806515d2b8c972eb7d0f3f2515338b0d4a0a88e4122fd20cb3e727a975845ffca349bb6a127fe823ad6a851")
 expected_keys:=tls12_test_array(40,"fd3f04d6ac8f1220efa20d4e7ce8de6c532c6b7b42ba15560a98a22dee66d495294e191f0a967ced")
 expected_client_finished:=tls12_test_array(12,"94a0f21deb461681b6918f24")
 expected_server_finished:=tls12_test_array(12,"9da30a8a9dee0ded8ad6ad16")
 context.allocator=mem.nil_allocator();context.temp_allocator=mem.nil_allocator()
 master,e:=tls12_master_secret(secret[:],client,server);testing.expect_value(t,e,.None)
 testing.expect_value(t,master,expected_master)
 ems,ee:=tls12_extended_master_secret(secret[:],digest);testing.expect_value(t,ee,.None)
 testing.expect_value(t,ems,expected_ems);testing.expect(t,ems!=master)
 keys:=tls12_key_block(ems,client,server)
 testing.expect(t,bytes.equal(keys.client_key[:],expected_keys[:16]))
 testing.expect(t,bytes.equal(keys.server_key[:],expected_keys[16:32]))
 testing.expect(t,bytes.equal(keys.client_iv[:],expected_keys[32:36]))
 testing.expect(t,bytes.equal(keys.server_iv[:],expected_keys[36:]))
 testing.expect_value(t,tls12_finished_verify_data(ems,digest,false),expected_client_finished)
 testing.expect_value(t,tls12_finished_verify_data(ems,digest,true),expected_server_finished)
 tls12_key_block_clear(&keys)
 testing.expect(t,crypto.is_zero_constant_time(([^]u8)(rawptr(&keys))[:size_of(keys)])==1)
}

@(test)
tls12_prf_validation_preserves_sources :: proc(t:^testing.T) {
 storage:[5000]u8
 for &v in storage {v=0x5a}
 original:=storage
 cases:=[]struct{secret:[]u8,label:string,seed,dst:[]u8,error:TLS12_Schedule_Error}{
  {nil,"label",nil,storage[:32],.Invalid_Secret_Length},
  {storage[:513],"label",nil,storage[600:632],.Invalid_Secret_Length},
  {storage[:32],"",nil,storage[600:632],.Invalid_Label_Length},
  {storage[:32],string(storage[:65]),nil,storage[600:632],.Invalid_Label_Length},
  {storage[:32],"label",storage[:257],storage[600:632],.Seed_Oversized},
  {storage[:32],"label",nil,storage[600:4697],.Output_Oversized},
  {storage[:32],"label",nil,storage[:32],.Overlapping_Buffers},
  {storage[:32],"label",storage[600:632],storage[600:632],.Overlapping_Buffers},
  {storage[:32],string(storage[600:632]),nil,storage[600:632],.Overlapping_Buffers},
 }
 context.allocator=mem.nil_allocator();context.temp_allocator=mem.nil_allocator()
 for c in cases {
  testing.expect_value(t,tls12_prf_sha256(c.secret,c.label,c.seed,c.dst),c.error)
  testing.expect_value(t,storage,original)
 }
 // Long secrets exercise HMAC's hash-first branch without allocating.
 testing.expect_value(t,tls12_prf_sha256(storage[:512],"label",storage[520:776],storage[800:4896]),.None)
 invalid,ie:=tls12_master_secret(nil,[32]u8{},[32]u8{})
 testing.expect_value(t,ie,.Invalid_Secret_Length);testing.expect_value(t,invalid,[48]u8{})
}

@(test)
tls12_finished_framing_and_authentication :: proc(t:^testing.T) {
 master:[48]u8;hash:[32]u8
 for &v,i in master {v=u8(i)}
 message:[16]u8
 n,e:=tls12_finished_encode(message[:],master,hash,false)
 testing.expect(t,n==16 && e==.None)
 testing.expect_value(t,tls12_finished_verify(message[:],master,hash,false),.None)
 testing.expect_value(t,tls12_finished_verify(message[:],master,hash,true),.Verification_Failed)
 for i in 0..<len(message) {
  changed:=message;changed[i]~=1
  testing.expect(t,tls12_finished_verify(changed[:],master,hash,false)!=.None)
 }
 for cut in 0..<16 {testing.expect_value(t,tls12_finished_verify(message[:cut],master,hash,false),.Invalid_Length)}
 unchanged:=message
 _,small:=tls12_finished_encode(message[:15],master,hash,true)
 testing.expect_value(t,small,.Destination_Undersized);testing.expect_value(t,message,unchanged)
}
