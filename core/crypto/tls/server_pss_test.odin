package tls

import "core:testing"
import "core:time"
import credentials "credentials"
import credential_store "credentials/store"

@(test)
server_pss_sha256_certificate_chain_admission :: proc(t:^testing.T) {
	for mode in 0..<10 {
		chain:=#load("../../../tests/core/crypto/tls/credentials/testdata/pss-rsa-chain.pem")
		key:=#load("../../../tests/core/crypto/tls/credentials/testdata/rsa2048.pem")
		if mode==1 {chain=#load("../../../tests/core/crypto/tls/credentials/testdata/pss-ec-chain.pem");key=#load("../../../tests/core/crypto/tls/credentials/testdata/p256.pem")}
		if mode==2 {chain=#load("../../../tests/core/crypto/tls/credentials/testdata/pss-salt20-chain.pem")}
		if mode==3 {chain=#load("../../../tests/core/crypto/tls/credentials/testdata/pss-sha384-chain.pem")}
		if mode==4 {chain=#load("../../../tests/core/crypto/tls/credentials/testdata/pss-mgf384-chain.pem")}
		if mode==5 {chain=#load("../../../tests/core/crypto/tls/credentials/testdata/pss-wrong-issuer-chain.pem")}
		credential,ce:=credentials.create(chain,key,{},context.allocator);testing.expect_value(t,ce,.None);assert(credential!=nil)
		defer credentials.destroy(&credential)
		metadata,me:=credentials.certificate_algorithms(credential,0);testing.expect_value(t,me,.None);testing.expect_value(t,metadata.signature,.RSA_PSS)
		store,se:=credential_store.create({},context.allocator);assert(se.kind==.None);defer credential_store.destroy(&store)
		assert(credential_store.replace(store,&credential).kind==.None)
		share:=hello_test_share();base:=hello_test_extensions(share[:]);base[2].data=[]u8{0,4,8,4,4,3}
		exts:[6]Hello_Test_Extension;copy(exts[:],base[:]);exts[5]={50,[]u8{0,2,8,4}}
		if mode==6 {exts[5].data=[]u8{0,2,4,1}}
		if mode==8 {exts[5].data=[]u8{0,2,8,9}}
		if mode==9 {exts[2].data=[]u8{0,2,4,3}} // Key-specific CV scheme absent.
		storage:[1024]u8;hello:=hello_test_wire(storage[:],exts[:5 if mode==7 else 6])
		a:=Owner_Test_Audit{backing=context.allocator};o:Server_Handshake;owner_test_ready(t,&o,&a,hello)
		e:=server_handshake_start_flight(&o,store,time.from_nanoseconds(1790000000*1000000000))
		good:=mode==0 || mode==1 || mode==7
		testing.expect_value(t,e,.None if good else .Unsupported)
		before,_:=credential_store.stats(store);testing.expect_value(t,before.active_leases,1 if good else 0)
		server_handshake_destroy(&o);owner_test_clean(t,&a)
		after,_:=credential_store.stats(store);testing.expect_value(t,after.active_leases,0)
	}
}
