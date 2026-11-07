/* Memory BIO ClientHello capture; no socket or external traffic.
 * cc $(pkg-config --cflags openssl) SOURCE -o OUTPUT $(pkg-config --libs openssl)
 */
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
int main(void) {
 SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());
 if(!ctx || !SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION) ||
    !SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION) ||
    !SSL_CTX_set_ciphersuites(ctx,"TLS_AES_128_GCM_SHA256") ||
    !SSL_CTX_set1_groups_list(ctx,"X25519")) return 1;
 SSL *ssl=SSL_new(ctx);
 BIO *read_bio=BIO_new(BIO_s_mem()), *write_bio=BIO_new(BIO_s_mem());
 if(!ssl||!read_bio||!write_bio) return 2;
 SSL_set_bio(ssl,read_bio,write_bio);
 SSL_set_tlsext_host_name(ssl,"fixture.invalid");
 const unsigned char alpn[]={2,'h','2',8,'h','t','t','p','/','1','.','1'};
 if(SSL_set_alpn_protos(ssl,alpn,sizeof(alpn))) return 3;
 SSL_set_connect_state(ssl);
 int result=SSL_do_handshake(ssl);
 if(result!=-1 || SSL_get_error(ssl,result)!=SSL_ERROR_WANT_READ) return 4;
 unsigned char records[65536];
 int n=BIO_read(write_bio,records,sizeof(records));
 FILE *f=fopen("core/crypto/tls/testdata/server_openssl_client_hello.wire","wb");
 if(!f) return 5;
 for(int at=0;at<n;) {
   if(n-at<5) return 6;
   int length=(records[at+3]<<8)|records[at+4];
   if(length>n-at-5) return 7;
   if(records[at]==22 && fwrite(records+at+5,1,length,f)!=(size_t)length) return 8;
   at+=5+length;
 }
 fclose(f);
 printf("%s: captured %d record bytes using memory BIO only\n",OpenSSL_version(OPENSSL_VERSION),n);
 SSL_free(ssl); SSL_CTX_free(ctx); return 0;
}
