/* Independent standard OpenSSL client for the actual native async TCP driver. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sslerr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#define PAYLOAD 40960
static void require(int ok, const char *operation) {
    if (!ok) {fprintf(stderr,"%s failed\n",operation);ERR_print_errors_fp(stderr);exit(1);}
}
int main(int argc,char **argv) {
    require(argc==5,"endpoint CA-file groups mode");
    alarm(20);signal(SIGPIPE,SIG_IGN);
    const char *mode=argv[4];int ec_only=!strncmp(mode,"ecdsa",5)||!strcmp(mode,"pss-ec-no-offer");
    int pss_case=!strncmp(mode,"pss-",4);
    int protocol_negative=strstr(mode,"unsupported")!=NULL||!strcmp(mode,"pss-ec-no-offer");
    if(!strncmp(mode,"ecdsa-",6))mode+=6;
    int negative=0;long expected=0;
    if(!strcmp(mode,"pss-tampered")){negative=1;expected=X509_V_ERR_CERT_SIGNATURE_FAILURE;}
    if(!strcmp(mode,"trust")){negative=1;expected=18;}
    if(!strcmp(mode,"hostname")){negative=1;expected=62;}
    if(!strcmp(mode,"time")){negative=1;expected=10;}
    if(!strcmp(mode,"before")){negative=1;expected=9;}
    SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());require(ctx!=NULL,"context");
    require(SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION),"min TLS1.3");
    require(SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION),"max TLS1.3");
    require(SSL_CTX_set_ciphersuites(ctx,"TLS_AES_128_GCM_SHA256"),"cipher");
    require(SSL_CTX_set1_groups_list(ctx,argv[3]),"groups");
    require(SSL_CTX_set1_sigalgs_list(ctx,ec_only?"ecdsa_secp256r1_sha256":(pss_case?"ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256":"rsa_pss_rsae_sha256:rsa_pkcs1_sha256")),"signatures");
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    require(SSL_CTX_load_verify_locations(ctx,argv[2],NULL),"fixture roots");
    SSL_CTX_set_max_cert_list(ctx,1049088);
    X509_VERIFY_PARAM_set_time(SSL_CTX_get0_param(ctx),!strcmp(mode,"time")?2000000000:(!strcmp(mode,"before")?0:1790000000));
    const unsigned char offers[]={2,'h','2',8,'h','t','t','p','/','1','.','1'};
    require(SSL_CTX_set_alpn_protos(ctx,offers,sizeof offers)==0,"ALPN offers");
    BIO *bio=BIO_new_ssl_connect(ctx);require(bio!=NULL,"connect BIO");
    SSL *ssl=NULL;BIO_get_ssl(bio,&ssl);require(ssl!=NULL,"SSL handle");
    require(SSL_set_tlsext_host_name(ssl,"synthetic.invalid"),"SNI");
    require(X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl),!strcmp(mode,"hostname")?"wrong.invalid":"synthetic.invalid",0),"hostname");
    require(BIO_set_conn_hostname(bio,argv[1]),"owned endpoint");
    int connected=BIO_do_connect(bio)>0&&BIO_do_handshake(bio)>0;
    if(protocol_negative){require(!connected && ERR_GET_REASON(ERR_peek_last_error())==SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE,"exact remote handshake_failure");fprintf(stdout,"OpenSSL remote handshake_failure %s PASS\n",mode);BIO_free_all(bio);SSL_CTX_free(ctx);return 0;}
    if(negative){require(!connected && SSL_get_verify_result(ssl)==expected,"exact verification rejection");fprintf(stdout,"OpenSSL typed rejection %s code=%ld PASS\n",mode,expected);BIO_free_all(bio);SSL_CTX_free(ctx);return 0;}
    require(connected && SSL_get_verify_result(ssl)==X509_V_OK,"verified handshake");
    const unsigned char *selected=NULL;unsigned int selected_size=0;SSL_get0_alpn_selected(ssl,&selected,&selected_size);
    require(selected_size==8&&!memcmp(selected,"http/1.1",8),"server-preferred ALPN");
    unsigned char received[PAYLOAD],sent[PAYLOAD];size_t at=0,n=0;
    while(at<PAYLOAD){require(SSL_read_ex(ssl,received+at,PAYLOAD-at,&n)&&n>0,"server application data");at+=n;}
    for(size_t i=0;i<PAYLOAD;i++){require(received[i]==(unsigned char)(255-i),"server bytes");sent[i]=(unsigned char)i;}
    if(!strcmp(mode,"key-update")||!strcmp(mode,"pss-ec-key-update")){require(SSL_key_update(ssl,SSL_KEY_UPDATE_REQUESTED),"request KeyUpdate");require(SSL_do_handshake(ssl)>0,"flush KeyUpdate");}
    at=0;while(at<PAYLOAD){require(SSL_write_ex(ssl,sent+at,PAYLOAD-at,&n)&&n>0,"client application data");at+=n;}
    unsigned char extra[1];int end=SSL_read_ex(ssl,extra,sizeof extra,&n);
    require(!end&&SSL_get_error(ssl,end)==SSL_ERROR_ZERO_RETURN,"authenticated close_notify");
    (void)SSL_shutdown(ssl);BIO_free_all(bio);SSL_CTX_free(ctx);
    fprintf(stdout,"OpenSSL native async %s group=%s bytes=40960+40960 %s PASS\n",mode,argv[3],OpenSSL_version(OPENSSL_VERSION));return 0;
}
