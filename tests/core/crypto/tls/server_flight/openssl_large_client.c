/* Independent OpenSSL client with an explicit certificate-message budget.
 * Fixture only; no record/crypto implementation and no production interface. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(int ok, const char *operation) {
    if (!ok) { fprintf(stderr, "%s failed\n", operation); ERR_print_errors_fp(stderr); exit(1); }
}
int main(int argc, char **argv) {
    require(argc == 3, "arguments: loopback-address CA-file");
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method()); require(ctx != NULL, "SSL_CTX_new");
    require(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION), "min TLS1.3");
    require(SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION), "max TLS1.3");
    require(SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"), "cipher");
    require(SSL_CTX_set1_groups_list(ctx, "X25519"), "group");
    require(SSL_CTX_set1_sigalgs_list(ctx, "rsa_pss_rsae_sha256:rsa_pkcs1_sha256"), "signature algorithms");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    require(SSL_CTX_load_verify_locations(ctx, argv[2], NULL), "fixture roots");
    SSL_CTX_set_max_cert_list(ctx, 1049088); /* 1MiB DER plus bounded wire overhead. */
    X509_VERIFY_PARAM_set_time(SSL_CTX_get0_param(ctx), 1790000000);
    BIO *bio = BIO_new_ssl_connect(ctx); require(bio != NULL, "BIO_new_ssl_connect");
    SSL *ssl = NULL; BIO_get_ssl(bio, &ssl); require(ssl != NULL, "SSL handle");
    require(SSL_set_tlsext_host_name(ssl, "synthetic.invalid"), "SNI");
    require(X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), "synthetic.invalid", 0), "hostname");
    require(BIO_set_conn_hostname(bio, argv[1]), "loopback address");
    require(BIO_do_connect(bio) > 0 && BIO_do_handshake(bio) > 0, "verified handshake");
    require(SSL_get_verify_result(ssl) == X509_V_OK, "verification result");
    unsigned char server[6], client[7]; size_t at = 0, n = 0;
    while (at < sizeof(server)) {require(SSL_read_ex(ssl, server+at, sizeof(server)-at, &n) && n > 0, "server data"); at += n;}
    require(memcmp(server, "server", 6) == 0, "server bytes");
    require(fwrite(server, 1, sizeof(server), stdout) == sizeof(server) && fflush(stdout) == 0, "stdout");
    require(fread(client, 1, sizeof(client), stdin) == sizeof(client), "stdin");
    require(memcmp(client, "client\n", 7) == 0, "client bytes");
    at = 0;
    while (at < sizeof(client)) {require(SSL_write_ex(ssl, client+at, sizeof(client)-at, &n) && n > 0, "client data"); at += n;}
    fprintf(stderr, "OpenSSL C client: %s max_cert_list=%ld\n", OpenSSL_version(OPENSSL_VERSION), SSL_CTX_get_max_cert_list(ctx));
    (void)SSL_shutdown(ssl); /* First call sends close_notify, without waiting. */
    BIO_free_all(bio); SSL_CTX_free(ctx); return 0;
}
