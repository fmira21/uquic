#include "quic.h"

int main() {
    int sock;
    int ret;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    ngtcp2_crypto_ossl_ctx *ossl_ctx = NULL;
    quic_server server = {0};
    const char *host = "127.0.0.1";
    const char *port = "4433";
    const char *cert_file = "cert.pem";
    const char *key_file = "key.pem";

    ret = 0;

    server.conn_ref.user_data = &server;

    sock = quic_create_listen_socket(host, port);
    if (sock < 0) {
        fprintf(stderr, "quic_server.c, main(): quic_create_listen_socket failed");
        return -1;
    }

    fprintf(stderr, "quic_server.c, main(): listening on %s:%s\n", host, port);

    if (quic_create_server_ssl_ctx(cert_file, key_file, &ssl_ctx) != 0) {
        ret = -1;
        goto cleanup_sock;
    }

    if (quic_setup_server_tls_session(ssl_ctx, &server.conn_ref, &ssl, &ossl_ctx) != 0) {
        ret = -1;
        goto cleanup_ssl_ctx;
    }

    fprintf(stderr, "quic_server.c, main(): server TLS session ready\n");

    ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
    SSL_free(ssl);
cleanup_ssl_ctx:
    SSL_CTX_free(ssl_ctx);
cleanup_sock:
    close(sock);
    return ret;
}
