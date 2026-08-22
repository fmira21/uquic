#include "quic.h"

int main() {
    int sock;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    ngtcp2_crypto_ossl_ctx *ossl_ctx = NULL;
    ngtcp2_path_storage ps;
    quic_client client = {0};
    const char *host = "127.0.0.1";
    const char *port = "4433";
    int ret = 0;

    client.conn_ref.user_data = &client;

    sock = quic_create_socket(host, port);
    if (sock < 0) {
        return -1;
    }

    if (quic_setup_path(sock, &ps) != 0) {
        ret = -1;
        goto cleanup_sock;
    }

    if (quic_create_ssl_ctx(&ssl_ctx) != 0) {
        ret = -1;
        goto cleanup_sock;
    }

    if (quic_setup_tls_session(ssl_ctx, host, &client.conn_ref, &ssl, &ossl_ctx) != 0) {
        ret = -1;
        goto cleanup_ssl_ctx;
    }

    if (quic_setup_conn(&ps, ossl_ctx, &client) != 0) {
        ret = -1;
        goto cleanup_ssl;
    }

    return 0;

cleanup_ssl:
    SSL_free(ssl);
cleanup_ssl_ctx:
    SSL_CTX_free(ssl_ctx);
cleanup_sock:
    close(sock);
    return ret;
}
