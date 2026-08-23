#include "quic.h"
#include <poll.h>

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
    uint8_t rbuf[65536];
    uint8_t sbuf[1452];
    struct pollfd pfd;
    ngtcp2_pkt_info pi;

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

    pfd.fd = sock;
    pfd.events = POLLIN;
    memset(&pi, 0, sizeof(pi));

    for (;;) {
        ngtcp2_tstamp now, expiry, diff;
        int timeout_ms, pr;

        for (;;) {
            ngtcp2_ssize datalen, wlen;

            now = quic_timestamp();
            wlen = ngtcp2_conn_writev_stream(client.conn, &ps.path, &pi, sbuf, sizeof(sbuf), &datalen, 0, -1, NULL, 0, now);

            if (wlen < 0) {
                fprintf(stderr, "quic_main.c, main(): ngtcp2_conn_writev_stream failed\n");
                ret = -1;
                goto cleanup_ssl;
            }

            if (wlen == 0) {
                break;
            }

            if (send(sock, sbuf, (size_t)wlen, 0) < 0) {
                fprintf(stderr, "quic_main.c, main(): send(): %s\n", strerror(errno));
                ret = -1;
                goto cleanup_ssl;
            }
        }

        if (client.handshake_done) {
            break;
        }

        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(client.conn);

        if (expiry <= now) {
            if (ngtcp2_conn_handle_expiry(client.conn, now) != 0) {
                fprintf(stderr, "quic_main.c, main(): ngtcp2_conn_handle_expiry failed\n");
                ret = -1;
                goto cleanup_ssl;
            }
            now = quic_timestamp();
            expiry = ngtcp2_conn_get_expiry(client.conn);
        }

        if (expiry == UINT64_MAX) {
            timeout_ms = -1;
        } else {
            diff = expiry > now ? expiry - now : 0;
            timeout_ms = (int)((diff + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS);
        }

        pr = poll(&pfd, 1, timeout_ms);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "quic_main.c, main(): poll(): %s\n", strerror(errno));
            ret = -1;
            goto cleanup_ssl;
        }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(sock, rbuf, sizeof(rbuf), 0);

            if (n < 0) {
                fprintf(stderr, "quic_main.c, main(): recv(): %s\n", strerror(errno));
                ret = -1;
                goto cleanup_ssl;
            }

            now = quic_timestamp();

            if (ngtcp2_conn_read_pkt(client.conn, &ps.path, &pi, rbuf, (size_t)n, now) != 0) {
                fprintf(stderr, "quic_main.c, main(): ngtcp2_conn_read_pkt failed\n");
                ret = -1;
                goto cleanup_ssl;
            }
        }
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
