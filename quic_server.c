#include "quic.h"
#include <poll.h>

int main() {
    int sock;
    int ret;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    ngtcp2_crypto_ossl_ctx *ossl_ctx = NULL;
    ngtcp2_path_storage ps;
    quic_server server = {0};
    const char *host = "127.0.0.1";
    const char *port = "4433";
    const char *cert_file = "cert.pem";
    const char *key_file = "key.pem";
    uint8_t rbuf[65536];
    uint8_t sbuf[1452];
    struct sockaddr_storage peer_addr;
    socklen_t peer_len;
    ssize_t n;
    ngtcp2_pkt_hd hd;
    ngtcp2_pkt_info pi;
    struct pollfd pfd;

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

    peer_len = sizeof(peer_addr);
    n = recvfrom(sock, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&peer_addr, &peer_len);
    if (n < 0) {
        fprintf(stderr, "quic_server.c, main(): recvfrom(): %s\n", strerror(errno));
        ret = -1;
        goto cleanup_ssl;
    }

    if (connect(sock, (struct sockaddr *)&peer_addr, peer_len) != 0) {
        fprintf(stderr, "quic_server.c, main(): connect(): %s\n", strerror(errno));
        ret = -1;
        goto cleanup_ssl;
    }

    if (quic_setup_path(sock, &ps) != 0) {
        fprintf(stderr, "quic_server.c, main(): quic_setup_path failed\n");
        ret = -1;
        goto cleanup_ssl;
    }

    if (ngtcp2_accept(&hd, rbuf, (size_t)n) != 0) {
        fprintf(stderr, "quic_server.c, main(): ngtcp2_accept failed\n");
        ret = -1;
        goto cleanup_ssl;
    }

    if (quic_setup_server_conn(&ps, ossl_ctx, &server, &hd) != 0) {
        ret = -1;
        goto cleanup_ssl;
    }

    memset(&pi, 0, sizeof(pi));

    if (ngtcp2_conn_read_pkt(server.conn, &ps.path, &pi, rbuf, (size_t)n, quic_timestamp()) != 0) {
        fprintf(stderr, "quic_server.c, main(): ngtcp2_conn_read_pkt failed\n");
        ret = -1;
        goto cleanup_ssl;
    }

    fprintf(stderr, "quic_server.c, main(): first Initial packet accepted, connection established\n");

    pfd.fd = sock;
    pfd.events = POLLIN;

    for (;;) {
        ngtcp2_tstamp now, expiry, diff;
        int timeout_ms, pr;

        for (;;) {
            ngtcp2_ssize datalen, wlen;

            now = quic_timestamp();
            wlen = ngtcp2_conn_writev_stream(server.conn, &ps.path, &pi, sbuf, sizeof(sbuf), &datalen, 0, -1, NULL, 0, now);

            if (wlen < 0) {
                fprintf(stderr, "quic_server.c, main(): ngtcp2_conn_writev_stream failed\n");
                ret = -1;
                goto cleanup_ssl;
            }

            if (wlen == 0) {
                break;
            }

            if (send(sock, sbuf, (size_t)wlen, 0) < 0) {
                fprintf(stderr, "quic_server.c, main(): send(): %s\n", strerror(errno));
                ret = -1;
                goto cleanup_ssl;
            }
        }

        if (server.handshake_done) {
            break;
        }

        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(server.conn);

        if (expiry <= now) {
            if (ngtcp2_conn_handle_expiry(server.conn, now) != 0) {
                fprintf(stderr, "quic_server.c, main(): ngtcp2_conn_handle_expiry failed\n");
                ret = -1;
                goto cleanup_ssl;
            }
            now = quic_timestamp();
            expiry = ngtcp2_conn_get_expiry(server.conn);
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
            fprintf(stderr, "quic_server.c, main(): poll(): %s\n", strerror(errno));
            ret = -1;
            goto cleanup_ssl;
        }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            ssize_t rn = recv(sock, rbuf, sizeof(rbuf), 0);

            if (rn < 0) {
                fprintf(stderr, "quic_server.c, main(): recv(): %s\n", strerror(errno));
                ret = -1;
                goto cleanup_ssl;
            }

            now = quic_timestamp();

            if (ngtcp2_conn_read_pkt(server.conn, &ps.path, &pi, rbuf, (size_t)rn, now) != 0) {
                fprintf(stderr, "quic_server.c, main(): ngtcp2_conn_read_pkt failed\n");
                ret = -1;
                goto cleanup_ssl;
            }
        }
    }

    fprintf(stderr, "quic_server.c, main(): handshake done\n");

cleanup_ssl:
    if (server.conn) {
        ngtcp2_conn_del(server.conn);
    }
    ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
    SSL_free(ssl);
cleanup_ssl_ctx:
    SSL_CTX_free(ssl_ctx);
cleanup_sock:
    close(sock);
    return ret;
}
