#include "quic.h"
#include <poll.h>

int main() {
    int sock;
    int ret;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    ngtcp2_crypto_ossl_ctx *ossl_ctx = NULL;
    ngtcp2_path_storage ps;
    quic_client client = {0};
    const char *host = "127.0.0.1";
    const char *port = "4433";
    uint8_t rbuf[65536];
    uint8_t sbuf[1452];
    struct pollfd pfd;
    ngtcp2_pkt_info pi;
    ngtcp2_ccerr ccerr;
    ngtcp2_ssize close_ret;
    const char ping_msg[] = "ping";
    size_t ping_len = sizeof(ping_msg) - 1;
    size_t send_offset = 0;
    int64_t stream_id = -1;
    int stream_opened = 0;

    ret = 0;

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

        if (client.handshake_done && !stream_opened) {
            if (ngtcp2_conn_open_bidi_stream(client.conn, &stream_id, NULL) != 0) {
                fprintf(stderr, "quic_client.c, main(): ngtcp2_conn_open_bidi_stream failed\n");
                ret = -1;
                goto cleanup_ssl;
            }
            stream_opened = 1;
        }

        for (;;) {
            ngtcp2_ssize datalen, wlen;
            ngtcp2_vec vec;
            const ngtcp2_vec *datav;
            size_t datavcnt;
            int64_t wstream_id;
            uint32_t wflags;

            now = quic_timestamp();

            if (stream_opened && send_offset < ping_len) {
                vec.base = (uint8_t *)ping_msg + send_offset;
                vec.len = ping_len - send_offset;
                datav = &vec;
                datavcnt = 1;
                wstream_id = stream_id;
                wflags = NGTCP2_WRITE_STREAM_FLAG_FIN;
            } else {
                datav = NULL;
                datavcnt = 0;
                wstream_id = -1;
                wflags = 0;
            }

            wlen = ngtcp2_conn_writev_stream(client.conn, &ps.path, &pi, sbuf, sizeof(sbuf), &datalen, wflags, wstream_id, datav, datavcnt, now);

            if (wlen < 0) {
                fprintf(stderr, "quic_client.c, main(): ngtcp2_conn_writev_stream failed\n");
                ret = -1;
                goto cleanup_ssl;
            }

            if (wlen == 0) {
                break;
            }

            if (datalen > 0 && wstream_id == stream_id) {
                send_offset += (size_t)datalen;
            }

            if (send(sock, sbuf, (size_t)wlen, 0) < 0) {
                if (errno == ECONNREFUSED) {
                    fprintf(stderr, "quic_client.c, main(): send(): peer already gone (ECONNREFUSED), stopping\n");
                    goto cleanup_ssl;
                }
                fprintf(stderr, "quic_client.c, main(): send(): %s\n", strerror(errno));
                ret = -1;
                goto cleanup_ssl;
            }
        }

        if (client.pong_received) {
            break;
        }

        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(client.conn);

        if (expiry <= now) {
            if (ngtcp2_conn_handle_expiry(client.conn, now) != 0) {
                fprintf(stderr, "quic_client.c, main(): ngtcp2_conn_handle_expiry failed\n");
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
            fprintf(stderr, "quic_client.c, main(): poll(): %s\n", strerror(errno));
            ret = -1;
            goto cleanup_ssl;
        }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(sock, rbuf, sizeof(rbuf), 0);

            if (n < 0) {
                if (errno == ECONNREFUSED) {
                    fprintf(stderr, "quic_client.c, main(): recv(): peer already gone (ECONNREFUSED), stopping\n");
                    goto cleanup_ssl;
                }
                fprintf(stderr, "quic_client.c, main(): recv(): %s\n", strerror(errno));
                ret = -1;
                goto cleanup_ssl;
            }

            now = quic_timestamp();

            if (ngtcp2_conn_read_pkt(client.conn, &ps.path, &pi, rbuf, (size_t)n, now) != 0) {
                fprintf(stderr, "quic_client.c, main(): ngtcp2_conn_read_pkt failed\n");
                ret = -1;
                goto cleanup_ssl;
            }
        }
    }

    ngtcp2_ccerr_default(&ccerr);
    close_ret = ngtcp2_conn_write_connection_close(client.conn, &ps.path, &pi, sbuf, sizeof(sbuf), &ccerr, quic_timestamp());
    if (close_ret > 0) {
        if (send(sock, sbuf, (size_t)close_ret, 0) < 0) {
            fprintf(stderr, "quic_client.c, main(): send() for connection_close failed (peer likely already gone): %s\n", strerror(errno));
        }
    }

    if (client.conn) {
        ngtcp2_conn_del(client.conn);
    }
    ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sock);

    return 0;

cleanup_ssl:
    if (client.conn) {
        ngtcp2_conn_del(client.conn);
    }
    ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
    SSL_free(ssl);
cleanup_ssl_ctx:
    SSL_CTX_free(ssl_ctx);
cleanup_sock:
    close(sock);
    return ret;
}
