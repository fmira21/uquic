#include "quic.h"
#include <liburing.h>

#define QUIC_SEND_BATCH 8

static int quic_wait_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_out) {
    int rc;

    for (;;) {
        rc = io_uring_wait_cqe(ring, cqe_out);
        if (rc == -EINTR) {
            continue;
        }
        return rc;
    }
}

static int quic_flush_sends(struct io_uring *ring, size_t count, const char *tag) {
    struct io_uring_cqe *cqe;
    size_t i;

    if (io_uring_submit(ring) < 0) {
        fprintf(stderr, "%s: io_uring_submit (send) failed\n", tag);
        return -1;
    }

    for (i = 0; i < count; i++) {
        int wret;

        if (quic_wait_cqe(ring, &cqe) < 0) {
            fprintf(stderr, "%s: io_uring_wait_cqe (send) failed\n", tag);
            return -1;
        }

        wret = cqe->res;
        io_uring_cqe_seen(ring, cqe);

        if (wret < 0) {
            if (-wret == ECONNREFUSED) {
                fprintf(stderr, "%s: send(): peer already gone (ECONNREFUSED), stopping\n", tag);
                return 1;
            }
            fprintf(stderr, "%s: send(): %s\n", tag, strerror(-wret));
            return -1;
        }
    }

    return 0;
}

int main() {
    int sock;
    int ret = 0;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    ngtcp2_crypto_ossl_ctx *ossl_ctx = NULL;
    ngtcp2_path_storage ps;
    quic_client client = {0};
    const char *host = "127.0.0.1";
    const char *port = "4433";
    uint8_t rbuf[65536];
    uint8_t sbuf[QUIC_SEND_BATCH][1452];
    struct io_uring ring;
    ngtcp2_pkt_info pi;
    ngtcp2_ccerr ccerr;
    ngtcp2_ssize close_ret;
    const char ping_msg[] = "ping";
    size_t ping_len = sizeof(ping_msg) - 1;
    size_t send_offset = 0;
    int64_t stream_id = -1;
    int stream_opened = 0;

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

    if (io_uring_queue_init(16, &ring, 0) != 0) {
        fprintf(stderr, "quic_client.c, main(): io_uring_queue_init failed\n");
        ret = -1;
        goto cleanup_ssl;
    }

    memset(&pi, 0, sizeof(pi));

    for (;;) {
        ngtcp2_tstamp now, expiry, diff;
        int timeout_ms;
        size_t send_pending = 0;

        if (client.handshake_done && !stream_opened) {
            if (ngtcp2_conn_open_bidi_stream(client.conn, &stream_id, NULL) != 0) {
                fprintf(stderr, "quic_client.c, main(): ngtcp2_conn_open_bidi_stream failed\n");
                ret = -1;
                goto cleanup_ring;
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
            struct io_uring_sqe *sqe;

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

            wlen = ngtcp2_conn_writev_stream(client.conn, &ps.path, &pi, sbuf[send_pending], sizeof(sbuf[send_pending]), &datalen, wflags, wstream_id, datav, datavcnt, now);

            if (wlen < 0) {
                fprintf(stderr, "quic_client.c, main(): ngtcp2_conn_writev_stream failed\n");
                ret = -1;
                goto cleanup_ring;
            }

            if (wlen == 0) {
                if (send_pending > 0) {
                    int fr = quic_flush_sends(&ring, send_pending, "quic_client.c, main()");

                    send_pending = 0;

                    if (fr == 1) {
                        goto cleanup_ring;
                    }
                    if (fr < 0) {
                        ret = -1;
                        goto cleanup_ring;
                    }
                }
                break;
            }

            if (datalen > 0 && wstream_id == stream_id) {
                send_offset += (size_t)datalen;
            }

            sqe = io_uring_get_sqe(&ring);
            if (sqe == NULL) {
                fprintf(stderr, "quic_client.c, main(): io_uring_get_sqe (send) returned NULL\n");
                ret = -1;
                goto cleanup_ring;
            }
            io_uring_prep_send(sqe, sock, sbuf[send_pending], (size_t)wlen, 0);
            send_pending++;

            if (send_pending == QUIC_SEND_BATCH) {
                int fr = quic_flush_sends(&ring, send_pending, "quic_client.c, main()");

                send_pending = 0;

                if (fr == 1) {
                    goto cleanup_ring;
                }
                if (fr < 0) {
                    ret = -1;
                    goto cleanup_ring;
                }
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
                goto cleanup_ring;
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

        {
            struct io_uring_sqe *rsqe;
            struct __kernel_timespec ts;
            int have_timeout = (timeout_ms >= 0);
            int recv_res = 0;
            int got_recv = 0;
            int pending = 1;

            rsqe = io_uring_get_sqe(&ring);
            if (rsqe == NULL) {
                fprintf(stderr, "quic_client.c, main(): io_uring_get_sqe (recv) returned NULL\n");
                ret = -1;
                goto cleanup_ring;
            }
            io_uring_prep_recv(rsqe, sock, rbuf, sizeof(rbuf), 0);
            io_uring_sqe_set_data(rsqe, (void *)(uintptr_t)1);

            if (have_timeout) {
                struct io_uring_sqe *tsqe;

                rsqe->flags |= IOSQE_IO_LINK;
                ts.tv_sec = timeout_ms / 1000;
                ts.tv_nsec = (long long)(timeout_ms % 1000) * 1000000;

                tsqe = io_uring_get_sqe(&ring);
                if (tsqe == NULL) {
                    fprintf(stderr, "quic_client.c, main(): io_uring_get_sqe (timeout) returned NULL\n");
                    ret = -1;
                    goto cleanup_ring;
                }
                io_uring_prep_link_timeout(tsqe, &ts, 0);
                io_uring_sqe_set_data(tsqe, (void *)(uintptr_t)2);
                pending = 2;
            }

            if (io_uring_submit(&ring) < 0) {
                fprintf(stderr, "quic_client.c, main(): io_uring_submit (recv) failed\n");
                ret = -1;
                goto cleanup_ring;
            }

            while (pending > 0) {
                struct io_uring_cqe *cqe;

                if (quic_wait_cqe(&ring, &cqe) < 0) {
                    fprintf(stderr, "quic_client.c, main(): io_uring_wait_cqe (recv) failed\n");
                    ret = -1;
                    goto cleanup_ring;
                }

                if ((uintptr_t)io_uring_cqe_get_data(cqe) == 1) {
                    recv_res = cqe->res;
                    got_recv = 1;
                }

                io_uring_cqe_seen(&ring, cqe);
                pending--;
            }

            if (got_recv && recv_res != -ECANCELED) {
                if (recv_res < 0) {
                    if (-recv_res == ECONNREFUSED) {
                        fprintf(stderr, "quic_client.c, main(): recv(): peer already gone (ECONNREFUSED), stopping\n");
                        goto cleanup_ring;
                    }
                    fprintf(stderr, "quic_client.c, main(): recv(): %s\n", strerror(-recv_res));
                    ret = -1;
                    goto cleanup_ring;
                }

                now = quic_timestamp();

                if (ngtcp2_conn_read_pkt(client.conn, &ps.path, &pi, rbuf, (size_t)recv_res, now) != 0) {
                    fprintf(stderr, "quic_client.c, main(): ngtcp2_conn_read_pkt failed\n");
                    ret = -1;
                    goto cleanup_ring;
                }
            }
        }
    }

    ngtcp2_ccerr_default(&ccerr);
    close_ret = ngtcp2_conn_write_connection_close(client.conn, &ps.path, &pi, sbuf[0], sizeof(sbuf[0]), &ccerr, quic_timestamp());
    if (close_ret > 0) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        struct io_uring_cqe *cqe;

        if (sqe == NULL) {
            fprintf(stderr, "quic_client.c, main(): io_uring_get_sqe (connection_close) returned NULL\n");
        } else {
            io_uring_prep_send(sqe, sock, sbuf[0], (size_t)close_ret, 0);

            if (io_uring_submit(&ring) < 0 || quic_wait_cqe(&ring, &cqe) < 0) {
                fprintf(stderr, "quic_client.c, main(): io_uring send for connection_close failed\n");
            } else {
                if (cqe->res < 0) {
                    fprintf(stderr, "quic_client.c, main(): send() for connection_close failed (peer likely already gone): %s\n", strerror(-cqe->res));
                }
                io_uring_cqe_seen(&ring, cqe);
            }
        }
    }

    io_uring_queue_exit(&ring);

    if (client.conn) {
        ngtcp2_conn_del(client.conn);
    }
    ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sock);

    return 0;

cleanup_ring:
    io_uring_queue_exit(&ring);
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
