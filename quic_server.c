#include "quic.h"
#include <liburing.h>

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

int main() {
    int sock;
    int ret = 0;
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
    struct io_uring ring;
    ngtcp2_ccerr ccerr;
    ngtcp2_ssize close_ret;
    const char pong_msg[] = "pong";
    size_t pong_len = sizeof(pong_msg) - 1;
    size_t send_offset = 0;

    server.conn_ref.user_data = &server;
    server.stream_id = -1;

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

    if (io_uring_queue_init(8, &ring, 0) != 0) {
        fprintf(stderr, "quic_server.c, main(): io_uring_queue_init failed\n");
        ret = -1;
        goto cleanup_ssl;
    }

    for (;;) {
        ngtcp2_tstamp now, expiry, diff;
        int timeout_ms;

        for (;;) {
            ngtcp2_ssize datalen, wlen;
            ngtcp2_vec vec;
            const ngtcp2_vec *datav;
            size_t datavcnt;
            int64_t wstream_id;
            uint32_t wflags;
            struct io_uring_sqe *sqe;
            struct io_uring_cqe *cqe;
            int wret;

            now = quic_timestamp();

            if (server.ping_received && send_offset < pong_len) {
                vec.base = (uint8_t *)pong_msg + send_offset;
                vec.len = pong_len - send_offset;
                datav = &vec;
                datavcnt = 1;
                wstream_id = server.stream_id;
                wflags = NGTCP2_WRITE_STREAM_FLAG_FIN;
            } else {
                datav = NULL;
                datavcnt = 0;
                wstream_id = -1;
                wflags = 0;
            }

            wlen = ngtcp2_conn_writev_stream(server.conn, &ps.path, &pi, sbuf, sizeof(sbuf), &datalen, wflags, wstream_id, datav, datavcnt, now);

            if (wlen < 0) {
                fprintf(stderr, "quic_server.c, main(): ngtcp2_conn_writev_stream failed\n");
                ret = -1;
                goto cleanup_ring;
            }

            if (wlen == 0) {
                break;
            }

            if (datalen > 0 && wstream_id == server.stream_id) {
                send_offset += (size_t)datalen;
            }

            sqe = io_uring_get_sqe(&ring);
            if (sqe == NULL) {
                fprintf(stderr, "quic_server.c, main(): io_uring_get_sqe (send) returned NULL\n");
                ret = -1;
                goto cleanup_ring;
            }
            io_uring_prep_send(sqe, sock, sbuf, (size_t)wlen, 0);

            if (io_uring_submit(&ring) < 0) {
                fprintf(stderr, "quic_server.c, main(): io_uring_submit (send) failed\n");
                ret = -1;
                goto cleanup_ring;
            }

            if (quic_wait_cqe(&ring, &cqe) < 0) {
                fprintf(stderr, "quic_server.c, main(): io_uring_wait_cqe (send) failed\n");
                ret = -1;
                goto cleanup_ring;
            }

            wret = cqe->res;
            io_uring_cqe_seen(&ring, cqe);

            if (wret < 0) {
                if (-wret == ECONNREFUSED) {
                    fprintf(stderr, "quic_server.c, main(): send(): peer already gone (ECONNREFUSED), stopping\n");
                    goto cleanup_ring;
                }
                fprintf(stderr, "quic_server.c, main(): send(): %s\n", strerror(-wret));
                ret = -1;
                goto cleanup_ring;
            }
        }

        if (server.ping_received && send_offset >= pong_len) {
            break;
        }

        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(server.conn);

        if (expiry <= now) {
            if (ngtcp2_conn_handle_expiry(server.conn, now) != 0) {
                fprintf(stderr, "quic_server.c, main(): ngtcp2_conn_handle_expiry failed\n");
                ret = -1;
                goto cleanup_ring;
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

        {
            struct io_uring_sqe *rsqe;
            struct __kernel_timespec ts;
            int have_timeout = (timeout_ms >= 0);
            int recv_res = 0;
            int got_recv = 0;
            int pending = 1;

            rsqe = io_uring_get_sqe(&ring);
            if (rsqe == NULL) {
                fprintf(stderr, "quic_server.c, main(): io_uring_get_sqe (recv) returned NULL\n");
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
                    fprintf(stderr, "quic_server.c, main(): io_uring_get_sqe (timeout) returned NULL\n");
                    ret = -1;
                    goto cleanup_ring;
                }
                io_uring_prep_link_timeout(tsqe, &ts, 0);
                io_uring_sqe_set_data(tsqe, (void *)(uintptr_t)2);
                pending = 2;
            }

            if (io_uring_submit(&ring) < 0) {
                fprintf(stderr, "quic_server.c, main(): io_uring_submit (recv) failed\n");
                ret = -1;
                goto cleanup_ring;
            }

            while (pending > 0) {
                struct io_uring_cqe *cqe;

                if (quic_wait_cqe(&ring, &cqe) < 0) {
                    fprintf(stderr, "quic_server.c, main(): io_uring_wait_cqe (recv) failed\n");
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
                        fprintf(stderr, "quic_server.c, main(): recv(): peer already gone (ECONNREFUSED), stopping\n");
                        goto cleanup_ring;
                    }
                    fprintf(stderr, "quic_server.c, main(): recv(): %s\n", strerror(-recv_res));
                    ret = -1;
                    goto cleanup_ring;
                }

                now = quic_timestamp();

                if (ngtcp2_conn_read_pkt(server.conn, &ps.path, &pi, rbuf, (size_t)recv_res, now) != 0) {
                    fprintf(stderr, "quic_server.c, main(): ngtcp2_conn_read_pkt failed\n");
                    ret = -1;
                    goto cleanup_ring;
                }
            }
        }
    }

    fprintf(stderr, "quic_server.c, main(): pong sent\n");

    ngtcp2_ccerr_default(&ccerr);
    close_ret = ngtcp2_conn_write_connection_close(server.conn, &ps.path, &pi, sbuf, sizeof(sbuf), &ccerr, quic_timestamp());
    if (close_ret > 0) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        struct io_uring_cqe *cqe;

        if (sqe == NULL) {
            fprintf(stderr, "quic_server.c, main(): io_uring_get_sqe (connection_close) returned NULL\n");
        } else {
            io_uring_prep_send(sqe, sock, sbuf, (size_t)close_ret, 0);

            if (io_uring_submit(&ring) < 0 || quic_wait_cqe(&ring, &cqe) < 0) {
                fprintf(stderr, "quic_server.c, main(): io_uring send for connection_close failed\n");
            } else {
                if (cqe->res < 0) {
                    fprintf(stderr, "quic_server.c, main(): send() for connection_close failed (peer likely already gone): %s\n", strerror(-cqe->res));
                }
                io_uring_cqe_seen(&ring, cqe);
            }
        }
    }

cleanup_ring:
    io_uring_queue_exit(&ring);
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
