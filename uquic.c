#include "quic.h"
#include "uquic.h"

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

static int uquic_rand_failed(struct uquic_conn *uc, const char *tag) {
    if (uc->rand_failed) {
        fprintf(stderr, "%s: RNG failure reported by quic_rand_cb, aborting connection\n", tag);
        return 1;
    }

    return 0;
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

static void uquic_teardown(struct uquic_conn *uc, int ring_ready) {
    if (ring_ready) {
        io_uring_queue_exit(&uc->ring);
    }
    if (uc->conn) {
        ngtcp2_conn_del(uc->conn);
    }
    if (uc->ossl_ctx) {
        ngtcp2_crypto_ossl_ctx_del(uc->ossl_ctx);
    }
    if (uc->ssl) {
        SSL_free(uc->ssl);
    }
    if (uc->ssl_ctx) {
        SSL_CTX_free(uc->ssl_ctx);
    }
    if (uc->sock >= 0) {
        close(uc->sock);
    }
    free(uc);
}

/* One iteration: flush any pending outgoing packets (retransmits, ACKs, or
 * data previously handed to ngtcp2 via uquic_send), then wait for incoming
 * data up to the current retransmit-timer deadline via a linked io_uring
 * timeout, and process one incoming packet if it arrived in time.
 * Returns 0 (keep going), 1 (peer gone, ECONNREFUSED), or -1 (fatal). */
static int uquic_pump(struct uquic_conn *uc) {
    ngtcp2_tstamp now, expiry, diff;
    int timeout_ms;
    size_t send_pending = 0;

    for (;;) {
        ngtcp2_ssize datalen, wlen;
        struct io_uring_sqe *sqe;

        now = quic_timestamp();

        wlen = ngtcp2_conn_writev_stream(uc->conn, &uc->ps.path, &uc->pi, uc->sbuf[send_pending], sizeof(uc->sbuf[send_pending]), &datalen, 0, -1, NULL, 0, now);

        if (wlen < 0) {
            fprintf(stderr, "uquic.c, uquic_pump(): ngtcp2_conn_writev_stream failed\n");
            return -1;
        }

        if (wlen == 0) {
            if (send_pending > 0) {
                int fr = quic_flush_sends(&uc->ring, send_pending, "uquic.c, uquic_pump()");

                send_pending = 0;

                if (fr != 0) {
                    return fr;
                }
            }
            break;
        }

        sqe = io_uring_get_sqe(&uc->ring);
        if (sqe == NULL) {
            fprintf(stderr, "uquic.c, uquic_pump(): io_uring_get_sqe (send) returned NULL\n");
            return -1;
        }
        io_uring_prep_send(sqe, uc->sock, uc->sbuf[send_pending], (size_t)wlen, 0);
        send_pending++;

        if (send_pending == QUIC_SEND_BATCH) {
            int fr = quic_flush_sends(&uc->ring, send_pending, "uquic.c, uquic_pump()");

            send_pending = 0;

            if (fr != 0) {
                return fr;
            }
        }
    }

    now = quic_timestamp();
    expiry = ngtcp2_conn_get_expiry(uc->conn);

    if (expiry <= now) {
        if (ngtcp2_conn_handle_expiry(uc->conn, now) != 0) {
            fprintf(stderr, "uquic.c, uquic_pump(): ngtcp2_conn_handle_expiry failed\n");
            return -1;
        }
        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(uc->conn);
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
        int rv;

        rsqe = io_uring_get_sqe(&uc->ring);
        if (rsqe == NULL) {
            fprintf(stderr, "uquic.c, uquic_pump(): io_uring_get_sqe (recv) returned NULL\n");
            return -1;
        }
        io_uring_prep_recv(rsqe, uc->sock, uc->pktbuf, sizeof(uc->pktbuf), 0);
        io_uring_sqe_set_data(rsqe, (void *)(uintptr_t)1);

        if (have_timeout) {
            struct io_uring_sqe *tsqe;

            rsqe->flags |= IOSQE_IO_LINK;
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = (long long)(timeout_ms % 1000) * 1000000;

            tsqe = io_uring_get_sqe(&uc->ring);
            if (tsqe == NULL) {
                fprintf(stderr, "uquic.c, uquic_pump(): io_uring_get_sqe (timeout) returned NULL\n");
                return -1;
            }
            io_uring_prep_link_timeout(tsqe, &ts, 0);
            io_uring_sqe_set_data(tsqe, (void *)(uintptr_t)2);
            pending = 2;
        }

        if (io_uring_submit(&uc->ring) < 0) {
            fprintf(stderr, "uquic.c, uquic_pump(): io_uring_submit (recv) failed\n");
            return -1;
        }

        while (pending > 0) {
            struct io_uring_cqe *cqe;

            if (quic_wait_cqe(&uc->ring, &cqe) < 0) {
                fprintf(stderr, "uquic.c, uquic_pump(): io_uring_wait_cqe (recv) failed\n");
                return -1;
            }

            if ((uintptr_t)io_uring_cqe_get_data(cqe) == 1) {
                recv_res = cqe->res;
                got_recv = 1;
            }

            io_uring_cqe_seen(&uc->ring, cqe);
            pending--;
        }

        if (got_recv && recv_res != -ECANCELED) {
            if (recv_res < 0) {
                if (-recv_res == ECONNREFUSED) {
                    fprintf(stderr, "uquic.c, uquic_pump(): recv(): peer already gone (ECONNREFUSED), stopping\n");
                    return 1;
                }
                fprintf(stderr, "uquic.c, uquic_pump(): recv(): %s\n", strerror(-recv_res));
                return -1;
            }

            now = quic_timestamp();

            rv = ngtcp2_conn_read_pkt(uc->conn, &uc->ps.path, &uc->pi, uc->pktbuf, (size_t)recv_res, now);

            if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                fprintf(stderr, "uquic.c, uquic_pump(): peer closed the connection\n");
                uc->peer_closed = 1;
                return 1;
            }

            if (rv != 0) {
                fprintf(stderr, "uquic.c, uquic_pump(): ngtcp2_conn_read_pkt failed\n");
                return -1;
            }
        }
    }

    if (uquic_rand_failed(uc, "uquic.c, uquic_pump()")) {
        return -1;
    }

    return 0;
}

uquic_conn *uquic_connect(const char *host, const char *port, const uquic_client_opts *opts) {
    struct uquic_conn *uc;
    uquic_client_opts defaults;
    const char *server_name;

    if (opts == NULL) {
        memset(&defaults, 0, sizeof(defaults));
        opts = &defaults;
    }

    server_name = opts->server_name != NULL ? opts->server_name : host;

    uc = calloc(1, sizeof(*uc));
    if (uc == NULL) {
        fprintf(stderr, "uquic.c, uquic_connect(): calloc failed\n");
        return NULL;
    }
    uc->sock = -1;
    uc->recv_stream_id = -1;
    uc->conn_ref.user_data = uc;

    uc->sock = quic_create_socket(host, port);
    if (uc->sock < 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_setup_path(uc->sock, &uc->ps) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_create_ssl_ctx(opts->ca_file, opts->insecure_skip_verify, &uc->ssl_ctx) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_setup_tls_session(uc->ssl_ctx, server_name, opts->insecure_skip_verify, &uc->conn_ref, &uc->ssl, &uc->ossl_ctx) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_setup_conn(&uc->ps, uc->ossl_ctx, uc) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (io_uring_queue_init(16, &uc->ring, 0) != 0) {
        fprintf(stderr, "uquic.c, uquic_connect(): io_uring_queue_init failed\n");
        uquic_teardown(uc, 0);
        return NULL;
    }

    while (!uc->handshake_done) {
        if (uquic_pump(uc) != 0) {
            uquic_teardown(uc, 1);
            return NULL;
        }
    }

    return uc;
}

uquic_conn *uquic_accept(const char *host, const char *port, const char *cert_file, const char *key_file) {
    struct uquic_conn *uc;
    struct sockaddr_storage peer_addr;
    socklen_t peer_len;
    ssize_t n;
    ngtcp2_pkt_hd hd;

    uc = calloc(1, sizeof(*uc));
    if (uc == NULL) {
        fprintf(stderr, "uquic.c, uquic_accept(): calloc failed\n");
        return NULL;
    }
    uc->sock = -1;
    uc->recv_stream_id = -1;
    uc->conn_ref.user_data = uc;

    uc->sock = quic_create_listen_socket(host, port);
    if (uc->sock < 0) {
        fprintf(stderr, "uquic.c, uquic_accept(): quic_create_listen_socket failed\n");
        uquic_teardown(uc, 0);
        return NULL;
    }

    fprintf(stderr, "uquic.c, uquic_accept(): listening on %s:%s\n", host, port);

    if (quic_create_server_ssl_ctx(cert_file, key_file, &uc->ssl_ctx) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_setup_server_tls_session(uc->ssl_ctx, &uc->conn_ref, &uc->ssl, &uc->ossl_ctx) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    fprintf(stderr, "uquic.c, uquic_accept(): server TLS session ready\n");

    peer_len = sizeof(peer_addr);
    n = recvfrom(uc->sock, uc->pktbuf, sizeof(uc->pktbuf), 0, (struct sockaddr *)&peer_addr, &peer_len);
    if (n < 0) {
        fprintf(stderr, "uquic.c, uquic_accept(): recvfrom(): %s\n", strerror(errno));
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (connect(uc->sock, (struct sockaddr *)&peer_addr, peer_len) != 0) {
        fprintf(stderr, "uquic.c, uquic_accept(): connect(): %s\n", strerror(errno));
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_setup_path(uc->sock, &uc->ps) != 0) {
        fprintf(stderr, "uquic.c, uquic_accept(): quic_setup_path failed\n");
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (ngtcp2_accept(&hd, uc->pktbuf, (size_t)n) != 0) {
        fprintf(stderr, "uquic.c, uquic_accept(): ngtcp2_accept failed\n");
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_setup_server_conn(&uc->ps, uc->ossl_ctx, uc, &hd) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (ngtcp2_conn_read_pkt(uc->conn, &uc->ps.path, &uc->pi, uc->pktbuf, (size_t)n, quic_timestamp()) != 0) {
        fprintf(stderr, "uquic.c, uquic_accept(): ngtcp2_conn_read_pkt failed\n");
        uquic_teardown(uc, 0);
        return NULL;
    }

    fprintf(stderr, "uquic.c, uquic_accept(): first Initial packet accepted, connection established\n");

    if (io_uring_queue_init(16, &uc->ring, 0) != 0) {
        fprintf(stderr, "uquic.c, uquic_accept(): io_uring_queue_init failed\n");
        uquic_teardown(uc, 0);
        return NULL;
    }

    while (!uc->handshake_done) {
        if (uquic_pump(uc) != 0) {
            uquic_teardown(uc, 1);
            return NULL;
        }
    }

    return uc;
}

int64_t uquic_stream_open(uquic_conn *conn) {
    struct uquic_conn *uc = conn;
    int64_t stream_id;

    if (ngtcp2_conn_open_bidi_stream(uc->conn, &stream_id, NULL) != 0) {
        fprintf(stderr, "uquic.c, uquic_stream_open(): ngtcp2_conn_open_bidi_stream failed\n");
        return -1;
    }

    return stream_id;
}

int uquic_send(uquic_conn *conn, int64_t stream_id, const uint8_t *data, size_t len, int fin) {
    struct uquic_conn *uc = conn;
    size_t offset = 0;
    size_t send_pending = 0;

    for (;;) {
        ngtcp2_ssize datalen, wlen;
        ngtcp2_vec vec;
        const ngtcp2_vec *datav;
        size_t datavcnt;
        int64_t wstream_id;
        uint32_t wflags;
        struct io_uring_sqe *sqe;
        ngtcp2_tstamp now = quic_timestamp();

        if (offset < len) {
            vec.base = (uint8_t *)data + offset;
            vec.len = len - offset;
            datav = &vec;
            datavcnt = 1;
            wstream_id = stream_id;
            wflags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
        } else {
            datav = NULL;
            datavcnt = 0;
            wstream_id = -1;
            wflags = 0;
        }

        wlen = ngtcp2_conn_writev_stream(uc->conn, &uc->ps.path, &uc->pi, uc->sbuf[send_pending], sizeof(uc->sbuf[send_pending]), &datalen, wflags, wstream_id, datav, datavcnt, now);

        if (wlen < 0) {
            fprintf(stderr, "uquic.c, uquic_send(): ngtcp2_conn_writev_stream failed\n");
            return -1;
        }

        if (wlen == 0) {
            if (send_pending > 0) {
                int fr = quic_flush_sends(&uc->ring, send_pending, "uquic.c, uquic_send()");

                send_pending = 0;

                if (fr != 0) {
                    return -1;
                }
            }

            if (offset < len) {
                if (uquic_pump(uc) != 0) {
                    fprintf(stderr, "uquic.c, uquic_send(): connection failed with %zu of %zu bytes sent\n", offset, len);
                    uc->failed = 1;
                    return -1;
                }
                continue;
            }

            break;
        }

        if (datalen > 0 && wstream_id == stream_id) {
            offset += (size_t)datalen;
            uc->tx_sent += (uint64_t)datalen;
        }

        sqe = io_uring_get_sqe(&uc->ring);
        if (sqe == NULL) {
            fprintf(stderr, "uquic.c, uquic_send(): io_uring_get_sqe (send) returned NULL\n");
            return -1;
        }
        io_uring_prep_send(sqe, uc->sock, uc->sbuf[send_pending], (size_t)wlen, 0);
        send_pending++;

        if (send_pending == QUIC_SEND_BATCH) {
            int fr = quic_flush_sends(&uc->ring, send_pending, "uquic.c, uquic_send()");

            send_pending = 0;

            if (fr != 0) {
                return -1;
            }
        }
    }

    if (uquic_rand_failed(uc, "uquic.c, uquic_send()")) {
        return -1;
    }

    return 0;
}

ssize_t uquic_recv(uquic_conn *conn, int64_t *stream_id, uint8_t *buf, size_t buflen, int *fin) {
    struct uquic_conn *uc = conn;

    for (;;) {
        int rv;

        if (uc->recv_len > 0) {
            size_t n = uc->recv_len < buflen ? uc->recv_len : buflen;
            size_t first = sizeof(uc->recv_buf) - uc->recv_head;

            if (first > n) {
                first = n;
            }

            memcpy(buf, uc->recv_buf + uc->recv_head, first);

            if (n > first) {
                memcpy(buf + first, uc->recv_buf, n - first);
            }

            uc->recv_head = (uc->recv_head + n) % sizeof(uc->recv_buf);
            uc->recv_len -= n;

            if (stream_id != NULL) {
                *stream_id = uc->recv_stream_id;
            }
            if (fin != NULL) {
                *fin = (uc->recv_fin && uc->recv_len == 0) ? 1 : 0;
            }

            ngtcp2_conn_extend_max_stream_offset(uc->conn, uc->recv_stream_id, n);
            ngtcp2_conn_extend_max_offset(uc->conn, n);

            return (ssize_t)n;
        }

        if (uc->recv_fin) {
            if (stream_id != NULL) {
                *stream_id = uc->recv_stream_id;
            }
            if (fin != NULL) {
                *fin = 1;
            }

            return 0;
        }

        if (uc->peer_closed || uc->failed) {
            return -1;
        }

        rv = uquic_pump(uc);

        if (rv < 0) {
            uc->failed = 1;
            return -1;
        }

        if (rv > 0) {
            uc->peer_closed = 1;
        }
    }
}

static int uquic_close_wait_acked(struct uquic_conn *uc) {
    ngtcp2_tstamp deadline;

    if (uc->failed || uc->peer_closed || uc->tx_acked >= uc->tx_sent) {
        return 0;
    }

    deadline = quic_timestamp() + 3 * ngtcp2_conn_get_pto2(uc->conn);

    while (uc->tx_acked < uc->tx_sent) {
        if (quic_timestamp() >= deadline) {
            fprintf(stderr, "uquic.c, uquic_close(): %llu of %llu bytes still unacknowledged, closing anyway\n", (unsigned long long)(uc->tx_sent - uc->tx_acked), (unsigned long long)uc->tx_sent);
            return -1;
        }

        if (uquic_pump(uc) != 0) {
            return -1;
        }
    }

    return 0;
}

static void uquic_close_linger(struct uquic_conn *uc, size_t pktlen) {
    ngtcp2_duration quiet = ngtcp2_conn_get_pto2(uc->conn);
    ngtcp2_tstamp now = quic_timestamp();
    ngtcp2_tstamp deadline = now + 3 * quiet;

    while (now < deadline) {
        struct io_uring_sqe *rsqe, *tsqe, *ssqe;
        struct io_uring_cqe *cqe;
        struct __kernel_timespec ts;
        ngtcp2_duration left = deadline - now;
        ngtcp2_duration wait = quiet < left ? quiet : left;
        int timeout_ms = (int)((wait + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS);
        int recv_res = 0;
        int got_recv = 0;
        int pending = 2;

        rsqe = io_uring_get_sqe(&uc->ring);
        if (rsqe == NULL) {
            return;
        }
        io_uring_prep_recv(rsqe, uc->sock, uc->pktbuf, sizeof(uc->pktbuf), 0);
        io_uring_sqe_set_data(rsqe, (void *)(uintptr_t)1);
        rsqe->flags |= IOSQE_IO_LINK;

        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long long)(timeout_ms % 1000) * 1000000;

        tsqe = io_uring_get_sqe(&uc->ring);
        if (tsqe == NULL) {
            return;
        }
        io_uring_prep_link_timeout(tsqe, &ts, 0);
        io_uring_sqe_set_data(tsqe, (void *)(uintptr_t)2);

        if (io_uring_submit(&uc->ring) < 0) {
            return;
        }

        while (pending > 0) {
            if (quic_wait_cqe(&uc->ring, &cqe) < 0) {
                return;
            }

            if ((uintptr_t)io_uring_cqe_get_data(cqe) == 1) {
                recv_res = cqe->res;
                got_recv = 1;
            }

            io_uring_cqe_seen(&uc->ring, cqe);
            pending--;
        }

        if (!got_recv || recv_res < 0) {
            return;
        }

        ssqe = io_uring_get_sqe(&uc->ring);
        if (ssqe == NULL) {
            return;
        }
        io_uring_prep_send(ssqe, uc->sock, uc->sbuf[0], pktlen, 0);

        if (io_uring_submit(&uc->ring) < 0 || quic_wait_cqe(&uc->ring, &cqe) < 0) {
            return;
        }
        io_uring_cqe_seen(&uc->ring, cqe);

        now = quic_timestamp();
    }
}

int uquic_close(uquic_conn *conn) {
    struct uquic_conn *uc = conn;
    ngtcp2_ccerr ccerr;
    ngtcp2_ssize close_ret;
    int rc = 0;

    if (uquic_close_wait_acked(uc) != 0) {
        rc = -1;
    }

    if (uc->peer_closed) {
        uquic_teardown(uc, 1);
        return rc;
    }

    ngtcp2_ccerr_default(&ccerr);
    close_ret = ngtcp2_conn_write_connection_close(uc->conn, &uc->ps.path, &uc->pi, uc->sbuf[0], sizeof(uc->sbuf[0]), &ccerr, quic_timestamp());
    if (close_ret > 0) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&uc->ring);
        struct io_uring_cqe *cqe;

        if (sqe == NULL) {
            fprintf(stderr, "uquic.c, uquic_close(): io_uring_get_sqe (connection_close) returned NULL\n");
        } else {
            io_uring_prep_send(sqe, uc->sock, uc->sbuf[0], (size_t)close_ret, 0);

            if (io_uring_submit(&uc->ring) < 0 || quic_wait_cqe(&uc->ring, &cqe) < 0) {
                fprintf(stderr, "uquic.c, uquic_close(): io_uring send for connection_close failed\n");
            } else {
                if (cqe->res < 0) {
                    fprintf(stderr, "uquic.c, uquic_close(): send() for connection_close failed (peer likely already gone): %s\n", strerror(-cqe->res));
                    io_uring_cqe_seen(&uc->ring, cqe);
                    uquic_teardown(uc, 1);
                    return rc;
                }
                io_uring_cqe_seen(&uc->ring, cqe);
                uquic_close_linger(uc, (size_t)close_ret);
            }
        }
    }

    uquic_teardown(uc, 1);

    return rc;
}
