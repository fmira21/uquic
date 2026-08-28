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

static void uquic_send_cqe(struct io_uring_cqe *cqe) {
    struct uquic_conn *sc = io_uring_cqe_get_data(cqe);

    if (!(cqe->flags & IORING_CQE_F_NOTIF)) {
        if (cqe->res < 0) {
            if (-cqe->res == ECONNREFUSED) {
                fprintf(stderr, "uquic.c, uquic_send_cqe(): send(): peer already gone (ECONNREFUSED)\n");
                sc->peer_closed = 1;
            } else {
                fprintf(stderr, "uquic.c, uquic_send_cqe(): send(): %s\n", strerror(-cqe->res));
                sc->failed = 1;
            }
        }

        if (cqe->flags & IORING_CQE_F_MORE) {
            return;
        }
    }

    if (sc->sbuf_inflight > 0) {
        sc->sbuf_inflight--;
    }
}

static int uquic_cqe_is_send(struct io_uring_cqe *cqe) {
    return (uintptr_t)io_uring_cqe_get_data(cqe) > 2;
}

static void uquic_prep_send(struct uquic_conn *uc, struct io_uring_sqe *sqe, const uint8_t *buf, size_t len) {
    if (uc->listener != NULL) {
        io_uring_prep_sendto(sqe, QUIC_FIXED_FD, buf, len, 0, uc->ps.path.remote.addr, uc->ps.path.remote.addrlen);
    } else {
        io_uring_prep_send_zc(sqe, QUIC_FIXED_FD, buf, len, 0, 0);
    }

    sqe->flags |= IOSQE_FIXED_FILE;
}

static int uquic_reap_ready(struct uquic_conn *uc) {
    struct io_uring_cqe *cqe;
    int reaped = 0;

    while (io_uring_peek_cqe(uc->ring, &cqe) == 0) {
        if (uquic_cqe_is_send(cqe)) {
            uquic_send_cqe(cqe);
            io_uring_cqe_seen(uc->ring, cqe);
            reaped++;
            continue;
        }

        break;
    }

    return reaped;
}

static int uquic_reap_one(struct uquic_conn *uc) {
    struct io_uring_cqe *cqe;

    if (uquic_reap_ready(uc) > 0) {
        return 0;
    }

    if (io_uring_submit_and_wait(uc->ring, 1) < 0) {
        fprintf(stderr, "uquic.c, uquic_reap_one(): io_uring_submit_and_wait failed\n");
        return -1;
    }

    if (quic_wait_cqe(uc->ring, &cqe) < 0) {
        fprintf(stderr, "uquic.c, uquic_reap_one(): io_uring_wait_cqe failed\n");
        return -1;
    }

    if (uquic_cqe_is_send(cqe)) {
        uquic_send_cqe(cqe);
    }

    io_uring_cqe_seen(uc->ring, cqe);

    return 0;
}

static int uquic_queue_send(struct uquic_conn *uc, const uint8_t *buf, size_t len) {
    struct io_uring_sqe *sqe;

    while (uc->sbuf_inflight == QUIC_SEND_BATCH) {
        if (uquic_reap_one(uc) < 0) {
            return -1;
        }
    }

    sqe = io_uring_get_sqe(uc->ring);

    if (sqe == NULL) {
        if (io_uring_submit(uc->ring) < 0) {
            fprintf(stderr, "uquic.c, uquic_queue_send(): io_uring_submit failed\n");
            return -1;
        }

        sqe = io_uring_get_sqe(uc->ring);

        if (sqe == NULL) {
            fprintf(stderr, "uquic.c, uquic_queue_send(): io_uring_get_sqe returned NULL\n");
            return -1;
        }
    }

    uquic_prep_send(uc, sqe, buf, len);
    io_uring_sqe_set_data(sqe, uc);
    uc->sbuf_inflight++;

    return 0;
}

static int uquic_drain_sends(struct uquic_conn *uc) {
    while (uc->sbuf_inflight > 0) {
        if (uquic_reap_one(uc) < 0) {
            return -1;
        }
    }

    return 0;
}

static void uquic_listener_drop(struct uquic_listener *l, struct uquic_conn *uc) {
    size_t i;

    for (i = 0; i < l->nconns; i++) {
        if (l->conns[i] == uc) {
            l->conns[i] = l->conns[l->nconns - 1];
            l->nconns--;
            return;
        }
    }
}

static int uquic_bufring_setup(struct io_uring *ring, struct io_uring_buf_ring **out_br, uint8_t **out_buf) {
    struct io_uring_buf_ring *br;
    uint8_t *buf;
    int ret = 0;
    int i;

    buf = malloc((size_t)QUIC_RECV_BUFS * QUIC_RECV_BUF_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "uquic.c, uquic_bufring_setup(): malloc failed\n");
        return -1;
    }

    br = io_uring_setup_buf_ring(ring, QUIC_RECV_BUFS, QUIC_BGID, 0, &ret);
    if (br == NULL) {
        fprintf(stderr, "uquic.c, uquic_bufring_setup(): io_uring_setup_buf_ring: %s\n", strerror(-ret));
        free(buf);
        return -1;
    }

    for (i = 0; i < QUIC_RECV_BUFS; i++) {
        io_uring_buf_ring_add(br, buf + (size_t)i * QUIC_RECV_BUF_SIZE, QUIC_RECV_BUF_SIZE, (unsigned short)i, io_uring_buf_ring_mask(QUIC_RECV_BUFS), i);
    }

    io_uring_buf_ring_advance(br, QUIC_RECV_BUFS);

    *out_br = br;
    *out_buf = buf;

    return 0;
}

static void uquic_bufring_free(struct io_uring *ring, struct io_uring_buf_ring *br, uint8_t *buf) {
    if (br != NULL) {
        io_uring_free_buf_ring(ring, br, QUIC_RECV_BUFS, QUIC_BGID);
    }

    free(buf);
}

static void uquic_bufring_recycle(struct io_uring_buf_ring *br, uint8_t *buf, unsigned short bid) {
    io_uring_buf_ring_add(br, buf + (size_t)bid * QUIC_RECV_BUF_SIZE, QUIC_RECV_BUF_SIZE, bid, io_uring_buf_ring_mask(QUIC_RECV_BUFS), 0);
    io_uring_buf_ring_advance(br, 1);
}

static struct io_uring_sqe *uquic_get_sqe(struct io_uring *ring, const char *tag) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    if (sqe != NULL) {
        return sqe;
    }

    if (io_uring_submit(ring) < 0) {
        fprintf(stderr, "%s: io_uring_submit failed\n", tag);
        return NULL;
    }

    sqe = io_uring_get_sqe(ring);

    if (sqe == NULL) {
        fprintf(stderr, "%s: io_uring_get_sqe returned NULL\n", tag);
    }

    return sqe;
}

static int uquic_arm_recv(struct uquic_conn *uc) {
    struct io_uring_sqe *sqe;

    if (uc->recv_armed) {
        return 0;
    }

    sqe = uquic_get_sqe(uc->ring, "uquic.c, uquic_arm_recv()");
    if (sqe == NULL) {
        return -1;
    }

    io_uring_prep_recv_multishot(sqe, QUIC_FIXED_FD, NULL, 0, 0);
    sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
    sqe->buf_group = QUIC_BGID;
    io_uring_sqe_set_data(sqe, (void *)(uintptr_t)1);

    uc->recv_armed = 1;

    return 0;
}

static int uquic_listener_arm_recv(struct uquic_listener *l) {
    struct io_uring_sqe *sqe;

    if (l->recv_armed) {
        return 0;
    }

    memset(&l->rmsg, 0, sizeof(l->rmsg));
    l->rmsg.msg_namelen = sizeof(struct sockaddr_storage);

    sqe = uquic_get_sqe(&l->ring, "uquic.c, uquic_listener_arm_recv()");
    if (sqe == NULL) {
        return -1;
    }

    io_uring_prep_recvmsg_multishot(sqe, QUIC_FIXED_FD, &l->rmsg, 0);
    sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
    sqe->buf_group = QUIC_BGID;
    io_uring_sqe_set_data(sqe, (void *)(uintptr_t)1);

    l->recv_armed = 1;

    return 0;
}

static void uquic_teardown(struct uquic_conn *uc, int ring_ready) {
    if (uc->sbuf_inflight > 0 && (ring_ready || uc->listener != NULL)) {
        uquic_drain_sends(uc);
    }

    if (uc->listener != NULL) {
        uquic_listener_drop(uc->listener, uc);
    } else if (ring_ready) {
        uquic_bufring_free(&uc->own_ring, uc->bring, uc->bbuf);
        io_uring_queue_exit(&uc->own_ring);
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
    if (uc->listener == NULL) {
        if (uc->ssl_ctx) {
            SSL_CTX_free(uc->ssl_ctx);
        }
        if (uc->sock >= 0) {
            close(uc->sock);
        }
    }
    free(uc);
}

/* One iteration: flush any pending outgoing packets (retransmits, ACKs, or
 * data previously handed to ngtcp2 via uquic_send), then wait for incoming
 * data up to the current retransmit-timer deadline via a linked io_uring
 * timeout, and process one incoming packet if it arrived in time.
 * Returns 0 (keep going), 1 (peer gone, ECONNREFUSED), or -1 (fatal). */
static int uquic_conn_flush(struct uquic_conn *uc) {
    for (;;) {
        ngtcp2_ssize datalen, wlen;
        size_t slot;
        ngtcp2_tstamp now = quic_timestamp();

        while (uc->sbuf_inflight == QUIC_SEND_BATCH) {
            if (uquic_reap_one(uc) < 0) {
                return -1;
            }
        }

        slot = uc->sbuf_next;

        wlen = ngtcp2_conn_writev_stream(uc->conn, &uc->ps.path, &uc->pi, uc->sbuf[slot], sizeof(uc->sbuf[slot]), &datalen, 0, -1, NULL, 0, now);

        if (wlen < 0) {
            fprintf(stderr, "uquic.c, uquic_conn_flush(): ngtcp2_conn_writev_stream failed\n");
            return -1;
        }

        if (wlen == 0) {
            return uc->peer_closed ? 1 : 0;
        }

        if (uquic_queue_send(uc, uc->sbuf[slot], (size_t)wlen) < 0) {
            return -1;
        }

        uc->sbuf_next = (slot + 1) % QUIC_SEND_BATCH;
    }
}

static int uquic_client_recv_cqe(struct uquic_conn *uc, struct io_uring_cqe *cqe) {
    unsigned short bid;
    int rv;

    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        uc->recv_armed = 0;
    }

    if (cqe->res < 0) {
        if (cqe->res == -ENOBUFS) {
            return 0;
        }
        if (-cqe->res == ECONNREFUSED) {
            fprintf(stderr, "uquic.c, uquic_client_recv_cqe(): recv(): peer already gone (ECONNREFUSED), stopping\n");
            return 1;
        }
        fprintf(stderr, "uquic.c, uquic_client_recv_cqe(): recv(): %s\n", strerror(-cqe->res));
        return -1;
    }

    if (cqe->res == 0 || !(cqe->flags & IORING_CQE_F_BUFFER)) {
        return 0;
    }

    bid = (unsigned short)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);

    rv = ngtcp2_conn_read_pkt(uc->conn, &uc->ps.path, &uc->pi, uc->bbuf + (size_t)bid * QUIC_RECV_BUF_SIZE, (size_t)cqe->res, quic_timestamp());

    uquic_bufring_recycle(uc->bring, uc->bbuf, bid);

    if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
        fprintf(stderr, "uquic.c, uquic_client_recv_cqe(): peer closed the connection\n");
        uc->peer_closed = 1;
        return 1;
    }

    if (rv != 0) {
        fprintf(stderr, "uquic.c, uquic_client_recv_cqe(): ngtcp2_conn_read_pkt failed\n");
        return -1;
    }

    return 0;
}

static int uquic_wait_timeout(struct io_uring *ring, int timeout_ms, const char *tag) {
    struct __kernel_timespec ts;
    struct __kernel_timespec *tsp = NULL;
    struct io_uring_cqe *cqe;
    int rc;

    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long long)(timeout_ms % 1000) * 1000000;
        tsp = &ts;
    }

    rc = io_uring_submit_and_wait_timeout(ring, &cqe, 1, tsp, NULL);

    if (rc < 0 && rc != -ETIME && rc != -EINTR && rc != -EAGAIN) {
        fprintf(stderr, "%s: io_uring_submit_and_wait_timeout: %s\n", tag, strerror(-rc));
        return -1;
    }

    return 0;
}

static int uquic_pump(struct uquic_conn *uc) {
    struct io_uring_cqe *cqe;
    ngtcp2_tstamp now, expiry, diff;
    unsigned head;
    unsigned seen = 0;
    int timeout_ms;
    int result = 0;
    int fr;

    fr = uquic_conn_flush(uc);
    if (fr != 0) {
        return fr;
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

    if (uquic_arm_recv(uc) < 0) {
        return -1;
    }

    if (uquic_wait_timeout(uc->ring, timeout_ms, "uquic.c, uquic_pump()") < 0) {
        return -1;
    }

    io_uring_for_each_cqe(uc->ring, head, cqe) {
        int rv;

        seen++;

        if (uquic_cqe_is_send(cqe)) {
            uquic_send_cqe(cqe);
            continue;
        }

        if ((uintptr_t)io_uring_cqe_get_data(cqe) != 1) {
            continue;
        }

        rv = uquic_client_recv_cqe(uc, cqe);

        if (rv != 0 && result == 0) {
            result = rv;
        }
    }

    io_uring_cq_advance(uc->ring, seen);

    if (result != 0) {
        return result;
    }

    if (uquic_rand_failed(uc, "uquic.c, uquic_pump()")) {
        return -1;
    }

    return 0;
}

static struct uquic_conn *uquic_listener_find(struct uquic_listener *l, const uint8_t *dcid, size_t dcidlen) {
    size_t i, j;

    for (i = 0; i < l->nconns; i++) {
        struct uquic_conn *uc = l->conns[i];

        for (j = 0; j < uc->ncids; j++) {
            if (uc->cids[j].datalen == dcidlen && memcmp(uc->cids[j].data, dcid, dcidlen) == 0) {
                return uc;
            }
        }
    }

    return NULL;
}

static struct uquic_conn *uquic_conn_accept_new(struct uquic_listener *l, const ngtcp2_pkt_hd *hd) {
    struct uquic_conn *uc;

    if (l->nconns == QUIC_MAX_CONNS) {
        fprintf(stderr, "uquic.c, uquic_conn_accept_new(): connection table full, dropping new connection\n");
        return NULL;
    }

    uc = calloc(1, sizeof(*uc));
    if (uc == NULL) {
        fprintf(stderr, "uquic.c, uquic_conn_accept_new(): calloc failed\n");
        return NULL;
    }

    uc->listener = l;
    uc->sock = l->sock;
    uc->ring = &l->ring;
    uc->ssl_ctx = l->ssl_ctx;
    uc->recv_stream_id = -1;
    uc->conn_ref.user_data = uc;

    quic_setup_path_addrs(&uc->ps, (struct sockaddr *)&l->local_addr, l->local_len, (struct sockaddr *)&l->peer_addr, l->peer_len);

    if (quic_setup_server_tls_session(l->ssl_ctx, &uc->conn_ref, &uc->ssl, &uc->ossl_ctx) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_setup_server_conn(&uc->ps, uc->ossl_ctx, uc, hd) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    if (quic_conn_add_cid(uc, &hd->dcid) != 0) {
        uquic_teardown(uc, 0);
        return NULL;
    }

    l->conns[l->nconns++] = uc;

    return uc;
}

static void uquic_conn_resend_close(struct uquic_conn *uc) {
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    if (uc->close_len == 0) {
        return;
    }

    sqe = io_uring_get_sqe(uc->ring);
    if (sqe == NULL) {
        return;
    }

    uquic_prep_send(uc, sqe, uc->sbuf[0], uc->close_len);

    if (io_uring_submit(uc->ring) < 0 || quic_wait_cqe(uc->ring, &cqe) < 0) {
        return;
    }

    io_uring_cqe_seen(uc->ring, cqe);
}

static void uquic_listener_route(struct uquic_listener *l, const uint8_t *pkt, size_t pktlen) {
    ngtcp2_version_cid vc;
    struct uquic_conn *uc;
    ngtcp2_pkt_hd hd;
    int rv;

    if (ngtcp2_pkt_decode_version_cid(&vc, pkt, pktlen, QUIC_CIDLEN) != 0) {
        return;
    }

    uc = uquic_listener_find(l, vc.dcid, vc.dcidlen);

    if (uc == NULL) {
        if (ngtcp2_accept(&hd, pkt, pktlen) != 0) {
            return;
        }

        uc = uquic_conn_accept_new(l, &hd);

        if (uc == NULL) {
            return;
        }
    }

    if (uc->closing) {
        uquic_conn_resend_close(uc);
        return;
    }

    rv = ngtcp2_conn_read_pkt(uc->conn, &uc->ps.path, &uc->pi, pkt, pktlen, quic_timestamp());

    if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
        uc->peer_closed = 1;
        return;
    }

    if (rv != 0) {
        fprintf(stderr, "uquic.c, uquic_listener_route(): ngtcp2_conn_read_pkt failed\n");
        uc->failed = 1;
    }
}

static int uquic_listener_recv_cqe(struct uquic_listener *l, struct io_uring_cqe *cqe) {
    struct io_uring_recvmsg_out *o;
    unsigned short bid;
    void *buf;
    void *name;
    void *payload;
    size_t paylen;

    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        l->recv_armed = 0;
    }

    if (cqe->res < 0) {
        if (cqe->res == -ENOBUFS) {
            return 0;
        }
        if (-cqe->res == ECONNREFUSED) {
            return 0;
        }
        fprintf(stderr, "uquic.c, uquic_listener_recv_cqe(): recvmsg(): %s\n", strerror(-cqe->res));
        return -1;
    }

    if (cqe->res == 0 || !(cqe->flags & IORING_CQE_F_BUFFER)) {
        return 0;
    }

    bid = (unsigned short)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    buf = l->bbuf + (size_t)bid * QUIC_RECV_BUF_SIZE;

    o = io_uring_recvmsg_validate(buf, cqe->res, &l->rmsg);

    if (o == NULL) {
        uquic_bufring_recycle(l->bring, l->bbuf, bid);
        return 0;
    }

    name = io_uring_recvmsg_name(o);
    payload = io_uring_recvmsg_payload(o, &l->rmsg);
    paylen = io_uring_recvmsg_payload_length(o, cqe->res, &l->rmsg);

    if (o->namelen > sizeof(l->peer_addr) || paylen == 0) {
        uquic_bufring_recycle(l->bring, l->bbuf, bid);
        return 0;
    }

    memcpy(&l->peer_addr, name, o->namelen);
    l->peer_len = o->namelen;

    uquic_listener_route(l, payload, paylen);

    uquic_bufring_recycle(l->bring, l->bbuf, bid);

    return 1;
}

static int uquic_listener_pump(struct uquic_listener *l, int max_wait_ms) {
    struct io_uring_cqe *cqe;
    ngtcp2_tstamp now, min_expiry = UINT64_MAX;
    unsigned head;
    unsigned seen = 0;
    size_t i;
    int timeout_ms;
    int got_data = 0;
    int result = 0;

    for (i = 0; i < l->nconns; i++) {
        struct uquic_conn *uc = l->conns[i];
        ngtcp2_tstamp expiry;

        if (uc->failed || uc->closing) {
            continue;
        }

        now = quic_timestamp();
        expiry = ngtcp2_conn_get_expiry(uc->conn);

        if (expiry <= now && ngtcp2_conn_handle_expiry(uc->conn, now) != 0) {
            fprintf(stderr, "uquic.c, uquic_listener_pump(): ngtcp2_conn_handle_expiry failed\n");
            uc->failed = 1;
            continue;
        }

        if (uquic_conn_flush(uc) != 0) {
            uc->failed = 1;
            continue;
        }

        if (uquic_rand_failed(uc, "uquic.c, uquic_listener_pump()")) {
            uc->failed = 1;
            continue;
        }

        expiry = ngtcp2_conn_get_expiry(uc->conn);

        if (expiry < min_expiry) {
            min_expiry = expiry;
        }
    }

    now = quic_timestamp();

    if (min_expiry == UINT64_MAX) {
        timeout_ms = max_wait_ms;
    } else {
        ngtcp2_duration diff = min_expiry > now ? min_expiry - now : 0;

        timeout_ms = (int)((diff + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS);

        if (max_wait_ms >= 0 && max_wait_ms < timeout_ms) {
            timeout_ms = max_wait_ms;
        }
    }

    if (uquic_listener_arm_recv(l) < 0) {
        return -1;
    }

    if (uquic_wait_timeout(&l->ring, timeout_ms, "uquic.c, uquic_listener_pump()") < 0) {
        return -1;
    }

    io_uring_for_each_cqe(&l->ring, head, cqe) {
        int rv;

        seen++;

        if (uquic_cqe_is_send(cqe)) {
            uquic_send_cqe(cqe);
            continue;
        }

        if ((uintptr_t)io_uring_cqe_get_data(cqe) != 1) {
            continue;
        }

        rv = uquic_listener_recv_cqe(l, cqe);

        if (rv < 0) {
            result = -1;
        } else if (rv > 0) {
            got_data = 1;
        }
    }

    io_uring_cq_advance(&l->ring, seen);

    if (result < 0) {
        return -1;
    }

    return got_data;
}

static int uquic_conn_progress(struct uquic_conn *uc) {
    int rv;

    if (uc->listener == NULL) {
        return uquic_pump(uc);
    }

    rv = uquic_listener_pump(uc->listener, -1);

    if (rv < 0) {
        return -1;
    }

    if (uc->peer_closed) {
        return 1;
    }

    if (uc->failed) {
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

    if (io_uring_queue_init(QUIC_RING_ENTRIES, &uc->own_ring, 0) != 0) {
        fprintf(stderr, "uquic.c, uquic_connect(): io_uring_queue_init failed\n");
        uquic_teardown(uc, 0);
        return NULL;
    }

    uc->ring = &uc->own_ring;

    if (io_uring_register_files(&uc->own_ring, &uc->sock, 1) != 0) {
        fprintf(stderr, "uquic.c, uquic_connect(): io_uring_register_files failed\n");
        uquic_teardown(uc, 1);
        return NULL;
    }

    if (uquic_bufring_setup(&uc->own_ring, &uc->bring, &uc->bbuf) != 0) {
        uquic_teardown(uc, 1);
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

uquic_listener *uquic_listen(const char *host, const char *port, const char *cert_file, const char *key_file) {
    struct uquic_listener *l;

    l = calloc(1, sizeof(*l));
    if (l == NULL) {
        fprintf(stderr, "uquic.c, uquic_listen(): calloc failed\n");
        return NULL;
    }

    l->sock = quic_create_listen_socket(host, port);
    if (l->sock < 0) {
        fprintf(stderr, "uquic.c, uquic_listen(): quic_create_listen_socket failed\n");
        free(l);
        return NULL;
    }

    if (quic_get_local_addr(l->sock, &l->local_addr, &l->local_len) != 0) {
        close(l->sock);
        free(l);
        return NULL;
    }

    if (quic_create_server_ssl_ctx(cert_file, key_file, &l->ssl_ctx) != 0) {
        close(l->sock);
        free(l);
        return NULL;
    }

    if (io_uring_queue_init(QUIC_LISTENER_RING_ENTRIES, &l->ring, 0) != 0) {
        fprintf(stderr, "uquic.c, uquic_listen(): io_uring_queue_init failed\n");
        SSL_CTX_free(l->ssl_ctx);
        close(l->sock);
        free(l);
        return NULL;
    }

    if (io_uring_register_files(&l->ring, &l->sock, 1) != 0) {
        fprintf(stderr, "uquic.c, uquic_listen(): io_uring_register_files failed\n");
        io_uring_queue_exit(&l->ring);
        SSL_CTX_free(l->ssl_ctx);
        close(l->sock);
        free(l);
        return NULL;
    }

    if (uquic_bufring_setup(&l->ring, &l->bring, &l->bbuf) != 0) {
        io_uring_queue_exit(&l->ring);
        SSL_CTX_free(l->ssl_ctx);
        close(l->sock);
        free(l);
        return NULL;
    }

    fprintf(stderr, "uquic.c, uquic_listen(): listening on %s:%s\n", host, port);

    return l;
}

void uquic_listener_close(uquic_listener *listener) {
    struct uquic_listener *l = listener;

    while (l->nconns > 0) {
        uquic_teardown(l->conns[0], 0);
    }

    uquic_bufring_free(&l->ring, l->bring, l->bbuf);
    io_uring_queue_exit(&l->ring);
    SSL_CTX_free(l->ssl_ctx);
    close(l->sock);
    free(l);
}

uquic_conn *uquic_accept(uquic_listener *listener) {
    struct uquic_listener *l = listener;

    for (;;) {
        size_t i;

        for (i = 0; i < l->nconns; i++) {
            struct uquic_conn *uc = l->conns[i];

            if (uc->accepted) {
                continue;
            }

            if (uc->handshake_done) {
                uc->accepted = 1;
                fprintf(stderr, "uquic.c, uquic_accept(): connection established\n");
                return uc;
            }

            if (uc->failed || uc->peer_closed) {
                uquic_teardown(uc, 0);
                i--;
            }
        }

        if (uquic_listener_pump(l, -1) < 0) {
            return NULL;
        }
    }
}

uquic_conn *uquic_next(uquic_listener *listener, int timeout_ms) {
    struct uquic_listener *l = listener;
    ngtcp2_tstamp deadline = timeout_ms >= 0 ? quic_timestamp() + (ngtcp2_duration)timeout_ms * NGTCP2_MILLISECONDS : UINT64_MAX;

    for (;;) {
        ngtcp2_tstamp now;
        int wait_ms = -1;
        size_t i;

        for (i = 0; i < l->nconns; i++) {
            struct uquic_conn *uc = l->conns[i];

            if (!uc->accepted || uc->closing) {
                continue;
            }

            if (uc->recv_len > 0 || uc->recv_fin || uc->peer_closed || uc->failed) {
                return uc;
            }
        }

        now = quic_timestamp();

        if (deadline != UINT64_MAX) {
            if (now >= deadline) {
                return NULL;
            }
            wait_ms = (int)((deadline - now + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS);
        }

        if (uquic_listener_pump(l, wait_ms) < 0) {
            return NULL;
        }
    }
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
    const size_t cap = sizeof(uc->txbuf);
    size_t copied = 0;
    size_t slot;
    int fin_done = 0;

    for (;;) {
        ngtcp2_ssize datalen, wlen;
        ngtcp2_vec vec;
        const ngtcp2_vec *datav;
        size_t datavcnt;
        int64_t wstream_id;
        uint32_t wflags;
        ngtcp2_tstamp now = quic_timestamp();

        while (uc->sbuf_inflight == QUIC_SEND_BATCH) {
            if (uquic_reap_one(uc) < 0) {
                return -1;
            }
        }

        slot = uc->sbuf_next;

        while (copied < len) {
            size_t staged = (size_t)(uc->tx_written - uc->tx_acked);
            size_t space = cap - staged;
            size_t idx, run, n;

            if (space == 0) {
                break;
            }

            idx = (size_t)(uc->tx_written % cap);
            run = cap - idx;
            n = len - copied;

            if (n > space) {
                n = space;
            }
            if (n > run) {
                n = run;
            }

            memcpy(uc->txbuf + idx, data + copied, n);
            copied += n;
            uc->tx_written += n;
        }

        if (uc->tx_sent < uc->tx_written) {
            size_t idx = (size_t)(uc->tx_sent % cap);
            size_t avail = (size_t)(uc->tx_written - uc->tx_sent);
            size_t run = cap - idx;

            if (avail > run) {
                avail = run;
            }

            vec.base = uc->txbuf + idx;
            vec.len = avail;
            datav = &vec;
            datavcnt = 1;
            wstream_id = stream_id;
            wflags = (fin && copied == len && uc->tx_sent + avail == uc->tx_written) ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
        } else if (fin && !fin_done && copied == len) {
            datav = NULL;
            datavcnt = 0;
            wstream_id = stream_id;
            wflags = NGTCP2_WRITE_STREAM_FLAG_FIN;
        } else {
            datav = NULL;
            datavcnt = 0;
            wstream_id = -1;
            wflags = 0;
        }

        wlen = ngtcp2_conn_writev_stream(uc->conn, &uc->ps.path, &uc->pi, uc->sbuf[slot], sizeof(uc->sbuf[slot]), &datalen, wflags, wstream_id, datav, datavcnt, now);

        if (wlen < 0) {
            fprintf(stderr, "uquic.c, uquic_send(): ngtcp2_conn_writev_stream failed\n");
            return -1;
        }

        if (wlen == 0) {
            if (copied < len || uc->tx_sent < uc->tx_written || (fin && !fin_done)) {
                if (uquic_conn_progress(uc) != 0) {
                    fprintf(stderr, "uquic.c, uquic_send(): connection failed with %llu of %zu bytes sent\n", (unsigned long long)uc->tx_sent, len);
                    uc->failed = 1;
                    return -1;
                }
                continue;
            }

            break;
        }

        if (wstream_id == stream_id) {
            if (datalen > 0) {
                uc->tx_sent += (uint64_t)datalen;
            }

            if ((wflags & NGTCP2_WRITE_STREAM_FLAG_FIN) && uc->tx_sent == uc->tx_written && copied == len) {
                fin_done = 1;
            }
        }

        if (uquic_queue_send(uc, uc->sbuf[slot], (size_t)wlen) < 0) {
            return -1;
        }

        uc->sbuf_next = (slot + 1) % QUIC_SEND_BATCH;
    }

    if (uquic_rand_failed(uc, "uquic.c, uquic_send()")) {
        return -1;
    }

    if (io_uring_submit(uc->ring) < 0) {
        fprintf(stderr, "uquic.c, uquic_send(): io_uring_submit failed\n");
        uc->failed = 1;
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

        rv = uquic_conn_progress(uc);

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

        if (uquic_conn_progress(uc) != 0) {
            return -1;
        }
    }

    return 0;
}

static void uquic_close_linger_listener(struct uquic_conn *uc) {
    ngtcp2_duration quiet = ngtcp2_conn_get_pto2(uc->conn);
    ngtcp2_tstamp now = quic_timestamp();
    ngtcp2_tstamp deadline = now + 3 * quiet;

    while (now < deadline) {
        ngtcp2_duration left = deadline - now;
        ngtcp2_duration wait = quiet < left ? quiet : left;
        int timeout_ms = (int)((wait + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS);
        int rv = uquic_listener_pump(uc->listener, timeout_ms);

        if (rv <= 0) {
            return;
        }

        now = quic_timestamp();
    }
}

static void uquic_close_linger(struct uquic_conn *uc, size_t pktlen) {
    ngtcp2_duration quiet = ngtcp2_conn_get_pto2(uc->conn);
    ngtcp2_tstamp now = quic_timestamp();
    ngtcp2_tstamp deadline = now + 3 * quiet;

    if (uc->listener != NULL) {
        uquic_close_linger_listener(uc);
        return;
    }

    while (now < deadline) {
        struct io_uring_cqe *cqe;
        ngtcp2_duration left = deadline - now;
        ngtcp2_duration wait = quiet < left ? quiet : left;
        int timeout_ms = (int)((wait + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS);
        unsigned head;
        unsigned seen = 0;
        int got_data = 0;

        if (uquic_arm_recv(uc) < 0) {
            return;
        }

        if (uquic_wait_timeout(uc->ring, timeout_ms, "uquic.c, uquic_close_linger()") < 0) {
            return;
        }

        io_uring_for_each_cqe(uc->ring, head, cqe) {
            seen++;

            if (uquic_cqe_is_send(cqe)) {
                uquic_send_cqe(cqe);
                continue;
            }

            if ((uintptr_t)io_uring_cqe_get_data(cqe) != 1) {
                continue;
            }

            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                uc->recv_armed = 0;
            }

            if (cqe->flags & IORING_CQE_F_BUFFER) {
                uquic_bufring_recycle(uc->bring, uc->bbuf, (unsigned short)(cqe->flags >> IORING_CQE_BUFFER_SHIFT));
            }

            if (cqe->res > 0) {
                got_data = 1;
            }
        }

        io_uring_cq_advance(uc->ring, seen);

        if (!got_data) {
            return;
        }

        if (uquic_queue_send(uc, uc->sbuf[0], pktlen) < 0) {
            return;
        }

        if (io_uring_submit(uc->ring) < 0) {
            return;
        }

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
        struct io_uring_sqe *sqe = io_uring_get_sqe(uc->ring);
        struct io_uring_cqe *cqe;

        uc->closing = 1;
        uc->close_len = (size_t)close_ret;

        if (sqe == NULL) {
            fprintf(stderr, "uquic.c, uquic_close(): io_uring_get_sqe (connection_close) returned NULL\n");
        } else {
            uquic_prep_send(uc, sqe, uc->sbuf[0], (size_t)close_ret);

            if (io_uring_submit(uc->ring) < 0 || quic_wait_cqe(uc->ring, &cqe) < 0) {
                fprintf(stderr, "uquic.c, uquic_close(): io_uring send for connection_close failed\n");
            } else {
                if (cqe->res < 0) {
                    fprintf(stderr, "uquic.c, uquic_close(): send() for connection_close failed (peer likely already gone): %s\n", strerror(-cqe->res));
                    io_uring_cqe_seen(uc->ring, cqe);
                    uquic_teardown(uc, 1);
                    return rc;
                }
                io_uring_cqe_seen(uc->ring, cqe);
                uquic_close_linger(uc, (size_t)close_ret);
            }
        }
    }

    uquic_teardown(uc, 1);

    return rc;
}
