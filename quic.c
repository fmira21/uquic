#include "quic.h"

int quic_create_socket(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *res, *rp;
    int rv;
    int s = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    rv = getaddrinfo(host, port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "quic.c, quic_create_socket(): %s\n", gai_strerror(rv));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == -1) {
            continue;
        }

        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(s);
        s = -1;
    }

    freeaddrinfo(res);

    if (s == -1) {
        fprintf(stderr, "quic.c, quic_create_socket(): %s\n", strerror(errno));
        return -1;
    }

    return s;
}

int quic_create_listen_socket(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *res, *rp;
    int rv;
    int s = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    rv = getaddrinfo(host, port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "quic.c, quic_create_listen_socket(): %s\n", gai_strerror(rv));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        int on = 1;

        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == -1) {
            continue;
        }

        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        if (bind(s, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(s);
        s = -1;
    }

    freeaddrinfo(res);

    if (s == -1) {
        fprintf(stderr, "quic.c, quic_create_listen_socket(): %s\n", strerror(errno));
        return -1;
    }

    return s;
}

int quic_get_local_addr (int sock, struct sockaddr_storage *out_addr, socklen_t *out_len) {
    socklen_t ss_len;
    int sn;

    ss_len = sizeof(struct sockaddr_storage);
    sn = getsockname(sock, (struct sockaddr *)out_addr, &ss_len);

    if(sn == -1) {
        fprintf(stderr, "quic.c, quic_get_local_addr(): %s\n", strerror(errno));
        return -1;
    }

    *out_len = ss_len;

    return sn;
}

int quic_get_remote_addr(int sock, struct sockaddr_storage *out_addr, socklen_t *out_len) {
    socklen_t ss_len;
    int pn;

    ss_len = sizeof(struct sockaddr_storage);
    pn = getpeername(sock, (struct sockaddr *)out_addr, &ss_len);

    if(pn == -1) {
        fprintf(stderr, "quic.c, quic_get_remote_addr(): %s\n", strerror(errno));
        return -1;
    }

    *out_len = ss_len;

    return pn;
}

int quic_create_ssl_ctx(const char *ca_file, int insecure, SSL_CTX **out_ctx) {
    SSL_CTX *sslctx;

    sslctx = SSL_CTX_new(TLS_client_method());

    if (sslctx == NULL) {
        fprintf(stderr, "quic.c, quic_create_ssl_ctx(): SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_CTX_set_min_proto_version(sslctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);

    if (insecure) {
        fprintf(stderr, "quic.c, quic_create_ssl_ctx(): certificate verification disabled, connection is not protected against MITM\n");
        SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);

        *out_ctx = sslctx;

        return 0;
    }

    SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER, NULL);

    if (ca_file != NULL) {
        if (SSL_CTX_load_verify_file(sslctx, ca_file) != 1) {
            fprintf(stderr, "quic.c, quic_create_ssl_ctx(): SSL_CTX_load_verify_file failed for %s\n", ca_file);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(sslctx);
            return -1;
        }
    } else if (SSL_CTX_set_default_verify_paths(sslctx) != 1) {
        fprintf(stderr, "quic.c, quic_create_ssl_ctx(): SSL_CTX_set_default_verify_paths failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(sslctx);
        return -1;
    }

    *out_ctx = sslctx;

    return 0;
}

static ngtcp2_conn *quic_get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    struct uquic_conn *uc;

    uc = conn_ref->user_data;

    return uc->conn;
}

static int quic_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;

    if (SSL_select_next_proto((unsigned char **)out, outlen, (const unsigned char *)"\x02h3", 3, in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;
}

int quic_create_server_ssl_ctx(const char *cert_file, const char *key_file, SSL_CTX **out_ctx) {
    SSL_CTX *sslctx;

    sslctx = SSL_CTX_new(TLS_server_method());

    if (sslctx == NULL) {
        fprintf(stderr, "quic.c, quic_create_server_ssl_ctx(): SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_CTX_set_min_proto_version(sslctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(sslctx, quic_alpn_select_cb, NULL);

    if (SSL_CTX_use_certificate_file(sslctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "quic.c, quic_create_server_ssl_ctx(): SSL_CTX_use_certificate_file failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(sslctx);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(sslctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "quic.c, quic_create_server_ssl_ctx(): SSL_CTX_use_PrivateKey_file failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(sslctx);
        return -1;
    }

    if (SSL_CTX_check_private_key(sslctx) != 1) {
        fprintf(stderr, "quic.c, quic_create_server_ssl_ctx(): SSL_CTX_check_private_key failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(sslctx);
        return -1;
    }

    *out_ctx = sslctx;

    return 0;
}

static int quic_is_ip_literal(const char *name) {
    struct in_addr v4;
    struct in6_addr v6;

    return inet_pton(AF_INET, name, &v4) == 1 || inet_pton(AF_INET6, name, &v6) == 1;
}

static int quic_set_verify_name(SSL *ssl, const char *server_name) {
    if (quic_is_ip_literal(server_name)) {
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        if (X509_VERIFY_PARAM_set1_ip_asc(param, server_name) != 1) {
            fprintf(stderr, "quic.c, quic_set_verify_name(): X509_VERIFY_PARAM_set1_ip_asc failed\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }

        return 0;
    }

    if (SSL_set1_host(ssl, server_name) != 1) {
        fprintf(stderr, "quic.c, quic_set_verify_name(): SSL_set1_host failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

int quic_setup_tls_session(SSL_CTX *ssl_ctx, const char *server_name, int insecure, ngtcp2_crypto_conn_ref *conn_ref, SSL **out_ssl, ngtcp2_crypto_ossl_ctx **out_ossl_ctx) {
    SSL *ssl;
    int alpnproto, tlshn;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;

    ssl = SSL_new(ssl_ctx);

    if (ssl == NULL) {
        fprintf(stderr, "quic.c, quic_setup_tls_session(): SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_set_connect_state(ssl);

    alpnproto = SSL_set_alpn_protos(ssl, (const unsigned char *)"\x02h3", 3);

    if (alpnproto != 0) {
        fprintf(stderr, "quic.c, quic_setup_tls_session(): SSL_set_alpn_protos failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return -1;
    }

    tlshn = SSL_set_tlsext_host_name(ssl, server_name);

    if (tlshn == 0) {
        fprintf(stderr, "quic.c, quic_setup_tls_session(): SSL_set_tlsext_host_name failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return -1;
    }

    if (!insecure && quic_set_verify_name(ssl, server_name) != 0) {
        SSL_free(ssl);
        return -1;
    }

    conn_ref->get_conn = quic_get_conn;
    SSL_set_app_data(ssl, conn_ref);

    if (ngtcp2_crypto_ossl_configure_client_session(ssl) != 0) {
        fprintf(stderr, "quic.c, quic_setup_tls_session(): ngtcp2_crypto_ossl_configure_client_session failed\n");
        SSL_free(ssl);
        return -1;
    }

    if (ngtcp2_crypto_ossl_ctx_new(&ossl_ctx, ssl) != 0) {
        fprintf(stderr, "quic.c, quic_setup_tls_session(): ngtcp2_crypto_ossl_ctx_new failed\n");
        SSL_free(ssl);
        return -1;
    }

    *out_ssl = ssl;
    *out_ossl_ctx = ossl_ctx;

    return 0;
}

int quic_setup_server_tls_session(SSL_CTX *ssl_ctx, ngtcp2_crypto_conn_ref *conn_ref, SSL **out_ssl, ngtcp2_crypto_ossl_ctx **out_ossl_ctx) {
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;

    ssl = SSL_new(ssl_ctx);

    if (ssl == NULL) {
        fprintf(stderr, "quic.c, quic_setup_server_tls_session(): SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_set_accept_state(ssl);

    conn_ref->get_conn = quic_get_conn;
    SSL_set_app_data(ssl, conn_ref);

    if (ngtcp2_crypto_ossl_configure_server_session(ssl) != 0) {
        fprintf(stderr, "quic.c, quic_setup_server_tls_session(): ngtcp2_crypto_ossl_configure_server_session failed\n");
        SSL_free(ssl);
        return -1;
    }

    if (ngtcp2_crypto_ossl_ctx_new(&ossl_ctx, ssl) != 0) {
        fprintf(stderr, "quic.c, quic_setup_server_tls_session(): ngtcp2_crypto_ossl_ctx_new failed\n");
        SSL_free(ssl);
        return -1;
    }

    *out_ssl = ssl;
    *out_ossl_ctx = ossl_ctx;

    return 0;
}

static void quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    struct uquic_conn *uc = rand_ctx->native_handle;

    if (RAND_bytes(dest, (int)destlen) != 1) {
        fprintf(stderr, "quic.c, quic_rand_cb(): RAND_bytes failed\n");
        if (uc != NULL) {
            uc->rand_failed = 1;
        }
    }
}

static int quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token, size_t cidlen, void *user_data) {
    (void)conn;
    (void)user_data;

    if (RAND_bytes(cid->data, (int)cidlen) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    if (RAND_bytes(token->data, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    struct uquic_conn *uc = user_data;

    (void)conn;

    fprintf(stderr, "quic.c, quic_handshake_completed_cb(): handshake completed\n");

    uc->handshake_done = 1;

    return 0;
}

static int quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
    struct uquic_conn *uc = user_data;
    size_t n;

    (void)offset;
    (void)stream_user_data;

    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn, datalen);

    n = datalen < sizeof(uc->recv_buf) ? datalen : sizeof(uc->recv_buf);
    memcpy(uc->recv_buf, data, n);

    uc->recv_stream_id = stream_id;
    uc->recv_len = n;
    uc->recv_fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
    uc->recv_pending = 1;

    return 0;
}

static int quic_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data) {
    struct uquic_conn *uc = user_data;

    (void)conn;
    (void)stream_id;
    (void)offset;
    (void)stream_user_data;

    uc->tx_acked += datalen;

    return 0;
}

void quic_build_callbacks(ngtcp2_callbacks *callbacks) {
    memset(callbacks, 0, sizeof(*callbacks));

    callbacks->client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks->update_key = ngtcp2_crypto_update_key_cb;
    callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks->rand = quic_rand_cb;
    callbacks->get_new_connection_id2 = quic_get_new_connection_id_cb;
    callbacks->handshake_completed = quic_handshake_completed_cb;
    callbacks->recv_stream_data = quic_recv_stream_data_cb;
    callbacks->acked_stream_data_offset = quic_acked_stream_data_offset_cb;
}

void quic_build_server_callbacks(ngtcp2_callbacks *callbacks) {
    memset(callbacks, 0, sizeof(*callbacks));

    callbacks->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks->update_key = ngtcp2_crypto_update_key_cb;
    callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks->rand = quic_rand_cb;
    callbacks->get_new_connection_id2 = quic_get_new_connection_id_cb;
    callbacks->handshake_completed = quic_handshake_completed_cb;
    callbacks->recv_stream_data = quic_recv_stream_data_cb;
    callbacks->acked_stream_data_offset = quic_acked_stream_data_offset_cb;
}

int quic_setup_path(int sock, ngtcp2_path_storage *ps) {
    struct sockaddr_storage local_addr, remote_addr;
    socklen_t local_len, remote_len;
    int la, ra;

    la = quic_get_local_addr(sock, &local_addr, &local_len);

    if (la != 0) {
        fprintf(stderr, "quic.c, quic_setup_path(): quic_get_local_addr failed\n");
        return -1;
    }

    ra = quic_get_remote_addr(sock, &remote_addr, &remote_len);

    if (ra != 0) {
        fprintf(stderr, "quic.c, quic_setup_path(): quic_get_remote_addr failed\n");
        return -1;
    }

    ngtcp2_path_storage_init(ps, (struct sockaddr *)&local_addr, local_len, (struct sockaddr *)&remote_addr, remote_len, NULL);

    return 0;
}

ngtcp2_tstamp quic_timestamp(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

int quic_setup_conn(ngtcp2_path_storage *ps, ngtcp2_crypto_ossl_ctx *ossl_ctx, struct uquic_conn *uc) {
    uint8_t buf[NGTCP2_MAX_CIDLEN];
    size_t cidlen = 8;
    ngtcp2_cid dcid, scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_callbacks callbacks;
    ngtcp2_conn *conn;

    if (RAND_bytes(buf, (int)cidlen) != 1) {
        fprintf(stderr, "quic.c, quic_setup_conn(): RAND_bytes (dcid) failed\n");
        return -1;
    }

    ngtcp2_cid_init(&dcid, buf, cidlen);

    if (RAND_bytes(buf, (int)cidlen) != 1) {
        fprintf(stderr, "quic.c, quic_setup_conn(): RAND_bytes (scid) failed\n");
        return -1;
    }

    ngtcp2_cid_init(&scid, buf, cidlen);

    quic_build_callbacks(&callbacks);

    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();
    settings.rand_ctx.native_handle = uc;

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 3;
    params.initial_max_streams_bidi = 1;
    params.initial_max_stream_data_bidi_local = 65536;
    params.initial_max_stream_data_bidi_remote = 65536;
    params.initial_max_data = 65536;
    params.max_idle_timeout = 30 * NGTCP2_SECONDS;

    if (ngtcp2_conn_client_new(&conn, &dcid, &scid, &ps->path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, NULL, uc) != 0) {
        fprintf(stderr, "quic.c, quic_setup_conn(): ngtcp2_conn_client_new failed\n");
        return -1;
    }

    uc->conn = conn;
    ngtcp2_conn_set_tls_native_handle(conn, ossl_ctx);

    return 0;
}

int quic_setup_server_conn(ngtcp2_path_storage *ps, ngtcp2_crypto_ossl_ctx *ossl_ctx, struct uquic_conn *uc, const ngtcp2_pkt_hd *hd) {
    uint8_t buf[NGTCP2_MAX_CIDLEN];
    size_t cidlen = 8;
    ngtcp2_cid scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_callbacks callbacks;
    ngtcp2_conn *conn;

    if (RAND_bytes(buf, (int)cidlen) != 1) {
        fprintf(stderr, "quic.c, quic_setup_server_conn(): RAND_bytes (scid) failed\n");
        return -1;
    }

    ngtcp2_cid_init(&scid, buf, cidlen);

    quic_build_server_callbacks(&callbacks);

    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();
    settings.rand_ctx.native_handle = uc;

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 3;
    params.initial_max_streams_bidi = 1;
    params.initial_max_stream_data_bidi_local = 65536;
    params.initial_max_stream_data_bidi_remote = 65536;
    params.initial_max_data = 65536;
    params.max_idle_timeout = 30 * NGTCP2_SECONDS;
    params.original_dcid = hd->dcid;
    params.original_dcid_present = 1;

    if (ngtcp2_conn_server_new(&conn, &hd->scid, &scid, &ps->path, hd->version, &callbacks, &settings, &params, NULL, uc) != 0) {
        fprintf(stderr, "quic.c, quic_setup_server_conn(): ngtcp2_conn_server_new failed\n");
        return -1;
    }

    uc->conn = conn;
    ngtcp2_conn_set_tls_native_handle(conn, ossl_ctx);

    return 0;
}
