#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <liburing.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#define QUIC_SEND_BATCH 8

struct uquic_conn {
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_conn *conn;
    int handshake_done;
    int rand_failed;
    int peer_closed;
    int failed;

    uint64_t tx_sent;
    uint64_t tx_acked;

    int sock;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    struct io_uring ring;

    uint8_t sbuf[QUIC_SEND_BATCH][1452];
    uint8_t pktbuf[65536];

    int64_t recv_stream_id;
    int recv_fin;
    size_t recv_head;
    size_t recv_len;
    uint8_t recv_buf[65536];
};

int quic_create_socket(const char *host, const char *port);
int quic_create_listen_socket(const char *host, const char *port);
int quic_get_local_addr (int sock, struct sockaddr_storage *out_addr, socklen_t *out_len);
int quic_get_remote_addr(int sock, struct sockaddr_storage *out_addr, socklen_t *out_len);
int quic_create_ssl_ctx(const char *ca_file, int insecure, SSL_CTX **out_ctx);
int quic_create_server_ssl_ctx(const char *cert_file, const char *key_file, SSL_CTX **out_ctx);
int quic_setup_tls_session(SSL_CTX *ssl_ctx, const char *server_name, int insecure, ngtcp2_crypto_conn_ref *conn_ref, SSL **out_ssl, ngtcp2_crypto_ossl_ctx **out_ossl_ctx);
int quic_setup_server_tls_session(SSL_CTX *ssl_ctx, ngtcp2_crypto_conn_ref *conn_ref, SSL **out_ssl, ngtcp2_crypto_ossl_ctx **out_ossl_ctx);
int quic_setup_path(int sock, ngtcp2_path_storage *ps);
void quic_build_callbacks(ngtcp2_callbacks *callbacks);
void quic_build_server_callbacks(ngtcp2_callbacks *callbacks);
int quic_setup_conn(ngtcp2_path_storage *ps, ngtcp2_crypto_ossl_ctx *ossl_ctx, struct uquic_conn *uc);
int quic_setup_server_conn(ngtcp2_path_storage *ps, ngtcp2_crypto_ossl_ctx *ossl_ctx, struct uquic_conn *uc, const ngtcp2_pkt_hd *hd);
ngtcp2_tstamp quic_timestamp(void);
