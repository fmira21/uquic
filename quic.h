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
#define QUIC_RING_ENTRIES 64
#define QUIC_LISTENER_RING_ENTRIES 256
#define QUIC_FIXED_FD 0
#define QUIC_RECV_BUFS 64
#define QUIC_RECV_BUF_SIZE 2048
#define QUIC_BGID 1
#define QUIC_CIDLEN 8
#define QUIC_CONN_CIDS 8
#define QUIC_MAX_CONNS 64

struct uquic_listener;

struct uquic_conn {
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_conn *conn;
    struct uquic_listener *listener;
    int handshake_done;
    int accepted;
    int rand_failed;
    int peer_closed;
    int failed;
    int closing;
    size_t close_len;

    uint64_t tx_sent;
    uint64_t tx_acked;
    uint64_t tx_written;
    uint8_t txbuf[65536];

    int sock;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    struct io_uring *ring;
    struct io_uring own_ring;
    struct io_uring_buf_ring *bring;
    uint8_t *bbuf;
    int recv_armed;

    ngtcp2_cid cids[QUIC_CONN_CIDS];
    size_t ncids;

    uint8_t sbuf[QUIC_SEND_BATCH][1452];
    size_t sbuf_next;
    size_t sbuf_inflight;
    uint8_t pktbuf[65536];

    int64_t recv_stream_id;
    int recv_fin;
    size_t recv_head;
    size_t recv_len;
    uint8_t recv_buf[65536];
};

struct uquic_listener {
    int sock;
    SSL_CTX *ssl_ctx;
    struct io_uring ring;

    struct sockaddr_storage local_addr;
    socklen_t local_len;

    struct uquic_conn *conns[QUIC_MAX_CONNS];
    size_t nconns;

    struct sockaddr_storage peer_addr;
    socklen_t peer_len;
    uint8_t pktbuf[65536];

    struct io_uring_buf_ring *bring;
    uint8_t *bbuf;
    int recv_armed;
    struct msghdr rmsg;
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
void quic_setup_path_addrs(ngtcp2_path_storage *ps, const struct sockaddr *local, socklen_t local_len, const struct sockaddr *remote, socklen_t remote_len);
int quic_conn_add_cid(struct uquic_conn *uc, const ngtcp2_cid *cid);
void quic_build_callbacks(ngtcp2_callbacks *callbacks);
void quic_build_server_callbacks(ngtcp2_callbacks *callbacks);
int quic_setup_conn(ngtcp2_path_storage *ps, ngtcp2_crypto_ossl_ctx *ossl_ctx, struct uquic_conn *uc);
int quic_setup_server_conn(ngtcp2_path_storage *ps, ngtcp2_crypto_ossl_ctx *ossl_ctx, struct uquic_conn *uc, const ngtcp2_pkt_hd *hd);
ngtcp2_tstamp quic_timestamp(void);
