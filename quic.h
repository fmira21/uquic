#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

typedef struct {
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_conn *conn;
    int handshake_done;
} quic_client;

int quic_create_socket(const char *host, const char *port);
int quic_get_local_addr (int sock, struct sockaddr_storage *out_addr, socklen_t *out_len);
int quic_get_remote_addr(int sock, struct sockaddr_storage *out_addr, socklen_t *out_len);
int quic_create_ssl_ctx(SSL_CTX **out_ctx);
int quic_setup_tls_session(SSL_CTX *ssl_ctx, const char *host, ngtcp2_crypto_conn_ref *conn_ref, SSL **out_ssl, ngtcp2_crypto_ossl_ctx **out_ossl_ctx);
int quic_setup_path(int sock, ngtcp2_path_storage *ps);
void quic_build_callbacks(ngtcp2_callbacks *callbacks);
int quic_setup_conn(ngtcp2_path_storage *ps, ngtcp2_crypto_ossl_ctx *ossl_ctx, quic_client *client);
