#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct uquic_conn uquic_conn;

typedef struct {
    int insecure_skip_verify;
    const char *ca_file;
    const char *server_name;
} uquic_client_opts;

uquic_conn *uquic_connect(const char *host, const char *port, const uquic_client_opts *opts);
uquic_conn *uquic_accept(const char *host, const char *port, const char *cert_file, const char *key_file);

int64_t uquic_stream_open(uquic_conn *conn);

int uquic_send(uquic_conn *conn, int64_t stream_id, const uint8_t *data, size_t len, int fin);
ssize_t uquic_recv(uquic_conn *conn, int64_t *stream_id, uint8_t *buf, size_t buflen, int *fin);

int uquic_close(uquic_conn *conn);
