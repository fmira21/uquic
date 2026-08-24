#include "uquic.h"
#include <stdio.h>
#include <string.h>

int main() {
    uquic_conn *conn;
    uquic_client_opts opts;
    int64_t stream_id;
    const char ping_msg[] = "ping";
    uint8_t buf[64];
    ssize_t n;
    int fin;

    memset(&opts, 0, sizeof(opts));
    opts.insecure_skip_verify = 1;

    conn = uquic_connect("127.0.0.1", "4433", &opts);
    if (conn == NULL) {
        fprintf(stderr, "example_client.c, main(): uquic_connect failed\n");
        return -1;
    }

    stream_id = uquic_stream_open(conn);
    if (stream_id < 0) {
        fprintf(stderr, "example_client.c, main(): uquic_stream_open failed\n");
        uquic_close(conn);
        return -1;
    }

    if (uquic_send(conn, stream_id, (const uint8_t *)ping_msg, sizeof(ping_msg) - 1, 1) != 0) {
        fprintf(stderr, "example_client.c, main(): uquic_send failed\n");
        uquic_close(conn);
        return -1;
    }

    n = uquic_recv(conn, NULL, buf, sizeof(buf), &fin);
    if (n < 0) {
        fprintf(stderr, "example_client.c, main(): uquic_recv failed\n");
        uquic_close(conn);
        return -1;
    }

    fprintf(stderr, "example_client.c, main(): received %zd bytes: %.*s\n", n, (int)n, buf);

    uquic_close(conn);

    return 0;
}
