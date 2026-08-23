#include "uquic.h"
#include <stdio.h>

int main() {
    uquic_conn *conn;
    int64_t stream_id;
    const char ping_msg[] = "ping";
    uint8_t buf[64];
    ssize_t n;
    int fin;

    conn = uquic_connect("127.0.0.1", "4433");
    if (conn == NULL) {
        fprintf(stderr, "quic_client.c, main(): uquic_connect failed\n");
        return -1;
    }

    stream_id = uquic_stream_open(conn);
    if (stream_id < 0) {
        fprintf(stderr, "quic_client.c, main(): uquic_stream_open failed\n");
        uquic_close(conn);
        return -1;
    }

    if (uquic_send(conn, stream_id, (const uint8_t *)ping_msg, sizeof(ping_msg) - 1, 1) != 0) {
        fprintf(stderr, "quic_client.c, main(): uquic_send failed\n");
        uquic_close(conn);
        return -1;
    }

    n = uquic_recv(conn, NULL, buf, sizeof(buf), &fin);
    if (n < 0) {
        fprintf(stderr, "quic_client.c, main(): uquic_recv failed\n");
        uquic_close(conn);
        return -1;
    }

    fprintf(stderr, "quic_client.c, main(): received %zd bytes: %.*s\n", n, (int)n, buf);

    uquic_close(conn);

    return 0;
}
