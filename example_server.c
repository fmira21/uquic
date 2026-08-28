#include "uquic.h"
#include <stdio.h>

int main() {
    uquic_listener *listener;
    uquic_conn *conn;
    int64_t stream_id;
    const char pong_msg[] = "pong";
    uint8_t buf[64];
    ssize_t n;
    int fin;

    listener = uquic_listen("127.0.0.1", "4433", "cert.pem", "key.pem");
    if (listener == NULL) {
        fprintf(stderr, "example_server.c, main(): uquic_listen failed\n");
        return -1;
    }

    conn = uquic_accept(listener);
    if (conn == NULL) {
        fprintf(stderr, "example_server.c, main(): uquic_accept failed\n");
        uquic_listener_close(listener);
        return -1;
    }

    n = uquic_recv(conn, &stream_id, buf, sizeof(buf), &fin);
    if (n < 0) {
        fprintf(stderr, "example_server.c, main(): uquic_recv failed\n");
        uquic_close(conn);
        uquic_listener_close(listener);
        return -1;
    }

    fprintf(stderr, "example_server.c, main(): received %zd bytes on stream %lld: %.*s\n", n, (long long)stream_id, (int)n, buf);

    if (uquic_send(conn, stream_id, (const uint8_t *)pong_msg, sizeof(pong_msg) - 1, 1) != 0) {
        fprintf(stderr, "example_server.c, main(): uquic_send failed\n");
        uquic_close(conn);
        uquic_listener_close(listener);
        return -1;
    }

    fprintf(stderr, "example_server.c, main(): pong sent\n");

    uquic_close(conn);
    uquic_listener_close(listener);

    return 0;
}
