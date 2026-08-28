#include "uquic.h"
#include <stdio.h>
#include <unistd.h>

int main(void) {
    uquic_listener *listener;
    uquic_conn *conn;

    listener = uquic_listen("127.0.0.1", "4433", "cert.pem", "key.pem");
    if (listener == NULL) {
        fprintf(stderr, "deaf_server: listen failed\n");
        return 1;
    }

    conn = uquic_accept(listener);
    if (conn == NULL) {
        fprintf(stderr, "deaf_server: accept failed\n");
        uquic_listener_close(listener);
        return 1;
    }

    fprintf(stderr, "deaf_server: accepted, going silent\n");

    sleep(300);

    uquic_close(conn);
    uquic_listener_close(listener);

    return 0;
}
