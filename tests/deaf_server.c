#include "uquic.h"
#include <stdio.h>
#include <unistd.h>

int main(void) {
    uquic_conn *conn;

    conn = uquic_accept("127.0.0.1", "4433", "cert.pem", "key.pem");
    if (conn == NULL) {
        fprintf(stderr, "deaf_server: accept failed\n");
        return 1;
    }

    fprintf(stderr, "deaf_server: accepted, going silent\n");

    sleep(300);

    uquic_close(conn);

    return 0;
}
