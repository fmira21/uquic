#include "uquic.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    uquic_conn *conn;
    uint8_t buf[65536];
    int64_t sid = -1;
    ssize_t n;
    int fin = 0;
    unsigned long long got = 0;
    unsigned long calls = 0;
    unsigned long long expect = argc > 1 ? strtoull(argv[1], NULL, 10) : 0;
    int corrupt = 0;

    conn = uquic_accept("127.0.0.1", "4433", "cert.pem", "key.pem");
    if (conn == NULL) {
        fprintf(stderr, "bulk_server: accept failed\n");
        return 1;
    }

    for (;;) {
        n = uquic_recv(conn, &sid, buf, sizeof(buf), &fin);
        if (n < 0) {
            fprintf(stderr, "bulk_server: recv failed after %llu bytes\n", got);
            uquic_close(conn);
            return 1;
        }

        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] != (uint8_t)((got + (unsigned long long)i) & 0xff)) {
                corrupt = 1;
                break;
            }
        }

        got += (unsigned long long)n;
        calls++;

        if (fin) {
            break;
        }
    }

    if (sid >= 0) {
        uquic_send(conn, sid, (const uint8_t *)"done", 4, 1);
        usleep(200000);
    }

    uquic_close(conn);

    if (corrupt) {
        fprintf(stderr, "bulk_server: FAIL payload corrupt at ~%llu\n", got);
        return 1;
    }
    if (expect != 0 && got != expect) {
        fprintf(stderr, "bulk_server: FAIL got %llu want %llu\n", got, expect);
        return 1;
    }

    fprintf(stderr, "bulk_server: OK %llu bytes in %lu recv calls\n", got, calls);

    return 0;
}
