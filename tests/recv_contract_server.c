#include "uquic.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    uquic_listener *listener;
    uquic_conn *conn;
    uint8_t buf[65536];
    unsigned long long expect = argc > 1 ? strtoull(argv[1], NULL, 10) : 5000;
    size_t buflen = argc > 2 ? (size_t)strtoul(argv[2], NULL, 10) : 100;
    int64_t sid = -1;
    ssize_t n;
    int fin = 0;
    unsigned long long got = 0;
    unsigned long calls = 0;
    unsigned long fins = 0;
    int eof = 0;
    int corrupt = 0;
    int early_fin = 0;

    if (buflen > sizeof(buf)) {
        buflen = sizeof(buf);
    }

    listener = uquic_listen("127.0.0.1", "4433", "cert.pem", "key.pem");
    if (listener == NULL) {
        fprintf(stderr, "recv_contract_server: listen failed\n");
        return 1;
    }

    conn = uquic_accept(listener);
    if (conn == NULL) {
        fprintf(stderr, "recv_contract_server: accept failed\n");
        return 1;
    }

    for (;;) {
        fin = 0;
        n = uquic_recv(conn, &sid, buf, buflen, &fin);

        if (n < 0) {
            fprintf(stderr, "recv_contract_server: FAIL recv returned -1 after %llu of %llu bytes\n", got, expect);
            uquic_close(conn);
            return 1;
        }

        if (n == 0) {
            eof = 1;
            if (!fin) {
                fprintf(stderr, "recv_contract_server: FAIL EOF returned without fin set\n");
                uquic_close(conn);
                return 1;
            }
            break;
        }

        if ((size_t)n > buflen) {
            fprintf(stderr, "recv_contract_server: FAIL returned %zd bytes for a %zu byte buffer\n", n, buflen);
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
            fins++;
            if (got != expect) {
                early_fin = 1;
            }
        }
    }

    if (corrupt) {
        fprintf(stderr, "recv_contract_server: FAIL payload corrupt or out of order at ~%llu\n", got);
        uquic_close(conn);
        uquic_listener_close(listener);
        return 1;
    }

    if (got != expect) {
        fprintf(stderr, "recv_contract_server: FAIL got %llu want %llu\n", got, expect);
        uquic_close(conn);
        uquic_listener_close(listener);
        return 1;
    }

    if (!eof) {
        fprintf(stderr, "recv_contract_server: FAIL never saw the 0 return for end of stream\n");
        uquic_close(conn);
        uquic_listener_close(listener);
        return 1;
    }

    if (fins != 1 || early_fin) {
        fprintf(stderr, "recv_contract_server: FAIL fin flagged %lu times, early=%d\n", fins, early_fin);
        uquic_close(conn);
        uquic_listener_close(listener);
        return 1;
    }

    fprintf(stderr, "recv_contract_server: OK %llu bytes in %lu calls of %zu, fin once, EOF returned 0\n", got, calls, buflen);

    if (sid >= 0) {
        uquic_send(conn, sid, (const uint8_t *)"done", 4, 1);
    }

    uquic_close(conn);
    uquic_listener_close(listener);

    return 0;
}
