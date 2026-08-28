#include "uquic.h"
#include <stdio.h>
#include <stdlib.h>

#define MULTI_MAX 32

struct slot {
    uquic_conn *conn;
    unsigned long long got;
    int64_t sid;
    int corrupt;
    int done;
};

static struct slot *slot_of(struct slot *slots, size_t n, uquic_conn *conn) {
    size_t i;

    for (i = 0; i < n; i++) {
        if (slots[i].conn == conn) {
            return &slots[i];
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    uquic_listener *listener;
    struct slot slots[MULTI_MAX];
    uint8_t buf[65536];
    size_t nconns = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 4;
    unsigned long long expect = argc > 2 ? strtoull(argv[2], NULL, 10) : 200000;
    size_t i;
    size_t finished = 0;
    int bad = 0;

    if (nconns > MULTI_MAX) {
        nconns = MULTI_MAX;
    }

    listener = uquic_listen("127.0.0.1", "4433", "cert.pem", "key.pem");
    if (listener == NULL) {
        fprintf(stderr, "multi_server: listen failed\n");
        return 1;
    }

    for (i = 0; i < nconns; i++) {
        slots[i].conn = uquic_accept(listener);
        slots[i].got = 0;
        slots[i].sid = -1;
        slots[i].corrupt = 0;
        slots[i].done = 0;

        if (slots[i].conn == NULL) {
            fprintf(stderr, "multi_server: accept %zu failed\n", i);
            uquic_listener_close(listener);
            return 1;
        }

        fprintf(stderr, "multi_server: accepted connection %zu of %zu\n", i + 1, nconns);
    }

    while (finished < nconns) {
        uquic_conn *conn = uquic_next(listener, 60000);
        struct slot *s;
        ssize_t n;
        int fin = 0;

        if (conn == NULL) {
            fprintf(stderr, "multi_server: FAIL timed out with %zu of %zu finished\n", finished, nconns);
            bad = 1;
            break;
        }

        s = slot_of(slots, nconns, conn);
        if (s == NULL || s->done) {
            continue;
        }

        n = uquic_recv(conn, &s->sid, buf, sizeof(buf), &fin);

        if (n < 0) {
            fprintf(stderr, "multi_server: FAIL recv failed after %llu bytes\n", s->got);
            bad = 1;
            s->done = 1;
            finished++;
            continue;
        }

        for (ssize_t k = 0; k < n; k++) {
            if (buf[k] != (uint8_t)((s->got + (unsigned long long)k) & 0xff)) {
                s->corrupt = 1;
                break;
            }
        }

        s->got += (unsigned long long)n;

        if (n == 0 || fin) {
            if (s->got != expect || s->corrupt) {
                fprintf(stderr, "multi_server: FAIL got %llu want %llu corrupt=%d\n", s->got, expect, s->corrupt);
                bad = 1;
            }

            if (s->sid >= 0) {
                uquic_send(conn, s->sid, (const uint8_t *)"done", 4, 1);
            }

            s->done = 1;
            finished++;
            uquic_close(conn);
            s->conn = NULL;
        }
    }

    for (i = 0; i < nconns; i++) {
        if (slots[i].conn != NULL) {
            uquic_close(slots[i].conn);
        }
    }

    uquic_listener_close(listener);

    if (bad) {
        return 1;
    }

    fprintf(stderr, "multi_server: OK %zu concurrent connections, %llu bytes each\n", nconns, expect);

    return 0;
}
