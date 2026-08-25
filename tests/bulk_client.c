#include "uquic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    uquic_conn *conn;
    uquic_client_opts opts;
    int64_t stream_id;
    size_t total = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 200000;
    int expect_fail = argc > 2 && argv[2][0] == 'f';
    uint8_t *payload;
    uint8_t ack[16];
    int afin = 0;
    int rc;

    payload = malloc(total);
    if (payload == NULL) {
        fprintf(stderr, "bulk_client: malloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < total; i++) {
        payload[i] = (uint8_t)(i & 0xff);
    }

    memset(&opts, 0, sizeof(opts));
    opts.insecure_skip_verify = 1;

    conn = uquic_connect("127.0.0.1", "4433", &opts);
    if (conn == NULL) {
        fprintf(stderr, "bulk_client: connect failed\n");
        free(payload);
        return 1;
    }

    stream_id = uquic_stream_open(conn);
    if (stream_id < 0) {
        fprintf(stderr, "bulk_client: stream_open failed\n");
        uquic_close(conn);
        free(payload);
        return 1;
    }

    rc = uquic_send(conn, stream_id, payload, total, 1);
    free(payload);

    if (expect_fail) {
        uquic_close(conn);
        if (rc == 0) {
            fprintf(stderr, "bulk_client: FAIL expected send to fail, it returned 0\n");
            return 1;
        }
        fprintf(stderr, "bulk_client: OK send failed as expected\n");
        return 0;
    }

    if (rc != 0) {
        fprintf(stderr, "bulk_client: FAIL send returned %d\n", rc);
        uquic_close(conn);
        return 1;
    }

    if (uquic_recv(conn, NULL, ack, sizeof(ack), &afin) < 0) {
        fprintf(stderr, "bulk_client: FAIL no ack from peer\n");
        uquic_close(conn);
        return 1;
    }

    uquic_close(conn);

    fprintf(stderr, "bulk_client: OK sent %zu bytes, ack received\n", total);

    return 0;
}
