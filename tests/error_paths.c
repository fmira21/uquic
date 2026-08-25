#include "uquic.h"
#include <stdio.h>
#include <string.h>

static int expect_null(const char *what, uquic_conn *conn) {
    if (conn != NULL) {
        fprintf(stderr, "error_paths: FAIL %s returned a connection, expected NULL\n", what);
        uquic_close(conn);
        return 1;
    }

    fprintf(stderr, "error_paths: OK %s returned NULL\n", what);

    return 0;
}

int main(void) {
    uquic_client_opts opts;
    int bad = 0;

    memset(&opts, 0, sizeof(opts));
    opts.ca_file = "tests/nonexistent-ca.pem";
    bad |= expect_null("connect with missing ca_file",
                       uquic_connect("127.0.0.1", "4433", &opts));

    memset(&opts, 0, sizeof(opts));
    opts.ca_file = "Makefile";
    bad |= expect_null("connect with non-certificate ca_file",
                       uquic_connect("127.0.0.1", "4433", &opts));

    memset(&opts, 0, sizeof(opts));
    opts.insecure_skip_verify = 1;
    bad |= expect_null("connect to unresolvable host",
                       uquic_connect("no.such.host.invalid", "4433", &opts));

    bad |= expect_null("accept with missing cert",
                       uquic_accept("127.0.0.1", "4434", "tests/nonexistent-cert.pem", "key.pem"));

    bad |= expect_null("accept with missing key",
                       uquic_accept("127.0.0.1", "4434", "cert.pem", "tests/nonexistent-key.pem"));

    bad |= expect_null("accept with non-certificate cert",
                       uquic_accept("127.0.0.1", "4434", "Makefile", "key.pem"));

    if (bad) {
        return 1;
    }

    fprintf(stderr, "error_paths: all constructor failures returned NULL cleanly\n");

    return 0;
}
