#include "uquic.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    uquic_conn *conn;
    uquic_client_opts opts;
    const char *mode = argc > 1 ? argv[1] : "default";
    int want_success;

    memset(&opts, 0, sizeof(opts));

    if (strcmp(mode, "default") == 0) {
        want_success = 0;
        conn = uquic_connect("127.0.0.1", "4433", NULL);
    } else if (strcmp(mode, "ca_only") == 0) {
        want_success = 0;
        opts.ca_file = "cert.pem";
        conn = uquic_connect("127.0.0.1", "4433", &opts);
    } else if (strcmp(mode, "ca_and_name") == 0) {
        want_success = 1;
        opts.ca_file = "cert.pem";
        opts.server_name = "uquic-test";
        conn = uquic_connect("127.0.0.1", "4433", &opts);
    } else if (strcmp(mode, "insecure") == 0) {
        want_success = 1;
        opts.insecure_skip_verify = 1;
        conn = uquic_connect("127.0.0.1", "4433", &opts);
    } else if (strcmp(mode, "bad_ca") == 0) {
        want_success = 0;
        opts.ca_file = "tests/nonexistent-ca.pem";
        conn = uquic_connect("127.0.0.1", "4433", &opts);
    } else {
        fprintf(stderr, "verify_client: unknown mode %s\n", mode);
        return 2;
    }

    if (conn != NULL) {
        uquic_close(conn);
    }

    if (want_success && conn == NULL) {
        fprintf(stderr, "verify_client: FAIL mode=%s expected connect to SUCCEED, it failed\n", mode);
        return 1;
    }
    if (!want_success && conn != NULL) {
        fprintf(stderr, "verify_client: FAIL mode=%s expected connect to be REJECTED, it succeeded\n", mode);
        return 1;
    }

    fprintf(stderr, "verify_client: OK mode=%s %s as expected\n", mode, want_success ? "connected" : "rejected");

    return 0;
}
