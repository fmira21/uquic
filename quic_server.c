#include "quic.h"

int main() {
    int sock;
    const char *host = "127.0.0.1";
    const char *port = "4433";

    sock = quic_create_listen_socket(host, port);
    if (sock < 0) {
        return -1;
    }

    fprintf(stderr, "quic_server.c, main(): listening on %s:%s\n", host, port);

    close(sock);

    return 0;
}
