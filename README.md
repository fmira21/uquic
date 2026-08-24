# uquic

uquic implements interaction between processes over network using io_uring for in-host leg and QUIC protocol in between.

This library is a prototype and serves rather for testing the concept against similar implementations in various usecases.

QUIC implementation uses [ngtcp2](https://github.com/ngtcp2/ngtcp2) with OpenSSL.
io_uring layer uses [liburing](https://github.com/axboe/liburing/blob/master/src/include/liburing.h). 

## API

`uquic.h` contains connect/accept/send/recv functions over `uquic_conn`:

```c
uquic_conn *uquic_connect(const char *host, const char *port, const uquic_client_opts *opts);
uquic_conn *uquic_accept(const char *host, const char *port, const char *cert_file, const char *key_file);
int64_t uquic_stream_open(uquic_conn *conn);
int uquic_send(uquic_conn *conn, int64_t stream_id, const uint8_t *data, size_t len, int fin);
ssize_t uquic_recv(uquic_conn *conn, int64_t *stream_id, uint8_t *buf, size_t buflen, int *fin);
int uquic_close(uquic_conn *conn);
```

Underlying QUIC functions are covered in `quic.h`

See `example_client.c`/`example_server.c` for usage.

## TLS verification

By default the client verifies the server certificate against the system trust
store and matches it against `host`. Passing `NULL` as `opts` keeps that default.

```c
typedef struct {
    int insecure_skip_verify;
    const char *ca_file;
    const char *server_name;
} uquic_client_opts;
```

- `ca_file` — trust this PEM bundle instead of the system store.
- `server_name` — name to send as SNI and to match the certificate against,
  when it differs from `host`.
- `insecure_skip_verify` — **accept any certificate from anyone.** This disables
  MITM protection entirely: the connection is still encrypted, but there is
  nothing to prove the peer on the other end is the one you meant to reach. Use
  it for local testing only, never against a real network.

`example_client.c` sets `insecure_skip_verify`, because the self-signed
`cert.pem` below is not in any trust store and carries no SAN for `127.0.0.1`.

## Run test Linux environment in Docker

Run `run_env.sh` to build a test environment in Docker.
This might be helpful if you use Mac or Windows.

Mind that Docker doesn't enable io_uring support by default (security concerns), so you have to add the flag `--security-opt seccomp=unconfined`.

## Build and run

- QUIC client: `make client`.
- QUIC server: `make server`.
- Both: `make all`.

## Generating a test certificate

The QUIC server (`example_server.c`) needs `cert.pem`/`key.pem` in the repo root. Generate a self-signed EC cert:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=uquic-test"
```
