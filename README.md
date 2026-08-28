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

## Receiving

`uquic_recv` reads from a stream the way `read()` does:

| return | meaning |
|---|---|
| `> 0` | bytes copied into `buf`; `fin` is set only on the chunk that ends the stream |
| `0` | clean end of stream, everything has been delivered |
| `-1` | failure, including the peer vanishing before it finished sending |

A buffer smaller than what has arrived is fine — the remainder stays queued for the
next call, so no read can lose data.

Received data is held in a 64KB per-connection buffer, and the QUIC flow control
window is extended only as the application consumes it. That is what applies
backpressure: a peer cannot get more than one window ahead of a slow reader, and
the buffer cannot overflow.

The consequence is that `uquic_send` blocks while the peer's window is closed. Two
peers that each send more than a window before either starts reading will deadlock
until the idle timeout fires — the same thing happens with TCP and full socket
buffers. Full-duplex use needs a non-blocking mode, which this prototype does not
have yet.

A connection carries a single stream. Data arriving on a second stream is refused
rather than mixed into the buffer.

## Closing

`uquic_close` closes gracefully.
It first waits for the peer to acknowledge everything passed to `uquic_send`,
because a QUIC CONNECTION_CLOSE discards whatever is still in flight. It then
sends CONNECTION_CLOSE and stays in the closing period, answering any further
incoming packet with that same terminal packet, before releasing the socket; otherwise the peer's next datagram bounces back as ICMP port-unreachable and it
sees `ECONNREFUSED` instead of the data it was waiting for.

Both waits are bounded by 3×PTO, so closing a peer that has already gone away
costs a few tens of milliseconds rather than blocking. `uquic_close` returns `-1`
if it gave up with data still unacknowledged, `0` otherwise. It always releases
the connection, whatever it returns.

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

`example_client.c` sets `insecure_skip_verify`, because the self-signed `cert.pem` generated in the section below is not in any trust store and carries no SAN for `127.0.0.1`.

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
