# uquic

uquic implements interaction between processes over network using io_uring for in-host leg and QUIC protocol in between.

QUIC implementation uses ngtcp2 with openssl.

## Run test Linux environment in Docker

Run `run_env.sh` to build a test environment in Docker.
This might be helpful if you use Mac or Windows.

## Build and run

- QUIC client: `make client`.
- QUIC server: `make server`.
- Both: `make all`.

## Generating a test certificate

The QUIC server (`quic_server.c`) needs `cert.pem`/`key.pem` in the repo root. Generate a self-signed EC cert:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=uquic-test"
```
