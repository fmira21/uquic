#!/bin/sh
set -u

. "$(dirname -- "$0")/lib.sh"

require_certs

TMP=$(mktemp -d)
trap 'stop_server; rm -rf "$TMP"' EXIT

CONNS=${CONNS:-4}
SIZE=${SIZE:-200000}

echo "concurrency: one listener must serve $CONNS connections at once, and survive junk packets"

if ! start_server "$TMP/s.log" "$ROOT/tests/multi_server" "$CONNS" "$SIZE"; then
    fail "server never came up"
    cat "$TMP/s.log" >&2
    exit "$TESTS_FAILED"
fi

printf 'not a quic packet' | timeout 2 nc -u -w1 127.0.0.1 4433 >/dev/null 2>&1 || true

i=0
while [ "$i" -lt "$CONNS" ]; do
    ( cd "$ROOT" && exec timeout 120 "$ROOT/tests/bulk_client" "$SIZE" ) >"$TMP/c$i.log" 2>&1 &
    eval "cpid$i=$!"
    i=$((i + 1))
done

crc=0
i=0
while [ "$i" -lt "$CONNS" ]; do
    eval "wait \$cpid$i" || crc=1
    i=$((i + 1))
done

reap_server

if [ "$crc" -ne 0 ]; then
    fail "at least one client exited nonzero"
    cat "$TMP"/c*.log >&2
    cat "$TMP/s.log" >&2
    exit "$TESTS_FAILED"
fi

if [ "$SERVER_RC" -ne 0 ]; then
    fail "server rc=$SERVER_RC"
    cat "$TMP/s.log" >&2
    exit "$TESTS_FAILED"
fi

pass "$(grep -o 'OK .*' "$TMP/s.log" || echo served) (junk packet ignored)"

exit $TESTS_FAILED
