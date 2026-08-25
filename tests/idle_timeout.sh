#!/bin/sh
set -u

. "$(dirname -- "$0")/lib.sh"

require_certs

TMP=$(mktemp -d)
trap 'stop_server; rm -rf "$TMP"' EXIT

BUDGET=${BUDGET:-90}

echo "idle timeout: a peer that stops reading must not hang uquic_send forever"

if ! start_server "$TMP/s.log" "$ROOT/tests/deaf_server"; then
    fail "deaf server never came up"
    cat "$TMP/s.log" >&2
    exit 1
fi

start=$(date +%s)
( cd "$ROOT" && exec timeout "$BUDGET" "$ROOT/tests/bulk_client" 5000000 fail ) >"$TMP/c.log" 2>&1
crc=$?
end=$(date +%s)
elapsed=$((end - start))

stop_server

if [ "$crc" -eq 124 ]; then
    fail "uquic_send hung: still running after ${BUDGET}s"
    cat "$TMP/c.log" >&2
elif [ "$crc" -ne 0 ]; then
    fail "client rc=$crc after ${elapsed}s"
    cat "$TMP/c.log" >&2
else
    pass "send gave up after ${elapsed}s instead of hanging"
    note "$(grep -o 'connection failed with.*' "$TMP/c.log" || true)"
fi

exit $TESTS_FAILED
