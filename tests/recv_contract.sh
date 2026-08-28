#!/bin/sh
set -u

. "$(dirname -- "$0")/lib.sh"

require_certs

TMP=$(mktemp -d)
trap 'stop_server; rm -rf "$TMP"' EXIT

CASES=${CASES:-"500:1 5000:100 200000:1500 1000000:65536"}

echo "recv contract: a small buffer must not lose the rest of the stream, and EOF must return 0"

for c in $CASES; do
    size=${c%:*}
    buflen=${c#*:}

    if ! start_server "$TMP/s.log" "$ROOT/tests/recv_contract_server" "$size" "$buflen"; then
        fail "size=$size buflen=$buflen server never came up"
        cat "$TMP/s.log" >&2
        continue
    fi

    ( cd "$ROOT" && exec timeout 120 "$ROOT/tests/bulk_client" "$size" ) >"$TMP/c.log" 2>&1
    crc=$?

    reap_server

    if [ "$SERVER_RC" -ne 0 ]; then
        fail "size=$size buflen=$buflen server rc=$SERVER_RC"
        cat "$TMP/s.log" >&2
        continue
    fi

    if [ "$crc" -ne 0 ]; then
        fail "size=$size buflen=$buflen client rc=$crc"
        cat "$TMP/c.log" >&2
        continue
    fi

    pass "size=$size buflen=$buflen $(grep -o 'OK .*' "$TMP/s.log" || echo delivered)"
done

exit $TESTS_FAILED
