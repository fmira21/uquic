#!/bin/sh
set -u

. "$(dirname -- "$0")/lib.sh"

require_certs

TMP=$(mktemp -d)
trap 'stop_server; rm -rf "$TMP"' EXIT

SIZES=${SIZES:-"4 60000 200000 1000000 5000000"}

echo "bulk transfer: every offered byte must arrive in order (uquic_send completion contract)"

for size in $SIZES; do
    if ! start_server "$TMP/s.log" "$ROOT/tests/bulk_server" "$size"; then
        fail "size=$size server never came up"
        cat "$TMP/s.log" >&2
        continue
    fi

    ( cd "$ROOT" && exec timeout 120 "$ROOT/tests/bulk_client" "$size" ) >"$TMP/c.log" 2>&1
    crc=$?

    reap_server

    if [ "$crc" -ne 0 ]; then
        fail "size=$size client rc=$crc"
        cat "$TMP/c.log" >&2
        cat "$TMP/s.log" >&2
        continue
    fi

    if [ "$SERVER_RC" -ne 0 ]; then
        fail "size=$size server rc=$SERVER_RC"
        cat "$TMP/s.log" >&2
        continue
    fi

    pass "size=$size $(grep -o 'OK .*' "$TMP/s.log" || echo delivered)"
done

exit $TESTS_FAILED
