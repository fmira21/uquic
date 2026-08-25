#!/bin/sh
set -u

. "$(dirname -- "$0")/lib.sh"

require_certs

TMP=$(mktemp -d)
trap 'stop_server; rm -rf "$TMP"' EXIT

echo "TLS verification: ca_only must still be REJECTED (cert has no SAN for 127.0.0.1)"

for mode in default ca_only bad_ca ca_and_name insecure; do
    if ! start_server "$TMP/s.log" "$ROOT/example_server"; then
        fail "mode=$mode server never came up"
        cat "$TMP/s.log" >&2
        continue
    fi

    ( cd "$ROOT" && exec timeout 60 "$ROOT/tests/verify_client" "$mode" ) >"$TMP/c.log" 2>&1
    crc=$?

    stop_server

    if [ "$crc" -eq 0 ]; then
        pass "$(grep -o 'OK mode=.*' "$TMP/c.log" || echo "mode=$mode")"
    else
        fail "mode=$mode"
        cat "$TMP/c.log" >&2
    fi
done

exit $TESTS_FAILED
