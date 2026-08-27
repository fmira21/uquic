#!/bin/sh
set -u

. "$(dirname -- "$0")/lib.sh"

require_certs

TMP=$(mktemp -d)
trap 'stop_server; rm -rf "$TMP"' EXIT

ROUNDS=${ROUNDS:-5}

CLIENT_EXPECT="received 4 bytes: pong"
SERVER_EXPECT="received 4 bytes on stream 0: ping"

echo "ping/pong: payload asserted on both sides, not just exit codes"

run_once() {
    if ! start_server "$TMP/s.log" "$ROOT/example_server"; then
        return 1
    fi

    ( cd "$ROOT" && exec timeout 15 "$ROOT/example_client" ) >"$TMP/c.log" 2>&1
    crc=$?

    reap_server

    [ "$crc" -eq 0 ] || return 1
    [ "$SERVER_RC" -eq 0 ] || return 1
    grep -q "$CLIENT_EXPECT" "$TMP/c.log" || return 2
    grep -q "$SERVER_EXPECT" "$TMP/s.log" || return 2

    return 0
}

round=1
while [ "$round" -le "$ROUNDS" ]; do
    run_once
    rc=$?

    if [ "$rc" -ne 0 ]; then
        cat "$TMP/c.log" >&2
        cat "$TMP/s.log" >&2

        if [ "$rc" -eq 2 ]; then
            fail "round $round: payload assertion failed"
        else
            fail "round $round: client or server exited nonzero"
        fi

        exit "$TESTS_FAILED"
    fi

    round=$((round + 1))
done

pass "$ROUNDS/$ROUNDS rounds, ping seen by server, pong seen by client"

exit $TESTS_FAILED
