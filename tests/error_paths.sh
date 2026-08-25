#!/bin/sh
set -u

. "$(dirname -- "$0")/lib.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "constructor error paths: failures must return NULL and free what they built"

( cd "$ROOT" && exec timeout 120 "$ROOT/tests/error_paths" ) >"$TMP/e.log" 2>&1
rc=$?

if [ "$rc" -eq 0 ]; then
    pass "all constructor failures returned NULL"
else
    fail "error_paths rc=$rc"
    cat "$TMP/e.log" >&2
fi

exit $TESTS_FAILED
