#!/bin/sh
set -u

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

SUITES="ping_pong.sh bulk.sh recv_contract.sh multi.sh tls_verify.sh error_paths.sh"
SLOW_SUITES="idle_timeout.sh"

failed=0
ran=0

for s in $SUITES; do
    ran=$((ran + 1))
    "$DIR/$s" || failed=$((failed + 1))
done

for s in $SLOW_SUITES; do
    if [ "${SLOW:-0}" = "1" ]; then
        ran=$((ran + 1))
        "$DIR/$s" || failed=$((failed + 1))
    else
        echo "SKIP  $s (set SLOW=1, or run 'make test-slow')"
    fi
done

echo
if [ "$failed" -eq 0 ]; then
    echo "ALL PASS ($ran suites)"
    exit 0
fi

echo "$failed of $ran suites FAILED"
exit 1
