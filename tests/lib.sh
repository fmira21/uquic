ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export ROOT

TESTS_FAILED=0

note() {
    echo "    $*" >&2
}

pass() {
    echo "  PASS  $*"
}

fail() {
    echo "  FAIL  $*" >&2
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

require_certs() {
    if [ ! -f "$ROOT/cert.pem" ] || [ ! -f "$ROOT/key.pem" ]; then
        echo "FAIL: cert.pem/key.pem missing - see README" >&2
        exit 1
    fi
}

start_server() {
    _log=$1
    shift
    : >"$_log"
    ( cd "$ROOT" && exec "$@" ) >"$_log" 2>&1 &
    SERVER_PID=$!

    _i=0
    while [ "$_i" -lt 100 ]; do
        if grep -q "listening on" "$_log" 2>/dev/null; then
            return 0
        fi
        kill -0 "$SERVER_PID" 2>/dev/null || return 1
        _i=$((_i + 1))
        sleep 0.05
    done

    return 1
}

stop_server() {
    [ -n "${SERVER_PID:-}" ] || return 0
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=
    sleep 0.1
}

reap_server() {
    wait "$SERVER_PID" 2>/dev/null
    SERVER_RC=$?
    SERVER_PID=
    sleep 0.1
}
