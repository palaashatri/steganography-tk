#!/bin/sh
set -eu

display=:99
auth_file="$(mktemp)"
xvfb_pid=

cleanup() {
    if [ -n "$xvfb_pid" ]; then
        kill "$xvfb_pid" 2>/dev/null || true
        wait "$xvfb_pid" 2>/dev/null || true
    fi
    rm -f "$auth_file"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cookie="$(mcookie)"
xauth -f "$auth_file" add "$display" MIT-MAGIC-COOKIE-1 "$cookie"
Xvfb "$display" -screen 0 1280x1024x24 -nolisten tcp -auth "$auth_file" &
xvfb_pid=$!

attempt=0
until DISPLAY="$display" XAUTHORITY="$auth_file" xdpyinfo >/dev/null 2>&1; do
    if ! kill -0 "$xvfb_pid" 2>/dev/null; then
        wait "$xvfb_pid" || true
        echo "Xvfb exited before the display became ready" >&2
        exit 1
    fi

    attempt=$((attempt + 1))
    if [ "$attempt" -ge 50 ]; then
        echo "Timed out waiting for the Xvfb display to become ready" >&2
        exit 1
    fi
    sleep 0.1
done

DISPLAY="$display" XAUTHORITY="$auth_file" "$@"
