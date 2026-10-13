#!/bin/bash

# Starts the 4 experiment servers and stops them all on exit.
# Usage: ./start_servers.sh [--http]
#   --http  start the servers in plain TCP mode

QUERY_SERVER_BIN="/home/ubuntu/RAMEN/experiment/server/target/release/query-server"
RESOLUTION_SERVER_BIN="/home/ubuntu/RAMEN/experiment/server/target/release/resolution-server"

PORT_QUERY=8080
PORT_RESOLUTION=8081
PORT_QUERY_NODEF=8082
PORT_RESOLUTION_NODEF=8083

HTTP_FLAG=""
for arg in "$@"; do
    [ "$arg" = "--http" ] && HTTP_FLAG="--http" && break
done

PIDS=()

cleanup() {
    echo ""
    echo "Interrupt received, stopping all servers..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait "${PIDS[@]}" 2>/dev/null || true
    echo "All servers stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "Starting experiment servers"
if [ -n "$HTTP_FLAG" ]; then
    echo "Mode: HTTP (plain TCP)"
else
    echo "Mode: HTTPS (TLS)"
fi
echo ""

"$QUERY_SERVER_BIN"      "$PORT_QUERY"            $HTTP_FLAG &
PIDS+=($!)
echo "  [PID $!] query-server       :$PORT_QUERY      (defended)"

"$RESOLUTION_SERVER_BIN" "$PORT_RESOLUTION"       $HTTP_FLAG &
PIDS+=($!)
echo "  [PID $!] resolution-server  :$PORT_RESOLUTION    (defended)"

"$QUERY_SERVER_BIN"      "$PORT_QUERY_NODEF"      $HTTP_FLAG &
PIDS+=($!)
echo "  [PID $!] query-server       :$PORT_QUERY_NODEF    (no_def)"

"$RESOLUTION_SERVER_BIN" "$PORT_RESOLUTION_NODEF" $HTTP_FLAG &
PIDS+=($!)
echo "  [PID $!] resolution-server  :$PORT_RESOLUTION_NODEF  (no_def)"

echo ""
echo "All servers running. Ctrl+C to stop them."
echo ""

# If one server crashes, stop the others too
wait_any() {
    while true; do
        for pid in "${PIDS[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "Server PID $pid exited unexpectedly."
                cleanup
            fi
        done
        sleep 2
    done
}

wait_any
