#!/bin/bash

# Lancia i 4 server degli esperimenti e li termina tutti alla chiusura.
# Uso: ./start_servers.sh [--http]
#   --http  avvia i server in modalità plain TCP

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
    echo "Interruzione ricevuta, termino tutti i server..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait "${PIDS[@]}" 2>/dev/null || true
    echo "Tutti i server terminati."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "==================================="
echo "Avvio server esperimenti"
if [ -n "$HTTP_FLAG" ]; then
    echo "Modalità: HTTP (plain TCP)"
else
    echo "Modalità: HTTPS (TLS)"
fi
echo "==================================="
echo ""

"$QUERY_SERVER_BIN"      "$PORT_QUERY"            $HTTP_FLAG &
PIDS+=($!)
echo "  [PID $!] query-server       → :$PORT_QUERY      (con difesa)"

"$RESOLUTION_SERVER_BIN" "$PORT_RESOLUTION"       $HTTP_FLAG &
PIDS+=($!)
echo "  [PID $!] resolution-server  → :$PORT_RESOLUTION    (con difesa)"

"$QUERY_SERVER_BIN"      "$PORT_QUERY_NODEF"      $HTTP_FLAG &
PIDS+=($!)
echo "  [PID $!] query-server       → :$PORT_QUERY_NODEF    (no_def)"

"$RESOLUTION_SERVER_BIN" "$PORT_RESOLUTION_NODEF" $HTTP_FLAG &
PIDS+=($!)
echo "  [PID $!] resolution-server  → :$PORT_RESOLUTION_NODEF  (no_def)"

echo ""
echo "Tutti i server attivi. Ctrl+C per fermarli."
echo ""

# Se uno dei server crasha, termina anche gli altri
wait_any() {
    while true; do
        for pid in "${PIDS[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "Server PID $pid terminato inaspettatamente."
                cleanup
            fi
        done
        sleep 2
    done
}

wait_any
