#!/bin/bash

# Script per testare diverse combinazioni di probabilità.
# Il loop delle richieste (N_REQUESTS) è gestito qui, non nel client.
# Per ogni singola request:
#   - il client viene invocato con n_requests=1
#   - tcpdump cattura esattamente quella connessione (1 TCP stream per query,
#     N_PARALLEL_PACKETS stream paralleli per resolution)
#   - i byte wire (incluse modifiche TC/eBPF) vengono contati e salvati
# => RTT file e bytes file hanno lo stesso numero di righe.

set -e

# ── Percorsi ─────────────────────────────────────────────────────────────────
CLIENT_PATH="/home/ubuntu/WFSafeBPF/client/target/release/client"
QUERY_CLIENT_BIN="/home/ubuntu/WFSafeBPF/experiment/client/target/release/query-client"
RESOLUTION_CLIENT_BIN="/home/ubuntu/WFSafeBPF/experiment/client/target/release/resolution-client"
RESULTS_DIR="/home/ubuntu/WFSafeBPF/results"

# ── Parametri esperimento ─────────────────────────────────────────────────────
N_REQUESTS=50      # richieste per ogni run (loop gestito qui)
ROUNDS=100           # round per ogni combinazione
NET_INTERFACE="enp7s0"

# ── Indirizzi server ──────────────────────────────────────────────────────────
QUERY_SERVER="10.10.0.2:8080"
RESOLUTION_SERVER="10.10.0.2:8081"
QUERY_NO_DEF_SERVER="10.10.0.2:8082"
RESOLUTION_NO_DEF_SERVER="10.10.0.2:8083"

# ── Directory temporanea pcap ─────────────────────────────────────────────────
PCAP_TMPDIR=$(mktemp -d /tmp/wfsafe_pcap_XXXXXX)
trap 'rm -rf "$PCAP_TMPDIR"' EXIT

# ── Sessione ──────────────────────────────────────────────────────────────────
mkdir -p "$RESULTS_DIR"
SESSION_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_DIR/session_$SESSION_TIMESTAMP"
QUERY_DIR="$SESSION_DIR/query"
RESOLUTION_DIR="$SESSION_DIR/resolution"
mkdir -p "$QUERY_DIR" "$RESOLUTION_DIR"

echo "==================================="
echo "Test Probabilità - Sessione: $SESSION_TIMESTAMP"
echo "==================================="
echo ""

# ── Verifica dipendenze ───────────────────────────────────────────────────────
TSHARK_OK=1; TCPDUMP_OK=1
command -v tshark  &>/dev/null || { echo "⚠ tshark non trovato  (sudo apt install tshark)";  TSHARK_OK=0; }
command -v tcpdump &>/dev/null || { echo "⚠ tcpdump non trovato (sudo apt install tcpdump)"; TCPDUMP_OK=0; }

# ── Combinazioni ──────────────────────────────────────────────────────────────
Q_VALUES=(10 20 30 50 70 100)
COMBOS=()
for q in "${Q_VALUES[@]}"; do
    COMBOS+=("${q},${q},${q}" "${q},0,${q}" "${q},${q},0"
             "0,${q},${q}"   "${q},0,0"    "0,${q},0" "0,0,${q}")
done
COMBOS+=("0,0,0")

TEST_NUM=0
TOTAL_TESTS=$(( (${#COMBOS[@]} + 1) * ROUNDS ))   # +1 per il no_def run per round

echo "Interfaccia tcpdump : $NET_INTERFACE"
echo "Richieste per run   : $N_REQUESTS"
echo "Round               : $ROUNDS"
echo "Combinazioni/round  : ${#COMBOS[@]} + 1 no_def"
echo "Test totali         : $TOTAL_TESTS"
echo ""

# ── PID tcpdump corrente ──────────────────────────────────────────────────────
CAPTURE_PID=""

# ─────────────────────────────────────────────────────────────────────────────
# Funzioni di supporto
# ─────────────────────────────────────────────────────────────────────────────

update_probability() {
    sudo "$CLIENT_PATH" update server1 "$1" "$2" > /dev/null 2>&1
    sleep 1
}

# Avvia tcpdump in background su $NET_INTERFACE filtrando tcp port $2.
# Il pcap viene scritto in $1.
start_capture() {
    local pcap=$1 port=$2
    if [ "$TCPDUMP_OK" -eq 0 ]; then CAPTURE_PID=""; return; fi
    sudo tcpdump -i "$NET_INTERFACE" -w "$pcap" "tcp port $port" 2>/dev/null &
    CAPTURE_PID=$!
    # Attendi che tcpdump crei il file (conferma che è in ascolto)
    local i=0
    while [ ! -f "$pcap" ] && [ "$i" -lt 30 ]; do
        sleep 0.05; i=$((i+1))
    done
    sleep 0.05   # margine extra per il primo pacchetto
}

# Ferma tcpdump, conta byte wire per direzione, appende 1 riga a $3.
# sent = frame con tcp.dstport == porta  (client → server, dopo TC egress)
# recv = frame con tcp.srcport == porta  (server → client, wire-level)
stop_and_count() {
    local pcap=$1 port=$2 bytes_file=$3

    if [ -n "$CAPTURE_PID" ]; then
        sudo pkill -INT -f "tcpdump.*$(basename "$pcap")" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
        CAPTURE_PID=""
    fi

    local sent=0 recv=0
    if [ "$TSHARK_OK" -eq 1 ] && [ -f "$pcap" ]; then
        sent=$(tshark -r "$pcap" -Y "tcp.dstport == $port" \
                 -T fields -e frame.len 2>/dev/null \
               | awk '{s+=$1} END {print s+0}')
        recv=$(tshark -r "$pcap" -Y "tcp.srcport == $port" \
                 -T fields -e frame.len 2>/dev/null \
               | awk '{s+=$1} END {print s+0}')
    fi
    rm -f "$pcap"

    # Scrivi header solo alla prima riga
    [ -f "$bytes_file" ] || echo "sent_bytes,recv_bytes" > "$bytes_file"
    echo "${sent:-0},${recv:-0}" >> "$bytes_file"
}

# Esegue N_REQUESTS iterazioni per un singolo client (query o resolution).
# Ogni iterazione: 1 request → 1 riga RTT (client appende) + 1 riga bytes.
# $1=bin $2=server_addr $3=rtt_file $4=bytes_file $5=pcap_prefix
run_requests() {
    local bin=$1 addr=$2 rtt_file=$3 bytes_file=$4 prefix=$5
    local port="${addr##*:}"

    for req in $(seq 1 "$N_REQUESTS"); do
        local pcap="$PCAP_TMPDIR/${prefix}_${req}.pcap"
        start_capture "$pcap" "$port"
        # n_requests=1: il client fa 1 request e appende 1 riga al file RTT
        timeout 60 "$bin" "$rtt_file" "$addr" 1 > /dev/null 2>&1 || true
        stop_and_count "$pcap" "$port" "$bytes_file"
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# run_test: una combinazione (con difesa) su 8080/8081
# ─────────────────────────────────────────────────────────────────────────────
run_test() {
    local frag=$1 dummy=$2 padding=$3 round=$4
    TEST_NUM=$((TEST_NUM + 1))

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test $TEST_NUM/$TOTAL_TESTS | Round $round | CON DIFESA"
    echo "Pp=${padding}%  Pd=${dummy}%  Pf=${frag}%"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo "  → aggiorno probabilità..."
    update_probability "padding_probability"       "$padding"
    update_probability "dummy_probability"         "$dummy"
    update_probability "fragmentation_probability" "$frag"

    local BASE="p${padding}_d${dummy}_f${frag}_r${round}"

    echo "  → [Query] $N_REQUESTS request su $QUERY_SERVER"
    run_requests "$QUERY_CLIENT_BIN" "$QUERY_SERVER" \
        "$QUERY_DIR/results_${BASE}.csv" \
        "$QUERY_DIR/bytes_${BASE}.csv"  \
        "q_${BASE}"
    echo "  ✓ Query completato"

    echo "  → [Resolution] $N_REQUESTS request su $RESOLUTION_SERVER"
    run_requests "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" \
        "$RESOLUTION_DIR/results_${BASE}.csv" \
        "$RESOLUTION_DIR/bytes_${BASE}.csv"  \
        "r_${BASE}"
    echo "  ✓ Resolution completato"

    sleep 3
}

# ─────────────────────────────────────────────────────────────────────────────
# run_no_def: 1 run per round (senza difesa) su 8082/8083
# I file RTT e bytes accumulano su results_no_def.csv / bytes_no_def.csv
# ─────────────────────────────────────────────────────────────────────────────
run_no_def() {
    local round=$1
    TEST_NUM=$((TEST_NUM + 1))

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test $TEST_NUM/$TOTAL_TESTS | Round $round | SENZA DIFESA (no_def)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo "  → [Query no_def] $N_REQUESTS request su $QUERY_NO_DEF_SERVER"
    run_requests "$QUERY_CLIENT_BIN" "$QUERY_NO_DEF_SERVER" \
        "$QUERY_DIR/results_no_def.csv" \
        "$QUERY_DIR/bytes_no_def.csv"   \
        "q_nodef_r${round}"
    echo "  ✓ Query no_def completato"

    echo "  → [Resolution no_def] $N_REQUESTS request su $RESOLUTION_NO_DEF_SERVER"
    run_requests "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_NO_DEF_SERVER" \
        "$RESOLUTION_DIR/results_no_def.csv" \
        "$RESOLUTION_DIR/bytes_no_def.csv"   \
        "r_nodef_r${round}"
    echo "  ✓ Resolution no_def completato"

    sleep 3
}

# ─────────────────────────────────────────────────────────────────────────────
# Loop principale
# ─────────────────────────────────────────────────────────────────────────────
for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "===== Round $round/$ROUNDS ====="
    echo ""

    mapfile -t SHUFFLED < <(printf "%s\n" "${COMBOS[@]}" | shuf)

    echo "--- Fase 1: 8080/8081 (con difesa) ---"
    for combo in "${SHUFFLED[@]}"; do
        IFS=',' read -r padding dummy frag <<< "$combo"
        run_test "$frag" "$dummy" "$padding" "$round"
    done

    echo ""
    echo "--- Fase 2: 8082/8083 (senza difesa, run unica) ---"
    run_no_def "$round"
done

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "==================================="
echo "Tutti i test completati!"
echo "Risultati in: $SESSION_DIR"
echo "==================================="
echo ""

generate_summary() {
    local pattern=$1 out=$2 label=$3
    echo "# Summary $SESSION_TIMESTAMP ($label)" > "$out"
    echo "padding_prob,dummy_prob,frag_prob,n_rows,status" >> "$out"
    for f in $pattern; do
        [ -f "$f" ] || continue
        fn=$(basename "$f")
        pp=$(echo "$fn" | sed -n 's/results_p\([0-9]*\)_.*/\1/p')
        pd=$(echo "$fn" | sed -n 's/results_p[0-9]*_d\([0-9]*\)_.*/\1/p')
        pf=$(echo "$fn" | sed -n 's/results_p[0-9]*_d[0-9]*_f\([0-9]*\).*/\1/p')
        rows=$(( $(wc -l < "$f") - 1 ))   # escludi header
        echo "$pp,$pd,$pf,$rows,ok" >> "$out"
    done
}

generate_summary "$QUERY_DIR/results_p*.csv"      "$SESSION_DIR/summary_query.csv"      "query"
generate_summary "$RESOLUTION_DIR/results_p*.csv" "$SESSION_DIR/summary_resolution.csv" "resolution"

echo "Anteprima (query):"
column -t -s',' "$SESSION_DIR/summary_query.csv" | head -20
