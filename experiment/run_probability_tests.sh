#!/bin/bash

# Script per testare diverse combinazioni di probabilità.
# Il loop delle richieste (N_REQUESTS) è gestito qui, non nel client.
# Per ogni singola request il client viene invocato con n_requests=1.

set -e

# ── Percorsi ─────────────────────────────────────────────────────────────────
CLIENT_PATH="/home/ubuntu/WFSafeBPF/client/target/release/client"
QUERY_CLIENT_BIN="/home/ubuntu/WFSafeBPF/experiment/client/target/release/query-client"
RESOLUTION_CLIENT_BIN="/home/ubuntu/WFSafeBPF/experiment/client/target/release/resolution-client"
RESULTS_DIR="/home/ubuntu/WFSafeBPF/results"

# ── Parametri esperimento ─────────────────────────────────────────────────────
N_REQUESTS=50      # richieste per ogni run (loop gestito qui)
ROUNDS=100         # round per ogni combinazione
TARGET=$((N_REQUESTS * ROUNDS))   # entries target per ogni file CSV

# ── Indirizzi server ──────────────────────────────────────────────────────────
QUERY_SERVER="10.133.6.2:8080"
RESOLUTION_SERVER="10.133.6.2:8081"
QUERY_NO_DEF_SERVER="10.133.6.2:8082"
RESOLUTION_NO_DEF_SERVER="10.133.6.2:8083"

# ── Sessione ──────────────────────────────────────────────────────────────────
mkdir -p "$RESULTS_DIR"
SESSION_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_DIR/session_$SESSION_TIMESTAMP"
QUERY_DIR="$SESSION_DIR/query"
RESOLUTION_DIR="$SESSION_DIR/resolution"
mkdir -p "$QUERY_DIR/times" "$RESOLUTION_DIR/times"

echo "==================================="
echo "Test Probabilità - Sessione: $SESSION_TIMESTAMP"
echo "==================================="
echo ""

# ── Combinazioni ──────────────────────────────────────────────────────────────
Q_VALUES=(10 20 30 50 70)
COMBOS=()
for q in "${Q_VALUES[@]}"; do
    COMBOS+=("${q},${q},${q}" "${q},0,${q}" "${q},${q},0"
             "0,${q},${q}"   "${q},0,0"    "0,${q},0" "0,0,${q}")
done
COMBOS+=("0,0,0")

TEST_NUM=0
TOTAL_TESTS=$(( (${#COMBOS[@]} + 1) * ROUNDS ))   # +1 per il no_def run per round

echo "Richieste per run   : $N_REQUESTS"
echo "Round               : $ROUNDS"
echo "Combinazioni/round  : ${#COMBOS[@]} + 1 no_def"
echo "Test totali         : $TOTAL_TESTS"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Funzioni di supporto
# ─────────────────────────────────────────────────────────────────────────────

update_probability() {
    sudo "$CLIENT_PATH" update server_query "$1" "$2" > /dev/null 2>&1
    sudo "$CLIENT_PATH" update server_res   "$1" "$2" > /dev/null 2>&1
}

# Conta le entries in un CSV (esclude header). Restituisce 0 se il file non esiste.
count_entries() {
    local file=$1
    [ -f "$file" ] || { echo 0; return; }
    local lines
    lines=$(wc -l < "$file")
    echo $(( lines > 0 ? lines - 1 : 0 ))
}

# Esegue N_REQUESTS iterazioni per un singolo client (query o resolution).
# $1=bin $2=server_addr $3=rtt_file
run_requests() {
    local bin=$1 addr=$2 rtt_file=$3

    for req in $(seq 1 "$N_REQUESTS"); do
        timeout 60 "$bin" "$rtt_file" "$addr" 1 > /dev/null 2>&1 || true
    done
}

# Come run_requests ma con numero di iterazioni esplicito.
# $1=bin $2=server_addr $3=rtt_file $4=n
run_n_requests() {
    local bin=$1 addr=$2 rtt_file=$3 n=$4
    for req in $(seq 1 "$n"); do
        timeout 60 "$bin" "$rtt_file" "$addr" 1 > /dev/null 2>&1 || true
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

    local BASE="p${padding}_d${dummy}_f${frag}"

    echo "  → [Query] $N_REQUESTS request su $QUERY_SERVER"
    run_requests "$QUERY_CLIENT_BIN" "$QUERY_SERVER" \
        "$QUERY_DIR/times/${BASE}.csv"
    echo "  ✓ Query completato"

    echo "  → [Resolution] $N_REQUESTS request su $RESOLUTION_SERVER"
    run_requests "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" \
        "$RESOLUTION_DIR/times/${BASE}.csv"
    echo "  ✓ Resolution completato"

}


# ─────────────────────────────────────────────────────────────────────────────
# run_no_def: 1 run per round (senza difesa) su 8082/8083
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
        "$QUERY_DIR/times/no_def.csv"
    echo "  ✓ Query no_def completato"

    echo "  → [Resolution no_def] $N_REQUESTS request su $RESOLUTION_NO_DEF_SERVER"
    run_requests "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_NO_DEF_SERVER" \
        "$RESOLUTION_DIR/times/no_def.csv"
    echo "  ✓ Resolution no_def completato"

}


# ─────────────────────────────────────────────────────────────────────────────
# topup_phase: dopo il loop principale, completa i file che non hanno raggiunto
# TARGET entries. Itera al massimo MAX_TOPUP_ITER volte.
# ─────────────────────────────────────────────────────────────────────────────
topup_phase() {
    local max_iter=10 iter=0 all_done q_count r_count q_miss r_miss

    echo ""
    echo "==================================="
    echo "Fase di completamento (top-up)"
    echo "Target per file: $TARGET entries"
    echo "==================================="

    while true; do
        iter=$((iter + 1))
        all_done=1

        if [ "$iter" -gt "$max_iter" ]; then
            echo "  ⚠ Raggiunto limite massimo di iterazioni ($max_iter). Alcuni file potrebbero essere incompleti."
            break
        fi

        echo ""
        echo "  -- Iterazione top-up $iter/$max_iter --"

        # ── Combos con difesa ──────────────────────────────────────────────
        for combo in "${COMBOS[@]}"; do
            IFS=',' read -r padding dummy frag <<< "$combo"
            local BASE="p${padding}_d${dummy}_f${frag}"
            local q_file="$QUERY_DIR/times/${BASE}.csv"
            local r_file="$RESOLUTION_DIR/times/${BASE}.csv"

            q_count=$(count_entries "$q_file")
            r_count=$(count_entries "$r_file")
            q_miss=$(( TARGET - q_count )); [ "$q_miss" -lt 0 ] && q_miss=0
            r_miss=$(( TARGET - r_count )); [ "$r_miss" -lt 0 ] && r_miss=0

            if [ "$q_miss" -eq 0 ] && [ "$r_miss" -eq 0 ]; then
                continue
            fi

            all_done=0
            echo "  [${BASE}] Q:$q_count/$TARGET R:$r_count/$TARGET → mancano Q:$q_miss R:$r_miss"
            update_probability "padding_probability"       "$padding"
            update_probability "dummy_probability"         "$dummy"
            update_probability "fragmentation_probability" "$frag"

            if [ "$q_miss" -gt 0 ]; then
                run_n_requests "$QUERY_CLIENT_BIN" "$QUERY_SERVER" "$q_file" "$q_miss"
            fi
            if [ "$r_miss" -gt 0 ]; then
                run_n_requests "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" "$r_file" "$r_miss"
            fi
        done

        # ── no_def ────────────────────────────────────────────────────────
        local q_nd="$QUERY_DIR/times/no_def.csv"
        local r_nd="$RESOLUTION_DIR/times/no_def.csv"

        q_count=$(count_entries "$q_nd")
        r_count=$(count_entries "$r_nd")
        q_miss=$(( TARGET - q_count )); [ "$q_miss" -lt 0 ] && q_miss=0
        r_miss=$(( TARGET - r_count )); [ "$r_miss" -lt 0 ] && r_miss=0

        if [ "$q_miss" -gt 0 ] || [ "$r_miss" -gt 0 ]; then
            all_done=0
            echo "  [no_def] Q:$q_count/$TARGET R:$r_count/$TARGET → mancano Q:$q_miss R:$r_miss"
            if [ "$q_miss" -gt 0 ]; then
                run_n_requests "$QUERY_CLIENT_BIN" "$QUERY_NO_DEF_SERVER" "$q_nd" "$q_miss"
            fi
            if [ "$r_miss" -gt 0 ]; then
                run_n_requests "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_NO_DEF_SERVER" "$r_nd" "$r_miss"
            fi
        fi

        if [ "$all_done" -eq 1 ]; then
            echo ""
            echo "  ✓ Tutti i file hanno raggiunto il target ($TARGET entries)."
            break
        fi
    done
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

topup_phase

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
        pp=$(echo "$fn" | sed -n 's/p\([0-9]*\)_.*/\1/p')
        pd=$(echo "$fn" | sed -n 's/p[0-9]*_d\([0-9]*\)_.*/\1/p')
        pf=$(echo "$fn" | sed -n 's/p[0-9]*_d[0-9]*_f\([0-9]*\).*/\1/p')
        rows=$(( $(wc -l < "$f") - 1 ))   # escludi header
        echo "$pp,$pd,$pf,$rows,ok" >> "$out"
    done
}

generate_summary "$QUERY_DIR/times/p*.csv"      "$SESSION_DIR/summary_query.csv"      "query"
generate_summary "$RESOLUTION_DIR/times/p*.csv" "$SESSION_DIR/summary_resolution.csv" "resolution"

echo "Anteprima (query):"
column -t -s',' "$SESSION_DIR/summary_query.csv" | head -20
