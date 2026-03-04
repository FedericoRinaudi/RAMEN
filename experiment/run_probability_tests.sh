#!/bin/bash

# Script per testare diverse combinazioni di probabilità in due modalità:
#   fixed: min=max=valore (probabilità fissa per tutto il batch)
#   max:   per ogni singola request, lo script sceglie una prob casuale in [0,max]
#          e la passa al server come min=max (simula il comportamento reale con
#          PROB_REFRESH_INTERVAL_NS, che non si attiverebbe abbastanza velocemente
#          durante lo script)

set -e

# ── Argomenti ─────────────────────────────────────────────────────────────────
# Uso: ./run_probability_tests.sh [--http]
#   --http  usa plain TCP invece di TLS (payload aumentato per parità wire)
HTTP_FLAG=""
for arg in "$@"; do
    [ "$arg" = "--http" ] && HTTP_FLAG="--http" && break
done

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
mkdir -p "$QUERY_DIR/fixed" "$QUERY_DIR/max"
mkdir -p "$RESOLUTION_DIR/fixed" "$RESOLUTION_DIR/max"

echo "==================================="
echo "Test Probabilità - Sessione: $SESSION_TIMESTAMP"
if [ -n "$HTTP_FLAG" ]; then
    echo "Modalità trasporto: HTTP (plain TCP)"
else
    echo "Modalità trasporto: HTTPS (TLS)"
fi
echo "==================================="
echo ""

# ── Combinazioni (valori = max prob, usati come fixed o come upper bound) ──────
Q_VALUES=(30 50 70 100)
COMBOS=()
for q in "${Q_VALUES[@]}"; do
    COMBOS+=("${q},${q},${q}" "${q},0,${q}" "${q},${q},0"
             "0,${q},${q}"   "${q},0,0"    "0,${q},0" "0,0,${q}")
done
COMBOS+=("0,0,0")

TEST_NUM=0
# per ogni combo: 2 modalità (fixed + max); + 1 no_def per round
TOTAL_TESTS=$(( (${#COMBOS[@]} * 2 + 1) * ROUNDS ))

echo "Richieste per run   : $N_REQUESTS"
echo "Round               : $ROUNDS"
echo "Combinazioni/round  : ${#COMBOS[@]} (fixed + max) + 1 no_def"
echo "Test totali         : $TOTAL_TESTS"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Funzioni di supporto
# ─────────────────────────────────────────────────────────────────────────────

# Intero casuale in [0, max]
rand_in() {
    local max=$1
    [ "$max" -eq 0 ] && echo 0 && return
    echo $(( RANDOM % (max + 1) ))
}

# Imposta min=max=valore per entrambi i server (modalità fixed)
update_fixed() {
    local padding=$1 dummy=$2 frag=$3
    sudo "$CLIENT_PATH" update-probs "server_query" "$padding" "$padding" "$dummy" "$dummy" "$frag" "$frag" > /dev/null 2>&1
    sudo "$CLIENT_PATH" update-probs "server_res"   "$padding" "$padding" "$dummy" "$dummy" "$frag" "$frag" > /dev/null 2>&1
}

# Imposta min=max=prob_casuale su UN singolo server (modalità max, per ogni request)
update_random_for_server() {
    local server=$1 p_max=$2 d_max=$3 f_max=$4
    local p d f
    p=$(rand_in "$p_max")
    d=$(rand_in "$d_max")
    f=$(rand_in "$f_max")
    sudo "$CLIENT_PATH" update-probs "$server" "$p" "$p" "$d" "$d" "$f" "$f" > /dev/null 2>&1
}

# Conta le entries in un CSV (esclude header). Restituisce 0 se il file non esiste.
count_entries() {
    local file=$1
    [ -f "$file" ] || { echo 0; return; }
    local lines
    lines=$(wc -l < "$file")
    echo $(( lines > 0 ? lines - 1 : 0 ))
}

# Esegue N_REQUESTS request in modalità fixed (prob già impostata prima della chiamata).
# $1=bin $2=server_addr $3=rtt_file
run_requests_fixed() {
    local bin=$1 addr=$2 rtt_file=$3
    for req in $(seq 1 "$N_REQUESTS"); do
        timeout 60 "$bin" "$rtt_file" "$addr" 1 $HTTP_FLAG > /dev/null 2>&1 || true
    done
}

# Esegue N_REQUESTS request in modalità max: sceglie una prob casuale per ogni
# request e la passa al server (min=max=casuale).
# $1=bin $2=server_addr $3=rtt_file $4=server_name $5=p_max $6=d_max $7=f_max
run_requests_max() {
    local bin=$1 addr=$2 rtt_file=$3 server_name=$4 p_max=$5 d_max=$6 f_max=$7
    for req in $(seq 1 "$N_REQUESTS"); do
        update_random_for_server "$server_name" "$p_max" "$d_max" "$f_max"
        timeout 60 "$bin" "$rtt_file" "$addr" 1 $HTTP_FLAG > /dev/null 2>&1 || true
    done
}

# Versioni con numero di iterazioni esplicito (per il top-up)
run_n_requests_fixed() {
    local bin=$1 addr=$2 rtt_file=$3 n=$4
    for req in $(seq 1 "$n"); do
        timeout 60 "$bin" "$rtt_file" "$addr" 1 $HTTP_FLAG > /dev/null 2>&1 || true
    done
}

run_n_requests_max() {
    local bin=$1 addr=$2 rtt_file=$3 server_name=$4 p_max=$5 d_max=$6 f_max=$7 n=$8
    for req in $(seq 1 "$n"); do
        update_random_for_server "$server_name" "$p_max" "$d_max" "$f_max"
        timeout 60 "$bin" "$rtt_file" "$addr" 1 $HTTP_FLAG > /dev/null 2>&1 || true
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# run_test: una combinazione (con difesa) su 8080/8081
# $1=frag $2=dummy $3=padding $4=round $5=mode (fixed|max)
# ─────────────────────────────────────────────────────────────────────────────
run_test() {
    local frag=$1 dummy=$2 padding=$3 round=$4 mode=$5
    TEST_NUM=$((TEST_NUM + 1))

    local BASE="p${padding}_d${dummy}_f${frag}"
    local Q_FILE="$QUERY_DIR/$mode/${BASE}.csv"
    local R_FILE="$RESOLUTION_DIR/$mode/${BASE}.csv"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test $TEST_NUM/$TOTAL_TESTS | Round $round | Modo: $mode | CON DIFESA"
    echo "Pp=${padding}%  Pd=${dummy}%  Pf=${frag}%"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [ "$mode" = "fixed" ]; then
        echo "  → [fixed] setto probabilità fisse per tutto il batch..."
        update_fixed "$padding" "$dummy" "$frag"

        echo "  → [Query] $N_REQUESTS request su $QUERY_SERVER"
        run_requests_fixed "$QUERY_CLIENT_BIN" "$QUERY_SERVER" "$Q_FILE"
        echo "  ✓ Query completato"

        echo "  → [Resolution] $N_REQUESTS request su $RESOLUTION_SERVER"
        run_requests_fixed "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" "$R_FILE"
        echo "  ✓ Resolution completato"
    else
        echo "  → [max] prob casuale [0-P] per ogni query/resolution (upper_bound: Pp=${padding}% Pd=${dummy}% Pf=${frag}%)"

        echo "  → [Query] $N_REQUESTS request su $QUERY_SERVER"
        run_requests_max "$QUERY_CLIENT_BIN" "$QUERY_SERVER" "$Q_FILE" \
            "server_query" "$padding" "$dummy" "$frag"
        echo "  ✓ Query completato"

        echo "  → [Resolution] $N_REQUESTS request su $RESOLUTION_SERVER"
        run_requests_max "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" "$R_FILE" \
            "server_res" "$padding" "$dummy" "$frag"
        echo "  ✓ Resolution completato"
    fi
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
    run_requests_fixed "$QUERY_CLIENT_BIN" "$QUERY_NO_DEF_SERVER" \
        "$QUERY_DIR/no_def.csv"
    echo "  ✓ Query no_def completato"

    echo "  → [Resolution no_def] $N_REQUESTS request su $RESOLUTION_NO_DEF_SERVER"
    run_requests_fixed "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_NO_DEF_SERVER" \
        "$RESOLUTION_DIR/no_def.csv"
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

        # ── Combos con difesa (entrambe le modalità) ───────────────────────
        for mode in fixed max; do
            for combo in "${COMBOS[@]}"; do
                IFS=',' read -r padding dummy frag <<< "$combo"
                local BASE="p${padding}_d${dummy}_f${frag}"
                local q_file="$QUERY_DIR/$mode/${BASE}.csv"
                local r_file="$RESOLUTION_DIR/$mode/${BASE}.csv"

                q_count=$(count_entries "$q_file")
                r_count=$(count_entries "$r_file")
                q_miss=$(( TARGET - q_count )); [ "$q_miss" -lt 0 ] && q_miss=0
                r_miss=$(( TARGET - r_count )); [ "$r_miss" -lt 0 ] && r_miss=0

                if [ "$q_miss" -eq 0 ] && [ "$r_miss" -eq 0 ]; then
                    continue
                fi

                all_done=0
                echo "  [$mode/${BASE}] Q:$q_count/$TARGET R:$r_count/$TARGET → mancano Q:$q_miss R:$r_miss"

                if [ "$mode" = "fixed" ]; then
                    update_fixed "$padding" "$dummy" "$frag"
                    [ "$q_miss" -gt 0 ] && run_n_requests_fixed \
                        "$QUERY_CLIENT_BIN" "$QUERY_SERVER" "$q_file" "$q_miss"
                    [ "$r_miss" -gt 0 ] && run_n_requests_fixed \
                        "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" "$r_file" "$r_miss"
                else
                    [ "$q_miss" -gt 0 ] && run_n_requests_max \
                        "$QUERY_CLIENT_BIN" "$QUERY_SERVER" "$q_file" \
                        "server_query" "$padding" "$dummy" "$frag" "$q_miss"
                    [ "$r_miss" -gt 0 ] && run_n_requests_max \
                        "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" "$r_file" \
                        "server_res" "$padding" "$dummy" "$frag" "$r_miss"
                fi
            done
        done

        # ── no_def ────────────────────────────────────────────────────────
        local q_nd="$QUERY_DIR/no_def.csv"
        local r_nd="$RESOLUTION_DIR/no_def.csv"

        q_count=$(count_entries "$q_nd")
        r_count=$(count_entries "$r_nd")
        q_miss=$(( TARGET - q_count )); [ "$q_miss" -lt 0 ] && q_miss=0
        r_miss=$(( TARGET - r_count )); [ "$r_miss" -lt 0 ] && r_miss=0

        if [ "$q_miss" -gt 0 ] || [ "$r_miss" -gt 0 ]; then
            all_done=0
            echo "  [no_def] Q:$q_count/$TARGET R:$r_count/$TARGET → mancano Q:$q_miss R:$r_miss"
            [ "$q_miss" -gt 0 ] && run_n_requests_fixed \
                "$QUERY_CLIENT_BIN" "$QUERY_NO_DEF_SERVER" "$q_nd" "$q_miss"
            [ "$r_miss" -gt 0 ] && run_n_requests_fixed \
                "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_NO_DEF_SERVER" "$r_nd" "$r_miss"
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

    echo "--- Fase 1: 8080/8081 (con difesa, fixed + max) ---"
    for combo in "${SHUFFLED[@]}"; do
        IFS=',' read -r padding dummy frag <<< "$combo"
        run_test "$frag" "$dummy" "$padding" "$round" "fixed"
        run_test "$frag" "$dummy" "$padding" "$round" "max"
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
    echo "mode,padding_prob,dummy_prob,frag_prob,n_rows,status" >> "$out"
    for f in $pattern; do
        [ -f "$f" ] || continue
        local fn mode pp pd pf rows
        fn=$(basename "$f")
        mode=$(basename "$(dirname "$f")")
        pp=$(echo "$fn" | sed -n 's/p\([0-9]*\)_.*/\1/p')
        pd=$(echo "$fn" | sed -n 's/p[0-9]*_d\([0-9]*\)_.*/\1/p')
        pf=$(echo "$fn" | sed -n 's/p[0-9]*_d[0-9]*_f\([0-9]*\).*/\1/p')
        rows=$(( $(wc -l < "$f") - 1 ))
        echo "$mode,$pp,$pd,$pf,$rows,ok" >> "$out"
    done
}

generate_summary "$QUERY_DIR/*/p*.csv"      "$SESSION_DIR/summary_query.csv"      "query"
generate_summary "$RESOLUTION_DIR/*/p*.csv" "$SESSION_DIR/summary_resolution.csv" "resolution"

echo "Anteprima (query):"
column -t -s',' "$SESSION_DIR/summary_query.csv" | head -20
