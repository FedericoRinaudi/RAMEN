#!/bin/bash

# Tests several probability combinations in two modes:
#   fixed: min=max=value (fixed probability for the whole trace)
#   max:   for each trace the script picks a random prob in [0,max]
#          and sends it to the server as min=max (emulates the real behaviour of
#          PROB_REFRESH_INTERVAL_NS, which would not trigger quickly enough
#          while the script runs)

set -e

# Usage: ./run_probability_tests.sh [--http]
#   --http  use plain TCP instead of TLS (payload enlarged for equal wire size)
HTTP_FLAG=""
for arg in "$@"; do
    [ "$arg" = "--http" ] && HTTP_FLAG="--http" && break
done

CLIENT_PATH="/home/ubuntu/RAMEN/client/target/release/client"
QUERY_CLIENT_BIN="/home/ubuntu/RAMEN/experiment/client/target/release/query-client"
RESOLUTION_CLIENT_BIN="/home/ubuntu/RAMEN/experiment/client/target/release/resolution-client"
RESULTS_DIR="/home/ubuntu/RAMEN/results"

N_REQUESTS=10      # requests per run (the loop is handled here)
ROUNDS=500
TARGET=$((N_REQUESTS * ROUNDS))   # target entries for each CSV file

QUERY_SERVER="10.133.6.2:8080"
RESOLUTION_SERVER="10.133.6.2:8081"
QUERY_NO_DEF_SERVER="10.133.6.2:8082"
RESOLUTION_NO_DEF_SERVER="10.133.6.2:8083"

mkdir -p "$RESULTS_DIR"
SESSION_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_DIR/session_$SESSION_TIMESTAMP"
QUERY_DIR="$SESSION_DIR/query"
RESOLUTION_DIR="$SESSION_DIR/resolution"
mkdir -p "$QUERY_DIR/fixed" "$QUERY_DIR/max"
mkdir -p "$RESOLUTION_DIR/fixed" "$RESOLUTION_DIR/max"

echo "Probability Tests - Session: $SESSION_TIMESTAMP"
if [ -n "$HTTP_FLAG" ]; then
    echo "Transport mode: HTTP (plain TCP)"
else
    echo "Transport mode: HTTPS (TLS)"
fi
echo ""

# Combinations (values = max prob, used as fixed value or as upper bound)
Q_VALUES=(30 50 70 100)
COMBOS=()
for q in "${Q_VALUES[@]}"; do
    COMBOS+=("${q},${q},${q}" "${q},0,${q}" "${q},${q},0"
             "0,${q},${q}"   "${q},0,0"    "0,${q},0" "0,0,${q}")
done
COMBOS+=("0,0,0")

TEST_NUM=0
# for each combo: 2 modes (fixed + max); + 1 no_def per round
TOTAL_TESTS=$(( (${#COMBOS[@]} * 2 + 1) * ROUNDS ))

echo "Requests per run    : $N_REQUESTS"
echo "Rounds              : $ROUNDS"
echo "Combinations/round  : ${#COMBOS[@]} (fixed + max) + 1 no_def"
echo "Total tests         : $TOTAL_TESTS"
echo ""

rand_in() {
    local max=$1
    [ "$max" -eq 0 ] && echo 0 && return
    echo $(( RANDOM % (max + 1) ))
}

# Sets min=max=value on both servers (fixed mode)
update_fixed() {
    local padding=$1 dummy=$2 frag=$3
    sudo "$CLIENT_PATH" update-probs "server_query" "$padding" "$padding" "$dummy" "$dummy" "$frag" "$frag" > /dev/null 2>&1
    sudo "$CLIENT_PATH" update-probs "server_res"   "$padding" "$padding" "$dummy" "$dummy" "$frag" "$frag" > /dev/null 2>&1
    sleep 0.001
}

# Sets min=max=random_prob on ONE server (max mode)
update_random_for_server() {
    local server=$1 p_max=$2 d_max=$3 f_max=$4
    local p d f
    p=$(rand_in "$p_max")
    d=$(rand_in "$d_max")
    f=$(rand_in "$f_max")
    sudo "$CLIENT_PATH" update-probs "$server" "$p" "$p" "$d" "$d" "$f" "$f" > /dev/null 2>&1
    sleep 0.001
}

# Counts the entries in a CSV (header excluded). Returns 0 if the file does not exist.
count_entries() {
    local file=$1
    [ -f "$file" ] || { echo 0; return; }
    local lines
    lines=$(wc -l < "$file")
    echo $(( lines > 0 ? lines - 1 : 0 ))
}

# Runs N_REQUESTS requests in fixed mode (prob already set before the call).
# $1=bin $2=server_addr $3=rtt_file
run_requests_fixed() {
    local bin=$1 addr=$2 rtt_file=$3
    for req in $(seq 1 "$N_REQUESTS"); do
        timeout 60 "$bin" "$rtt_file" "$addr" 1 $HTTP_FLAG > /dev/null 2>&1 || true
    done
}

# Runs N_REQUESTS requests in max mode: picks a random prob ONCE
# per trace and sets it before the loop (min=max=random).
# $1=bin $2=server_addr $3=rtt_file $4=server_name $5=p_max $6=d_max $7=f_max
run_requests_max() {
    local bin=$1 addr=$2 rtt_file=$3 server_name=$4 p_max=$5 d_max=$6 f_max=$7
    update_random_for_server "$server_name" "$p_max" "$d_max" "$f_max"
    for req in $(seq 1 "$N_REQUESTS"); do
        timeout 60 "$bin" "$rtt_file" "$addr" 1 $HTTP_FLAG > /dev/null 2>&1 || true
    done
}

# Variants with an explicit iteration count (for the top-up)
run_n_requests_fixed() {
    local bin=$1 addr=$2 rtt_file=$3 n=$4
    for req in $(seq 1 "$n"); do
        timeout 60 "$bin" "$rtt_file" "$addr" 1 $HTTP_FLAG > /dev/null 2>&1 || true
    done
}

run_n_requests_max() {
    local bin=$1 addr=$2 rtt_file=$3 server_name=$4 p_max=$5 d_max=$6 f_max=$7 n=$8
    update_random_for_server "$server_name" "$p_max" "$d_max" "$f_max"
    for req in $(seq 1 "$n"); do
        timeout 60 "$bin" "$rtt_file" "$addr" 1 $HTTP_FLAG > /dev/null 2>&1 || true
    done
}

# run_test: one combination (defended) on 8080/8081
# $1=frag $2=dummy $3=padding $4=round $5=mode (fixed|max)
run_test() {
    local frag=$1 dummy=$2 padding=$3 round=$4 mode=$5
    TEST_NUM=$((TEST_NUM + 1))

    local BASE="p${padding}_d${dummy}_f${frag}"
    local Q_FILE="$QUERY_DIR/$mode/${BASE}.csv"
    local R_FILE="$RESOLUTION_DIR/$mode/${BASE}.csv"

    echo ""
    echo "Test $TEST_NUM/$TOTAL_TESTS | Round $round | Mode: $mode | DEFENDED"
    echo "Pp=${padding}%  Pd=${dummy}%  Pf=${frag}%"

    if [ "$mode" = "fixed" ]; then
        echo "  [fixed] setting fixed probabilities for the whole trace..."
        update_fixed "$padding" "$dummy" "$frag"

        echo "  [Query] $N_REQUESTS requests to $QUERY_SERVER"
        run_requests_fixed "$QUERY_CLIENT_BIN" "$QUERY_SERVER" "$Q_FILE"
        echo "  Query done"

        echo "  [Resolution] $N_REQUESTS requests to $RESOLUTION_SERVER"
        run_requests_fixed "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" "$R_FILE"
        echo "  Resolution done"
    else
        echo "  [max] random prob in [0-P] drawn once per trace (upper_bound: Pp=${padding}% Pd=${dummy}% Pf=${frag}%)"

        echo "  [Query] $N_REQUESTS requests to $QUERY_SERVER"
        run_requests_max "$QUERY_CLIENT_BIN" "$QUERY_SERVER" "$Q_FILE" \
            "server_query" "$padding" "$dummy" "$frag"
        echo "  Query done"

        echo "  [Resolution] $N_REQUESTS requests to $RESOLUTION_SERVER"
        run_requests_max "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_SERVER" "$R_FILE" \
            "server_res" "$padding" "$dummy" "$frag"
        echo "  Resolution done"
    fi
}

run_no_def() {
    local round=$1
    TEST_NUM=$((TEST_NUM + 1))

    echo ""
    echo "Test $TEST_NUM/$TOTAL_TESTS | Round $round | UNDEFENDED (no_def)"

    echo "  [Query no_def] $N_REQUESTS requests to $QUERY_NO_DEF_SERVER"
    run_requests_fixed "$QUERY_CLIENT_BIN" "$QUERY_NO_DEF_SERVER" \
        "$QUERY_DIR/no_def.csv"
    echo "  Query no_def done"

    echo "  [Resolution no_def] $N_REQUESTS requests to $RESOLUTION_NO_DEF_SERVER"
    run_requests_fixed "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_NO_DEF_SERVER" \
        "$RESOLUTION_DIR/no_def.csv"
    echo "  Resolution no_def done"
}

# topup_phase: after the main loop, completes the files that have not reached
# TARGET entries. Iterates at most MAX_TOPUP_ITER times.
topup_phase() {
    local max_iter=10 iter=0 all_done q_count r_count q_miss r_miss

    echo ""
    echo "Completion phase (top-up)"
    echo "Target per file: $TARGET entries"

    while true; do
        iter=$((iter + 1))
        all_done=1

        if [ "$iter" -gt "$max_iter" ]; then
            echo "  Maximum number of iterations reached ($max_iter). Some files may be incomplete."
            break
        fi

        echo ""
        echo "  Top-up iteration $iter/$max_iter"

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
                echo "  [$mode/${BASE}] Q:$q_count/$TARGET R:$r_count/$TARGET, missing Q:$q_miss R:$r_miss"

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

        local q_nd="$QUERY_DIR/no_def.csv"
        local r_nd="$RESOLUTION_DIR/no_def.csv"

        q_count=$(count_entries "$q_nd")
        r_count=$(count_entries "$r_nd")
        q_miss=$(( TARGET - q_count )); [ "$q_miss" -lt 0 ] && q_miss=0
        r_miss=$(( TARGET - r_count )); [ "$r_miss" -lt 0 ] && r_miss=0

        if [ "$q_miss" -gt 0 ] || [ "$r_miss" -gt 0 ]; then
            all_done=0
            echo "  [no_def] Q:$q_count/$TARGET R:$r_count/$TARGET, missing Q:$q_miss R:$r_miss"
            [ "$q_miss" -gt 0 ] && run_n_requests_fixed \
                "$QUERY_CLIENT_BIN" "$QUERY_NO_DEF_SERVER" "$q_nd" "$q_miss"
            [ "$r_miss" -gt 0 ] && run_n_requests_fixed \
                "$RESOLUTION_CLIENT_BIN" "$RESOLUTION_NO_DEF_SERVER" "$r_nd" "$r_miss"
        fi

        if [ "$all_done" -eq 1 ]; then
            echo ""
            echo "  All files reached the target ($TARGET entries)."
            break
        fi
    done
}

for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "Round $round/$ROUNDS"
    echo ""

    mapfile -t SHUFFLED < <(printf "%s\n" "${COMBOS[@]}" | shuf)

    echo "Phase 1: 8080/8081 (defended, fixed + max)"
    for combo in "${SHUFFLED[@]}"; do
        IFS=',' read -r padding dummy frag <<< "$combo"
        run_test "$frag" "$dummy" "$padding" "$round" "fixed"
        run_test "$frag" "$dummy" "$padding" "$round" "max"
    done

    echo ""
    echo "Phase 2: 8082/8083 (undefended, single run)"
    run_no_def "$round"
done

topup_phase

echo ""
echo "All tests completed!"
echo "Results in: $SESSION_DIR"
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

echo "Preview (query):"
column -t -s',' "$SESSION_DIR/summary_query.csv" | head -20
