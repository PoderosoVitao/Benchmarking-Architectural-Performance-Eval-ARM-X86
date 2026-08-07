#!/bin/bash
set -u
OUTDIR="${1:-/tmp/perf_matrix_016}"
BIN="${2:-./liboqs016-bin/bench_pqc_fast}"
mkdir -p "$OUTDIR"

PQC_ALGOS=(
  "SLH_DSA_PURE_SHA2_128S" "SLH_DSA_PURE_SHA2_192S" "SLH_DSA_PURE_SHA2_256S"
  "SLH_DSA_PURE_SHAKE_128S" "SLH_DSA_PURE_SHAKE_256S"
  "Falcon-512" "Falcon-1024"
  "ML-DSA-44" "ML-DSA-65" "ML-DSA-87"
)
OPS=("keygen" "sign" "verify")
EVENTS="instructions,cycles,cache-references,cache-misses,branch-misses"

for algo in "${PQC_ALGOS[@]}"; do
  for op in "${OPS[@]}"; do
    safe_algo="${algo//[^A-Za-z0-9_-]/_}"
    out="$OUTDIR/${safe_algo}_${op}.txt"
    echo "[$(date +%T)] $algo $op"
    perf stat -e "$EVENTS" -- "$BIN" /tmp/pm016_scratch.csv /tmp/pm016_scratch_raw.csv "$algo" "$op" > "$out.stdout" 2> "$out"
  done
done
echo "DONE" > "$OUTDIR/.done"
echo "[$(date +%T)] all combinations complete"
