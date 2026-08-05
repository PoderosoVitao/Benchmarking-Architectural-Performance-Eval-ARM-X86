#!/bin/bash
# Full algorithm x operation perf-stat matrix, using the _fast (N=100) binaries.
# Usage: ./run_perf_matrix.sh <outdir>
set -u
OUTDIR="${1:-/tmp/perf_matrix}"
mkdir -p "$OUTDIR"

PQC_ALGOS=(
  "SLH_DSA_PURE_SHA2_128S"
  "SLH_DSA_PURE_SHA2_192S"
  "SLH_DSA_PURE_SHA2_256S"
  "SLH_DSA_PURE_SHAKE_128S"
  "SLH_DSA_PURE_SHAKE_256S"
  "Falcon-512"
  "Falcon-1024"
  "ML-DSA-44"
  "ML-DSA-65"
  "ML-DSA-87"
)
CLASSICAL_ALGOS=("RSA-3072" "ECDSA-P256")
OPS=("keygen" "sign" "verify")

EVENTS="instructions,cycles,cache-references,cache-misses,branch-misses"

run_one() {
  local bin="$1" algo="$2" op="$3"
  local safe_algo="${algo//[^A-Za-z0-9_-]/_}"
  local out="$OUTDIR/${safe_algo}_${op}.txt"
  echo "[$(date +%T)] $algo $op"
  perf stat -e "$EVENTS" -- "./$bin" /tmp/pm_scratch.csv /tmp/pm_scratch_raw.csv "$algo" "$op" > "$out.stdout" 2> "$out"
}

for algo in "${PQC_ALGOS[@]}"; do
  for op in "${OPS[@]}"; do
    run_one "bench_pqc_fast" "$algo" "$op"
  done
done

for algo in "${CLASSICAL_ALGOS[@]}"; do
  for op in "${OPS[@]}"; do
    run_one "bench_classical_fast" "$algo" "$op"
  done
done

echo "DONE" > "$OUTDIR/.done"
echo "[$(date +%T)] all combinations complete"
