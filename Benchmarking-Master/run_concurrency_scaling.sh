#!/bin/bash
# Concurrency/throughput scaling: launch K parallel copies of the _fast
# (N=100), op-isolated binary for one algorithm+op, time the whole batch,
# and report aggregate throughput = K*N/wall_time.
#
# Usage: ./run_concurrency_scaling.sh <outcsv> <k1,k2,k3,...>
set -u
OUTCSV="${1:-concurrency_scaling.csv}"
KLIST="${2:-1,2,4,8}"
N_PER_COPY=100

# algorithm,binary,oqs_name,op
JOBS=(
  "RSA-3072|bench_classical_fast|RSA-3072|sign"
  "ML-DSA-65|bench_pqc_fast|ML-DSA-65|sign"
  "Falcon-1024|bench_pqc_fast|Falcon-1024|sign"
  "SLH-DSA-SHA2-128s|bench_pqc_fast|SLH_DSA_PURE_SHA2_128S|sign"
)

echo "algorithm,K,wall_seconds,total_ops,throughput_ops_per_sec" > "$OUTCSV"

IFS=',' read -ra KS <<< "$KLIST"

for job in "${JOBS[@]}"; do
  IFS='|' read -r label bin oqs_name op <<< "$job"
  for K in "${KS[@]}"; do
    echo "[$(date +%T)] $label K=$K"
    t0=$(date +%s.%N)
    for i in $(seq 1 "$K"); do
      "./$bin" "/tmp/cs_${label}_${K}_${i}.csv" "/tmp/cs_${label}_${K}_${i}_raw.csv" "$oqs_name" "$op" > /dev/null 2>&1 &
    done
    wait
    t1=$(date +%s.%N)
    elapsed=$(python3 -c "print($t1 - $t0)")
    total_ops=$((K * N_PER_COPY))
    throughput=$(python3 -c "print($total_ops / $elapsed)")
    echo "$label,$K,$elapsed,$total_ops,$throughput" >> "$OUTCSV"
  done
done

echo "DONE"
