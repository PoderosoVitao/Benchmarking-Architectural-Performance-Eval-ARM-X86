#!/bin/bash
# Thread-level scalability sweep: for each representative algorithm/op, run
# the *_threaded binary at increasing thread counts. Each binary spawns T
# pthreads inside ONE process (barrier-synchronized so setup time never
# leaks into the timed window) and reports aggregate throughput plus mean
# per-op latency under contention.
#
# Complements run_concurrency_scaling.sh's process-level (K separate OS
# processes, separate address spaces) numbers with the intra-process,
# shared-cache/memory-bandwidth contention story thread-level parallelism
# actually captures. Same algorithm selection as the process-level sweep
# (one representative per band) so the two datasets line up directly.
#
# Both sign AND verify are swept (not sign alone): a service under real
# traffic does far more verifies than signs, and the two operations are
# expected to scale differently — SLH-DSA sign is CPU-bound and should
# scale close to linear, while high-rate ML-DSA can start hitting memory
# bandwidth on the Pi's shared bus before its 4 cores are even saturated.
#
# Default thread list is x86's (1-6, this machine's 6 physical cores —
# see run_benchmark.sh's SMT-disable step for why going past 6 would
# start measuring hyperthread contention, not real parallelism). Pass
# 1,2,3,4 explicitly on the Pi (4 physical cores, no SMT).
#
# Usage: ./run_thread_scaling.sh <outcsv> <t1,t2,t3,...> <iters_per_thread>
set -u
OUTCSV="${1:-thread_scaling.csv}"
TLIST="${2:-1,2,3,4,5,6}"
ITERS="${3:-200}"

# label|binary|name|op   (name = oqs_name for PQC, algo string for classical)
JOBS=(
  "RSA-3072|./bench_classical_threaded|RSA-3072|sign"
  "RSA-3072|./bench_classical_threaded|RSA-3072|verify"
  "ML-DSA-65|./bench_pqc_threaded|ML-DSA-65|sign"
  "ML-DSA-65|./bench_pqc_threaded|ML-DSA-65|verify"
  "Falcon-1024|./bench_pqc_threaded|Falcon-1024|sign"
  "Falcon-1024|./bench_pqc_threaded|Falcon-1024|verify"
  "SLH-DSA-SHA2-128s|./bench_pqc_threaded|SLH_DSA_PURE_SHA2_128S|sign"
  "SLH-DSA-SHA2-128s|./bench_pqc_threaded|SLH_DSA_PURE_SHA2_128S|verify"
)

rm -f "$OUTCSV"   # let the binary write a fresh header with the first row

IFS=',' read -ra TS <<< "$TLIST"

for job in "${JOBS[@]}"; do
  IFS='|' read -r label bin name op <<< "$job"
  if [ ! -x "$bin" ]; then
    echo "ERROR: $bin not found or not executable — run 'make threaded' first." >&2
    exit 1
  fi
  for T in "${TS[@]}"; do
    echo "[$(date +%T)] $label op=$op threads=$T"
    "$bin" "$name" "$op" "$T" "$ITERS" "$OUTCSV"
  done
done

echo "DONE — results in $OUTCSV"
echo "Parallel efficiency = throughput(T) / (T * throughput(1)); compute"
echo "post-hoc from the throughput_ops_per_sec column, grouped by"
echo "(algorithm, operation) — not written here to keep this script's"
echo "job purely data collection, not analysis."
