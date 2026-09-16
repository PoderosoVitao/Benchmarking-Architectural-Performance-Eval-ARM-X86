#!/usr/bin/env bash
# run_message_size_sweep.sh
# Every other measurement in this suite signs a fixed 64-byte dummy
# message. That's fine for a bare signature comparison, but it hides
# whatever fraction of latency is actually the message hash rather than
# the signature scheme itself — and that fraction is exactly what decides
# whether the ranking observed at 64B still holds for firmware signing
# (KB-scale) or build-artifact/container-image signing (MB-scale), the
# workloads this study explicitly recommends SLH-DSA for.
#
# MESSAGE_LEN is now an #ifndef-guarded compile-time constant in
# benchmark.h (same pattern as N_ITERATIONS/WARMUP_MS_DURATION), so each
# size in the sweep is its own binary build rather than a runtime branch —
# zero risk of the sweep itself perturbing the hot loop.
#
# Scoped to one representative algorithm per performance band (the same
# selection used by run_concurrency_scaling.sh / run_thread_scaling.sh
# this round) rather than the full 13-algorithm x 2-library set: a message-
# size sweep across everything would multiply an already-large data
# collection pass by 4x for marginal extra insight over the band
# representatives. N_ITERATIONS=100 (not the canonical 1000): this
# measures whether the RANKING/shape changes with message size, not fine
# percentile statistics, which the canonical 1000-iteration 64B runs
# already cover.
#
# Usage: ./run_message_size_sweep.sh <outdir> [oqs_prefix]
set -eu

OUTDIR="${1:-msg_size_sweep}"
OQS_PREFIX="${2:-$HOME/liboqs-install}"
mkdir -p "$OUTDIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# label,bytes
SIZES=(
  "64B:64"
  "1KB:1024"
  "64KB:65536"
  "1MB:1048576"
)

CC=gcc
CFLAGS="-O2 -Wall -Wextra -pthread -DN_ITERATIONS=100 -DWARMUP_MS_DURATION=200"

for entry in "${SIZES[@]}"; do
  label="${entry%%:*}"
  bytes="${entry##*:}"
  echo "=== building for MESSAGE_LEN=$bytes ($label) ==="

  $CC $CFLAGS -DMESSAGE_LEN=$bytes \
      -I"$OQS_PREFIX/include" -o "/tmp/bench_pqc_msg_$label" bench_pqc.c \
      -L"$OQS_PREFIX/lib" -l:liboqs.a $(pkg-config --libs openssl) -lm -lpthread

  $CC $CFLAGS -DMESSAGE_LEN=$bytes \
      -o "/tmp/bench_classical_msg_$label" bench_classical.c \
      $(pkg-config --cflags --libs openssl) -lm -lpthread

  PQC_ALGOS=("ML-DSA-65" "Falcon-1024" "SLH_DSA_PURE_SHA2_128S")
  for algo in "${PQC_ALGOS[@]}"; do
    echo "  [$label] $algo"
    LD_LIBRARY_PATH="$OQS_PREFIX/lib" "/tmp/bench_pqc_msg_$label" \
        "$OUTDIR/pqc_${label}_${algo}.csv" "$OUTDIR/pqc_${label}_${algo}_raw.csv" \
        "$algo" > "$OUTDIR/pqc_${label}_${algo}.log" 2>&1
  done

  echo "  [$label] RSA-3072 / ECDSA-P256"
  "/tmp/bench_classical_msg_$label" \
      "$OUTDIR/classical_${label}.csv" "$OUTDIR/classical_${label}_raw.csv" \
      > "$OUTDIR/classical_${label}.log" 2>&1
done

echo ""
echo "DONE — per-size CSVs in $OUTDIR/ (message size is encoded in the filename,"
echo "not a column — concatenate with a size column added post-hoc)."
