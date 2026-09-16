#!/usr/bin/env bash
# run_full_suite.sh
# Single entry point for the whole x86 data-collection pass this round:
# canonical latency tables (all algorithms, 1000 iterations, now with
# time-bounded warm-up / CPU-time jitter / verify_invalid / sig_len
# distribution baked in), isolated peak-RSS + stack HWM, thread-level
# throughput scaling (sign+verify, 1-6 threads), and the message-size
# sweep — plus a continuous frequency/thermal monitor running throughout.
#
# Meant to be launched once and left alone; every stage logs to its own
# file under $OUTDIR so a crash partway through still leaves everything
# collected up to that point on disk.
#
# Usage: ./run_full_suite.sh [oqs_prefix]
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OQS_PREFIX="${1:-$HOME/liboqs-install}"
export OQS_PREFIX
export LD_LIBRARY_PATH="$OQS_PREFIX/lib"

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
OUTDIR="results_full_${TIMESTAMP}"
mkdir -p "$OUTDIR"

echo "=================================================================" | tee "$OUTDIR/_suite.log"
echo "  Full suite run — x86_64 — $TIMESTAMP"                            | tee -a "$OUTDIR/_suite.log"
echo "  OQS_PREFIX: $OQS_PREFIX"                                          | tee -a "$OUTDIR/_suite.log"
echo "  Output:     $OUTDIR/"                                             | tee -a "$OUTDIR/_suite.log"
echo "=================================================================" | tee -a "$OUTDIR/_suite.log"

log() { echo "[$(date -u +%T)] $*" | tee -a "$OUTDIR/_suite.log"; }

# ── 0. Environment + continuous monitor ────────────────────────────────
log "capturing environment"
LIBOQS_SRC="/tmp/claude-1000/-home-vhbr-Projects-TCC/331554f5-91af-4588-8bce-57120c4e7aaf/scratchpad/liboqs-016"
./capture_environment.sh "$LIBOQS_SRC" > "$OUTDIR/environment.txt" 2>&1

log "starting monitor_system.sh (1Hz, background for the whole suite)"
./monitor_system.sh "$OUTDIR/system_monitor.csv" 1 &
MONITOR_PID=$!

RUN_PINNED="setarch $(uname -m) -R taskset -c 1"

# ── 1. Build everything ─────────────────────────────────────────────────
log "building all binaries"
make clean >> "$OUTDIR/_build.log" 2>&1
make all fast threaded mem_isolated bench_openssl_pqc bench_openssl_pqc_fast \
    >> "$OUTDIR/_build.log" 2>&1
if [ $? -ne 0 ]; then
    log "BUILD FAILED — see $OUTDIR/_build.log — aborting suite"
    kill "$MONITOR_PID" 2>/dev/null
    exit 1
fi
log "build OK"

# ── 2. Canonical latency tables (1000 iterations, all algorithms) ──────
log "canonical: bench_classical"
$RUN_PINNED ./bench_classical \
    "$OUTDIR/results_classical_x86.csv" "$OUTDIR/results_classical_x86_raw.csv" \
    > "$OUTDIR/classical.log" 2>&1
log "canonical: bench_classical done"

log "canonical: bench_pqc (17 algorithms x 4 ops — this is the long one)"
$RUN_PINNED ./bench_pqc \
    "$OUTDIR/results_pqc_x86.csv" "$OUTDIR/results_pqc_x86_raw.csv" \
    > "$OUTDIR/pqc.log" 2>&1
log "canonical: bench_pqc done"

log "canonical: bench_openssl_pqc"
$RUN_PINNED ./bench_openssl_pqc \
    "$OUTDIR/results_openssl_pqc_x86.csv" "$OUTDIR/results_openssl_pqc_x86_raw.csv" \
    > "$OUTDIR/openssl_pqc.log" 2>&1
log "canonical: bench_openssl_pqc done"

# ── 3. Isolated peak-RSS + stack HWM ────────────────────────────────────
log "mem_isolated (fresh process per algorithm/operation/library)"
$RUN_PINNED ./bench_mem_isolated "$OUTDIR/mem_isolated.csv" \
    > "$OUTDIR/mem_isolated.log" 2>&1
log "mem_isolated done"

# ── 4. Thread-level throughput scaling (1-6 threads, sign+verify) ──────
log "thread scaling sweep"
./run_thread_scaling.sh "$OUTDIR/thread_scaling_x86.csv" "1,2,3,4,5,6" 200 \
    > "$OUTDIR/thread_scaling.log" 2>&1
log "thread scaling done"

# ── 5. Message-size sweep (64B/1KB/64KB/1MB) ────────────────────────────
log "message-size sweep"
./run_message_size_sweep.sh "$OUTDIR/msg_size_sweep" "$OQS_PREFIX" \
    > "$OUTDIR/msg_size_sweep.log" 2>&1
log "message-size sweep done"

# ── 6. Stop the monitor ──────────────────────────────────────────────────
kill "$MONITOR_PID" 2>/dev/null
wait "$MONITOR_PID" 2>/dev/null

log "SUITE COMPLETE"
echo "SUITE_COMPLETE" > "$OUTDIR/DONE"
