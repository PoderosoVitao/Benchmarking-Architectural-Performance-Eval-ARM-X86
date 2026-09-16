#!/usr/bin/env bash
# run_full_suite_arm.sh — Pi counterpart to run_full_suite.sh.
# Differences from the x86 version: OQS_PREFIX points at the ARM
# optimized install, thread list is 1-4 (4 physical cores, no SMT so no
# SMT-disable step needed), and vcgencmd-based temperature/throttle
# logging via monitor_system.sh is the whole point of running this on
# real hardware rather than trusting the theoretical governor argument.
#
# Usage: ./run_full_suite_arm.sh [oqs_prefix] [liboqs_src]
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OQS_PREFIX="${1:-$HOME/liboqs-016-opt-install}"
LIBOQS_SRC="${2:-$HOME/liboqs-016}"
export LD_LIBRARY_PATH="$OQS_PREFIX/lib"

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
OUTDIR="results_full_arm_${TIMESTAMP}"
mkdir -p "$OUTDIR"

log() { echo "[$(date -u +%T)] $*" | tee -a "$OUTDIR/_suite.log"; }

log "Full suite run — ARM (Pi) — $TIMESTAMP — OQS_PREFIX=$OQS_PREFIX"

log "capturing environment"
./capture_environment.sh "$LIBOQS_SRC" > "$OUTDIR/environment.txt" 2>&1

log "starting monitor_system.sh (1Hz, background for the whole suite)"
./monitor_system.sh "$OUTDIR/system_monitor.csv" 1 &
MONITOR_PID=$!

RUN_PINNED="setarch $(uname -m) -R taskset -c 1"

log "canonical: bench_classical"
$RUN_PINNED ./bench_classical \
    "$OUTDIR/results_classical_arm.csv" "$OUTDIR/results_classical_arm_raw.csv" \
    > "$OUTDIR/classical.log" 2>&1
log "canonical: bench_classical done"

log "canonical: bench_pqc (17 algorithms x 4 ops — this is the long one on the Pi)"
$RUN_PINNED ./bench_pqc \
    "$OUTDIR/results_pqc_arm.csv" "$OUTDIR/results_pqc_arm_raw.csv" \
    > "$OUTDIR/pqc.log" 2>&1
log "canonical: bench_pqc done"

log "canonical: bench_openssl_pqc"
$RUN_PINNED ./bench_openssl_pqc \
    "$OUTDIR/results_openssl_pqc_arm.csv" "$OUTDIR/results_openssl_pqc_arm_raw.csv" \
    > "$OUTDIR/openssl_pqc.log" 2>&1
log "canonical: bench_openssl_pqc done"

log "mem_isolated (fresh process per algorithm/operation/library)"
$RUN_PINNED ./bench_mem_isolated "$OUTDIR/mem_isolated.csv" \
    > "$OUTDIR/mem_isolated.log" 2>&1
log "mem_isolated done"

log "thread scaling sweep (1-4 threads: Pi's 4 physical cores)"
./run_thread_scaling.sh "$OUTDIR/thread_scaling_arm.csv" "1,2,3,4" 200 \
    > "$OUTDIR/thread_scaling.log" 2>&1
log "thread scaling done"

log "message-size sweep"
./run_message_size_sweep.sh "$OUTDIR/msg_size_sweep" "$OQS_PREFIX" \
    > "$OUTDIR/msg_size_sweep.log" 2>&1
log "message-size sweep done"

kill "$MONITOR_PID" 2>/dev/null
wait "$MONITOR_PID" 2>/dev/null

log "SUITE COMPLETE"
echo "SUITE_COMPLETE" > "$OUTDIR/DONE"
