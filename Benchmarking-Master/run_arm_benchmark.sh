#!/usr/bin/env bash
# Runs on the Pi. Launches temperature logging alongside the classical +
# PQC benchmark, then stops the logger. Meant to be invoked via ssh with
# nohup/background so it survives the SSH session ending.
set -e

OUTDIR="$HOME/Benchmarking/results_${1:-run}"
mkdir -p "$OUTDIR"
LIBOQS="$HOME/liboqs-install"

{
  echo "=== Benchmark Environment (native ARM, re-run) ==="
  echo "Date:        $(date)"
  echo "Hostname:    $(hostname)"
  echo "--- CPU ---"
  lscpu | grep -E "Model name|Architecture|CPU\(s\)|Thread|Core|Socket|MHz|cache" 2>/dev/null || true
  echo "--- Governor ---"
  cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u
  echo "--- OS ---"
  uname -a
  cat /etc/os-release | grep -E "^NAME|^VERSION"
  echo "--- Compiler ---"; gcc --version | head -1
  echo "--- OpenSSL ---"; openssl version
  echo "--- liboqs --- 0.15.0 (source build, -DOQS_DIST_BUILD=ON)"
  echo "--- Temp at start ---"; vcgencmd measure_temp
} > "$OUTDIR/environment.txt"

# Temperature logger: one sample every 5s until killed.
( while true; do
    printf "%s %s\n" "$(date +%s)" "$(vcgencmd measure_temp)"
    sleep 5
  done > "$OUTDIR/temp_log.txt" ) &
TEMP_PID=$!

cd "$HOME/Benchmarking"
LD_LIBRARY_PATH="$LIBOQS/lib" stdbuf -oL ./bench_classical \
    "$OUTDIR/results_classical_arm.csv" "$OUTDIR/results_classical_arm_raw.csv" \
    > "$OUTDIR/classical_log.txt" 2>&1

LD_LIBRARY_PATH="$LIBOQS/lib" stdbuf -oL ./bench_pqc \
    "$OUTDIR/results_pqc_arm.csv" "$OUTDIR/results_pqc_arm_raw.csv" \
    > "$OUTDIR/pqc_log.txt" 2>&1

kill "$TEMP_PID" 2>/dev/null || true
echo "ARM_RUN_COMPLETE" > "$OUTDIR/DONE"
