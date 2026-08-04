#!/usr/bin/env bash
# ── run_benchmark.sh ──────────────────────────────────────────────────────
# Full benchmark runner. Works on x86_64 or aarch64; output filenames are
# labeled from `uname -m` rather than hardcoded, since an earlier version
# of this script hardcoded "_x86" and got run on ARM by mistake, silently
# mislabeling a full data set.
#
# What this script does:
#   1. Records hardware and software environment metadata
#   2. Attempts to pin the CPU governor to 'performance' (requires sudo)
#   3. Runs both benchmarks, producing aggregate AND raw per-iteration CSVs
#   4. Restores the CPU governor
#   5. Merges both aggregate CSVs and prepends a metadata header
#
# On boards with a marginal power supply (e.g. a Raspberry Pi run off a
# PC USB port or an under-spec charger), pinning 'performance' can cause
# undervoltage crashes under sustained load — this happened during this
# project's own ARM re-run. If that's your situation, use
# run_arm_benchmark.sh instead, which skips governor pinning and logs
# temperature throughout instead.
#
# Usage:
#   chmod +x run_benchmark.sh
#   sudo ./run_benchmark.sh          # sudo required for governor pinning
#   ./run_benchmark.sh               # works without sudo, governor left alone
# ──────────────────────────────────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ARCH=$(uname -m)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="results_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

CSV_PQC="${OUTPUT_DIR}/results_pqc_${ARCH}.csv"
CSV_PQC_RAW="${OUTPUT_DIR}/results_pqc_${ARCH}_raw.csv"
CSV_CLASSICAL="${OUTPUT_DIR}/results_classical_${ARCH}.csv"
CSV_CLASSICAL_RAW="${OUTPUT_DIR}/results_classical_${ARCH}_raw.csv"
CSV_MERGED="${OUTPUT_DIR}/results_all_${ARCH}.csv"
META="${OUTPUT_DIR}/environment.txt"

echo "================================================================="
echo "  PQC Benchmark Suite — ${ARCH}"
echo "  Timestamp: ${TIMESTAMP}"
echo "  Output:    ${OUTPUT_DIR}/"
echo "================================================================="

# ── 1. Record environment metadata ───────────────────────────────────────
echo "Recording environment..."
{
    echo "=== Benchmark Environment ==="
    echo "Date:        $(date)"
    echo "Hostname:    $(hostname)"
    echo "Architecture: ${ARCH}"
    echo ""
    echo "--- CPU ---"
    lscpu | grep -E "Model name|Architecture|CPU\(s\)|Thread|Core|Socket|MHz|cache"
    echo ""
    echo "--- Governor ---"
    cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u || \
        echo "(cpufreq not available)"
    echo ""
    echo "--- Memory ---"
    free -h
    echo ""
    echo "--- OS ---"
    uname -a
    cat /etc/os-release | grep -E "^NAME|^VERSION"
    echo ""
    echo "--- Compiler ---"
    gcc --version | head -1
    echo ""
    echo "--- OpenSSL ---"
    openssl version
    echo ""
    echo "--- liboqs ---"
    grep -r "OQS_VERSION_TEXT" /usr/local/include/oqs/oqs.h 2>/dev/null || \
        echo "liboqs version: (check oqs.h manually, or your custom install prefix)"
    echo ""
    echo "--- CPU Extensions (x86 only) ---"
    grep -m1 "flags" /proc/cpuinfo 2>/dev/null | \
        grep -oE "avx512[a-z_]*|avx2|aes|sha_ni" | sort -u | tr '\n' ' '
    echo ""
} > "$META"

cat "$META"

# ── 2. Build ──────────────────────────────────────────────────────────────
echo ""
echo "Building..."
make clean
make all

# ── 3. Attempt to pin CPU governor to 'performance' ────────────────────────
GOVERNOR_RESTORED=0
if command -v cpupower &>/dev/null && [ "$EUID" -eq 0 ]; then
    echo ""
    echo "Setting CPU governor to 'performance'..."
    cpupower frequency-set -g performance
    GOVERNOR_RESTORED=1
else
    echo ""
    echo "WARNING: Not running as root or cpupower not found."
    echo "         CPU frequency scaling may affect timing results."
    echo "         For best results on a well-powered machine:"
    echo "           sudo cpupower frequency-set -g performance"
    echo "         On a board with a marginal power supply, leaving the"
    echo "         default governor active (as here) is the safer choice."
fi

# ── 4. Run benchmarks ─────────────────────────────────────────────────────
echo ""
echo "--- Classical baseline (RSA-3072, ECDSA P-256) ---"
./bench_classical "$CSV_CLASSICAL" "$CSV_CLASSICAL_RAW"

echo ""
echo "--- PQC algorithms (ML-DSA, Falcon, SLH-DSA) ---"
echo "NOTE: SLH-DSA signing will take from minutes to hours depending on"
echo "      platform — this is expected, not a hang."
./bench_pqc "$CSV_PQC" "$CSV_PQC_RAW"

# ── 5. Restore CPU governor ───────────────────────────────────────────────
if [ "$GOVERNOR_RESTORED" -eq 1 ]; then
    echo ""
    echo "Restoring CPU governor to 'powersave'..."
    cpupower frequency-set -g powersave
fi

# ── 6. Merge aggregate CSVs ────────────────────────────────────────────────
echo ""
echo "Merging aggregate CSVs..."
head -1 "$CSV_CLASSICAL" > "$CSV_MERGED"
tail -n +2 "$CSV_CLASSICAL" >> "$CSV_MERGED"
tail -n +2 "$CSV_PQC"       >> "$CSV_MERGED"

echo ""
echo "================================================================="
echo "  All benchmarks complete!"
echo "  Aggregate results:"
echo "    ${CSV_CLASSICAL}"
echo "    ${CSV_PQC}"
echo "  Raw per-iteration samples:"
echo "    ${CSV_CLASSICAL_RAW}"
echo "    ${CSV_PQC_RAW}"
echo "  Merged aggregate results:"
echo "    ${CSV_MERGED}"
echo "  Environment metadata:"
echo "    ${META}"
echo "================================================================="
