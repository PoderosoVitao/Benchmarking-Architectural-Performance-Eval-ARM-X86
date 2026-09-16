#!/usr/bin/env bash
# capture_environment.sh
# Single source of truth for run provenance, used by both run_benchmark.sh
# (x86) and run_arm_benchmark.sh (Pi) instead of each keeping its own
# hand-written copy — a benchmark run is not reproducible if the exact
# software/hardware state it ran under isn't captured alongside it, and
# two independently-maintained copies of that capture logic drift.
#
# Usage: ./capture_environment.sh [liboqs_source_dir]
#   Writes to stdout — callers redirect to their own environment.txt.
#   liboqs_source_dir defaults to ~/liboqs-016 (this study's 0.16.0
#   checkout); pass the actual path in use if it differs.
set -u

LIBOQS_SRC="${1:-$HOME/liboqs-016}"

echo "=== Benchmark Environment ==="
echo "Date:        $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Hostname:    $(hostname)"
echo ""

echo "--- CPU ---"
lscpu | grep -E "Model name|Architecture|CPU\(s\)|Thread|Core|Socket|MHz|cache" 2>/dev/null
echo ""

echo "--- CPU governor (per core) ---"
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [ -e "$gov" ] || continue
    printf "%s: %s\n" "$gov" "$(cat "$gov" 2>/dev/null)"
done
echo ""

echo "--- SMT / hyperthreading ---"
if [ -e /sys/devices/system/cpu/smt/control ]; then
    echo "smt/control: $(cat /sys/devices/system/cpu/smt/control)"
else
    echo "smt/control: not exposed (no SMT on this CPU, e.g. Cortex-A72)"
fi
echo ""

echo "--- Microcode / firmware ---"
if [ -e /sys/devices/system/cpu/cpu0/microcode/version ]; then
    echo "x86 microcode version: $(cat /sys/devices/system/cpu/cpu0/microcode/version)"
elif command -v vcgencmd >/dev/null 2>&1; then
    echo "Pi firmware: $(vcgencmd version 2>&1 | head -1)"
    echo "Pi bootloader: $(vcgencmd bootloader_version 2>&1 | head -1)"
else
    echo "no microcode/firmware source found for this platform"
fi
echo ""

echo "--- Memory ---"
free -h
echo ""

echo "--- OS ---"
uname -a
grep -E "^NAME|^VERSION" /etc/os-release 2>/dev/null
echo ""

echo "--- Compiler ---"
gcc --version | head -1
if command -v clang >/dev/null 2>&1; then
    echo "(clang also present: $(clang --version | head -1))"
fi
echo ""

echo "--- OpenSSL ---"
openssl version
pkg-config --modversion openssl 2>/dev/null && echo "(pkg-config openssl version above)"
echo ""

echo "--- liboqs ---"
if [ -d "$LIBOQS_SRC/.git" ]; then
    echo "source dir: $LIBOQS_SRC"
    echo "commit:     $(git -C "$LIBOQS_SRC" rev-parse HEAD 2>/dev/null)"
    echo "describe:   $(git -C "$LIBOQS_SRC" describe --tags 2>/dev/null || echo 'no tag')"
    echo "dirty:      $(git -C "$LIBOQS_SRC" diff --quiet 2>/dev/null && echo no || echo YES — uncommitted changes present)"
else
    echo "no git checkout found at $LIBOQS_SRC — pass the correct path as \$1"
fi
echo ""

echo "--- ASLR ---"
echo "kernel.randomize_va_space = $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"
echo ""

echo "--- perf_event_paranoid ---"
cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null
echo ""

echo "--- Temperature at capture time ---"
if command -v vcgencmd >/dev/null 2>&1; then
    vcgencmd measure_temp 2>&1
else
    TEMP_FOUND=0
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        [ -e "$zone" ] || continue
        echo "$zone: $(cat "$zone") m°C"
        TEMP_FOUND=1
        break
    done
    if [ "$TEMP_FOUND" = "0" ]; then
        # Same fallback as monitor_system.sh: this desktop has no
        # thermal_zone at all, only hwmon (k10temp/coretemp).
        for hwmon in /sys/class/hwmon/hwmon*; do
            [ -e "$hwmon/name" ] || continue
            name="$(cat "$hwmon/name" 2>/dev/null)"
            case "$name" in
                k10temp|coretemp|cpu_thermal)
                    if [ -e "$hwmon/temp1_input" ]; then
                        echo "$hwmon/temp1_input ($name): $(cat "$hwmon/temp1_input") m°C"
                        TEMP_FOUND=1
                    fi
                    ;;
            esac
            [ "$TEMP_FOUND" = "1" ] && break
        done
    fi
    [ "$TEMP_FOUND" = "0" ] && echo "no temperature source found"
fi
