#!/bin/bash
# monitor_system.sh
# Continuous 1Hz (by default) log of scaling_cur_freq, CPU temperature, and
# (on the Pi) vcgencmd's live throttling flags — run in the BACKGROUND
# alongside a benchmark, not as a substitute for it.
#
# Why this exists: the paper currently defends the Raspberry Pi's clock
# speed with a theoretical argument about the ondemand governor's sampling
# interval and up_threshold, and inspects vcgencmd get_throttled only once,
# after the run. Neither is a measurement of what actually happened DURING
# the run. This logs both continuously so any run can be checked, not
# argued about — "the Pi throttled" or "ran below 1.8GHz" becomes something
# you can look up in a CSV instead of a claim a reviewer can't verify.
#
# Cross-references against the benchmark's own raw per-iteration CSVs via
# wall-clock epoch (see benchmark.h's now_epoch()/epoch_start): both use
# `date`/CLOCK_REALTIME, the same clock, so a monitor row and a raw-sample
# row with close epoch values were recorded at roughly the same moment.
#
# Usage: ./monitor_system.sh <output_csv> [interval_seconds]
#   Runs until killed (SIGTERM/SIGINT/Ctrl-C) — intended usage:
#     ./monitor_system.sh monitor.csv 1 &
#     MONITOR_PID=$!
#     ./bench_pqc results.csv results_raw.csv
#     kill "$MONITOR_PID"
set -u

OUT="${1:-system_monitor.csv}"
INTERVAL="${2:-1}"

# ── temperature source auto-detection ───────────────────────────────────
# Raspberry Pi OS exposes CPU temp via thermal_zone (Broadcom driver);
# this x86 dev machine has NO thermal_zone entries at all (confirmed via
# `find /sys/class/thermal -name 'thermal_zone*'` returning nothing) and
# needs the hwmon interface instead (k10temp on this AMD box; coretemp is
# the Intel equivalent). Probed once at startup rather than assumed, same
# reasoning as build_perf_events.sh: a documented sysfs path existing on
# one machine doesn't mean it exists on another.
TEMP_PATH=""
TEMP_SOURCE="none"

# Try thermal_zone first (covers the Pi).
for zone in /sys/class/thermal/thermal_zone*/temp; do
    [ -e "$zone" ] || continue
    TEMP_PATH="$zone"
    TEMP_SOURCE="thermal_zone ($zone)"
    break
done

# Fall back to hwmon, looking for a known CPU-sensor driver name.
if [ -z "$TEMP_PATH" ]; then
    for hwmon in /sys/class/hwmon/hwmon*; do
        [ -e "$hwmon/name" ] || continue
        name="$(cat "$hwmon/name" 2>/dev/null)"
        case "$name" in
            k10temp|coretemp|cpu_thermal)
                if [ -e "$hwmon/temp1_input" ]; then
                    TEMP_PATH="$hwmon/temp1_input"
                    TEMP_SOURCE="hwmon/$name ($hwmon/temp1_input)"
                    break
                fi
                ;;
        esac
    done
fi

if [ -z "$TEMP_PATH" ]; then
    echo "monitor_system.sh: WARNING no temperature source found (checked" >&2
    echo "  thermal_zone and hwmon k10temp/coretemp/cpu_thermal) — temp column will be empty." >&2
else
    echo "monitor_system.sh: temperature source: $TEMP_SOURCE" >&2
fi

# ── vcgencmd (Pi only) ───────────────────────────────────────────────────
HAS_VCGENCMD=0
command -v vcgencmd >/dev/null 2>&1 && HAS_VCGENCMD=1
if [ "$HAS_VCGENCMD" = "1" ]; then
    echo "monitor_system.sh: vcgencmd available, logging get_throttled" >&2
else
    echo "monitor_system.sh: vcgencmd not found (expected on x86) — throttled column will be empty." >&2
fi

FREQ_PATH="/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
if [ ! -e "$FREQ_PATH" ]; then
    echo "monitor_system.sh: WARNING $FREQ_PATH not found — freq column will be empty." >&2
fi

echo "epoch,scaling_cur_freq_khz,temp_millic,throttled_hex" > "$OUT"

# Trap so a `kill` (SIGTERM, the default signal) or Ctrl-C exits the loop
# cleanly instead of leaving the process to be reaped as an error.
trap 'exit 0' TERM INT

while true; do
    EPOCH="$(date +%s.%3N)"
    FREQ="$( [ -e "$FREQ_PATH" ] && cat "$FREQ_PATH" 2>/dev/null )"
    TEMP="$( [ -n "$TEMP_PATH" ] && cat "$TEMP_PATH" 2>/dev/null )"
    if [ "$HAS_VCGENCMD" = "1" ]; then
        THROTTLED="$(vcgencmd get_throttled 2>/dev/null | sed 's/^throttled=//')"
    else
        THROTTLED=""
    fi
    echo "$EPOCH,$FREQ,$TEMP,$THROTTLED" >> "$OUT"
    sleep "$INTERVAL"
done
