#!/bin/bash
# build_perf_events.sh
# Probes which extended hardware-counter events actually work on THIS
# machine and prints a comma-separated perf-stat -e event list to stdout.
# Usage: EVENTS="$(./build_perf_events.sh)"   (diagnostics go to stderr)
#
# Why probe instead of hardcode: confirmed directly on this x86_64 dev
# machine that `perf list` documenting an event is not the same as the
# event actually working. "l3_misses" is listed, but this box has no
# uncore L3 PMU device at all (nothing under
# /sys/bus/event_source/devices/ matches L3/LLC) — the event errors out
# the instant it's used. Availability varies by exact CPU, kernel, and
# perf build, not just by architecture, so this checks for real on every
# invocation instead of assuming an architecture manual's event list
# applies unmodified to whichever specific box is collecting data.
#
# Extends the same reasoning to the ARM side: the Cortex-A72 PMUv3 event
# names below are standard/architectural, but have NOT been verified
# against the actual Raspberry Pi kernel's PMU driver (no SSH access to
# it at the time this script was written) — they go through the exact
# same probe as the x86 candidates, and are silently dropped (with a
# stderr note) if unavailable, rather than assumed.
set -u

probe_event() {
    perf stat -e "$1" -- sleep 0.01 >/dev/null 2>&1
}

ARCH="$(uname -m)"

# Core events: instructions/cycles for IPC, cache-references/cache-misses
# and branch-misses as the combined/generic proxies already used
# throughout this study. Kept as the floor regardless of what else probes
# successfully, so every run stays comparable to earlier perf-matrix data.
CORE="instructions,cycles,cache-references,cache-misses,branch-misses"

EXTRA=()

if [ "$ARCH" = "x86_64" ]; then
    CANDIDATES=(
        # Vector-instruction fraction. Verified empirically (not just
        # "listed by perf list"): compared against liboqs built with
        # -DOQS_DIST_BUILD=OFF (no AVX2 backend compiled in at all) vs.
        # the optimized build, same ML-DSA-65 sign call — the optimized
        # build's vector_all / instructions ratio came out ~12x higher
        # (8.2% vs 0.7%), confirming this event tracks real AVX2 vector
        # issue rate, not just total instruction count. AMD's PMU
        # classifies both integer and floating-point vector ops through
        # the shared FP/vector execution cluster, so this also catches
        # ML-DSA/Falcon's *integer* AVX2 ops (NTT butterflies etc.), not
        # only floating-point SIMD.
        "fp_ops_retired_by_type.vector_all"
        # L1D misses: generic alias, confirmed working on this box.
        "L1-dcache-load-misses"
        # LLC/L3 misses: listed by `perf list` on this box but NOT
        # actually usable (see header) — included here anyway so the
        # probe step below documents that fact in the run log rather
        # than silently omitting it with no explanation.
        "l3_misses"
    )
elif [ "$ARCH" = "aarch64" ]; then
    CANDIDATES=(
        "ase_spec"            # Advanced SIMD (NEON) instrs, speculative
        "vfp_spec"             # scalar+vector FP instrs, speculative
        "stall_frontend"       # cycles stalled: frontend can't supply
        "stall_backend"        # cycles stalled: backend can't accept
        "l1d_cache_refill"     # L1 data cache refills (misses)
        "ll_cache_miss_rd"     # last-level cache read misses
        "br_mis_pred_retired"  # retired mispredicted branches
    )
else
    echo "build_perf_events.sh: unrecognized architecture '$ARCH' (uname -m); using core events only" >&2
    CANDIDATES=()
fi

for ev in "${CANDIDATES[@]}"; do
    if probe_event "$ev"; then
        EXTRA+=("$ev")
        echo "build_perf_events.sh: '$ev' OK" >&2
    else
        echo "build_perf_events.sh: '$ev' NOT AVAILABLE on this machine, skipping" >&2
    fi
done

if [ ${#EXTRA[@]} -gt 0 ]; then
    IFS=,
    echo "$CORE,${EXTRA[*]}"
else
    echo "$CORE"
fi
