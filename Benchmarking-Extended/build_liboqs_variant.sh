#!/bin/bash
# build_liboqs_variant.sh
# Builds liboqs in one of two configurations, so the vectorization gain
# from ML-DSA/Falcon's per-CPU-arch backends (and, indirectly, SLH-DSA's
# SHA2/SHA3 primitives) can be measured directly instead of inferred from
# a liboqs *version* difference:
#
#   ref        liboqs with -DOQS_DIST_BUILD=OFF. This does not merely let
#              runtime dispatch "choose" the reference implementation —
#              the AVX2/NEON asm backends are never compiled into the
#              library at all (OQS_ENABLE_SIG_ml_dsa_*_x86_64/_aarch64 and
#              the equivalent Falcon/SHA2/SHA3 flags are all gated by the
#              same OQS_DIST_*_BUILD variables OQS_DIST_BUILD sets). There
#              is nothing else the binary could call even if it wanted to.
#
#   optimized  liboqs with -DOQS_DIST_BUILD=ON — identical to the build
#              already used for every other result in this study (see
#              Table~tab:hardware / Methodology). Compiles in BOTH the
#              reference and the platform-optimized backends, with a
#              genuine runtime OQS_CPU_has_extension() check inside each
#              compiled function deciding which one actually executes
#              (see sig_ml_dsa_44.c et al.) — this is real runtime CPU
#              feature detection, not a build-time label; confirmed by
#              reading liboqs 0.16.0's own source before writing this
#              script, not assumed.
#
# CMAKE_BUILD_TYPE is deliberately left unset in both variants, exactly
# matching every other liboqs build in this study: with no CMAKE_BUILD_TYPE
# override, liboqs's own top-level CMakeLists.txt defaults it to Release,
# which is where the -O3 already documented in the paper's Methodology
# comes from. Only OQS_DIST_BUILD differs between the two variants.
#
# Usage: ./build_liboqs_variant.sh <ref|optimized> <liboqs_source_dir> <install_prefix>
#
# Run once per variant per platform (x86 and ARM each need their own
# ref+optimized pair — this script does not cross-compile).
set -eu

VARIANT="${1:-}"
SRC="${2:-}"
PREFIX="${3:-}"

if [ "$VARIANT" != "ref" ] && [ "$VARIANT" != "optimized" ]; then
    echo "Usage: $0 <ref|optimized> <liboqs_source_dir> <install_prefix>" >&2
    exit 1
fi
if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
    echo "liboqs source dir not found: $SRC" >&2
    exit 1
fi
if [ -z "$PREFIX" ]; then
    echo "install prefix required" >&2
    exit 1
fi

BUILD_DIR="$SRC/build-$VARIANT"
echo "=== Building liboqs [$VARIANT] ==="
echo "    source : $SRC"
echo "    build  : $BUILD_DIR"
echo "    prefix : $PREFIX"

rm -rf "$BUILD_DIR"

if [ "$VARIANT" = "ref" ]; then
    # -DOQS_DIST_BUILD=OFF alone is NOT sufficient: empirically verified
    # (via cmake --trace-expand on this exact source tree) that the
    # per-architecture derived variables it's supposed to gate
    # (OQS_DIST_X86_64_BUILD / OQS_DIST_ARM64_V8_BUILD, consumed by
    # .CMake/alg_support.cmake to decide whether e.g.
    # OQS_ENABLE_SIG_ml_dsa_65_x86_64 gets turned on) do not reliably end
    # up OFF from OQS_DIST_BUILD=OFF alone in this liboqs version — a
    # first attempt built ml_dsa_65 with the AVX2 backend compiled in
    # despite OQS_DIST_BUILD=OFF, confirmed via `nm` on the resulting
    # liboqs.a. Forcing every derived flag explicitly is what actually
    # works; verified the same way.
    cmake -S "$SRC" -B "$BUILD_DIR" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DOQS_DIST_BUILD=OFF \
        -DOQS_DIST_X86_64_BUILD=OFF \
        -DOQS_DIST_ARM64_V8_BUILD=OFF \
        -DOQS_USE_AVX2_INSTRUCTIONS=OFF \
        -DOQS_USE_AVX512_INSTRUCTIONS=OFF \
        -DOQS_USE_BMI1_INSTRUCTIONS=OFF \
        -DOQS_USE_BMI2_INSTRUCTIONS=OFF \
        -DOQS_USE_POPCNT_INSTRUCTIONS=OFF \
        -DOQS_USE_AES_INSTRUCTIONS=OFF \
        -DOQS_USE_ARM_NEON_INSTRUCTIONS=OFF \
        -DOQS_USE_ARM_AES_INSTRUCTIONS=OFF \
        -DOQS_USE_ARM_SHA2_INSTRUCTIONS=OFF \
        -DOQS_USE_ARM_SHA3_INSTRUCTIONS=OFF \
        -DOQS_USE_SHA3_AVX512VL=OFF
elif [ "$VARIANT" = "optimized" ]; then
    cmake -S "$SRC" -B "$BUILD_DIR" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DOQS_DIST_BUILD=ON
fi

NPROC="$(nproc 2>/dev/null || echo 2)"
cmake --build "$BUILD_DIR" --parallel "$NPROC"
cmake --install "$BUILD_DIR"

echo "=== Done: $VARIANT liboqs installed to $PREFIX ==="

# Sanity marker: record which variant this prefix holds, so later scripts
# (and future-you) don't have to guess from the directory name alone.
echo "$VARIANT" > "$PREFIX/.liboqs_variant"
date -u +"built %Y-%m-%dT%H:%M:%SZ" >> "$PREFIX/.liboqs_variant"
