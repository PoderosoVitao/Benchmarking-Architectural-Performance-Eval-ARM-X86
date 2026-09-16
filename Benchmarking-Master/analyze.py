#!/usr/bin/env python3
"""Cross-platform latency comparison from a pair of result directories.

Given the x86 and ARM result directories, this:
  - prints the per-operation latency table for each platform (mean, std, P99
    and peak-RSS delta), the material behind the paper's Table 2;
  - prints and writes the ARM/x86 mean-latency ratios to
    <arm_dir>/slowdown_ratios.csv;
  - prints the per-family min-max ratio bands quoted in Section 5.1;
  - saves the slowdown bar chart to <arm_dir>/fig_slowdown_ratio.png.

Given only the x86 directory it stops after printing the x86 table.

It does not produce Table 1 (hardware environment, not measured here) or
Table 3 (the vectorization ablation, which needs the paired liboqs builds and
is not driven from this repository). Table 4 comes from parse_perf_matrix.py.
"""
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

X86_DIR = sys.argv[1] if len(sys.argv) > 1 else None
ARM_DIR = sys.argv[2] if len(sys.argv) > 2 else None

def load(outdir, suffix):
    pqc = pd.read_csv(f"{outdir}/results_pqc_{suffix}.csv")
    classical = pd.read_csv(f"{outdir}/results_classical_{suffix}.csv")
    df = pd.concat([classical, pqc], ignore_index=True)
    # normalize algorithm display names -> short keys used in the paper
    df["algorithm"] = df["algorithm"].str.replace(r"\s*\(.*\)", "", regex=True).str.strip()
    return df

def pivot(df):
    return df.pivot_table(index=["algorithm", "operation"], values="mean_ms")

def main():
    if not X86_DIR:
        print("Usage: analyze.py <x86_outdir> [arm_outdir]")
        sys.exit(1)

    x86 = load(X86_DIR, "x86")
    print("=== x86 loaded ===")
    print(x86[["algorithm", "operation", "mean_ms", "std_ms", "p99_ms", "peak_mem_delta_kb"]]
          .to_string(index=False))

    if not ARM_DIR:
        print("\n(No ARM dir given yet -- stopping after x86 validation.)")
        return

    arm = load(ARM_DIR, "arm")
    print("\n=== ARM loaded ===")
    print(arm[["algorithm", "operation", "mean_ms", "std_ms", "p99_ms", "peak_mem_delta_kb"]]
          .to_string(index=False))

    merged = x86.merge(arm, on=["algorithm", "operation"], suffixes=("_x86", "_arm"))
    merged["ratio"] = merged["mean_ms_arm"] / merged["mean_ms_x86"]

    print("\n=== ARM/x86 slowdown ratios ===")
    out = merged[["algorithm", "operation", "mean_ms_x86", "mean_ms_arm", "ratio"]].sort_values(
        ["algorithm", "operation"])
    print(out.to_string(index=False))

    out.to_csv(f"{ARM_DIR}/slowdown_ratios.csv", index=False)

    # bands per family
    families = {
        "ML-DSA": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        "Falcon": ["Falcon-512", "Falcon-1024"],
        "SLH-DSA-SHA2": [a for a in merged.algorithm.unique() if a.startswith("SLH-DSA-SHA2")],
        "SLH-DSA-SHAKE": [a for a in merged.algorithm.unique() if a.startswith("SLH-DSA-SHAKE")],
        "RSA-3072": ["RSA-3072"],
        "ECDSA-P256": ["ECDSA-P256"],
    }
    print("\n=== bands per family (min-max ratio across all ops) ===")
    for fam, algos in families.items():
        sub = merged[merged.algorithm.isin(algos)]
        if len(sub):
            print(f"{fam}: {sub.ratio.min():.1f}x -- {sub.ratio.max():.1f}x")

    # ---- Figure: slowdown ratio bar chart ----
    fig, ax = plt.subplots(figsize=(9, 5.5))
    order = out.sort_values("ratio")
    labels = [f"{r.algorithm} {r.operation}" for r in order.itertuples()]
    colors = {"keygen": "#4C72B0", "sign": "#DD8452", "verify": "#55A868"}
    bar_colors = [colors[r.operation] for r in order.itertuples()]
    y = np.arange(len(order))
    ax.barh(y, order["ratio"], color=bar_colors, height=0.7)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xscale("log")
    ax.axvline(1, color="black", linestyle="--", linewidth=1, label="parity")
    ax.set_xlabel("ARM / x86 mean latency ratio (log scale)", fontsize=11)
    ax.set_title("Cross-Architecture Slowdown Ratio per Algorithm/Operation", fontsize=12)
    ax.grid(axis="x", which="both", linestyle=":", alpha=0.5)
    from matplotlib.patches import Patch
    legend_elems = [Patch(facecolor=c, label=op) for op, c in colors.items()]
    ax.legend(handles=legend_elems, loc="lower right", fontsize=9)
    plt.tight_layout()
    fig.savefig(f"{ARM_DIR}/fig_slowdown_ratio.png", dpi=200)
    print(f"\nFigure saved to {ARM_DIR}/fig_slowdown_ratio.png")

if __name__ == "__main__":
    main()
