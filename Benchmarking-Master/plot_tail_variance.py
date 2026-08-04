#!/usr/bin/env python3
"""Boxplot of x86 sign-latency distributions, normalized by each algorithm's
own median, to visualize tail-variance shape across algorithm designs
(rejection-sampling vs deterministic hash evaluation)."""
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

X86_DIR = sys.argv[1]

raw_pqc = pd.read_csv(f"{X86_DIR}/results_pqc_x86_raw.csv")
raw_classical = pd.read_csv(f"{X86_DIR}/results_classical_x86_raw.csv")
raw = pd.concat([raw_classical, raw_pqc], ignore_index=True)
raw["algorithm"] = raw["algorithm"].str.replace(r"\s*\(.*\)", "", regex=True).str.strip()

selection = [
    "RSA-3072", "ECDSA-P256", "ML-DSA-65", "Falcon-1024",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s",
]
labels = ["RSA-3072", "ECDSA-P256", "ML-DSA-65", "Falcon-1024", "SLH-DSA\nSHA2-256s", "SLH-DSA\nSHAKE-256s"]

data = []
for algo in selection:
    sub = raw[(raw.algorithm == algo) & (raw.operation == "sign")]["ms"]
    med = sub.median()
    data.append(sub / med)

fig, ax = plt.subplots(figsize=(7.2, 4.2))
BLUE = "#2a78d6"
bp = ax.boxplot(
    data, tick_labels=labels, patch_artist=True, widths=0.55,
    showfliers=True,
    flierprops=dict(marker='o', markersize=2.5, markerfacecolor=BLUE,
                     markeredgecolor='none', alpha=0.35),
    medianprops=dict(color="#0b0b0b", linewidth=1.6),
    boxprops=dict(facecolor=BLUE, alpha=0.55, edgecolor="#0b0b0b", linewidth=1.0),
    whiskerprops=dict(color="#0b0b0b", linewidth=1.0),
    capprops=dict(color="#0b0b0b", linewidth=1.0),
)
ax.axhline(1.0, color="#52514e", linestyle=":", linewidth=1.0, zorder=0)
ax.set_ylabel("Sign latency / algorithm's own median", fontsize=10.5)
ax.set_title("x86 Signing Latency Distribution Shape (1,000 samples each)", fontsize=11.5)
ax.grid(axis="y", linestyle=":", alpha=0.4)
ax.tick_params(axis="x", labelsize=9.5)
ax.tick_params(axis="y", labelsize=9.5)
ax.set_ylim(0.8, ax.get_ylim()[1])
for spine in ["top", "right"]:
    ax.spines[spine].set_visible(False)
plt.tight_layout()
fig.savefig(f"{X86_DIR}/fig_tail_variance.png", dpi=200)
print(f"Saved to {X86_DIR}/fig_tail_variance.png")

for algo, arr in zip(selection, data):
    print(f"{algo}: median=1.00 p95={arr.quantile(0.95):.3f} p99={arr.quantile(0.99):.3f} max={arr.max():.3f}")
