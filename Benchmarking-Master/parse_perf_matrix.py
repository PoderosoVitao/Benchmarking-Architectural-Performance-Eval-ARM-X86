#!/usr/bin/env python3
"""Parse a directory of `perf stat` text captures (from run_perf_matrix.sh)
into a single CSV: algorithm,operation,instructions,cycles,ipc,
cache_references,cache_misses,cache_miss_rate,branch_misses.

perf's locale-formatted numbers (e.g. "108.552.652") use '.' as a thousands
separator; strip it before parsing.
"""
import csv
import re
import sys
from pathlib import Path

METRICS = {
    "instructions": "instructions",
    "cycles": "cycles",
    "cache-references": "cache_references",
    "cache-misses": "cache_misses",
    "branch-misses": "branch_misses",
}


def parse_file(path: Path):
    text = path.read_text()
    row = {}
    for line in text.splitlines():
        line = line.strip()
        for key, col in METRICS.items():
            if f" {key}" in line or line.endswith(key) or f"{key}:u" in line:
                # perf's locale-formatted counters use either ',' or '.' as
                # the thousands separator depending on the machine's locale
                # (e.g. x86 here is pt_BR-style "108.552.652", the Pi is
                # en_US-style "673,991,153") — strip both, never a decimal
                # point in these integer counts.
                m = re.match(r"^([\d.,]+)\s+" + re.escape(key), line)
                if m:
                    num = m.group(1).replace(".", "").replace(",", "")
                    row[col] = int(num)
    return row


def main(indir: str, outcsv: str):
    indir_p = Path(indir)
    rows = []
    for f in sorted(indir_p.glob("*.txt")):
        if f.name.endswith(".stdout"):
            continue
        stem = f.stem  # e.g. "ML-DSA-65_sign"
        if "_" not in stem:
            continue
        algo, op = stem.rsplit("_", 1)
        data = parse_file(f)
        if not data:
            print(f"WARNING: no perf counters parsed from {f}", file=sys.stderr)
            continue
        ipc = data.get("instructions", 0) / data["cycles"] if data.get("cycles") else 0
        cmiss_rate = (
            data.get("cache_misses", 0) / data["cache_references"]
            if data.get("cache_references")
            else 0
        )
        rows.append({
            "algorithm": algo,
            "operation": op,
            "instructions": data.get("instructions", ""),
            "cycles": data.get("cycles", ""),
            "ipc": round(ipc, 4),
            "cache_references": data.get("cache_references", ""),
            "cache_misses": data.get("cache_misses", ""),
            "cache_miss_rate": round(cmiss_rate, 6),
            "branch_misses": data.get("branch_misses", ""),
        })

    with open(outcsv, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "algorithm", "operation", "instructions", "cycles", "ipc",
            "cache_references", "cache_misses", "cache_miss_rate", "branch_misses",
        ])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows to {outcsv}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
