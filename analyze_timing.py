"""Summarize randomized interleaved timing blocks from measure_timing.c."""
import csv
import math
from pathlib import Path
import statistics
import sys


for name in sys.argv[1:]:
    rows = list(csv.DictReader(Path(name).open()))
    print(name)
    for mode in ("sampler", "decaps"):
        subset = [row for row in rows if row["mode"] == mode]
        n = len(subset)
        pairs = {
            "high-low": [float(row["high_ns"]) - float(row["low_ns"])
                         for row in subset],
            "zero-low": [float(row["zero_ns"]) - float(row["low_ns"])
                         for row in subset],
        }
        baseline = statistics.mean(float(row["low_ns"]) for row in subset)
        print(f"  {mode}: blocks={n}, low mean={baseline:.1f} ns")
        for label, diffs in pairs.items():
            mean = statistics.mean(diffs)
            sd = statistics.stdev(diffs)
            se = sd / math.sqrt(n)
            wins = sum(value > 0 for value in diffs)
            print(f"    {label}: mean={mean:.1f} ns, median={statistics.median(diffs):.1f}, "
                  f"block sd={sd:.1f}, SE={se:.1f}, approx 95% CI="
                  f"[{mean-1.96*se:.1f}, {mean+1.96*se:.1f}], "
                  f"positive blocks={wins}/{n}, delta/low={100*mean/baseline:.3f}%")
            middle = n // 2
            print(f"      first-half={statistics.mean(diffs[:middle]):.1f} ns, "
                  f"second-half={statistics.mean(diffs[middle:]):.1f} ns")
