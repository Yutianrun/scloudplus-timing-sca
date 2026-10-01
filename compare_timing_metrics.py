"""Compare paired timing classifiers, tuning on old data and testing fresh data."""
import argparse
import csv
import json
from pathlib import Path

import numpy as np


def load(path):
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != ["i", "low_ns", "high_ns"]:
            raise ValueError(f"{path}: expected raw paired timings")
        rows = list(reader)
    low = np.array([float(x["low_ns"]) for x in rows])
    high = np.array([float(x["high_ns"]) for x in rows])
    return low, high


def trim(x, fraction):
    ordered = np.sort(x, axis=1)
    cut = int(fraction * x.shape[1])
    return ordered[:, cut:x.shape[1] - cut].mean(axis=1)


def winsor(x, fraction):
    lo = np.quantile(x, fraction, axis=1)[:, None]
    hi = np.quantile(x, 1.0 - fraction, axis=1)[:, None]
    return np.clip(x, lo, hi).mean(axis=1)


def metrics(low, high):
    delta = high - low
    log_ratio = np.log(high / low)
    mid_ratio = 2.0 * delta / (high + low)
    return {
        "mean_delta": delta.mean(axis=1),
        "trim_05_delta": trim(delta, 0.05),
        "trim_10_delta": trim(delta, 0.10),
        "trim_20_delta": trim(delta, 0.20),
        "trim_30_delta": trim(delta, 0.30),
        "winsor_10_delta": winsor(delta, 0.10),
        "median_delta": np.median(delta, axis=1),
        "q25_delta": np.quantile(delta, 0.25, axis=1),
        "sign_majority": (delta > 0).mean(axis=1) - 0.5,
        "mean_log_ratio": log_ratio.mean(axis=1),
        "trim_10_log_ratio": trim(log_ratio, 0.10),
        "winsor_10_log_ratio": winsor(log_ratio, 0.10),
        "median_log_ratio": np.median(log_ratio, axis=1),
        "mean_mid_ratio": mid_ratio.mean(axis=1),
        "trim_10_mid_ratio": trim(mid_ratio, 0.10),
    }


def summarize(name, low, high, sizes):
    row_metrics = metrics(low[None, :], high[None, :])
    one = {key: float(value[0]) for key, value in row_metrics.items()}
    result = {"name": name, "pairs": len(low), "signals": one, "sizes": []}
    for n in sizes:
        count = len(low) // n
        if count == 0:
            continue
        lows = low[:count * n].reshape(count, n)
        highs = high[:count * n].reshape(count, n)
        decisions = metrics(lows, highs)
        scores = {}
        for metric, value in decisions.items():
            hits = int((value > 0).sum())
            scores[metric] = {"correct": hits, "blocks": count,
                              "accuracy": hits / count}
        result["sizes"].append({"pairs_per_decision": n, "scores": scores})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("train", type=Path)
    parser.add_argument("test", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sizes = [256, 512, 1000, 1500, 2048, 3000, 5000, 7500, 15000]
    results = [summarize(args.train.name, *load(args.train), sizes),
               summarize(args.test.name, *load(args.test), sizes)]
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    for result in results:
        print(f"[{result['name']}] pairs={result['pairs']}")
        for size in result["sizes"]:
            n = size["pairs_per_decision"]
            entries = size["scores"]
            order = sorted(entries, key=lambda k: entries[k]["accuracy"], reverse=True)
            print(f" N={n}: " + ", ".join(
                f"{key}={entries[key]['correct']}/{entries[key]['blocks']}"
                for key in order[:6]))
        print(" full-sample signals(ns or transformed):")
        for key, value in sorted(result["signals"].items(),
                                 key=lambda kv: kv[1], reverse=True):
            print(f"  {key}: {value:.8g}")


if __name__ == "__main__":
    main()
