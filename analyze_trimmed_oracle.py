"""Compare ordinary and 10%-per-tail means of raw paired timing differences.

This measures the sign of a known high-minus-low pair, not an unknown-message
oracle's held-out accuracy. IID resampling discards serial dependence; its
Monte Carlo error bounds are not confidence intervals for deployment accuracy.
Only raw timing CSVs are accepted; sampler/decapsulation block means must not
be pooled. NumPy is used for bounded batches of reproducible resampling.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

import numpy as np


def trimmed_mean(values):
    ordered = np.sort(values, axis=-1)
    cut = ordered.shape[-1] // 10
    return ordered[..., cut:ordered.shape[-1] - cut].mean(axis=-1)


def analyze(path, repeats, seed):
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["i", "low_ns", "high_ns"]:
            raise ValueError("Expected raw i,low_ns,high_ns data; no block means")
        rows = list(reader)
    low = np.array([float(row["low_ns"]) for row in rows])
    high = np.array([float(row["high_ns"]) for row in rows])
    if len(low) < 2 or not np.isfinite(low + high).all():
        raise ValueError("Need at least two finite timing pairs")
    if (low <= 0).any() or (high <= 0).any():
        raise ValueError("Nonpositive timings")
    delta = high - low
    pair_seconds = float((low + high).mean() / 1e9)
    rng = np.random.default_rng(seed)
    result = {
        "input": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "pairs": len(rows), "seed": seed, "bootstrap_repeats": repeats,
        "trim_fraction_each_tail": 0.1,
        "ordinary_mean_delta_ns": float(delta.mean()),
        "trimmed_mean_delta_ns": float(trimmed_mean(delta)),
        "single_pair_positive_fraction": float((delta > 0).mean()),
        "mean_pair_seconds": pair_seconds,
        "scope": "Known high/low ordering from old local timings; no new timing run",
        "caveats": [
            "N pairs cost 2*N decapsulations. Time excludes setup and other overhead.",
            "IID bootstrap estimates assume independent resampled pairs; cannot test drift.",
            "Bootstrap errors are simulated, not new independent classification trials.",
            "Contiguous blocks retain order but may be correlated and few at large N.",
            "This is not accuracy of an unknown-ciphertext or coefficient classifier.",
        ],
        "results": [],
    }
    for count in (256, 512, 1000, 1500, 2048, 3000, 5000, 7500, 15000):
        if count > len(delta):
            continue
        mean_errors = trim_errors = 0
        for start in range(0, repeats, 64):
            sample = delta[rng.integers(len(delta), size=(min(64, repeats-start), count))]
            mean_errors += int((sample.mean(axis=1) <= 0).sum())
            trim_errors += int((trimmed_mean(sample) <= 0).sum())
        nblocks = len(delta) // count
        blocks = delta[:nblocks * count].reshape(nblocks, count)
        result["results"].append({
            "pairs_per_decision": count, "decapsulations": 2 * count,
            "estimated_decapsulation_seconds": count * pair_seconds,
            "iid_mean_errors": mean_errors, "iid_trimmed_errors": trim_errors,
            "iid_mean_accuracy": 1 - mean_errors / repeats,
            "iid_trimmed_accuracy": 1 - trim_errors / repeats,
            "contiguous_blocks": nblocks,
            "contiguous_mean_correct": int((blocks.mean(axis=1) > 0).sum()),
            "contiguous_trimmed_correct": int((trimmed_mean(blocks) > 0).sum()),
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--repeats", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    results = [analyze(path, args.repeats, args.seed) for path in args.inputs]
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    for result in results:
        print(result["input"], "trimmed signal(ns)", result["trimmed_mean_delta_ns"])
        print("pairs seconds mean_iid trim_iid trim_contiguous")
        for row in result["results"]:
            print(f'{row["pairs_per_decision"]:5} '
                  f'{row["estimated_decapsulation_seconds"]:7.2f} '
                  f'{row["iid_mean_accuracy"]:.4%} {row["iid_trimmed_accuracy"]:.4%} '
                  f'{row["contiguous_trimmed_correct"]}/{row["contiguous_blocks"]}')


if __name__ == "__main__":
    main()
