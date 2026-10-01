"""Measure original SHAKE C samplers and compare counts and coefficient digests."""
import argparse
import csv
import io
import json
import platform
from pathlib import Path
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--implementations", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=512)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--full-kem", action="store_true")
    args = parser.parse_args()
    work = Path(__file__).resolve().parent
    output_dir = (args.output_dir or work).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    core = args.implementations / "_shared/scloudplus_core"
    backend = "NEON" if platform.machine() == "arm64" else "AVX2"
    summaries = []
    for level in (128, 192, 256, 384, 512):
        reference = None
        for selected in ("REF", backend):
            binary = output_dir / f"verify-{level}-{selected.lower()}"
            command = ["clang", "-O2", "-std=c99", "-DSCLOUDPLUS_FAMILY_SHAKE"]
            if selected == "REF":
                command += ["-DSCLOUDPLUS_TIER_REFERENCE"]
            else:
                command += [f"-DSCLOUDPLUS_BACKEND_{selected}"]
                if selected == "AVX2":
                    command += ["-mavx2"]
            for directory in (
                args.implementations / f"Reference_Implementation/Scloudplus-{level}/kem",
                core / "include", core / "common", args.implementations / "_shared/api_pkc",
            ):
                command += ["-I", str(directory)]
            command += [str(work / "verify_sampler.c"), str(core / "common/hash_aes_shake.c")]
            if selected != "REF":
                command += [str(core / selected.lower() / f"sample_{selected.lower()}.c")]
            command += ["-o", str(binary)]
            subprocess.run(command, check=True)
            output = subprocess.check_output([str(binary), str(args.trials)], text=True)
            # Persist generated evidence, rather than a hand-written fixture.
            (output_dir / f"verify-{level}-{selected.lower()}.csv").write_text(output)
            if reference is None:
                reference = output
            elif output != reference:
                raise RuntimeError(f"Backend disagreement at level {level}")
            replay = subprocess.check_output([str(binary), "8"], text=True)
            if replay.splitlines() != output.splitlines()[:9]:
                raise RuntimeError(f"Replay disagreement at level {level}, {selected}")
            rows = list(csv.DictReader(io.StringIO(output)))
            summary = {"level": level, "backend": selected, "trials": len(rows)}
            for name in ("consumed", "generated"):
                values = [int(row[name]) for row in rows]
                summary[name] = {
                    "min": min(values), "max": max(values),
                    "mean": statistics.mean(values), "sd": statistics.pstdev(values),
                }
            rounds = [int(row["rounds_s"]) + int(row["rounds_e"]) for row in rows]
            summary["rounds"] = {
                "min": min(rounds), "max": max(rounds),
                "mean": statistics.mean(rounds), "sd": statistics.pstdev(rounds),
            }
            summaries.append(summary)
            print(json.dumps(summary), flush=True)
        print(f"level {level}: REF/{backend} exact CSV equality and replay PASS", flush=True)
    (output_dir / "verification-results.json").write_text(json.dumps(summaries, indent=2) + "\n")
    provenance = {
        "implementations": str(args.implementations.resolve()),
        "family": "SHAKE", "native_backend": backend,
        "platform": platform.platform(), "trials": args.trials,
        "compiler": subprocess.check_output(["clang", "--version"], text=True),
        "comparison": "counts and FNV coefficient digests, not raw coefficient bytes",
        "timing_measured": False,
    }
    if args.full_kem:
        binary = output_dir / "verify-full-kem-256"
        command = [
            "clang", "-O2", "-std=c99", "-DSCLOUDPLUS_FAMILY_SHAKE",
            "-DSCLOUDPLUS_REF_FAMILY_SHAKE", "-DSCLOUDPLUS_TIER_REFERENCE",
            "-DVERIFY_FULL_KEM",
        ]
        for directory in (
            args.implementations / "Reference_Implementation/Scloudplus-256/kem",
            core / "include", core / "common", args.implementations / "_shared/api_pkc",
        ):
            command += ["-I", str(directory)]
        command += [str(work / "verify_sampler.c")]
        command += [str(core / path) for path in (
            "common/hash_aes_shake.c", "common/kem.c", "common/pke.c",
            "common/encode.c", "common/random.c", "common/util.c",
            "ref/matrix_reference.c", "ref/pack_reference.c",
        )]
        command += ["-o", str(binary)]
        subprocess.run(command, check=True)
        result = subprocess.run([str(binary), "2048"], capture_output=True, text=True, check=True)
        (output_dir / "verify-full-kem-256.csv").write_text(result.stdout)
        (output_dir / "verify-full-kem-256.log").write_text(result.stderr)
        provenance["full_kem"] = (
            "level 256 REF, valid keypair, 2048 messages searched; first 8 invalid "
            "ciphertexts plus a different XOF-generated count replayed twice"
        )
        print(result.stderr, end="", flush=True)
    (output_dir / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")


if __name__ == "__main__":
    main()
