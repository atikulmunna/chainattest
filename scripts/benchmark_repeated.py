"""Run the end-to-end demo repeatedly and summarize its timings and gas.

Each run is a fresh `scripts/run_demo.py` invocation (its own Hardhat node and
signer service), so the runs are independent. For every metric the summary
reports the median, mean, sample standard deviation, and 95th percentile
(linear interpolation between closest ranks).

Usage:
    python scripts/benchmark_repeated.py --runs 30 --source-mode fabric

Emits artifacts/eval/repeated_benchmark_<mode>.{json,md}.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "artifacts" / "eval"

METRICS = [
    ("attestation_bundle_seconds", "Attestation bundle time (s)"),
    ("attestation_relay_seconds", "Attestation relay time (s)"),
    ("attestation_proof_seconds", "Semantic proof generation (s)"),
    ("eval_bundle_seconds", "Eval bundle time (s)"),
    ("eval_relay_seconds", "Eval relay time (s)"),
    ("eval_proof_seconds", "Eval proof generation (s)"),
    ("attestation_gas_used", "Attestation verification gas"),
    ("eval_gas_used", "Eval verification gas"),
]


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower, upper = math.floor(position), math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def summarize(values: list[float]) -> dict:
    return {
        "n": len(values),
        "median": statistics.median(values),
        "mean": statistics.fmean(values),
        "sd": statistics.stdev(values) if len(values) > 1 else 0.0,
        "p95": percentile(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--source-mode", choices=["evm", "fabric"], default="fabric")
    args = parser.parse_args()

    runs_root = REPO_ROOT / "artifacts" / "bench" / args.source_mode
    samples: dict[str, list[float]] = {key: [] for key, _ in METRICS}
    retries = 0
    for index in range(1, args.runs + 1):
        output_root = runs_root / f"run-{index:02d}"
        for attempt in (1, 2):
            completed = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "run_demo.py"), "--source-mode", args.source_mode,
                 "--output-root", str(output_root)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )
            if completed.returncode == 0:
                break
            if attempt == 2:
                raise RuntimeError(f"run {index} failed twice:\n{completed.stderr[-3000:]}")
            # A run that fails before producing a summary (for example a Hardhat port race)
            # is repeated once; the retry count is reported with the results.
            retries += 1
            print(f"run {index} failed, retrying:\n{completed.stderr[-500:]}", flush=True)
        summary = json.loads((output_root / "demo_summary.json").read_text())
        if not (summary["attestation"]["verified"] and summary["eval"]["verified"]):
            raise RuntimeError(f"run {index} did not verify on destination")
        for key, _ in METRICS:
            samples[key].append(float(summary["benchmark"][key]))
        print(f"run {index}/{args.runs} done", flush=True)

    stats = {key: summarize(values) for key, values in samples.items()}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    result = {"source_mode": args.source_mode, "runs": args.runs, "retries": retries, "metrics": stats,
              "samples": samples}
    (OUT_DIR / f"repeated_benchmark_{args.source_mode}.json").write_text(json.dumps(result, indent=2) + "\n")

    lines = [
        f"# Repeated end-to-end benchmark ({args.source_mode} source, {args.runs} runs)",
        "",
        f"Retried runs: {retries}. SD is the sample standard deviation; p95 interpolates between closest ranks.",
        "",
        "| Metric | Median | Mean | SD | p95 |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for key, label in METRICS:
        s = stats[key]
        fmt = "{:,.0f}" if key.endswith("gas_used") else "{:.3f}"
        lines.append(f"| {label} | {fmt.format(s['median'])} | {fmt.format(s['mean'])} | "
                     f"{fmt.format(s['sd'])} | {fmt.format(s['p95'])} |")
    (OUT_DIR / f"repeated_benchmark_{args.source_mode}.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
