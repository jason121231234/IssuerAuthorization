#!/usr/bin/env python3
"""Record the real complete GS refresh call nested inside holder unblinding."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import importlib.metadata
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

REVIEWER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REVIEWER_ROOT))

from benchmarks.compute import (
    PERMISSION_COUNTS,
    _build_base,
    _decomposition_source,
    _percentile,
    source_manifest,
)
from native_blind_abs import blind
from native_blind_abs.blind import abs_unblind
from native_blind_abs.core import abs_verify, representative_for


DEFAULT_OUTPUT_DIR = (
    Path(__file__).resolve().parents[1]
    / "results/computation/macos-formal-response-check-20261002/refresh-boundary"
)


def _measure_one(base, count: int, repetitions: int, warmup: int):
    pp = base["ra"].pp
    outer_samples: list[float] = []
    refresh_samples: list[float] = []
    last_signature = None
    for index in range(warmup + repetitions):
        _, (request, state), response = _decomposition_source(base)
        inner: list[float] = []
        real_refresh = blind.refresh

        def record_refresh(*args):
            start = time.perf_counter_ns()
            refreshed = real_refresh(*args)
            inner.append((time.perf_counter_ns() - start) / 1_000_000)
            return refreshed

        with patch.object(blind, "refresh", side_effect=record_refresh):
            start = time.perf_counter_ns()
            signature = abs_unblind(pp, request, state, response)
            outer_elapsed = (time.perf_counter_ns() - start) / 1_000_000
        if len(inner) != 1:
            raise RuntimeError("holder unblinding must invoke the complete GS refresh exactly once")
        representative = representative_for(
            pp, state.target_commitment, request.target_policy, request.epoch, "VP"
        )
        if not abs_verify(pp, representative, request.target_policy, request.epoch, signature):
            raise RuntimeError("the full-refresh output failed ABS verification")
        if index >= warmup:
            outer_samples.append(outer_elapsed)
            refresh_samples.append(inner[0])
            last_signature = signature
    return outer_samples, refresh_samples, last_signature


def _summary(values: list[float], name: str, count: int) -> dict[str, object]:
    q1 = _percentile(values, 0.25)
    q3 = _percentile(values, 0.75)
    return {
        "permission_count": count,
        "operation": name,
        "samples": len(values),
        "median_ms": statistics.median(values),
        "p25_ms": q1,
        "p75_ms": q3,
        "iqr_ms": q3 - q1,
        "min_ms": min(values),
        "max_ms": max(values),
        "sample_ms": values,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)
    if args.repetitions < 1 or args.warmup < 0:
        parser.error("--repetitions must be positive and --warmup cannot be negative")

    rows = []
    for count in PERMISSION_COUNTS:
        base = _build_base(count, 3)
        outer, inner, _ = _measure_one(base, count, args.repetitions, args.warmup)
        rows.extend((
            _summary(outer, "holder_unblind_with_complete_refresh", count),
            _summary(inner, "complete_gs_refresh_inner_call", count),
        ))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    cpu = platform.processor() or platform.machine()
    if sys.platform == "darwin":
        result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            cpu = result.stdout.strip()
    metadata = {
        "run_status": "complete",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": "paper_core; full protocol checks retained",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu": cpu,
        "logical_cpu_count": os.cpu_count(),
        "py_ecc": importlib.metadata.version("py-ecc"),
        "py_arkworks_bls12381": importlib.metadata.version("py-arkworks-bls12381"),
        "permission_counts": list(PERMISSION_COUNTS),
        "message_vector_length_L": 3,
        "repetitions": args.repetitions,
        "warmup": args.warmup,
        "timer": "time.perf_counter_ns",
        "outer_boundary": "abs_unblind call; includes exact-request blind-response verification, unblinding, and the complete GS refresh. Fixture construction and source VC/request/response generation are outside the timer.",
        "inner_boundary": "A recorder wraps the existing blind.refresh call during abs_unblind; timing begins immediately before the real refresh function and ends immediately after it returns. No production protocol function is changed.",
        "aggregation_note": "The inner refresh measurement is contained within holder_unblind_with_complete_refresh and is not added to either that row or the eight-operation sum.",
        "source_hashes": source_manifest(),
    }
    json_path = args.output_dir / "refresh-boundary.json"
    csv_path = args.output_dir / "refresh-boundary.csv"
    raw_path = args.output_dir / "refresh-boundary-raw-samples.csv"
    json_path.write_text(json.dumps({"metadata": metadata, "results": rows}, indent=2) + "\n", encoding="utf-8")
    fields = (
        "permission_count", "operation", "samples", "median_ms", "p25_ms",
        "p75_ms", "iqr_ms", "min_ms", "max_ms",
    )
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row[field] for field in fields} for row in rows)
    with raw_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("permission_count", "operation", "sample_index", "sample_ms"))
        writer.writeheader()
        for row in rows:
            for index, sample in enumerate(row["sample_ms"], start=1):
                writer.writerow({
                    "permission_count": row["permission_count"],
                    "operation": row["operation"],
                    "sample_index": index,
                    "sample_ms": sample,
                })
    print(f"json: {json_path}")
    print(f"csv: {csv_path}")
    print(f"raw samples: {raw_path}")
    for row in rows:
        print(
            f"n={row['permission_count']} {row['operation']} "
            f"median={row['median_ms']:.3f} ms IQR={row['iqr_ms']:.3f} ms"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
