#!/usr/bin/env python3
"""Measure one supplementary exact blind-response verification per n."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import importlib.metadata
import io
import json
import os
import platform
import sys
import time
from pathlib import Path

from compute import _build_base, _check_request, source_manifest
from native_blind_abs.blind import abs_blind_sign, vp_request
from native_blind_abs.core import abs_sign, abs_verify
from native_blind_abs.models import Credential


def cpu_description() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith(("model name", "hardware")):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "results/computation/pilot-linux-quick-1rep-1warmup-20261001",
    )
    args = parser.parse_args()
    rows = []
    for count in (3, 5, 10):
        base = _build_base(count, 3)
        pp = base["ra"].pp
        source_signature = abs_sign(
            pp, base["issuer_secret"], base["representative"], base["source_policy"], 7
        )
        source = Credential(
            pp.schema.schema_id, pp.pp_id, base["commitment"],
            base["source_policy"], 7, source_signature,
        )
        base["credential"] = source
        request, _state = vp_request(pp, source, base["opening"], base["target_policy"])
        checked = _check_request(base, request)
        response = abs_blind_sign(pp, base["issuer_secret"], checked)
        statement = (request.U, request.V, request.W)

        # One unrecorded warm-up; the measured interval contains only the
        # exact-request ABS signature verification call and its return value.
        if not abs_verify(pp, statement, request.target_policy, request.epoch, response.signature):
            raise RuntimeError("warm-up blind response failed exact-request verification")
        start_ns = time.perf_counter_ns()
        verified = abs_verify(
            pp, statement, request.target_policy, request.epoch, response.signature
        )
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        if not verified:
            raise RuntimeError("measured blind response failed exact-request verification")
        rows.append({
            "permission_count": count,
            "operation": "blind_response_verify_supplementary",
            "samples": 1,
            "warmup": 1,
            "verified": verified,
            "sample_ms": elapsed_ms,
            "p25_ms": elapsed_ms,
            "p75_ms": elapsed_ms,
            "dispersion_note": "one sample: quartiles are degenerate and do not measure variability",
            "timed_region": "time.perf_counter_ns immediately around abs_verify(pp, (request.U, request.V, request.W), request.target_policy, request.epoch, response.signature); response/request construction and warm-up excluded",
        })

    args.output_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": "paper_core fixed reviewer path",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu": cpu_description(),
        "logical_cpu_count": os.cpu_count(),
        "py_ecc": importlib.metadata.version("py-ecc"),
        "py_arkworks_bls12381": importlib.metadata.version("py-arkworks-bls12381"),
        "group_backend": "Arkworks G1/G2 and pairing checks; py_ecc pairing/GT operations",
        "randomness_policy": "Fresh OS-backed cryptographic randomness; no seed set. Public policy and L=3 message coordinates are fixed.",
        "aggregation_note": "Supplementary isolated response-check cost only; excluded from the eight-operation sum because vp_unblind_and_finalize includes this required check once.",
        "source_hashes": source_manifest(),
    }
    csv_fields = (
        "permission_count", "operation", "samples", "warmup", "verified", "sample_ms",
        "p25_ms", "p75_ms", "dispersion_note", "timed_region",
    )
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=csv_fields)
    writer.writeheader()
    writer.writerows(rows)
    csv_path = args.output_dir / "quick-response-check.csv"
    csv_path.write_text(buffer.getvalue(), encoding="utf-8")
    json_path = args.output_dir / "quick-response-check.json"
    json_path.write_text(
        json.dumps({"metadata": metadata, "results": rows}, indent=2) + "\n",
        encoding="utf-8",
    )
    for row in rows:
        print(f"n={row['permission_count']} blind_response_verify={row['sample_ms']:.3f} ms")
    print(f"json: {json_path}")
    print(f"csv: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
