#!/usr/bin/env python3
"""Run the fixed paper_core timing path for n=3, 5, and 10, with L=3."""

from __future__ import annotations

import csv
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
import math
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from native_blind_abs.backends import get_backend
from native_blind_abs.blind import (
    abs_blind_sign,
    abs_unblind,
    vp_check_request,
    vp_request,
    vp_show,
)
from native_blind_abs.commitment import commit
from native_blind_abs.core import abs_sign, representative_for
from native_blind_abs.groups import curve_order
from native_blind_abs.jr import add_credentials, issuer_keygen
from native_blind_abs.models import BlindRequest, CheckedBlindRequest, Credential
from native_blind_abs.policy import Attr, Attribute, Policy, and_all
from native_blind_abs.services import HolderService, IssuerService, RAService, VerifierService


PERMISSION_COUNTS = (3, 5, 10)
DEFAULT_OUTPUT_DIR = (
    Path(__file__).resolve().parents[1] / "results" / "computation"
)
MESSAGE_LENGTH = 3
WARMUP = 1
REPETITIONS = 1
EPOCH = 7
ATTRIBUTE_NAMESPACE = "ra:native-blind-benchmark"
N_DEFINITION = "n is the number of permission attributes"


OPERATION_ORDER = (
    "vector_commit",
    "identified_vc_sign",
    "identified_vc_verify",
    "vp_request_create",
    "vp_request_verify",
    "vp_blind_sign",
    "vp_unblind_and_finalize",
    "anonymous_vp_verify",
)
def source_manifest() -> list[dict[str, str]]:
    """Hash the exact reviewer package used to produce the result."""
    project_root = Path(__file__).resolve().parents[1]
    source_paths = [
        path
        for folder in ("src", "benchmarks", "examples", "tests")
        for path in (project_root / folder).rglob("*.py")
    ]
    requirements = project_root / "requirements.txt"
    if requirements.is_file():
        source_paths.append(requirements)
    return [
        {
            "source_file": path.relative_to(project_root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(set(source_paths))
    ]


def _write_source_manifest(output_dir: Path, manifest: list[dict[str, str]]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "source-manifest.json"
    _atomic_write(
        path,
        json.dumps({
            "algorithm": "SHA-256",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "files": manifest,
        }, indent=2) + "\n",
    )
    return path


def permissions(count: int) -> tuple[Attribute, ...]:
    if count not in PERMISSION_COUNTS:
        raise ValueError(f"permission count must be one of {PERMISSION_COUNTS}")
    return tuple(
        Attribute(ATTRIBUTE_NAMESPACE, "permission", f"permission-{index:02d}")
        for index in range(1, count + 1)
    )


def message_fields(length: int) -> tuple[str, ...]:
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= 64:
        raise ValueError("message-vector length L must be in 1..64")
    return tuple(f"content-{index}" for index in range(length))


def message_vector(length: int) -> tuple[int, ...]:
    message_fields(length)  # validate independently of the permission count n
    order = curve_order()
    vector = tuple(order // 2 + 17 + 12 * index for index in range(length))
    if any(value >= order for value in vector):
        raise ValueError("benchmark message vector contains a noncanonical scalar")
    return vector


def policies_for(count: int) -> tuple[tuple[Attribute, ...], Attribute, Attribute, Policy, Policy]:
    permission_attributes = permissions(count)
    identity = Attribute(ATTRIBUTE_NAMESPACE, "identity", "issuer-A")
    time_attribute = Attribute(ATTRIBUTE_NAMESPACE, "time", f"epoch-{EPOCH}")
    source_policy = and_all(
        *(Attr(attribute) for attribute in permission_attributes),
        Attr(identity),
        Attr(time_attribute),
    )
    target_policy = and_all(
        *(Attr(attribute) for attribute in permission_attributes),
        Attr(time_attribute),
    )
    return permission_attributes, identity, time_attribute, source_policy, target_policy


def _transition(source_policy: Policy, target_policy: Policy) -> Callable[[Policy, Policy], bool]:
    return lambda source, target: source == source_policy and target == target_policy


def _build_base(count: int, message_length: int) -> dict[str, Any]:
    """Build a valid vector-content identified VC fixture outside all timers."""
    permission_attributes, identity, time_attribute, source_policy, target_policy = policies_for(count)
    fields = message_fields(message_length)
    content = message_vector(message_length)
    schema_id = f"native-blind-benchmark-v3-L{message_length}"
    ra = RAService(fields, schema_id=schema_id)
    issuer_secret = issuer_keygen(ra.pp)  # generated locally by the issuer
    ra.register_issuer(issuer_secret.public_key)
    attributes = (*permission_attributes, identity, time_attribute)
    certificates = ra.authorize(issuer_secret.public_key, attributes, EPOCH)
    installed_key = add_credentials(issuer_secret, certificates)
    issuer = IssuerService(
        ra.pp,
        installed_key,
        certificates,
        allowed_transitions=((source_policy, target_policy),),
    )
    commitment, opening = commit(ra.pp, content)
    holder = HolderService(ra.pp)
    verifier = VerifierService(ra.pp)
    representative = representative_for(
        ra.pp, commitment, source_policy, EPOCH, "VC"
    )
    return {
        "ra": ra,
        "issuer_secret": installed_key,
        "issuer": issuer,
        "certificates": certificates,
        "permission_attributes": permission_attributes,
        "identity": identity,
        "time_attribute": time_attribute,
        "source_policy": source_policy,
        "target_policy": target_policy,
        "attributes": attributes,
        "commitment": commitment,
        "opening": opening,
        "holder": holder,
        "verifier": verifier,
        "representative": representative,
        "message_fields": fields,
        "message_vector": content,
        "schema_id": schema_id,
    }


def _check_request(base: dict[str, Any], request: BlindRequest) -> CheckedBlindRequest:
    return vp_check_request(
        base["ra"].pp,
        base["issuer_secret"],
        request,
        expected_source=base["credential"],
        transition_allowed=_transition(base["source_policy"], base["target_policy"]),
    )


def _receive_verified_vc(base: dict[str, Any], credential: Credential) -> Credential:
    """Measure holder-side opening and signature validation; return the stored VC."""
    base["holder"].receive_vc(credential, base["opening"])
    return credential


def _prepared_supplier(states: Iterable[Any]) -> Callable[[], Any]:
    iterator = iter(states)
    return lambda: next(iterator)


def _time_operation(
    count: int,
    operation: str,
    prepare: Callable[[], Any],
    run: Callable[[Any], Any],
    repetitions: int,
    warmup: int,
    boundary: str,
) -> tuple[dict[str, Any], list[Any], list[Any]]:
    warmup_outputs = [run(prepare()) for _ in range(warmup)]
    samples: list[float] = []
    measured_outputs: list[Any] = []
    for _ in range(repetitions):
        state = prepare()
        start_ns = time.perf_counter_ns()
        result = run(state)
        samples.append((time.perf_counter_ns() - start_ns) / 1_000_000)
        measured_outputs.append(result)
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, max(0, math.ceil(0.95 * len(ordered)) - 1))
    row = {
        "permission_count": count,
        "operation": operation,
        "timed_region": boundary,
        "samples": len(samples),
        "median_ms": statistics.median(samples),
        "min_ms": min(samples),
        "max_ms": max(samples),
        "p25_ms": _percentile(samples, 0.25),
        "p75_ms": _percentile(samples, 0.75),
        "dispersion_note": (
            "one sample: quartiles are degenerate and do not measure variability"
            if len(samples) == 1 else "descriptive spread for the observed sample"
        ),
        "mean_ms": statistics.mean(samples),
        "stdev_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "p95_ms": ordered[p95_index],
        "sample_ms": samples,
    }
    return row, warmup_outputs, measured_outputs


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _measure_workflow(
    base: dict[str, Any],
    count: int,
    repetitions: int,
    warmup: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ra: RAService = base["ra"]
    pp = ra.pp
    issuer_secret = base["issuer_secret"]
    holder: HolderService = base["holder"]

    def record(row: dict[str, Any]) -> None:
        index = len(rows)
        if index >= len(OPERATION_ORDER) or row["operation"] != OPERATION_ORDER[index]:
            raise RuntimeError("benchmark operation order diverged from the protocol sequence")
        rows.append(row)

    row, _, _ = _time_operation(
        count, "vector_commit",
        lambda: None,
        lambda _: commit(pp, base["message_vector"]),
        repetitions, warmup,
        f"vector commit call for the fixed L={len(base['message_vector'])}-coordinate content vector",
    )
    record(row)

    row, sign_warmups, sign_samples = _time_operation(
        count, "identified_vc_sign",
        lambda: None,
        lambda _: abs_sign(
            pp, issuer_secret, base["representative"], base["source_policy"], EPOCH
        ),
        repetitions, warmup,
        "abs_sign call on the prebuilt identified VC representative and installed issuer attributes",
    )
    record(row)

    row, _, vc_samples = _time_operation(
        count, "identified_vc_verify",
        _prepared_supplier(tuple(
            Credential(
                base["ra"].pp.schema.schema_id,
                pp.pp_id,
                base["commitment"],
                base["source_policy"],
                EPOCH,
                signature,
            )
            for signature in (*sign_warmups, *sign_samples)
        )),
        lambda credential: _receive_verified_vc(base, credential),
        repetitions, warmup,
        "HolderService.receive_vc call on a credential with a signature returned by the immediately preceding timed sign operation; validates opening and VC ABS signature and stores the opening",
    )
    base["credential"] = vc_samples[0]
    record(row)

    row, request_warmups, request_samples = _time_operation(
        count, "vp_request_create",
        lambda: base,
        lambda state: state["holder"].request_vp(
            state["credential"], state["target_policy"]
        ),
        repetitions, warmup,
        "HolderService.request_vp call; VC, opening, and target policy are already held",
    )
    record(row)

    row, checked_warmups, checked_samples = _time_operation(
        count, "vp_request_verify",
        _prepared_supplier((*request_warmups, *request_samples)),
        lambda request: _check_request(base, request),
        repetitions, warmup,
        "vp_check_request on a prebuilt request; checks canonical equality with the expected source-VC record, allowed policy transition, request proof, and issuer authorization. Source-VC opening and ABS signature validation were measured separately in identified_vc_verify; this fixed reviewer path does not repeat that signature check here.",
    )
    record(row)

    row, response_warmups, response_samples = _time_operation(
        count, "vp_blind_sign",
        _prepared_supplier((*checked_warmups, *checked_samples)),
        lambda checked: abs_blind_sign(pp, issuer_secret, checked),
        repetitions, warmup,
        "abs_blind_sign call on a prechecked request; request verification is measured separately",
    )
    record(row)

    finalize_states = tuple(
        (base, request, response, os.urandom(32))
        for request, response in zip(
            (*request_warmups, *request_samples),
            (*response_warmups, *response_samples),
        )
    )
    row, presentation_warmups, presentation_samples = _time_operation(
        count, "vp_unblind_and_finalize",
        _prepared_supplier(finalize_states),
        lambda state: state[0]["holder"].complete_vp(
            state[1], state[2], state[3]
        ),
        repetitions, warmup,
        "HolderService.complete_vp after receiving a fresh 32-byte verifier nonce; includes mandatory abs_verify on exact (U,V,W), unblinding, full signature refresh, and nonce-bound opening-proof generation",
    )
    record(row)

    presentations = (*presentation_warmups, *presentation_samples)
    verification_states = tuple(
        (presentation, finalize_state[3])
        for presentation, finalize_state in zip(presentations, finalize_states)
    )
    row, _, _ = _time_operation(
        count, "anonymous_vp_verify",
        _prepared_supplier(verification_states),
        lambda state: base["verifier"].verify(
            state[0],
            required_policy=base["target_policy"],
            required_epoch=EPOCH,
            expected_nonce=state[1],
        ),
        repetitions, warmup,
        "VerifierService.verify call on a prebuilt anonymous VP with required policy, epoch, and expected nonce saved independently from the finalization input state",
    )
    record(row)
    if tuple(row["operation"] for row in rows) != OPERATION_ORDER:
        raise RuntimeError("benchmark did not produce exactly the configured operation sequence")
    return rows


def _decomposition_source(base: dict[str, Any]) -> tuple[Credential, Any, Any]:
    """Build a fresh valid source VC, request state, and issuer response off-timer."""
    pp = base["ra"].pp
    signature = abs_sign(
        pp, base["issuer_secret"], base["representative"], base["source_policy"], EPOCH
    )
    credential = Credential(
        pp.schema.schema_id,
        pp.pp_id,
        base["commitment"],
        base["source_policy"],
        EPOCH,
        signature,
    )
    request, state = vp_request(
        pp, credential, base["opening"], base["target_policy"]
    )
    checked = vp_check_request(
        pp,
        base["issuer_secret"],
        request,
        expected_source=credential,
        transition_allowed=_transition(base["source_policy"], base["target_policy"]),
    )
    response = abs_blind_sign(pp, base["issuer_secret"], checked)
    return credential, (request, state), response


def _measure_decomposition(
    base: dict[str, Any], count: int, repetitions: int, warmup: int
) -> list[dict[str, Any]]:
    """Time existing holder preparation and presentation APIs as supplementary rows.

    These rows are independent explanatory measurements. They are not added to the
    eight-operation total because preparation and online stages overlap that path.
    """
    pp = base["ra"].pp
    rows: list[dict[str, Any]] = []

    row, _, _ = _time_operation(
        count,
        "advance_vp_preparation",
        lambda: (
            abs_sign(
                pp, base["issuer_secret"], base["representative"],
                base["source_policy"], EPOCH,
            ),
            base,
        ),
        lambda state: vp_request(
            pp,
            Credential(
                pp.schema.schema_id, pp.pp_id, state[1]["commitment"],
                state[1]["source_policy"], EPOCH, state[0],
            ),
            state[1]["opening"],
            state[1]["target_policy"],
        ),
        repetitions,
        warmup,
        "Holder vp_request preparation API, including target-commitment rerandomization and request-proof generation; source VC and opening are prepared before the timer; independent of a verifier nonce",
    )
    rows.append(row)

    # Prepare exact, authorized issuer responses outside the timed holder call.
    sources = [_decomposition_source(base) for _ in range(repetitions + warmup)]
    source_iter = iter(sources)
    row, _, _ = _time_operation(
        count,
        "holder_unblind_and_full_refresh",
        lambda: next(source_iter),
        lambda item: abs_unblind(pp, item[1][0], item[1][1], item[2]),
        repetitions,
        warmup,
        "abs_unblind call on a fresh exact request and valid blind response; includes mandatory exact-request response verification, unblinding, and complete signature/proof refresh. Fixture issuance, request authorization/proof checks, response signing, and response generation are outside the timer.",
    )
    rows.append(row)

    # Each measured opening proof uses a fresh independently generated nonce.
    show_sources = []
    for index in range(repetitions + warmup):
        credential, (request, state), response = _decomposition_source(base)
        refreshed = abs_unblind(pp, request, state, response)
        nonce = os.urandom(32)
        show_sources.append((request, state, refreshed, nonce))
    show_iter = iter(show_sources)
    row, _, presentations = _time_operation(
        count,
        "nonce_bound_hidden_opening_generation",
        lambda: next(show_iter),
        lambda item: vp_show(pp, item[0], item[1], item[2], item[3]),
        repetitions,
        warmup,
        "vp_show call on a precomputed refreshed VP signature and fresh 32-byte verifier nonce; includes nonce-bound hidden-opening proof generation and presentation construction; signature refresh is outside the timer",
    )
    rows.append(row)
    if any(presentation.nonce != source[3] for presentation, source in zip(
        presentations, show_sources[warmup:]
    )):
        raise RuntimeError("presentation nonce did not match its independently saved verifier nonce")
    verification_sources = [
        (presentation, source[3])
        for presentation, source in zip(presentations, show_sources[warmup:])
    ]
    verify_iter = iter(verification_sources)
    row, _, verification_results = _time_operation(
        count,
        "anonymous_vp_verification",
        lambda: next(verify_iter),
        lambda item: base["verifier"].verify(
            item[0],
            required_policy=base["target_policy"],
            required_epoch=EPOCH,
            expected_nonce=item[1],
        ),
        repetitions,
        0,
        "VerifierService.verify on the prebuilt anonymous VP using the required policy, epoch, and independently saved nonce; verification includes signature and hidden-opening proof checks",
    )
    if not all(verification_results):
        raise RuntimeError("a supplementary anonymous VP failed verification")
    rows.append(row)
    return rows


def _write_decomposition(
    output_dir: Path,
    metadata: dict[str, Any],
    rows: list[dict[str, Any]],
    main_rows: list[dict[str, Any]],
    output_stem: str,
) -> tuple[Path, Path, Path]:
    """Write supplementary stage timings without adding them to the main total."""
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = sorted({int(row["permission_count"]) for row in rows})
    grouped = []
    for count in counts:
        main_total = sum(
            float(row["median_ms"])
            for row in main_rows
            if int(row["permission_count"]) == count
        )
        selected = [row for row in rows if int(row["permission_count"]) == count]
        refresh = next(
            float(row["median_ms"])
            for row in selected
            if row["operation"] == "holder_unblind_and_full_refresh"
        )
        grouped.append({
            "permission_count": count,
            "eight_operation_median_sum_ms": main_total,
            "full_holder_unblind_refresh_median_ms": refresh,
            "full_holder_unblind_refresh_fraction_of_eight_operation_sum": refresh / main_total,
            "summation_note": "Supplementary stage medians are not added together or to the eight-operation sum; these stages explain portions of the main protocol path.",
            "operations": [
                {key: value for key, value in row.items() if key != "permission_count"}
                for row in selected
            ],
        })
    json_path = output_dir / f"{output_stem}.json"
    csv_path = output_dir / f"{output_stem}.csv"
    raw_path = output_dir / f"{output_stem}-raw-samples.csv"
    _atomic_write(json_path, json.dumps({
        "metadata": {
            **metadata,
            "run_status": "complete",
            "aggregation": "supplementary stage decomposition; not summed into the eight-operation total",
        },
        "results": grouped,
    }, indent=2, ensure_ascii=False) + "\n")
    fields = (
        "permission_count", "operation", "samples", "median_ms", "p25_ms", "p75_ms",
        "timed_region",
    )
    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(csv_buffer, fieldnames=fields)
    writer.writeheader()
    writer.writerows({field: row[field] for field in fields} for row in rows)
    _atomic_write(csv_path, csv_buffer.getvalue())
    raw_buffer = io.StringIO(newline="")
    raw_fields = ("permission_count", "operation", "sample_index", "sample_ms")
    raw_writer = csv.DictWriter(raw_buffer, fieldnames=raw_fields)
    raw_writer.writeheader()
    for row in rows:
        for index, value in enumerate(row["sample_ms"], start=1):
            raw_writer.writerow({
                "permission_count": row["permission_count"],
                "operation": row["operation"],
                "sample_index": index,
                "sample_ms": value,
            })
    _atomic_write(raw_path, raw_buffer.getvalue())
    return json_path, csv_path, raw_path


def _cpu_description() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith(("model name", "hardware")):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def _metadata(repetitions: int, warmup: int) -> dict[str, Any]:
    def version(package: str, fallback: str) -> str:
        try:
            return importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return fallback

    return {
        "profile": "paper_core",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu": _cpu_description(),
        "logical_cpu_count": os.cpu_count(),
        "py_ecc": version("py-ecc", "unknown"),
        "py_arkworks_bls12381": version("py-arkworks-bls12381", "unknown"),
        "group_backend": get_backend().backend_name,
        "permission_counts": list(PERMISSION_COUNTS),
        "n_definition": N_DEFINITION,
        "message_vector_length_L": MESSAGE_LENGTH,
        "repetitions": repetitions,
        "warmup": warmup,
        "timer": "time.perf_counter_ns",
        "timer_boundary": "Each row's prepare() runs before the timer. The interval begins immediately before run(state) and ends immediately after it returns; Python dispatch and argument evaluation are included.",
        "randomness_policy": "Fixed public schema/policy and deterministic L=3 message coordinates; cryptographic scalars, commitment randomness, proof randomness, and verifier nonces are sampled freshly with the implementation's OS-backed secrets source. No RNG seed is set.",
        "dispersion_interpretation": "For a one-sample pilot, p25 equals p75 by construction and has no statistical meaning; do not interpret it as stability evidence.",
        "aggregate_definition": "sum_of_operation_medians_ms is the sum of the eight non-overlapping operation medians, including mandatory blind-response verification once inside vp_unblind_and_finalize. It is an operation-level core-cost summary, not end-to-end wall-clock latency.",
        "workflow": "identified VC -> anonymous VP",
        "operation_order": list(OPERATION_ORDER),
        "source_hashes": source_manifest(),
    }


def _atomic_write(path: Path, payload: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def _output_documents(
    metadata: dict[str, Any], rows: list[dict[str, Any]]
) -> tuple[str, str, str]:
    counts = sorted({int(row["permission_count"]) for row in rows})
    grouped = [
        {
            "permission_count": count,
            "n_definition": N_DEFINITION,
            "sum_of_operation_medians_ms": sum(
                float(row["median_ms"])
                for row in rows
                if row["permission_count"] == count
            ),
            "operations": [
                {key: value for key, value in row.items() if key != "permission_count"}
                for row in rows
                if row["permission_count"] == count
            ],
        }
        for count in counts
    ]
    csv_fields = (
        "permission_count", "operation", "samples", "median_ms", "min_ms",
        "max_ms", "p25_ms", "p75_ms", "dispersion_note", "mean_ms", "stdev_ms", "p95_ms", "timed_region",
    )
    csv_rows = [{field: row[field] for field in csv_fields} for row in rows]
    csv_output = io.StringIO(newline="")
    writer = csv.DictWriter(csv_output, fieldnames=csv_fields)
    writer.writeheader()
    writer.writerows(csv_rows)
    raw_output = io.StringIO(newline="")
    raw_fields = ("permission_count", "operation", "sample_index", "sample_ms")
    raw_writer = csv.DictWriter(raw_output, fieldnames=raw_fields)
    raw_writer.writeheader()
    for row in rows:
        for index, sample in enumerate(row["sample_ms"], start=1):
            raw_writer.writerow({
                "permission_count": row["permission_count"],
                "operation": row["operation"],
                "sample_index": index,
                "sample_ms": sample,
            })
    json_output = json.dumps(
        {"metadata": metadata, "results": grouped}, indent=2, ensure_ascii=False
    ) + "\n"
    return json_output, csv_output.getvalue(), raw_output.getvalue()


def _write_final(
    output_dir: Path,
    metadata: dict[str, Any],
    rows: list[dict[str, Any]],
    output_stem: str,
) -> tuple[Path, Path, Path]:
    for count in metadata["permission_counts"]:
        actual = tuple(
            row["operation"] for row in rows if row["permission_count"] == count
        )
        if actual != OPERATION_ORDER:
            raise RuntimeError(
                f"final benchmark rows for n={count} must contain exactly the configured eight operations"
            )
    output_dir.mkdir(parents=True, exist_ok=True)
    final_metadata = {**metadata, "run_status": "complete", "completed_operations": len(rows)}
    json_output, csv_output, raw_output = _output_documents(final_metadata, rows)
    json_path, csv_path = output_dir / f"{output_stem}.json", output_dir / f"{output_stem}.csv"
    _atomic_write(json_path, json_output)
    _atomic_write(csv_path, csv_output)
    raw_path = output_dir / f"{output_stem}-raw-samples.csv"
    _atomic_write(raw_path, raw_output)
    return json_path, csv_path, raw_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=REPETITIONS)
    parser.add_argument("--warmup", type=int, default=WARMUP)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--output-stem", default="latest")
    args = parser.parse_args(argv)
    if args.repetitions < 1 or args.warmup < 0:
        parser.error("--repetitions must be positive and --warmup cannot be negative")
    if not args.output_stem or Path(args.output_stem).name != args.output_stem:
        parser.error("--output-stem must be a plain filename stem")
    output_dir = args.output_dir
    metadata = _metadata(args.repetitions, args.warmup)
    _write_source_manifest(output_dir, metadata["source_hashes"])
    rows: list[dict[str, Any]] = []
    decomposition_rows: list[dict[str, Any]] = []
    for count in PERMISSION_COUNTS:
        fixture = _build_base(count, MESSAGE_LENGTH)
        rows.extend(_measure_workflow(fixture, count, args.repetitions, args.warmup))
        decomposition_rows.extend(
            _measure_decomposition(fixture, count, args.repetitions, args.warmup)
        )
    json_path, csv_path, raw_path = _write_final(
        output_dir, metadata, rows, args.output_stem
    )
    decomposition_paths = _write_decomposition(
        output_dir,
        metadata,
        decomposition_rows,
        rows,
        f"{args.output_stem}-decomposition",
    )
    for count in PERMISSION_COUNTS:
        operations = [row for row in rows if row["permission_count"] == count]
        print(f"n={count} operations={len(operations)}")
        for row in operations:
            print(f"  {row['operation']}: {row['median_ms']:.3f} ms")
    print(f"json: {json_path}")
    print(f"csv:  {csv_path}")
    print(f"raw samples: {raw_path}")
    print(f"decomposition json: {decomposition_paths[0]}")
    print(f"decomposition csv: {decomposition_paths[1]}")
    print(f"decomposition raw samples: {decomposition_paths[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
