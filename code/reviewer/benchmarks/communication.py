#!/usr/bin/env python3
"""Measure Native Blind ABS v3 payloads for an identified-VC to anonymous-VP flow.

Public protocol objects use the package's canonical serializer. Objects for
which v3 intentionally has no public serializer (attribute credentials and
commitment openings) use a documented measurement-only encoding; only lengths
are persisted. Outer transport framing is excluded.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
import sys
from pathlib import Path
from typing import Any

from native_blind_abs.commitment import commit
from native_blind_abs.encoding import (
    encode_bytes,
    encode_sequence,
    encode_text,
    encode_u64,
)
from native_blind_abs.groups import (
    curve_order,
    encode_g1,
    encode_g2,
    scalar_bytes,
)
from native_blind_abs.jr import issuer_keygen
from native_blind_abs.models import (
    AttributeCredential,
    BlindRequest,
    BlindResponse,
    CommitmentOpening,
    Credential,
    IssuerPublicKey,
    Presentation,
)
from native_blind_abs.policy import Attr, Attribute, Policy, and_all
from native_blind_abs.serialization import serialize_public
from native_blind_abs.services import HolderService, IssuerService, RAService


DEFAULT_OUTPUT_DIR = (
    Path(__file__).resolve().parents[1] / "results" / "communication"
)
PERMISSION_COUNTS = (3, 5, 10)
MESSAGE_LENGTH = 3
ROLES = ("RA", "ledger", "issuer", "holder", "verifier")
PHASES = (
    "setup",
    "issuer_registration",
    "vc_issuance",
    "vp_issuance",
    "presentation_delivery",
)
EPOCH = 7
N_DEFINITION = "n is the number of permission attributes"
NAMESPACE = "ra:native-blind-v3-message-measurement"
NONCE = b"native-blind-v3-message-measurement-nonce"


def permissions(count: int) -> tuple[Attribute, ...]:
    if count not in PERMISSION_COUNTS:
        raise ValueError(f"permission count must be one of {PERMISSION_COUNTS}")
    return tuple(
        Attribute(NAMESPACE, "permission", f"permission-{index:02d}")
        for index in range(1, count + 1)
    )


def message_vector(length: int) -> tuple[int, ...]:
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= 64:
        raise ValueError("message-vector length L must be in 1..64")
    order = curve_order()
    vector = tuple(order // 2 + 17 + 12 * index for index in range(length))
    if any(value >= order for value in vector):
        raise ValueError("benchmark message vector contains a noncanonical scalar")
    return vector


def _policy_pair(count: int) -> tuple[tuple[Attribute, ...], Attribute, Attribute, Policy, Policy]:
    permission_attributes = permissions(count)
    identity = Attribute(NAMESPACE, "identity", "issuer-A")
    time_attribute = Attribute(NAMESPACE, "time", f"epoch-{EPOCH}")
    source = and_all(
        *(Attr(attribute) for attribute in permission_attributes),
        Attr(identity),
        Attr(time_attribute),
    )
    target = and_all(
        *(Attr(attribute) for attribute in permission_attributes),
        Attr(time_attribute),
    )
    return permission_attributes, identity, time_attribute, source, target


def _private_encoding(value: AttributeCredential | CommitmentOpening) -> bytes:
    """Return a deterministic, in-process length encoding for private models."""
    if isinstance(value, AttributeCredential):
        public_key = encode_sequence(encode_g2(point) for point in value.issuer_public_key.components)
        certificate = encode_sequence(
            encode_g2(point, allow_identity=True)
            if index != 4
            else encode_g1(point, allow_identity=True)
            for index, point in enumerate(value.certificate)
        )
        return encode_sequence((
            b"NATIVE-BLIND-V3-MEASURE-ATTRIBUTE-CREDENTIAL",
            public_key,
            value.attribute.canonical_bytes(),
            encode_u64(value.epoch),
            certificate,
        ))
    if isinstance(value, CommitmentOpening):
        return encode_sequence((
            b"NATIVE-BLIND-V3-MEASURE-COMMITMENT-OPENING",
            encode_text(value.schema_id),
            scalar_bytes(value.r),
            encode_sequence(scalar_bytes(coordinate) for coordinate in value.message),
        ))
    raise TypeError(f"unsupported private measurement object {type(value).__name__}")


def _component(name: str, value: Any) -> dict[str, Any]:
    if isinstance(value, (AttributeCredential, CommitmentOpening)):
        return {
            "name": name,
            "encoding": "private-measurement-only",
            "bytes": len(_private_encoding(value)),
        }
    return {
        "name": name,
        "encoding": "canonical-public",
        "bytes": len(serialize_public(value)),
    }


def _vector_component(vector: tuple[int, ...]) -> dict[str, Any]:
    encoded = encode_sequence(scalar_bytes(value) for value in vector)
    return {"name": "MessageVector", "encoding": "canonical-vector-scalars", "bytes": len(encoded)}


def _verification_request_components(
    required_policy: Policy, required_epoch: int, nonce: bytes
) -> list[dict[str, Any]]:
    """Encode the verifier's required VP statement as the measured challenge payload."""
    policy_bytes = required_policy.canonical_bytes()
    epoch_bytes = encode_u64(required_epoch)
    nonce_bytes = encode_bytes(nonce)
    return [
        {"name": "RequiredPolicy", "encoding": "policy-canonical-bytes", "bytes": len(policy_bytes)},
        {"name": "RequiredEpoch", "encoding": "u64-big-endian", "bytes": len(epoch_bytes)},
        {"name": "Nonce", "encoding": "u32-length-prefixed-bytes", "bytes": len(nonce_bytes)},
    ]


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
        (json.dumps({
            "algorithm": "SHA-256",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "files": manifest,
        }, indent=2) + "\n").encode("utf-8"),
    )
    return path


def _message(
    count: int,
    message_length: int,
    name: str,
    phase: str,
    sender: str,
    recipient: str,
    components: list[dict[str, Any]],
    *,
    context: str | None = None,
) -> dict[str, Any]:
    return {
        "permission_count": count,
        "n_definition": N_DEFINITION,
        "message_vector_length_L": message_length,
        "message": name,
        "phase": phase,
        "sender": sender,
        "recipient": recipient,
        "context": context,
        "components": components,
        "bytes": sum(int(component["bytes"]) for component in components),
    }


def _append_message(messages: list[dict[str, Any]], message: dict[str, Any]) -> None:
    messages.append(message)


def measure(
    count: int,
    message_length: int = MESSAGE_LENGTH,
) -> list[dict[str, Any]]:
    """Execute the fixed paper_core service flow and count logical payloads."""
    vector = message_vector(message_length)
    permission_attributes, identity, time_attribute, source_policy, target_policy = _policy_pair(count)
    fields = tuple(f"content-{index}" for index in range(message_length))
    ra = RAService(fields, schema_id=f"native-blind-v3-message-measurement-L{message_length}")
    messages: list[dict[str, Any]] = []

    pp_component = _component("PublicParams", ra.pp)
    _append_message(messages, _message(
        count, message_length, "global-public-parameters", "setup", "RA", "ledger",
        [pp_component],
    ))

    issuer_secret = issuer_keygen(ra.pp)
    issuer_public_key: IssuerPublicKey = issuer_secret.public_key
    ra.register_issuer(issuer_public_key)
    registration_component = _component("IssuerPublicKey", issuer_public_key)
    _append_message(messages, _message(
        count, message_length, "issuer-public-key-registration", "issuer_registration",
        "issuer", "RA", [registration_component],
    ))

    attributes = (*permission_attributes, identity, time_attribute)
    authorization_request = encode_sequence((
        encode_sequence(attribute.canonical_bytes() for attribute in attributes),
        encode_u64(EPOCH),
    ))
    _append_message(messages, _message(
        count, message_length, "attribute-authorization-request", "issuer_registration",
        "issuer", "RA",
        [
            _component("IssuerPublicKey", issuer_public_key),
            {
                "name": "AuthorizationAttributesAndEpoch",
                "encoding": "canonical-attribute-list",
                "bytes": len(authorization_request),
            },
        ],
    ))
    certificates = ra.authorize(issuer_public_key, attributes, EPOCH)
    credential_components = [_component("AttributeCredential", item) for item in certificates]
    _append_message(messages, _message(
        count, message_length, "issuer-attribute-credentials", "issuer_registration",
        "RA", "issuer", credential_components,
    ))

    issuer = IssuerService(
        ra.pp,
        issuer_secret,
        certificates,
        allowed_transitions=((source_policy, target_policy),),
    )
    holder = HolderService(ra.pp)
    vector_component = _vector_component(vector)
    _append_message(messages, _message(
        count, message_length, "vc-message-vector", "vc_issuance", "holder", "issuer",
        [vector_component], context="identified-VC",
    ))

    credential, opening = issuer.issue_vc(vector, source_policy, EPOCH)
    vc_component = _component("Credential", credential)
    opening_component = _component("CommitmentOpening", opening)
    _append_message(messages, _message(
        count, message_length, "identified-vc-and-opening", "vc_issuance",
        "issuer", "holder", [vc_component, opening_component], context="identified-VC",
    ))
    holder.receive_vc(credential, opening)

    request = holder.request_vp(credential, target_policy)
    request_component = _component("BlindRequest", request)
    _append_message(messages, _message(
        count, message_length, "vp-blind-request", "vp_issuance", "holder", "issuer",
        [request_component], context="identified-to-anonymous",
    ))

    response = issuer.blind_sign(request)
    response_component = _component("BlindResponse", response)
    _append_message(messages, _message(
        count, message_length, "vp-blind-response", "vp_issuance", "issuer", "holder",
        [response_component], context="anonymous-VP",
    ))

    challenge_components = _verification_request_components(target_policy, EPOCH, NONCE)
    _append_message(messages, _message(
        count, message_length, "vp-verification-request", "presentation_delivery",
        "verifier", "holder", challenge_components, context="anonymous-VP",
    ))

    presentation = holder.complete_vp(request, response, NONCE)
    presentation_component = _component("Presentation", presentation)
    _append_message(messages, _message(
        count, message_length, "anonymous-vp-presentation", "presentation_delivery",
        "holder", "verifier", [presentation_component], context="anonymous-VP",
    ))
    return messages


def role_phase_totals(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    totals = {
        (role, phase): {"sent_bytes": 0, "received_bytes": 0}
        for phase in PHASES
        for role in ROLES
    }
    for message in messages:
        size = int(message["bytes"])
        totals[(message["sender"], message["phase"])]["sent_bytes"] += size
        totals[(message["recipient"], message["phase"])]["received_bytes"] += size
    rows = []
    for phase in PHASES:
        for role in ROLES:
            sent = totals[(role, phase)]["sent_bytes"]
            received = totals[(role, phase)]["received_bytes"]
            rows.append({
                "role": role,
                "phase": phase,
                "sent_bytes": sent,
                "received_bytes": received,
                "total_bytes": sent + received,
                "sent_kib": round(sent / 1024, 6),
                "received_kib": round(received / 1024, 6),
                "total_kib": round((sent + received) / 1024, 6),
            })
    return rows


def _group_results(
    messages: list[dict[str, Any]],
    counts: tuple[int, ...] = PERMISSION_COUNTS,
) -> list[dict[str, Any]]:
    results = []
    for count in counts:
        selected = [message for message in messages if message["permission_count"] == count]
        network_bytes = sum(int(message["bytes"]) for message in selected)
        role_rows = role_phase_totals(selected)
        endpoint_bytes = sum(int(row["total_bytes"]) for row in role_rows)
        if endpoint_bytes != 2 * network_bytes:
            raise RuntimeError("role endpoint totals must count each payload at both endpoints")
        results.append({
            "permission_count": count,
            "n_definition": N_DEFINITION,
            "message_vector_length_L": (
                selected[0]["message_vector_length_L"] if selected else None
            ),
            "messages": selected,
            "role_phase_totals": role_rows,
            "network_payload_bytes": network_bytes,
            "network_payload_kib": round(network_bytes / 1024, 6),
            "endpoint_sent_received_total_bytes": endpoint_bytes,
        })
    return results


def _package_version(name: str, fallback: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return fallback


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _metadata(message_length: int) -> dict[str, Any]:
    vector = message_vector(message_length)
    return {
        "profile": "paper_core",
        "python": sys.version,
        "py_ecc": importlib.metadata.version("py-ecc"),
        "py_arkworks_bls12381": importlib.metadata.version("py-arkworks-bls12381"),
        "group_backend": "Arkworks G1/G2 and pairing checks; py_ecc pairing and GT operations",
        "permission_counts": list(PERMISSION_COUNTS),
        "n_definition": N_DEFINITION,
        "message_vector_length_L": message_length,
        "message_vector_values": list(vector),
        "workflow": "identified VC -> anonymous VP; identical permission attributes and epoch",
        "epoch": EPOCH,
        "roles": list(ROLES),
        "phases": list(PHASES),
        "presentation_challenge_accounting": (
            "Before holder.complete_vp, the verifier-to-holder logical request is counted in "
            "presentation_delivery as three separately encoded components: required_policy "
            "using Policy.canonical_bytes(), required_epoch as u64, and nonce as a "
            "length-prefixed byte string. This is the measurement convention even when the "
            "application provisions policy or epoch in advance."
        ),
        "payload_accounting": (
            "Canonical public serialization is used for public objects. AttributeCredential and "
            "CommitmentOpening use deterministic measurement-only encodings; output stores lengths only. "
            "Transport framing is excluded. network_payload_bytes counts each message once, while "
            "role sent/received totals count it at both endpoints."
        ),
        "unit_definition": "1 KiB = 1024 bytes",
        "source_hashes": source_manifest(),
    }


def _render_outputs(
    metadata: dict[str, Any],
    messages: list[dict[str, Any]],
) -> tuple[bytes, bytes, bytes]:
    results = _group_results(messages)

    message_buffer = io.StringIO(newline="")
    message_fields = (
        "permission_count", "n_definition", "message_vector_length_L", "message",
        "phase", "sender", "recipient", "context", "components", "bytes",
    )
    writer = csv.DictWriter(message_buffer, fieldnames=message_fields)
    writer.writeheader()
    for message in messages:
        writer.writerow({
            **{field: message[field] for field in message_fields if field != "components"},
            "components": json.dumps(message["components"], sort_keys=True, separators=(",", ":")),
        })

    totals_buffer = io.StringIO(newline="")
    total_fields = (
        "permission_count", "n_definition", "message_vector_length_L", "role", "phase",
        "sent_bytes", "received_bytes", "total_bytes", "sent_kib", "received_kib", "total_kib",
    )
    totals_writer = csv.DictWriter(totals_buffer, fieldnames=total_fields)
    totals_writer.writeheader()
    for result in results:
        for row in result["role_phase_totals"]:
            totals_writer.writerow({
                "permission_count": result["permission_count"],
                "n_definition": result["n_definition"],
                "message_vector_length_L": result["message_vector_length_L"] or metadata["message_vector_length_L"],
                **row,
            })

    payload = json.dumps({
        "metadata": {**metadata, "run_status": "complete", "completed_messages": len(messages)},
        "results": results,
    }, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    return payload, message_buffer.getvalue().encode("utf-8"), totals_buffer.getvalue().encode("utf-8")


def write_outputs(output_dir: Path, metadata: dict[str, Any], messages: list[dict[str, Any]]) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_bytes, message_csv, totals_csv = _render_outputs(metadata, messages)
    names = ("latest.json", "messages.csv", "role_phase_totals.csv")
    paths = tuple(output_dir / name for name in names)
    for path, data in zip(paths, (json_bytes, message_csv, totals_csv)):
        _atomic_write(path, data)
    return {"json": paths[0], "messages_csv": paths[1], "totals_csv": paths[2]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)
    output_dir = args.output_dir
    metadata = _metadata(MESSAGE_LENGTH)
    _write_source_manifest(output_dir, metadata["source_hashes"])
    all_messages = [
        message
        for count in PERMISSION_COUNTS
        for message in measure(count, MESSAGE_LENGTH)
    ]
    paths = write_outputs(output_dir, metadata, all_messages)
    results = _group_results(all_messages)
    for result in results:
        print(
            f"n={result['permission_count']} messages={len(result['messages'])} "
            f"network_payload_bytes={result['network_payload_bytes']} "
            f"endpoint_sent_received_total_bytes={result['endpoint_sent_received_total_bytes']}"
        )
    print("mode: fixed paper_core path")
    print(f"json: {paths['json']}")
    print(f"messages csv: {paths['messages_csv']}")
    print(f"role totals csv: {paths['totals_csv']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
