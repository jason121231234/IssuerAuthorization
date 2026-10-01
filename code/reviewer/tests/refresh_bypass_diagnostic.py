"""Unsafe diagnostic: exact retained-session match when full GS refresh is stubbed.

This test-only diagnostic is not a protocol implementation or security proof.
It demonstrates one concrete incomplete-refresh behavior for the fixed n=3
fixture; it makes no claim about other partial-refresh variants.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sys
from unittest.mock import patch

REVIEWER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REVIEWER_ROOT))

from benchmarks.compute import source_manifest
from examples.reviewer_flow import run_flow
from native_blind_abs import blind
from native_blind_abs.groups import g2_equal


def _x1(signature):
    return next(
        item.value for item in signature.commitments.items
        if item.variable_name == "X1"
    )


def _same_x1(left, right) -> bool:
    left_x1, right_x1 = _x1(left), _x1(right)
    return (
        g2_equal(left_x1.first, right_x1.first)
        and g2_equal(left_x1.second, right_x1.second)
    )


def run_diagnostic() -> dict[str, object]:
    """Compare one refresh-bypassed adaptation with the full-refresh control."""
    flow = run_flow()
    holder = flow["holder"]
    issuer = flow["issuer"]
    credential = flow["credential"]
    target_policy = flow["target_policy"]
    verifier = flow["verifier"]

    def convert(*, bypass_refresh: bool):
        request = holder.request_vp(credential, target_policy)
        response = issuer.blind_sign(request)
        refresh_calls = []
        nonce = os.urandom(32)
        if bypass_refresh:
            real_refresh = blind.refresh

            def test_local_identity_refresh(pp, equations, commitments, proofs):
                refresh_calls.append("stubbed")
                return commitments, proofs

            with patch.object(blind, "refresh", side_effect=test_local_identity_refresh):
                presentation = holder.complete_vp(request, response, nonce)
        else:
            real_refresh = blind.refresh

            def record_real_refresh(*args):
                refresh_calls.append("full")
                return real_refresh(*args)

            with patch.object(blind, "refresh", side_effect=record_real_refresh):
                presentation = holder.complete_vp(request, response, nonce)
        verified = verifier.verify(
            presentation,
            required_policy=target_policy,
            required_epoch=7,
            expected_nonce=nonce,
        )
        return response, presentation, verified, refresh_calls

    bypass_response, bypass_vp, bypass_verified, bypass_calls = convert(bypass_refresh=True)
    full_response, full_vp, full_verified, full_calls = convert(bypass_refresh=False)
    bypass_match = _same_x1(bypass_response.signature, bypass_vp.signature)
    full_match = _same_x1(full_response.signature, full_vp.signature)
    if bypass_calls != ["stubbed"] or full_calls != ["full"]:
        raise AssertionError("the diagnostic did not exercise the intended refresh paths")
    if not bypass_match or full_match or not bypass_verified or not full_verified:
        raise AssertionError("the observed X1 matching or verification control differed")
    return {
        "diagnostic_only": True,
        "unsafe_weaker_output": "blind unblinding/signature normalization with the complete GS refresh replaced by an identity stub local to this diagnostic",
        "permission_count_n": 3,
        "retained_session_match_test": "exact equality of both mathematical G2 points in commitment X1 from the issuer's BlindResponse and the final VP signature",
        "refresh_bypassed_x1_equals_issued_response": bypass_match,
        "refresh_bypassed_vp_verifies": bypass_verified,
        "full_refresh_x1_equals_issued_response": full_match,
        "full_refresh_vp_verifies": full_verified,
        "refresh_stub_calls": bypass_calls,
        "full_refresh_control_calls": full_calls,
        "interpretation_boundary": "One concrete exact matching relation for this deliberately incomplete n=3 diagnostic only. It is not a general claim about all partial refresh variants, and verification success is not an unlinkability result.",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_hashes": source_manifest(),
    }


def main(argv: list[str] | None = None) -> int:
    default_output = (
        Path(__file__).resolve().parents[1]
        / "results/computation/macos-formal-response-check-20261002/refresh-bypass-diagnostic.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=default_output)
    args = parser.parse_args(argv)
    result = run_diagnostic()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "source_hashes"}, indent=2))
    print(f"diagnostic json: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
