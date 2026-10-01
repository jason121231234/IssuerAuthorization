import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from benchmarks.communication import main as communication_main
from native_blind_abs import blind, services
from examples.reviewer_flow import run_flow
from native_blind_abs.blind import BlindProtocolError
from native_blind_abs.groups import (
    curve_order,
    g1_add,
    g1_generator,
    g2_add,
    g2_generator,
)
from native_blind_abs.policy import Attr, Attribute
from tests.refresh_bypass_diagnostic import run_diagnostic


class ReviewerFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flow = run_flow()

    def test_identified_vc_converts_to_valid_anonymous_vp(self):
        self.assertTrue(self.flow["verified"])

    def test_verifier_rejects_wrong_policy_or_epoch(self):
        verifier = self.flow["verifier"]
        presentation = self.flow["presentation"]
        target_policy = self.flow["target_policy"]
        self.assertFalse(verifier.verify(
            presentation,
            required_policy=target_policy,
            required_epoch=8,
            expected_nonce=b"reviewer-example-nonce",
        ))
        self.assertFalse(verifier.verify(
            presentation,
            required_policy=Attr(Attribute("ra:reviewer-example", "permission", "other")),
            required_epoch=7,
            expected_nonce=b"reviewer-example-nonce",
        ))

    def test_verifier_rejects_tampered_signature(self):
        presentation = self.flow["presentation"]
        signature = replace(
            presentation.signature,
            gamma=g2_add(presentation.signature.gamma, g2_generator()),
        )
        altered = replace(presentation, signature=signature)
        self.assertFalse(self.flow["verifier"].verify(
            altered,
            required_policy=self.flow["target_policy"],
            required_epoch=7,
            expected_nonce=b"reviewer-example-nonce",
        ))

    def test_verifier_rejects_tampered_opening_proof(self):
        presentation = self.flow["presentation"]
        opening = replace(
            presentation.opening_proof,
            z_r=(presentation.opening_proof.z_r + 1) % curve_order(),
        )
        altered = replace(presentation, opening_proof=opening)
        self.assertFalse(self.flow["verifier"].verify(
            altered,
            required_policy=self.flow["target_policy"],
            required_epoch=7,
            expected_nonce=b"reviewer-example-nonce",
        ))

    def test_issuer_rejects_a_tampered_blind_request(self):
        request = self.flow["request"]
        altered = replace(request, W=g1_add(request.W, g1_generator()))
        with self.assertRaises(BlindProtocolError):
            self.flow["issuer"].blind_sign(altered)

    def test_holder_rejects_tampered_blind_response_before_show(self):
        holder = self.flow["holder"]
        request = holder.request_vp(self.flow["credential"], self.flow["target_policy"])
        response = self.flow["issuer"].blind_sign(request)
        altered_signature = replace(
            response.signature,
            gamma=g2_add(response.signature.gamma, g2_generator()),
        )
        altered_response = replace(response, signature=altered_signature)

        verification_calls = []
        real_abs_verify = blind.abs_verify

        def record_verification(*args):
            verification_calls.append(args)
            return real_abs_verify(*args)

        show_calls = []
        real_show = services.vp_show

        def record_show(*args):
            show_calls.append(args)
            return real_show(*args)

        with patch.object(blind, "abs_verify", side_effect=record_verification):
            with patch.object(services, "vp_show", side_effect=record_show):
                with self.assertRaisesRegex(BlindProtocolError, "exact request"):
                    holder.complete_vp(request, altered_response, b"fresh-verifier-nonce")

        self.assertEqual(len(verification_calls), 1)
        self.assertEqual(verification_calls[0][1], (request.U, request.V, request.W))
        self.assertEqual(verification_calls[0][2:4], (request.target_policy, request.epoch))
        self.assertIs(verification_calls[0][4], altered_signature)
        self.assertEqual(show_calls, [])

    def test_communication_cli_writes_to_explicit_output_directory(self):
        with TemporaryDirectory(prefix="reviewer-communication-") as temporary:
            output_dir = Path(temporary) / "dated-run"
            self.assertEqual(communication_main(["--output-dir", str(output_dir)]), 0)
            self.assertEqual(
                {path.name for path in output_dir.iterdir()},
                {
                    "latest.json",
                    "messages.csv",
                    "role_phase_totals.csv",
                    "source-manifest.json",
                },
            )

    def test_refresh_bypass_diagnostic_and_full_refresh_control(self):
        result = run_diagnostic()
        self.assertTrue(result["diagnostic_only"])
        self.assertTrue(result["refresh_bypassed_x1_equals_issued_response"])
        self.assertTrue(result["refresh_bypassed_vp_verifies"])
        self.assertFalse(result["full_refresh_x1_equals_issued_response"])
        self.assertTrue(result["full_refresh_vp_verifies"])
        self.assertEqual(result["refresh_stub_calls"], ["stubbed"])
        self.assertEqual(result["full_refresh_control_calls"], ["full"])


if __name__ == "__main__":
    unittest.main()
