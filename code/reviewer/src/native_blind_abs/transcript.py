"""Canonical transcript encodings shared by Fiat--Shamir proofs and wire code."""

from __future__ import annotations

from .encoding import encode_bytes, encode_sequence, encode_text, encode_u64
from .groups import encode_g1, encode_g2, scalar_bytes
from .models import (
    ABSSignature,
    BlindRequest,
    Credential,
    G1Vec,
    G2Vec,
    OpeningProof,
    RequestProof,
)
from .policy import Policy


def encode_policy_bytes(policy: Policy) -> bytes:
    return policy.canonical_bytes()


def encode_signature(signature: ABSSignature) -> bytes:
    commitment_parts: list[bytes] = []
    for item in signature.commitments.items:
        if isinstance(item.value, G1Vec):
            payload = b"1" + encode_g1(item.value.first, allow_identity=True) + encode_g1(item.value.second, allow_identity=True)
        elif isinstance(item.value, G2Vec):
            payload = b"2" + encode_g2(item.value.first, allow_identity=True) + encode_g2(item.value.second, allow_identity=True)
        else:
            raise TypeError("unsupported GS commitment type")
        commitment_parts.append(encode_text(item.variable_name) + encode_bytes(payload))
    proof_parts = [
        encode_g2(proof.pi1.first, allow_identity=True)
        + encode_g2(proof.pi1.second, allow_identity=True)
        + encode_g2(proof.pi2.first, allow_identity=True)
        + encode_g2(proof.pi2.second, allow_identity=True)
        + encode_g1(proof.theta1.first, allow_identity=True)
        + encode_g1(proof.theta1.second, allow_identity=True)
        + encode_g1(proof.theta2.first, allow_identity=True)
        + encode_g1(proof.theta2.second, allow_identity=True)
        for proof in signature.proofs
    ]
    return (
        b"ABS-NATIVE-BLIND-SIGNATURE-v3"
        + encode_g2(signature.gamma)
        + encode_sequence(commitment_parts)
        + encode_sequence(proof_parts)
    )


def encode_credential(credential: Credential) -> bytes:
    return (
        b"ABS-NATIVE-BLIND-CREDENTIAL-v3"
        + encode_bytes(credential.pp_id)
        + encode_text(credential.schema_id)
        + encode_g1(credential.commitment)
        + encode_bytes(encode_policy_bytes(credential.source_policy))
        + encode_u64(credential.epoch)
        + encode_text(credential.purpose)
        + encode_bytes(encode_signature(credential.signature))
    )


def encode_request_proof(proof: RequestProof) -> bytes:
    return (
        encode_text(proof.schema_id)
        + encode_g1(proof.A0, allow_identity=True)
        + encode_g1(proof.A1, allow_identity=True)
        + encode_g1(proof.A2, allow_identity=True)
        + scalar_bytes(proof.z_r)
        + encode_sequence(scalar_bytes(item) for item in proof.z_message)
        + scalar_bytes(proof.z_s)
        + scalar_bytes(proof.z_t)
    )


def encode_blind_request(request: BlindRequest) -> bytes:
    return (
        b"ABS-NATIVE-BLIND-REQUEST-v3"
        + encode_bytes(request.pp_id)
        + encode_text(request.schema_id)
        + encode_bytes(encode_credential(request.source_credential))
        + encode_bytes(encode_policy_bytes(request.target_policy))
        + encode_u64(request.epoch)
        + encode_text(request.purpose)
        + encode_g1(request.U)
        + encode_g1(request.V)
        + encode_g1(request.W)
        + encode_bytes(encode_request_proof(request.proof))
    )


def encode_opening_proof(proof: OpeningProof) -> bytes:
    return (
        encode_text(proof.schema_id)
        + encode_g1(proof.B, allow_identity=True)
        + scalar_bytes(proof.z_r)
        + encode_sequence(scalar_bytes(item) for item in proof.z_message)
    )
