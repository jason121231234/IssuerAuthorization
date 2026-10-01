"""Schnorr-style request and final opening proofs."""

from __future__ import annotations

from .encoding import encode_bytes, encode_text, encode_u64
from .groups import (
    curve_order,
    encode_g1,
    g1_add,
    g1_equal,
    g1_mul,
    random_scalar,
)
from .hashing import REQUEST_DOMAIN, SHOW_DOMAIN, hash_to_scalar_wide
from .models import (
    ABSSignature,
    CommitmentOpening,
    Credential,
    OpeningProof,
    PublicParams,
    RequestProof,
)
from .policy import Policy
from .transcript import encode_credential, encode_policy_bytes, encode_signature


def _linear_commit(pp: PublicParams, r: int, messages: tuple[int, ...]):
    result = g1_mul(pp.g1, r)
    for basis, message in zip(pp.schema.bases, messages):
        result = g1_add(result, g1_mul(basis, message))
    return result


def request_challenge(
    pp: PublicParams,
    source: Credential,
    target_policy: Policy,
    epoch: int,
    U,
    V,
    W,
    A0,
    A1,
    A2,
) -> int:
    return hash_to_scalar_wide(
        REQUEST_DOMAIN,
        encode_bytes(pp.pp_id),
        encode_bytes(encode_credential(source)),
        encode_bytes(source.source_policy.canonical_bytes()),
        encode_bytes(encode_policy_bytes(target_policy)),
        encode_u64(epoch),
        encode_text("VP"),
        encode_g1(U), encode_g1(V), encode_g1(W),
        encode_g1(A0, allow_identity=True),
        encode_g1(A1, allow_identity=True),
        encode_g1(A2, allow_identity=True),
    )


def prove_request(
    pp: PublicParams,
    source: Credential,
    opening: CommitmentOpening,
    target_policy: Policy,
    epoch: int,
    U,
    V,
    W,
    s: int,
    t: int,
) -> RequestProof:
    order = curve_order()
    alpha_r = random_scalar()
    alpha_messages = tuple(random_scalar() for _ in opening.message)
    alpha_s = random_scalar()
    alpha_t = random_scalar()
    A0 = _linear_commit(pp, alpha_r, alpha_messages)
    A1 = g1_mul(pp.g1, alpha_s)
    A2 = g1_add(g1_mul(source.commitment, alpha_s), g1_mul(pp.g1, alpha_t))
    challenge = request_challenge(pp, source, target_policy, epoch, U, V, W, A0, A1, A2)
    return RequestProof(
        pp.schema.schema_id,
        pp.schema.L,
        A0, A1, A2,
        (alpha_r + challenge * opening.r) % order,
        tuple((alpha + challenge * message) % order for alpha, message in zip(alpha_messages, opening.message)),
        (alpha_s + challenge * s) % order,
        (alpha_t + challenge * t) % order,
    )


def verify_request_proof(
    pp: PublicParams,
    source: Credential,
    target_policy: Policy,
    epoch: int,
    U,
    V,
    W,
    proof: RequestProof,
) -> bool:
    try:
        if proof.schema_id != pp.schema.schema_id or proof.message_length != pp.schema.L:
            return False
        challenge = request_challenge(
            pp, source, target_policy, epoch, U, V, W, proof.A0, proof.A1, proof.A2
        )
        left0 = _linear_commit(pp, proof.z_r, proof.z_message)
        right0 = g1_add(proof.A0, g1_mul(source.commitment, challenge))
        left1 = g1_mul(pp.g1, proof.z_s)
        right1 = g1_add(proof.A1, g1_mul(V, challenge))
        left2 = g1_add(g1_mul(source.commitment, proof.z_s), g1_mul(pp.g1, proof.z_t))
        right2 = g1_add(proof.A2, g1_mul(U, challenge))
        return g1_equal(left0, right0) and g1_equal(left1, right1) and g1_equal(left2, right2)
    except (TypeError, ValueError):
        return False


def opening_challenge(
    pp: PublicParams,
    commitment,
    policy: Policy,
    epoch: int,
    signature: ABSSignature,
    nonce: bytes,
    B,
) -> int:
    return hash_to_scalar_wide(
        SHOW_DOMAIN,
        encode_bytes(pp.pp_id),
        encode_g1(commitment),
        encode_bytes(policy.canonical_bytes()),
        encode_u64(epoch),
        encode_text("VP"),
        encode_bytes(encode_signature(signature)),
        encode_bytes(nonce),
        encode_g1(B, allow_identity=True),
    )


def prove_opening(
    pp: PublicParams,
    commitment,
    opening: CommitmentOpening,
    policy: Policy,
    epoch: int,
    signature: ABSSignature,
    nonce: bytes,
) -> OpeningProof:
    order = curve_order()
    alpha_r = random_scalar()
    alpha_messages = tuple(random_scalar() for _ in opening.message)
    B = _linear_commit(pp, alpha_r, alpha_messages)
    challenge = opening_challenge(pp, commitment, policy, epoch, signature, nonce, B)
    return OpeningProof(
        pp.schema.schema_id,
        pp.schema.L,
        B,
        (alpha_r + challenge * opening.r) % order,
        tuple((alpha + challenge * message) % order for alpha, message in zip(alpha_messages, opening.message)),
    )


def verify_opening_proof(
    pp: PublicParams,
    commitment,
    policy: Policy,
    epoch: int,
    signature: ABSSignature,
    nonce: bytes,
    proof: OpeningProof,
) -> bool:
    try:
        if proof.schema_id != pp.schema.schema_id or proof.message_length != pp.schema.L:
            return False
        challenge = opening_challenge(pp, commitment, policy, epoch, signature, nonce, proof.B)
        left = _linear_commit(pp, proof.z_r, proof.z_message)
        right = g1_add(proof.B, g1_mul(commitment, challenge))
        return g1_equal(left, right)
    except (TypeError, ValueError):
        return False
