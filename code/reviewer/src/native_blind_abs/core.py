"""Ordinary native ABS signing and public verification."""

from __future__ import annotations

from typing import Any

from .groups import g1_mul, g2_is_identity
from .gs import prove as gs_prove, verify as gs_verify
from .hashing import encode_policy
from .models import ABSSignature, IssuerSecretKey, PublicParams
from .policy import Policy
from .relations import build_equations, compile_policy, prepare_authorization, variable_order
from .sps_eq import sign as fhs_sign


def representative_for(
    pp: PublicParams,
    commitment: Any,
    policy: Policy,
    epoch: int,
    purpose: str,
) -> tuple[Any, Any, Any]:
    j = encode_policy(policy, epoch, purpose, pp.schema.schema_id)
    return commitment, pp.g1, g1_mul(pp.g1, j)


def abs_sign(
    pp: PublicParams,
    issuer_secret: IssuerSecretKey,
    representative: tuple[Any, Any, Any],
    policy: Policy,
    epoch: int,
) -> ABSSignature:
    compiled = compile_policy(policy)
    prepared = prepare_authorization(pp, issuer_secret, compiled, epoch)
    raw = fhs_sign(pp, issuer_secret, representative)
    equations = build_equations(pp, compiled, representative, raw.gamma, epoch)
    witness_g1 = dict(prepared.witness_g1)
    witness_g1.update({"Z": raw.Z, "Y": raw.Y})
    commitments, proofs = gs_prove(
        pp,
        equations,
        witness_g1,
        prepared.witness_g2,
        variable_order(compiled),
    )
    return ABSSignature(raw.gamma, commitments, proofs)


def abs_verify(
    pp: PublicParams,
    representative: tuple[Any, Any, Any],
    policy: Policy,
    epoch: int,
    signature: ABSSignature,
) -> bool:
    try:
        if len(representative) != 3:
            return False
        if g2_is_identity(signature.gamma):
            return False
        compiled = compile_policy(policy)
        expected_order = variable_order(compiled)
        actual_order = tuple(item.variable_name for item in signature.commitments.items)
        if actual_order != expected_order:
            return False
        equations = build_equations(pp, compiled, representative, signature.gamma, epoch)
        return gs_verify(pp, equations, signature.commitments, signature.proofs)
    except (TypeError, ValueError):
        return False
