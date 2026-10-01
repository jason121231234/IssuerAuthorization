"""Blind VP conversion, unblinding, complete refresh, and presentation."""

from __future__ import annotations

import hashlib
from typing import Callable

from .commitment import rerandomize_opening
from .core import abs_sign, abs_verify, representative_for
from .groups import (
    curve_order,
    g1_add,
    g1_equal,
    g1_is_identity,
    g1_mul,
    g2_mul,
    random_scalar,
    scalar_inv,
)
from .gs import g1v_mul, g2v_mul, refresh
from .hashing import encode_policy
from .models import (
    ABSSignature,
    BlindRequest,
    BlindResponse,
    CheckedBlindRequest,
    Credential,
    GSCommitment,
    GSPPEProof,
    GSPublicCommitments,
    HolderRequestState,
    IssuerSecretKey,
    Presentation,
    PublicParams,
)
from .policy import Policy
from .proofs import prove_opening, prove_request, verify_opening_proof, verify_request_proof
from .relations import build_equations, compile_policy, prepare_authorization
from .transcript import encode_blind_request, encode_credential


class BlindProtocolError(ValueError):
    pass


def vp_request(
    pp: PublicParams,
    source: Credential,
    source_opening,
    target_policy: Policy,
) -> tuple[BlindRequest, HolderRequestState]:
    if source.pp_id != pp.pp_id or source.schema_id != pp.schema.schema_id:
        raise BlindProtocolError("source credential uses different public parameters")
    source_representative = representative_for(
        pp, source.commitment, source.source_policy, source.epoch, "VC"
    )
    while True:
        delta = random_scalar(nonzero=True)
        target_commitment = g1_add(source.commitment, g1_mul(pp.g1, delta))
        if not g1_is_identity(target_commitment) and not g1_equal(target_commitment, source.commitment):
            break
    target_opening = rerandomize_opening(source_opening, delta)
    s = random_scalar(nonzero=True)
    t = s * delta % curve_order()
    U = g1_mul(target_commitment, s)
    V = g1_mul(pp.g1, s)
    j = encode_policy(target_policy, source.epoch, "VP", pp.schema.schema_id)
    W = g1_mul(V, j)
    proof = prove_request(
        pp, source, source_opening, target_policy, source.epoch, U, V, W, s, t
    )
    request = BlindRequest(
        source, target_policy, source.epoch, pp.schema.schema_id, pp.pp_id,
        U, V, W, proof,
    )
    binding = hashlib.sha256(encode_blind_request(request)).digest()
    state = HolderRequestState(
        source_opening, target_commitment, target_opening, s, delta, t, binding
    )
    return request, state


def vp_check_request(
    pp: PublicParams,
    issuer_secret: IssuerSecretKey,
    request: BlindRequest,
    *,
    expected_source: Credential,
    transition_allowed: Callable[[Policy, Policy], bool],
) -> CheckedBlindRequest:
    if request.pp_id != pp.pp_id or request.schema_id != pp.schema.schema_id:
        raise BlindProtocolError("request parameters or schema do not match")
    encode_blind_request(request)  # require canonical encodability on the checked path
    if encode_credential(request.source_credential) != encode_credential(expected_source):
        raise BlindProtocolError("source credential is not in the issuer record")
    if not transition_allowed(request.source_credential.source_policy, request.target_policy):
        raise BlindProtocolError("requested policy transition is not allowed")
    source_rep = representative_for(
        pp,
        request.source_credential.commitment,
        request.source_credential.source_policy,
        request.epoch,
        "VC",
    )
    # The issuer's trusted issuance record is bound by canonical equality above.
    if g1_is_identity(request.U) or g1_is_identity(request.V):
        raise BlindProtocolError("blind representative contains an identity element")
    j = encode_policy(request.target_policy, request.epoch, "VP", pp.schema.schema_id)
    if not g1_equal(request.W, g1_mul(request.V, j)):
        raise BlindProtocolError("W is not bound to V and the target policy")
    if not verify_request_proof(
        pp,
        request.source_credential,
        request.target_policy,
        request.epoch,
        request.U,
        request.V,
        request.W,
        request.proof,
    ):
        raise BlindProtocolError("request proof is invalid")
    compiled = compile_policy(request.target_policy)
    prepare_authorization(pp, issuer_secret, compiled, request.epoch)
    return CheckedBlindRequest(request, compiled, issuer_secret.public_key)


def abs_blind_sign(
    pp: PublicParams,
    issuer_secret: IssuerSecretKey,
    checked: CheckedBlindRequest,
) -> BlindResponse:
    if checked.issuer_public_key != issuer_secret.public_key:
        raise BlindProtocolError("checked request belongs to another issuer key")
    request = checked.request
    signature = abs_sign(
        pp,
        issuer_secret,
        (request.U, request.V, request.W),
        request.target_policy,
        request.epoch,
    )
    return BlindResponse(signature, pp.schema.schema_id, pp.pp_id, request.epoch)


def _scale_proof(proof: GSPPEProof, exponent: int) -> GSPPEProof:
    return GSPPEProof(
        g2v_mul(proof.pi1, exponent),
        g2v_mul(proof.pi2, exponent),
        g1v_mul(proof.theta1, exponent),
        g1v_mul(proof.theta2, exponent),
    )


def abs_unblind(
    pp: PublicParams,
    request: BlindRequest,
    state: HolderRequestState,
    response: BlindResponse,
) -> ABSSignature:
    if hashlib.sha256(encode_blind_request(request)).digest() != state.request_binding:
        raise BlindProtocolError("holder state is bound to another request")
    if request.pp_id != pp.pp_id or request.schema_id != pp.schema.schema_id:
        raise BlindProtocolError("request parameters or schema do not match")
    if response.pp_id != pp.pp_id or response.schema_id != pp.schema.schema_id:
        raise BlindProtocolError("response parameters or schema do not match")
    if response.epoch != request.epoch:
        raise BlindProtocolError("response epoch does not match request")
    if response.purpose != request.purpose:
        raise BlindProtocolError("response purpose does not match request")
    if not abs_verify(
        pp,
        (request.U, request.V, request.W),
        request.target_policy,
        request.epoch,
        response.signature,
    ):
        raise BlindProtocolError("blind response does not verify on the exact request")
    mu = scalar_inv(state.s)
    psi = random_scalar(nonzero=True)
    psi_inverse = scalar_inv(psi)
    scaled_items: list[GSCommitment] = []
    for item in response.signature.commitments.items:
        if item.variable_name == "Z":
            scaled_items.append(GSCommitment("Z", g1v_mul(item.value, psi * mu % curve_order())))
        elif item.variable_name == "Y":
            scaled_items.append(GSCommitment("Y", g1v_mul(item.value, psi_inverse)))
        else:
            scaled_items.append(item)
    proofs = list(response.signature.proofs)
    proofs[-2] = _scale_proof(proofs[-2], mu)
    proofs[-1] = _scale_proof(proofs[-1], psi_inverse)
    gamma = g2_mul(response.signature.gamma, psi_inverse)
    normalized = ABSSignature(gamma, GSPublicCommitments(tuple(scaled_items)), tuple(proofs))
    representative = representative_for(
        pp, state.target_commitment, request.target_policy, request.epoch, "VP"
    )
    compiled = compile_policy(request.target_policy)
    equations = build_equations(pp, compiled, representative, normalized.gamma, request.epoch)
    commitments, refreshed_proofs = refresh(
        pp, equations, normalized.commitments, normalized.proofs
    )
    refreshed = ABSSignature(normalized.gamma, commitments, refreshed_proofs)
    return refreshed


def vp_show(
    pp: PublicParams,
    request: BlindRequest,
    state: HolderRequestState,
    signature: ABSSignature,
    nonce: bytes,
) -> Presentation:
    representative = representative_for(
        pp, state.target_commitment, request.target_policy, request.epoch, "VP"
    )
    proof = prove_opening(
        pp, state.target_commitment, state.target_opening,
        request.target_policy, request.epoch, signature, nonce,
    )
    return Presentation(
        state.target_commitment,
        request.target_policy,
        request.epoch,
        signature,
        pp.schema.schema_id,
        pp.pp_id,
        nonce,
        proof,
    )


def vp_verify(
    pp: PublicParams,
    presentation: Presentation,
    *,
    required_policy: Policy,
    required_epoch: int,
    expected_nonce: bytes,
) -> bool:
    try:
        if presentation.pp_id != pp.pp_id or presentation.schema_id != pp.schema.schema_id:
            return False
        if presentation.target_policy != required_policy or presentation.epoch != required_epoch:
            return False
        if presentation.nonce != expected_nonce:
            return False
        representative = representative_for(
            pp, presentation.commitment, required_policy, required_epoch, "VP"
        )
        if not abs_verify(pp, representative, required_policy, required_epoch, presentation.signature):
            return False
        return verify_opening_proof(
            pp,
            presentation.commitment,
            required_policy,
            required_epoch,
            presentation.signature,
            expected_nonce,
            presentation.opening_proof,
        )
    except (TypeError, ValueError):
        return False
