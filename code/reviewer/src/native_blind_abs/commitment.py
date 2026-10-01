"""Vector Pedersen commitments for credential content."""

from __future__ import annotations

from typing import Iterable

from .groups import curve_order, g1_add, g1_equal, g1_identity, g1_mul, random_scalar, scalar
from .models import CommitmentOpening, PublicParams


def _message_vector(values: Iterable[int], expected: int) -> tuple[int, ...]:
    result = tuple(values)
    if len(result) != expected:
        raise ValueError(f"message vector must contain exactly {expected} coordinates")
    return tuple(scalar(value) for value in result)


def evaluate_commitment(pp: PublicParams, opening: CommitmentOpening):
    if opening.schema_id != pp.schema.schema_id:
        raise ValueError("opening uses a different schema")
    messages = _message_vector(opening.message, pp.schema.L)
    result = g1_mul(pp.g1, scalar(opening.r))
    for basis, message in zip(pp.schema.bases, messages):
        result = g1_add(result, g1_mul(basis, message))
    return result


def commit(
    pp: PublicParams,
    message_vector: Iterable[int],
    *,
    randomness: int | None = None,
) -> tuple[object, CommitmentOpening]:
    messages = _message_vector(message_vector, pp.schema.L)
    while True:
        r = random_scalar() if randomness is None else scalar(randomness)
        opening = CommitmentOpening(pp.schema.schema_id, r, messages)
        commitment = evaluate_commitment(pp, opening)
        if not g1_equal(commitment, g1_identity()):
            return commitment, opening
        if randomness is not None:
            raise ValueError("explicit randomness produced the identity commitment")


def verify_opening(pp: PublicParams, commitment: object, opening: CommitmentOpening) -> bool:
    try:
        return g1_equal(commitment, evaluate_commitment(pp, opening))
    except (TypeError, ValueError):
        return False


def rerandomize_opening(opening: CommitmentOpening, delta: int) -> CommitmentOpening:
    delta = scalar(delta)
    return CommitmentOpening(
        opening.schema_id,
        (opening.r + delta) % curve_order(),
        opening.message,
    )
