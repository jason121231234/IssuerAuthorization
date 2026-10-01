"""FHS Scheme-1 three-coordinate signing core."""

from __future__ import annotations

from dataclasses import dataclass

from .groups import (
    G1Point,
    G2Point,
    curve_order,
    g1_add,
    g1_mul,
    g2_mul,
    gt_equal,
    gt_identity,
    gt_mul,
    pairing_g1_g2,
    random_scalar,
    scalar_inv,
    validate_g1,
    validate_g2,
)
from .models import IssuerSecretKey, PublicParams


@dataclass(frozen=True, repr=False)
class RawSignature:
    Z: G1Point
    Y: G1Point
    gamma: G2Point

    def __repr__(self) -> str:
        return "RawSignature(<hidden witness>)"


Representative = tuple[G1Point, G1Point, G1Point]


def _validate_representative(representative: Representative) -> None:
    if not isinstance(representative, tuple) or len(representative) != 3:
        raise ValueError("representative must contain three G1 elements")
    for point in representative:
        validate_g1(point)


def sign(
    pp: PublicParams,
    issuer_secret: IssuerSecretKey,
    representative: Representative,
) -> RawSignature:
    _validate_representative(representative)
    order = curve_order()
    base = g1_mul(representative[0], issuer_secret.secret_exponents[0])
    base = g1_add(base, g1_mul(representative[1], issuer_secret.secret_exponents[1]))
    base = g1_add(base, g1_mul(representative[2], issuer_secret.secret_exponents[2]))
    y = random_scalar(nonzero=True)
    inverse = scalar_inv(y)
    return RawSignature(
        g1_mul(base, y),
        g1_mul(pp.g1, inverse),
        g2_mul(pp.g2, inverse),
    )


def verify_raw(
    pp: PublicParams,
    issuer_public_key,
    representative: Representative,
    signature: RawSignature,
) -> bool:
    try:
        _validate_representative(representative)
        validate_g1(signature.Z, allow_identity=True)
        validate_g1(signature.Y)
        validate_g2(signature.gamma)
        left = gt_identity()
        for message, public_component in zip(representative, issuer_public_key.components):
            left = gt_mul(left, pairing_g1_g2(message, public_component))
        if not gt_equal(left, pairing_g1_g2(signature.Z, signature.gamma)):
            return False
        return gt_equal(
            pairing_g1_g2(signature.Y, pp.g2),
            pairing_g1_g2(pp.g1, signature.gamma),
        )
    except (TypeError, ValueError):
        return False


def transform_raw(
    signature: RawSignature,
    *,
    message_scale: int,
    signature_scale: int,
) -> RawSignature:
    """Apply the blind normalization/randomization exponents to a raw witness.

    This helper is used only while constructing tests and issuer-side proofs;
    the holder transforms commitments and proofs without receiving Z or Y.
    """

    order = curve_order()
    message_scale %= order
    signature_scale %= order
    if not message_scale or not signature_scale:
        raise ValueError("signature transformation scales must be nonzero")
    inverse_signature_scale = scalar_inv(signature_scale)
    return RawSignature(
        g1_mul(signature.Z, message_scale * signature_scale % order),
        g1_mul(signature.Y, inverse_signature_scale),
        g2_mul(signature.gamma, inverse_signature_scale),
    )
