"""Stable group-operation interface for the native blind ABS Type-III backend.

Protocol modules use these helpers and never depend on a concrete backend.
Backend loading remains lazy so source-only tooling can inspect the package
before installing its curve dependency.
"""

from __future__ import annotations

import secrets
from typing import Any

from .backends import get_backend
from .backends.base import InvalidBackendInput
GROUP_ID = "BLS12-381-G1-G2-OPTIMIZED-NATIVE-BLIND-v3"
SCALAR_BYTES = 32
G1_BYTES = 48
G2_BYTES = 96

G1Point = Any
G2Point = Any
GTElement = Any


class GroupError(ValueError):
    """Raised when a group element or scalar is invalid."""


def _backend() -> Any:
    return get_backend()


def curve_order() -> int:
    return _backend().curve_order()


def scalar(value: int, *, nonzero: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise GroupError("scalar must be an integer")
    order = curve_order()
    if not 0 <= value < order:
        raise GroupError("scalar is not canonical modulo the curve order")
    if nonzero and value == 0:
        raise GroupError("scalar must be nonzero")
    return value


def scalar_bytes(value: int) -> bytes:
    return scalar(value).to_bytes(SCALAR_BYTES, "big")


def random_scalar(*, nonzero: bool = False) -> int:
    order = curve_order()
    while True:
        value = secrets.randbelow(order)
        if value or not nonzero:
            return value


def scalar_inv(value: int) -> int:
    value = scalar(value, nonzero=True)
    return pow(value, -1, curve_order())


def g1_generator() -> G1Point:
    return _backend().g1_generator()


def g2_generator() -> G2Point:
    return _backend().g2_generator()


def g1_identity() -> G1Point:
    return _backend().g1_identity()


def g2_identity() -> G2Point:
    return _backend().g2_identity()


def _check_encoded_g1(point: G1Point, *, allow_identity: bool) -> None:
    try:
        identity = _backend().g1_is_identity(point)
    except Exception as exc:
        raise GroupError("malformed G1 point") from exc
    if identity and not allow_identity:
        raise GroupError("G1 identity element is not permitted here")


def _check_encoded_g2(point: G2Point, *, allow_identity: bool) -> None:
    try:
        identity = _backend().g2_is_identity(point)
    except Exception as exc:
        raise GroupError("malformed G2 point") from exc
    if identity and not allow_identity:
        raise GroupError("G2 identity element is not permitted here")


def g1_add(left: G1Point, right: G1Point) -> G1Point:
    return _backend().g1_add(left, right)


def g2_add(left: G2Point, right: G2Point) -> G2Point:
    return _backend().g2_add(left, right)


def g1_mul(point: G1Point, exponent: int) -> G1Point:
    scalar(exponent)
    return _backend().g1_mul(point, exponent)


def g2_mul(point: G2Point, exponent: int) -> G2Point:
    scalar(exponent)
    return _backend().g2_mul(point, exponent)


def g1_add_trusted(left: G1Point, right: G1Point) -> G1Point:
    """Internal arithmetic after the public boundary validated both operands."""

    return _backend().g1_add(left, right)


def g2_add_trusted(left: G2Point, right: G2Point) -> G2Point:
    """Internal arithmetic after the public boundary validated both operands."""

    return _backend().g2_add(left, right)


def g1_mul_trusted(point: G1Point, exponent: int) -> G1Point:
    return _backend().g1_mul(point, exponent % curve_order())


def g2_mul_trusted(point: G2Point, exponent: int) -> G2Point:
    return _backend().g2_mul(point, exponent % curve_order())


def g1_neg(point: G1Point) -> G1Point:
    return _backend().g1_neg(point)


def g2_neg(point: G2Point) -> G2Point:
    return _backend().g2_neg(point)


def g1_is_identity(point: G1Point) -> bool:
    return _backend().g1_is_identity(point)


def g2_is_identity(point: G2Point) -> bool:
    return _backend().g2_is_identity(point)


def g1_equal(left: G1Point, right: G1Point) -> bool:
    return _backend().g1_equal(left, right)


def g2_equal(left: G2Point, right: G2Point) -> bool:
    return _backend().g2_equal(left, right)


def validate_g1(point: G1Point, *, allow_identity: bool = False) -> G1Point:
    try:
        valid, identity, subgroup = _backend().inspect_g1(point)
    except Exception as exc:
        raise GroupError("malformed G1 point") from exc
    if not valid or not subgroup or (identity and not allow_identity):
        raise GroupError("G1 point failed curve, subgroup, or identity validation")
    return point


def validate_g2(point: G2Point, *, allow_identity: bool = False) -> G2Point:
    try:
        valid, identity, subgroup = _backend().inspect_g2(point)
    except Exception as exc:
        raise GroupError("malformed G2 point") from exc
    if not valid or not subgroup or (identity and not allow_identity):
        raise GroupError("G2 point failed curve, subgroup, or identity validation")
    return point


def encode_g1(point: G1Point, *, allow_identity: bool = False) -> bytes:
    _check_encoded_g1(point, allow_identity=allow_identity)
    try:
        encoded = _backend().encode_g1(point)
    except (AttributeError, TypeError, ValueError) as exc:
        raise GroupError("unable to encode G1 point") from exc
    if not isinstance(encoded, bytes) or len(encoded) != G1_BYTES:
        raise GroupError("backend returned a non-canonical G1 encoding")
    return encoded


def encode_g2(point: G2Point, *, allow_identity: bool = False) -> bytes:
    _check_encoded_g2(point, allow_identity=allow_identity)
    try:
        encoded = _backend().encode_g2(point)
    except (AttributeError, TypeError, ValueError) as exc:
        raise GroupError("unable to encode G2 point") from exc
    if not isinstance(encoded, bytes) or len(encoded) != G2_BYTES:
        raise GroupError("backend returned a non-canonical G2 encoding")
    return encoded


def pairing_g1_g2(g1_point: G1Point, g2_point: G2Point) -> GTElement:
    return _backend().pairing(g1_point, g2_point)


def pairing_miller_trusted(g1_point: G1Point, g2_point: G2Point) -> GTElement:
    """Unfinalized internal pairing after callers validate public inputs once."""

    return _backend().pairing_miller(g1_point, g2_point)


def pairing_product_miller_trusted(
    terms: list[tuple[G1Point, G2Point, int]],
) -> GTElement:
    """Return one unfinalized Miller product for weighted pairing terms.

    The shared loop is scoped to the caller's single PPE component. Coefficients
    are moved to G1 before Miller evaluation; the result is therefore equivalent
    to the weighted product after final exponentiation, which is the pairing
    equation semantics. The active backend preserves this shared-loop
    implementation and its per-equation scope.
    """

    try:
        return _backend().pairing_product_miller(terms)
    except InvalidBackendInput as exc:
        raise GroupError(str(exc)) from exc


def pairing_product_is_identity(
    terms: list[tuple[G1Point, G2Point, int]],
) -> bool:
    """Check one PPE: ``product(e(P, Q) ** c) == 1``.

    This semantic interface lets a backend use a native pairing-check API while
    keeping callers independent of Miller-loop and GT representation details.
    The caller must keep each GS matrix component in a separate invocation.
    """

    try:
        return _backend().pairing_product_is_identity(terms)
    except InvalidBackendInput as exc:
        raise GroupError(str(exc)) from exc


def gt_final_exponentiate(value: GTElement) -> GTElement:
    return _backend().gt_final_exponentiate(value)


def gt_identity() -> GTElement:
    return _backend().gt_identity()


def gt_equal(left: GTElement, right: GTElement) -> bool:
    return _backend().gt_equal(left, right)


def gt_mul(left: GTElement, right: GTElement) -> GTElement:
    return _backend().gt_mul(left, right)


def gt_inv(value: GTElement) -> GTElement:
    return _backend().gt_inv(value)


def gt_pow(value: GTElement, exponent: int) -> GTElement:
    scalar(exponent)
    return _backend().gt_pow(value, exponent)


def hash_to_g1(message: bytes, dst: bytes) -> G1Point:
    """RFC 9380 hash-to-G1 using py_ecc's explicit SHA-256 ciphersuite."""

    if not isinstance(message, bytes) or not isinstance(dst, bytes):
        raise TypeError("hash input and DST must be bytes")
    if not dst or len(dst) > 255:
        raise GroupError("DST must contain 1..255 bytes")
    try:
        point = _backend().hash_to_g1(message, dst)
    except (ImportError, AttributeError, ValueError) as exc:
        raise RuntimeError("installed py-ecc lacks RFC 9380 hash-to-G1") from exc
    return validate_g1(point)


def hash_to_g2(message: bytes, dst: bytes) -> G2Point:
    """RFC 9380 hash-to-G2 using py_ecc's explicit SHA-256 ciphersuite."""

    if not isinstance(message, bytes) or not isinstance(dst, bytes):
        raise TypeError("hash input and DST must be bytes")
    if not dst or len(dst) > 255:
        raise GroupError("DST must contain 1..255 bytes")
    try:
        point = _backend().hash_to_g2(message, dst)
    except (ImportError, AttributeError, ValueError) as exc:
        raise RuntimeError("installed py-ecc lacks RFC 9380 hash-to-G2") from exc
    return validate_g2(point)


def random_g1(*, nonidentity: bool = True) -> G1Point:
    return g1_mul(g1_generator(), random_scalar(nonzero=nonidentity))


def random_g2(*, nonidentity: bool = True) -> G2Point:
    return g2_mul(g2_generator(), random_scalar(nonzero=nonidentity))


# Stable adapter spellings used by later protocol layers.  Keep the
# implementation names above explicit; these aliases are intentionally thin
# and do not create a second serialization or pairing convention.
serialize_g1 = encode_g1
serialize_g2 = encode_g2
pairing = pairing_g1_g2
gt_identity = gt_identity
gt_equal = gt_equal
gt_mul = gt_mul
gt_inv = gt_inv
gt_pow = gt_pow


def __getattr__(name: str) -> Any:
    # ORDER is exposed lazily because importing this package is allowed before
    # the optional py-ecc runtime has been installed.
    if name == "ORDER":
        return curve_order()
    raise AttributeError(name)
