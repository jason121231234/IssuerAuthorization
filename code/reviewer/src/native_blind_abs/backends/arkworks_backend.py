"""Arkworks G1/G2 and pairing checks with a checked py_ecc boundary.

The two libraries' point handles are never passed directly to one another.
Pairing inputs cross the boundary as canonical compressed G1/G2 encodings and
are checked by both decoders before py_ecc receives them.
"""

from __future__ import annotations

from typing import Any

from .base import InvalidBackendInput
from .py_ecc_backend import PyEccBackend


class ArkworksG1G2Backend:
    """Use Arkworks for G1/G2 and PPE checks; standalone pairing/GT stays py_ecc."""

    backend_name = "arkworks G1/G2 + Arkworks pairing_check; standalone pairing/GT via py_ecc"
    G1_BYTES = 48
    G2_BYTES = 96

    def __init__(self) -> None:
        try:
            from py_arkworks_bls12381 import G1Point, G2Point, GT, Scalar
        except ImportError as exc:
            raise RuntimeError(
                "the arkworks backend requires the 'arkworks' extra; "
                "install with `uv sync --extra arkworks`"
            ) from exc
        self._g1_type = G1Point
        self._g2_type = G2Point
        self._gt_type = GT
        self._scalar_type = Scalar
        self._pairing_backend = PyEccBackend()

    def curve_order(self) -> int:
        return self._pairing_backend.curve_order()

    def g1_generator(self) -> Any:
        return self._g1_type()

    def g2_generator(self) -> Any:
        return self._g2_type()

    def g1_identity(self) -> Any:
        return self._g1_type.identity()

    def g2_identity(self) -> Any:
        return self._g2_type.identity()

    def _require_g1(self, point: Any) -> Any:
        if not isinstance(point, self._g1_type):
            raise InvalidBackendInput("expected an Arkworks G1 point")
        return point

    def _require_g2(self, point: Any) -> Any:
        if not isinstance(point, self._g2_type):
            raise InvalidBackendInput("expected an Arkworks G2 point")
        return point

    def g1_add(self, left: Any, right: Any) -> Any:
        return self._require_g1(left) + self._require_g1(right)

    def g2_add(self, left: Any, right: Any) -> Any:
        return self._require_g2(left) + self._require_g2(right)

    def g1_neg(self, point: Any) -> Any:
        return -self._require_g1(point)

    def g2_neg(self, point: Any) -> Any:
        return -self._require_g2(point)

    def g1_mul(self, point: Any, exponent: int) -> Any:
        return self._require_g1(point) * self._scalar_type(exponent % self.curve_order())

    def g2_mul(self, point: Any, exponent: int) -> Any:
        return self._require_g2(point) * self._scalar_type(exponent % self.curve_order())

    def g1_is_identity(self, point: Any) -> bool:
        return self._require_g1(point) == self.g1_identity()

    def g2_is_identity(self, point: Any) -> bool:
        return self._require_g2(point) == self.g2_identity()

    def g1_equal(self, left: Any, right: Any) -> bool:
        return self._require_g1(left) == self._require_g1(right)

    def g2_equal(self, left: Any, right: Any) -> bool:
        return self._require_g2(left) == self._require_g2(right)

    def inspect_g1(self, point: Any) -> tuple[bool, bool, bool]:
        try:
            point = self._require_g1(point)
            return True, self.g1_is_identity(point), bool(point.is_in_subgroup())
        except Exception:
            return False, False, False

    def inspect_g2(self, point: Any) -> tuple[bool, bool, bool]:
        try:
            point = self._require_g2(point)
            return True, self.g2_is_identity(point), bool(point.is_in_subgroup())
        except Exception:
            return False, False, False

    def encode_g1(self, point: Any) -> bytes:
        encoded = self._require_g1(point).to_compressed_bytes()
        if not isinstance(encoded, bytes) or len(encoded) != self.G1_BYTES:
            raise InvalidBackendInput("Arkworks returned a non-canonical G1 encoding")
        return encoded

    def encode_g2(self, point: Any) -> bytes:
        encoded = self._require_g2(point).to_compressed_bytes()
        if not isinstance(encoded, bytes) or len(encoded) != self.G2_BYTES:
            raise InvalidBackendInput("Arkworks returned a non-canonical G2 encoding")
        return encoded

    def decode_g1(self, data: bytes) -> Any:
        if not isinstance(data, bytes) or len(data) != self.G1_BYTES:
            raise ValueError("G1 encoding must be exactly 48 bytes")
        point = self._g1_type.from_compressed_bytes(data)
        if (
            not point.is_in_subgroup()
            or self.encode_g1(point) != data
        ):
            raise ValueError("invalid or non-canonical compressed G1 encoding")
        return point

    def decode_g2(self, data: bytes) -> Any:
        if not isinstance(data, bytes) or len(data) != self.G2_BYTES:
            raise ValueError("G2 encoding must be exactly 96 bytes")
        point = self._g2_type.from_compressed_bytes(data)
        if (
            not point.is_in_subgroup()
            or self.encode_g2(point) != data
        ):
            raise ValueError("invalid or non-canonical compressed G2 encoding")
        return point

    def _to_py_ecc_g1(self, point: Any) -> Any:
        encoded = self.encode_g1(point)
        native_roundtrip = self._g1_type.from_compressed_bytes(encoded)
        if native_roundtrip != point or self.encode_g1(native_roundtrip) != encoded:
            raise InvalidBackendInput("G1 failed the checked Arkworks encoding round trip")
        converted = self._pairing_backend.decode_g1(encoded)
        valid, _identity, subgroup = self._pairing_backend.inspect_g1(converted)
        if (
            not valid
            or not subgroup
            or self._pairing_backend.encode_g1(converted) != encoded
        ):
            raise InvalidBackendInput("G1 failed the checked py_ecc conversion")
        return converted

    def _to_py_ecc_g2(self, point: Any) -> Any:
        encoded = self.encode_g2(point)
        native_roundtrip = self._g2_type.from_compressed_bytes(encoded)
        if native_roundtrip != point or self.encode_g2(native_roundtrip) != encoded:
            raise InvalidBackendInput("G2 failed the checked Arkworks encoding round trip")
        converted = self._pairing_backend.decode_g2(encoded)
        valid, _identity, subgroup = self._pairing_backend.inspect_g2(converted)
        if (
            not valid
            or not subgroup
            or self._pairing_backend.encode_g2(converted) != encoded
        ):
            raise InvalidBackendInput("G2 failed the checked py_ecc conversion")
        return converted

    def _from_py_ecc_g1(self, point: Any) -> Any:
        encoded = self._pairing_backend.encode_g1(point)
        native = self.decode_g1(encoded)
        if self.encode_g1(native) != encoded:
            raise InvalidBackendInput("G1 failed the checked Arkworks conversion")
        return native

    def _from_py_ecc_g2(self, point: Any) -> Any:
        encoded = self._pairing_backend.encode_g2(point)
        native = self.decode_g2(encoded)
        if self.encode_g2(native) != encoded:
            raise InvalidBackendInput("G2 failed the checked Arkworks conversion")
        return native

    def pairing(self, g1_point: Any, g2_point: Any) -> Any:
        return self._pairing_backend.pairing(
            self._to_py_ecc_g1(g1_point), self._to_py_ecc_g2(g2_point)
        )

    def pairing_miller(self, g1_point: Any, g2_point: Any) -> Any:
        return self._pairing_backend.pairing_miller(
            self._to_py_ecc_g1(g1_point), self._to_py_ecc_g2(g2_point)
        )

    def pairing_product_miller(self, terms: list[tuple[Any, Any, int]]) -> Any:
        order = self.curve_order()
        converted: list[tuple[Any, Any, int]] = []
        for g1_point, g2_point, coefficient in terms:
            if not isinstance(coefficient, int) or isinstance(coefficient, bool):
                raise InvalidBackendInput("pairing coefficient must be an integer")
            coefficient %= order
            if coefficient == 0:
                continue
            if self.g1_is_identity(g1_point) or self.g2_is_identity(g2_point):
                continue
            converted.append((
                self._to_py_ecc_g1(g1_point),
                self._to_py_ecc_g2(g2_point),
                coefficient,
            ))
        return self._pairing_backend.pairing_product_miller(converted)

    def pairing_product_is_identity(
        self, terms: list[tuple[Any, Any, int]]
    ) -> bool:
        order = self.curve_order()
        g1_points: list[Any] = []
        g2_points: list[Any] = []
        for g1_point, g2_point, coefficient in terms:
            if not isinstance(coefficient, int) or isinstance(coefficient, bool):
                raise InvalidBackendInput("pairing coefficient must be an integer")
            coefficient %= order
            if coefficient == 0:
                continue
            if self.g1_is_identity(g1_point) or self.g2_is_identity(g2_point):
                continue
            if coefficient == 1:
                weighted_g1 = g1_point
            elif coefficient == order - 1:
                weighted_g1 = self.g1_neg(g1_point)
            else:
                weighted_g1 = self.g1_mul(g1_point, coefficient)
            if self.g1_is_identity(weighted_g1):
                continue
            g1_points.append(weighted_g1)
            g2_points.append(g2_point)
        if not g1_points:
            return True
        return bool(self._gt_type.pairing_check(g1_points, g2_points))

    def gt_final_exponentiate(self, value: Any) -> Any:
        return self._pairing_backend.gt_final_exponentiate(value)

    def gt_identity(self) -> Any:
        return self._pairing_backend.gt_identity()

    def gt_equal(self, left: Any, right: Any) -> bool:
        return self._pairing_backend.gt_equal(left, right)

    def gt_mul(self, left: Any, right: Any) -> Any:
        return self._pairing_backend.gt_mul(left, right)

    def gt_inv(self, value: Any) -> Any:
        return self._pairing_backend.gt_inv(value)

    def gt_pow(self, value: Any, exponent: int) -> Any:
        return self._pairing_backend.gt_pow(value, exponent)

    def hash_to_g1(self, message: bytes, dst: bytes) -> Any:
        return self._from_py_ecc_g1(self._pairing_backend.hash_to_g1(message, dst))

    def hash_to_g2(self, message: bytes, dst: bytes) -> Any:
        return self._from_py_ecc_g2(self._pairing_backend.hash_to_g2(message, dst))
