"""The existing py_ecc implementation behind the internal backend contract."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from .base import InvalidBackendInput


class PyEccBackend:
    """Lazy adapter for ``py_ecc.optimized_bls12_381`` and its codecs."""

    backend_name = "py_ecc.optimized_bls12_381"

    def __init__(self) -> None:
        self._curve: Any | None = None
        self._codec: Any | None = None
        self._optimized_pairing: Any | None = None

    def _curve_module(self) -> Any:
        if self._curve is None:
            try:
                import py_ecc.optimized_bls12_381 as curve
            except ModuleNotFoundError as exc:
                raise RuntimeError(
                    "py-ecc is required for the BLS12-381 backend; install this project first"
                ) from exc
            self._curve = curve
        return self._curve

    def _codec_module(self) -> Any:
        if self._codec is None:
            try:
                from py_ecc.bls import g2_primitives
            except ModuleNotFoundError as exc:
                raise RuntimeError(
                    "py-ecc is required for canonical BLS12-381 serialization"
                ) from exc
            self._codec = g2_primitives
        return self._codec

    def _optimized_pairing_module(self) -> Any:
        if self._optimized_pairing is None:
            from py_ecc.optimized_bls12_381 import optimized_pairing

            self._optimized_pairing = optimized_pairing
        return self._optimized_pairing

    def curve_order(self) -> int:
        return int(self._curve_module().curve_order)

    def g1_generator(self) -> Any:
        return self._curve_module().G1

    def g2_generator(self) -> Any:
        return self._curve_module().G2

    def g1_identity(self) -> Any:
        return self._curve_module().Z1

    def g2_identity(self) -> Any:
        return self._curve_module().Z2

    def g1_add(self, left: Any, right: Any) -> Any:
        return self._curve_module().add(left, right)

    def g2_add(self, left: Any, right: Any) -> Any:
        return self._curve_module().add(left, right)

    def g1_neg(self, point: Any) -> Any:
        return self._curve_module().neg(point)

    def g2_neg(self, point: Any) -> Any:
        return self._curve_module().neg(point)

    def g1_mul(self, point: Any, exponent: int) -> Any:
        return self._curve_module().multiply(point, exponent)

    def g2_mul(self, point: Any, exponent: int) -> Any:
        return self._curve_module().multiply(point, exponent)

    def g1_is_identity(self, point: Any) -> bool:
        return bool(self._curve_module().is_inf(point))

    def g2_is_identity(self, point: Any) -> bool:
        return bool(self._curve_module().is_inf(point))

    def g1_equal(self, left: Any, right: Any) -> bool:
        curve = self._curve_module()
        return curve.normalize(left) == curve.normalize(right)

    def g2_equal(self, left: Any, right: Any) -> bool:
        curve = self._curve_module()
        return curve.normalize(left) == curve.normalize(right)

    def inspect_g1(self, point: Any) -> tuple[bool, bool, bool]:
        curve = self._curve_module()
        valid = bool(curve.is_on_curve(point, curve.b))
        identity = bool(curve.is_inf(point))
        subgroup = identity or curve.multiply(point, curve.curve_order) == curve.Z1
        return valid, identity, subgroup

    def inspect_g2(self, point: Any) -> tuple[bool, bool, bool]:
        curve = self._curve_module()
        valid = bool(curve.is_on_curve(point, curve.b2))
        identity = bool(curve.is_inf(point))
        subgroup = identity or curve.multiply(point, curve.curve_order) == curve.Z2
        return valid, identity, subgroup

    def encode_g1(self, point: Any) -> bytes:
        return self._codec_module().G1_to_pubkey(point)

    def encode_g2(self, point: Any) -> bytes:
        return self._codec_module().G2_to_signature(point)

    def decode_g1(self, data: bytes) -> Any:
        return self._codec_module().pubkey_to_G1(data)

    def decode_g2(self, data: bytes) -> Any:
        return self._codec_module().signature_to_G2(data)

    def pairing(self, g1_point: Any, g2_point: Any) -> Any:
        return self._curve_module().pairing(
            g2_point, g1_point, final_exponentiate=True
        )

    def pairing_miller(self, g1_point: Any, g2_point: Any) -> Any:
        return self._curve_module().pairing(
            g2_point, g1_point, final_exponentiate=False
        )

    def pairing_product_miller(
        self, terms: list[tuple[Any, Any, int]]
    ) -> Any:
        """Run the existing shared Miller loop for one PPE component."""

        curve = self._curve_module()
        optimized_pairing = self._optimized_pairing_module()
        active: list[tuple[Any, Any, Any, Any, Any]] = []
        order = int(curve.curve_order)
        for g1_point, g2_point, coefficient in terms:
            if not isinstance(coefficient, int) or isinstance(coefficient, bool):
                raise InvalidBackendInput("pairing coefficient must be an integer")
            coefficient %= order
            if coefficient == 0 or curve.is_inf(g1_point) or curve.is_inf(g2_point):
                continue
            if coefficient == 1:
                weighted_g1 = g1_point
            elif coefficient == order - 1:
                weighted_g1 = curve.neg(g1_point)
            else:
                weighted_g1 = curve.multiply(g1_point, coefficient)
            if curve.is_inf(weighted_g1):
                continue
            twist_q = optimized_pairing.twist(g2_point)
            active.append((
                twist_q,
                twist_q,
                optimized_pairing.cast_point_to_fq12(weighted_g1),
                g2_point,
                g2_point,
            ))
        if not active:
            return curve.FQ12.one()

        f_num = curve.FQ12.one()
        f_den = curve.FQ12.one()
        for bit in optimized_pairing.pseudo_binary_encoding[62::-1]:
            double_num = curve.FQ12.one()
            double_den = curve.FQ12.one()
            doubled = []
            for twist_r, twist_q, cast_p, r, q in active:
                numerator, denominator = optimized_pairing.linefunc(
                    twist_r, twist_r, cast_p
                )
                double_num *= numerator
                double_den *= denominator
                r = optimized_pairing.double(r)
                doubled.append((optimized_pairing.twist(r), twist_q, cast_p, r, q))
            f_num = f_num * f_num * double_num
            f_den = f_den * f_den * double_den
            active = doubled
            if bit == 1:
                add_num = curve.FQ12.one()
                add_den = curve.FQ12.one()
                added = []
                for twist_r, twist_q, cast_p, r, q in active:
                    numerator, denominator = optimized_pairing.linefunc(
                        twist_r, twist_q, cast_p
                    )
                    add_num *= numerator
                    add_den *= denominator
                    r = optimized_pairing.add(r, q)
                    added.append((optimized_pairing.twist(r), twist_q, cast_p, r, q))
                f_num *= add_num
                f_den *= add_den
                active = added
        return f_num / f_den

    def pairing_product_is_identity(
        self, terms: list[tuple[Any, Any, int]]
    ) -> bool:
        """Check one weighted PPE without final exponentiation for empty products."""

        curve = self._curve_module()
        order = int(curve.curve_order)
        active: list[tuple[Any, Any, int]] = []
        for g1_point, g2_point, coefficient in terms:
            if not isinstance(coefficient, int) or isinstance(coefficient, bool):
                raise InvalidBackendInput("pairing coefficient must be an integer")
            coefficient %= order
            if (
                coefficient == 0
                or curve.is_inf(g1_point)
                or curve.is_inf(g2_point)
            ):
                continue
            active.append((g1_point, g2_point, coefficient))
        if not active:
            return True

        product = self.pairing_product_miller(active)
        finalized = self.gt_final_exponentiate(product)
        return bool(self.gt_equal(finalized, self.gt_identity()))

    def gt_final_exponentiate(self, value: Any) -> Any:
        return self._curve_module().final_exponentiate(value)

    def gt_identity(self) -> Any:
        return self._curve_module().FQ12.one()

    def gt_equal(self, left: Any, right: Any) -> bool:
        return left == right

    def gt_mul(self, left: Any, right: Any) -> Any:
        return left * right

    def gt_inv(self, value: Any) -> Any:
        return value.inv()

    def gt_pow(self, value: Any, exponent: int) -> Any:
        return value**exponent

    def hash_to_g1(self, message: bytes, dst: bytes) -> Any:
        try:
            from py_ecc.bls.hash_to_curve import hash_to_G1

            return hash_to_G1(message, dst, sha256)
        except (ImportError, AttributeError, ValueError) as exc:
            raise RuntimeError("installed py_ecc lacks RFC 9380 hash-to-G1") from exc

    def hash_to_g2(self, message: bytes, dst: bytes) -> Any:
        try:
            from py_ecc.bls.hash_to_curve import hash_to_G2

            return hash_to_G2(message, dst, sha256)
        except (ImportError, AttributeError, ValueError) as exc:
            raise RuntimeError("installed py_ecc lacks RFC 9380 hash-to-G2") from exc
