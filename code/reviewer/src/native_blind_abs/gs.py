"""Complete Groth--Sahai PPE proofs and witness-free refresh.

The implementation follows the two-dimensional complete proof equations in
the project specification.  Equations are sparse and keep public operand slots
distinct even when two slots contain the same group element.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .groups import (
    curve_order,
    g1_add_trusted,
    g1_identity,
    g1_mul_trusted,
    g2_add_trusted,
    g2_identity,
    g2_mul_trusted,
    gt_identity,
    gt_inv,
    gt_mul,
    pairing_miller_trusted,
    pairing_product_is_identity,
    random_scalar,
)
from .models import (
    G1Vec,
    G2Vec,
    GSCommitment,
    GSPPEProof,
    GSPublicCommitments,
    PublicParams,
)


class GSError(ValueError):
    pass


@dataclass(frozen=True)
class G1Operand:
    slot: str
    variable: str | None = None
    point: Any | None = None

    def __post_init__(self) -> None:
        if bool(self.variable is None) == bool(self.point is None):
            raise GSError("a G1 operand must be exactly one of hidden or public")


@dataclass(frozen=True)
class G2Operand:
    slot: str
    variable: str | None = None
    point: Any | None = None

    def __post_init__(self) -> None:
        if bool(self.variable is None) == bool(self.point is None):
            raise GSError("a G2 operand must be exactly one of hidden or public")


@dataclass(frozen=True)
class PPETerm:
    left: G1Operand
    right: G2Operand
    coefficient: int


@dataclass(frozen=True)
class PPEEquation:
    label: str
    terms: tuple[PPETerm, ...]

    def __post_init__(self) -> None:
        if not self.label or not self.terms:
            raise GSError("PPE equation must have a label and at least one term")


@dataclass(frozen=True, repr=False)
class GSProverState:
    g1_masks: Mapping[str, tuple[int, int]]
    g2_masks: Mapping[str, tuple[int, int]]

    def __repr__(self) -> str:
        return "GSProverState(<redacted>)"


def hidden_g1(name: str) -> G1Operand:
    return G1Operand(name, variable=name)


def hidden_g2(name: str) -> G2Operand:
    return G2Operand(name, variable=name)


def public_g1(slot: str, point: Any) -> G1Operand:
    return G1Operand(slot, point=point)


def public_g2(slot: str, point: Any) -> G2Operand:
    return G2Operand(slot, point=point)


def _g1v_identity() -> G1Vec:
    return G1Vec(g1_identity(), g1_identity())


def _g2v_identity() -> G2Vec:
    return G2Vec(g2_identity(), g2_identity())


def g1v_add(left: G1Vec, right: G1Vec) -> G1Vec:
    return G1Vec(g1_add_trusted(left.first, right.first), g1_add_trusted(left.second, right.second))


def g2v_add(left: G2Vec, right: G2Vec) -> G2Vec:
    return G2Vec(g2_add_trusted(left.first, right.first), g2_add_trusted(left.second, right.second))


def g1v_mul(value: G1Vec, exponent: int) -> G1Vec:
    exponent %= curve_order()
    return G1Vec(g1_mul_trusted(value.first, exponent), g1_mul_trusted(value.second, exponent))


def g2v_mul(value: G2Vec, exponent: int) -> G2Vec:
    exponent %= curve_order()
    return G2Vec(g2_mul_trusted(value.first, exponent), g2_mul_trusted(value.second, exponent))


def iota1(point: Any) -> G1Vec:
    return G1Vec(g1_identity(), point)


def iota2(point: Any) -> G2Vec:
    return G2Vec(g2_identity(), point)


def commit_g1(pp: PublicParams, point: Any, r: int, s: int) -> G1Vec:
    return g1v_add(iota1(point), g1v_add(
        g1v_mul(pp.gs_public_key.v1, r), g1v_mul(pp.gs_public_key.w1, s)
    ))


def commit_g2(pp: PublicParams, point: Any, t: int, u: int) -> G2Vec:
    return g2v_add(iota2(point), g2v_add(
        g2v_mul(pp.gs_public_key.v2, t), g2v_mul(pp.gs_public_key.w2, u)
    ))


def _commitment_dict(commitments: GSPublicCommitments) -> dict[str, G1Vec | G2Vec]:
    return {item.variable_name: item.value for item in commitments.items}


def _equation_operands(equation: PPEEquation):
    left: dict[str, G1Operand] = {}
    right: dict[str, G2Operand] = {}
    gamma: dict[tuple[str, str], int] = {}
    order = curve_order()
    for term in equation.terms:
        prior_left = left.setdefault(term.left.slot, term.left)
        prior_right = right.setdefault(term.right.slot, term.right)
        if prior_left != term.left or prior_right != term.right:
            raise GSError("one equation reused an operand slot inconsistently")
        key = (term.left.slot, term.right.slot)
        gamma[key] = (gamma.get(key, 0) + term.coefficient) % order
    gamma = {key: value for key, value in gamma.items() if value}
    return left, right, gamma


def _actual_g1(operand: G1Operand, witness: Mapping[str, Any]):
    return witness[operand.variable] if operand.variable is not None else operand.point


def _actual_g2(operand: G2Operand, witness: Mapping[str, Any]):
    return witness[operand.variable] if operand.variable is not None else operand.point


def _committed_g1(operand: G1Operand, commitments: Mapping[str, G1Vec | G2Vec]) -> G1Vec:
    if operand.variable is None:
        return iota1(operand.point)
    value = commitments.get(operand.variable)
    if not isinstance(value, G1Vec):
        raise GSError(f"missing G1 commitment for {operand.variable}")
    return value


def _committed_g2(operand: G2Operand, commitments: Mapping[str, G1Vec | G2Vec]) -> G2Vec:
    if operand.variable is None:
        return iota2(operand.point)
    value = commitments.get(operand.variable)
    if not isinstance(value, G2Vec):
        raise GSError(f"missing G2 commitment for {operand.variable}")
    return value


def _prove_equation(
    pp: PublicParams,
    equation: PPEEquation,
    witness_g1: Mapping[str, Any],
    witness_g2: Mapping[str, Any],
    commitments: Mapping[str, G1Vec | G2Vec],
    state: GSProverState,
) -> GSPPEProof:
    left, right, gamma = _equation_operands(equation)
    order = curve_order()
    alpha, beta, chi, delta = (random_scalar() for _ in range(4))
    pi1 = _g2v_identity()
    pi2 = _g2v_identity()
    for right_slot, right_operand in right.items():
        coefficient_r = 0
        coefficient_s = 0
        for left_slot, left_operand in left.items():
            coefficient = gamma.get((left_slot, right_slot), 0)
            if not coefficient:
                continue
            r, s = state.g1_masks.get(left_operand.variable, (0, 0))
            coefficient_r = (coefficient_r + r * coefficient) % order
            coefficient_s = (coefficient_s + s * coefficient) % order
        committed = _committed_g2(right_operand, commitments)
        pi1 = g2v_add(pi1, g2v_mul(committed, coefficient_r))
        pi2 = g2v_add(pi2, g2v_mul(committed, coefficient_s))
    pi1 = g2v_add(pi1, g2v_add(g2v_mul(pp.gs_public_key.v2, alpha), g2v_mul(pp.gs_public_key.w2, beta)))
    pi2 = g2v_add(pi2, g2v_add(g2v_mul(pp.gs_public_key.v2, chi), g2v_mul(pp.gs_public_key.w2, delta)))

    theta1 = _g1v_identity()
    theta2 = _g1v_identity()
    for left_slot, left_operand in left.items():
        coefficient_t = 0
        coefficient_u = 0
        for right_slot, right_operand in right.items():
            coefficient = gamma.get((left_slot, right_slot), 0)
            if not coefficient:
                continue
            t, u = state.g2_masks.get(right_operand.variable, (0, 0))
            coefficient_t = (coefficient_t + coefficient * t) % order
            coefficient_u = (coefficient_u + coefficient * u) % order
        embedded = iota1(_actual_g1(left_operand, witness_g1))
        theta1 = g1v_add(theta1, g1v_mul(embedded, coefficient_t))
        theta2 = g1v_add(theta2, g1v_mul(embedded, coefficient_u))
    theta1 = g1v_add(theta1, g1v_add(g1v_mul(pp.gs_public_key.v1, -alpha), g1v_mul(pp.gs_public_key.w1, -chi)))
    theta2 = g1v_add(theta2, g1v_add(g1v_mul(pp.gs_public_key.v1, -beta), g1v_mul(pp.gs_public_key.w1, -delta)))
    return GSPPEProof(pi1, pi2, theta1, theta2)


def prove(
    pp: PublicParams,
    equations: tuple[PPEEquation, ...],
    witness_g1: Mapping[str, Any],
    witness_g2: Mapping[str, Any],
    variable_order: tuple[str, ...],
) -> tuple[GSPublicCommitments, tuple[GSPPEProof, ...]]:
    required_g1 = {term.left.variable for eq in equations for term in eq.terms if term.left.variable}
    required_g2 = {term.right.variable for eq in equations for term in eq.terms if term.right.variable}
    if set(witness_g1) != required_g1 or set(witness_g2) != required_g2:
        raise GSError("witness variable set does not match relation")
    if set(variable_order) != required_g1 | required_g2:
        raise GSError("variable order does not match relation")
    g1_masks = {name: (random_scalar(), random_scalar()) for name in required_g1}
    g2_masks = {name: (random_scalar(), random_scalar()) for name in required_g2}
    values: dict[str, G1Vec | G2Vec] = {}
    for name, point in witness_g1.items():
        values[name] = commit_g1(pp, point, *g1_masks[name])
    for name, point in witness_g2.items():
        values[name] = commit_g2(pp, point, *g2_masks[name])
    commitments = GSPublicCommitments(tuple(GSCommitment(name, values[name]) for name in variable_order))
    state = GSProverState(g1_masks, g2_masks)
    proofs = tuple(
        _prove_equation(pp, equation, witness_g1, witness_g2, values, state)
        for equation in equations
    )
    return commitments, proofs


def _matrix_identity():
    identity = gt_identity()
    return (identity, identity, identity, identity)


def _matrix_mul(left, right):
    return tuple(gt_mul(a, b) for a, b in zip(left, right))


def _matrix_pow(value, exponent: int):
    order = curve_order()
    exponent %= order
    if exponent > order // 2:
        return tuple(gt_inv(item) ** (order - exponent) for item in value)
    return tuple(item ** exponent for item in value)


def _pair_matrix(left: G1Vec, right: G2Vec):
    return (
        pairing_miller_trusted(left.first, right.first),
        pairing_miller_trusted(left.first, right.second),
        pairing_miller_trusted(left.second, right.first),
        pairing_miller_trusted(left.second, right.second),
    )


def _append_pair_matrix_terms(target, left: G1Vec, right: G2Vec, coefficient: int) -> None:
    for index, (g1_point, g2_point) in enumerate((
        (left.first, right.first),
        (left.first, right.second),
        (left.second, right.first),
        (left.second, right.second),
    )):
        target[index].append((g1_point, g2_point, coefficient))


def verify_equation(
    pp: PublicParams,
    equation: PPEEquation,
    commitments: GSPublicCommitments,
    proof: GSPPEProof,
) -> bool:
    try:
        left_operands, right_operands, gamma = _equation_operands(equation)
        committed = _commitment_dict(commitments)
        component_terms: list[list[tuple[Any, Any, int]]] = [[], [], [], []]
        for (left_slot, right_slot), coefficient in gamma.items():
            c = _committed_g1(left_operands[left_slot], committed)
            d = _committed_g2(right_operands[right_slot], committed)
            _append_pair_matrix_terms(component_terms, c, d, coefficient)
        # Each PPE matrix component gets its own multi-Miller loop and final
        # exponentiation. In particular, no terms from separate PPE equations
        # are ever combined into one check.
        for left, right in (
            (pp.gs_public_key.v1, proof.pi1),
            (pp.gs_public_key.w1, proof.pi2),
            (proof.theta1, pp.gs_public_key.v2),
            (proof.theta2, pp.gs_public_key.w2),
        ):
            _append_pair_matrix_terms(component_terms, left, right, -1)
        # Keep all four matrix components as separate PPE checks. The backend
        # may optimize each equation internally, but components are never mixed.
        return all(pairing_product_is_identity(terms) for terms in component_terms)
    except (KeyError, TypeError, ValueError):
        return False


def verify(
    pp: PublicParams,
    equations: tuple[PPEEquation, ...],
    commitments: GSPublicCommitments,
    proofs: tuple[GSPPEProof, ...],
) -> bool:
    if len(equations) != len(proofs):
        return False
    try:
        for item in commitments.items:
            if not isinstance(item.value, (G1Vec, G2Vec)):
                return False
    except (TypeError, ValueError):
        return False
    return all(
        verify_equation(pp, equation, commitments, proof)
        for equation, proof in zip(equations, proofs)
    )


def refresh(
    pp: PublicParams,
    equations: tuple[PPEEquation, ...],
    commitments: GSPublicCommitments,
    proofs: tuple[GSPPEProof, ...],
) -> tuple[GSPublicCommitments, tuple[GSPPEProof, ...]]:
    if len(equations) != len(proofs):
        raise GSError("equation and proof counts differ")
    old = _commitment_dict(commitments)
    delta_g1: dict[str, tuple[int, int]] = {}
    delta_g2: dict[str, tuple[int, int]] = {}
    new: dict[str, G1Vec | G2Vec] = {}
    for item in commitments.items:
        if isinstance(item.value, G1Vec):
            increment = (random_scalar(), random_scalar())
            delta_g1[item.variable_name] = increment
            new[item.variable_name] = g1v_add(item.value, g1v_add(
                g1v_mul(pp.gs_public_key.v1, increment[0]),
                g1v_mul(pp.gs_public_key.w1, increment[1]),
            ))
        elif isinstance(item.value, G2Vec):
            increment = (random_scalar(), random_scalar())
            delta_g2[item.variable_name] = increment
            new[item.variable_name] = g2v_add(item.value, g2v_add(
                g2v_mul(pp.gs_public_key.v2, increment[0]),
                g2v_mul(pp.gs_public_key.w2, increment[1]),
            ))
        else:
            raise GSError("unknown commitment group")
    refreshed_proofs: list[GSPPEProof] = []
    order = curve_order()
    for equation, proof in zip(equations, proofs):
        left, right, gamma = _equation_operands(equation)
        pi1, pi2, theta1, theta2 = proof.pi1, proof.pi2, proof.theta1, proof.theta2
        for right_slot, right_operand in right.items():
            a_sum = 0
            b_sum = 0
            for left_slot, left_operand in left.items():
                coefficient = gamma.get((left_slot, right_slot), 0)
                a, b = delta_g1.get(left_operand.variable, (0, 0))
                a_sum = (a_sum + a * coefficient) % order
                b_sum = (b_sum + b * coefficient) % order
            committed = _committed_g2(right_operand, new)
            pi1 = g2v_add(pi1, g2v_mul(committed, a_sum))
            pi2 = g2v_add(pi2, g2v_mul(committed, b_sum))
        for left_slot, left_operand in left.items():
            c_sum = 0
            d_sum = 0
            for right_slot, right_operand in right.items():
                coefficient = gamma.get((left_slot, right_slot), 0)
                c, d = delta_g2.get(right_operand.variable, (0, 0))
                c_sum = (c_sum + coefficient * c) % order
                d_sum = (d_sum + coefficient * d) % order
            committed = _committed_g1(left_operand, old)
            theta1 = g1v_add(theta1, g1v_mul(committed, c_sum))
            theta2 = g1v_add(theta2, g1v_mul(committed, d_sum))
        alpha, beta, chi, delta = (random_scalar() for _ in range(4))
        pi1 = g2v_add(pi1, g2v_add(g2v_mul(pp.gs_public_key.v2, alpha), g2v_mul(pp.gs_public_key.w2, beta)))
        pi2 = g2v_add(pi2, g2v_add(g2v_mul(pp.gs_public_key.v2, chi), g2v_mul(pp.gs_public_key.w2, delta)))
        theta1 = g1v_add(theta1, g1v_add(g1v_mul(pp.gs_public_key.v1, -alpha), g1v_mul(pp.gs_public_key.w1, -chi)))
        theta2 = g1v_add(theta2, g1v_add(g1v_mul(pp.gs_public_key.v1, -beta), g1v_mul(pp.gs_public_key.w1, -delta)))
        refreshed_proofs.append(GSPPEProof(pi1, pi2, theta1, theta2))
    refreshed_commitments = GSPublicCommitments(tuple(
        GSCommitment(item.variable_name, new[item.variable_name]) for item in commitments.items
    ))
    return refreshed_commitments, tuple(refreshed_proofs)
