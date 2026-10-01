"""Deterministic MSP compilation and finite-field reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .groups import curve_order
from .policy import And, Attr, Attribute, Or, Policy


class ReconstructionError(ValueError):
    pass


@dataclass(frozen=True)
class MSP:
    policy: Policy
    matrix: tuple[tuple[int, ...], ...]
    labels: tuple[Attribute, ...]

    @property
    def rows(self) -> int:
        return len(self.matrix)

    @property
    def columns(self) -> int:
        return len(self.matrix[0]) if self.matrix else 0


def compile_policy(policy: Policy) -> MSP:
    order = curve_order()
    rows: list[list[int]] = []
    labels: list[Attribute] = []
    width = 1

    def pad(vector: list[int]) -> list[int]:
        return vector + [0] * (width - len(vector))

    def visit(node: Policy, vector: list[int]) -> None:
        nonlocal width
        vector = pad(vector)
        if isinstance(node, Attr):
            rows.append(vector)
            labels.append(node.attribute)
            return
        if isinstance(node, Or):
            visit(node.left, vector)
            visit(node.right, pad(vector))
            return
        if isinstance(node, And):
            old_width = width
            width += 1
            parent = vector + [0] * (old_width - len(vector))
            left = parent + [1]
            right = [0] * old_width + [-1]
            visit(node.left, left)
            visit(node.right, pad(right))
            return
        raise TypeError("unsupported policy node")

    visit(policy, [1])
    normalized = tuple(tuple(value % order for value in pad(row)) for row in rows)
    if not normalized:
        raise ReconstructionError("compiled policy has no rows")
    return MSP(policy, normalized, tuple(labels))


def _solve_linear(matrix: list[list[int]], target: list[int], modulus: int) -> list[int]:
    """Solve A x = target over F_p, setting free variables to zero."""

    if len(matrix) != len(target):
        raise ReconstructionError("linear system dimension mismatch")
    columns = len(matrix[0]) if matrix else 0
    if any(len(row) != columns for row in matrix):
        raise ReconstructionError("ragged linear system")
    augmented = [[value % modulus for value in row] + [rhs % modulus]
                 for row, rhs in zip(matrix, target)]
    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(columns):
        candidate = next((r for r in range(pivot_row, len(augmented))
                          if augmented[r][column] % modulus), None)
        if candidate is None:
            continue
        augmented[pivot_row], augmented[candidate] = augmented[candidate], augmented[pivot_row]
        inverse = pow(augmented[pivot_row][column], -1, modulus)
        augmented[pivot_row] = [(value * inverse) % modulus for value in augmented[pivot_row]]
        for row_index, row in enumerate(augmented):
            if row_index == pivot_row:
                continue
            factor = row[column] % modulus
            if factor:
                augmented[row_index] = [
                    (left - factor * right) % modulus
                    for left, right in zip(row, augmented[pivot_row])
                ]
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == len(augmented):
            break
    for row in augmented:
        if all(value % modulus == 0 for value in row[:columns]) and row[-1] % modulus:
            raise ReconstructionError("attribute set does not satisfy policy")
    solution = [0] * columns
    for row_index, column in enumerate(pivot_columns):
        solution[column] = augmented[row_index][-1] % modulus
    if any(
        sum(row[column] * solution[column] for column in range(columns)) % modulus
        != rhs % modulus
        for row, rhs in zip(matrix, target)
    ):
        raise ReconstructionError("failed to reconstruct target vector")
    return solution


def reconstruction_weights(msp: MSP, available: Iterable[Attribute]) -> tuple[int, ...]:
    have = set(available)
    selected = [index for index, label in enumerate(msp.labels) if label in have]
    if not selected:
        raise ReconstructionError("no policy row is available")
    # M_selected^T * v = e1.
    transposed = [
        [msp.matrix[row][column] for row in selected]
        for column in range(msp.columns)
    ]
    target = [1] + [0] * (msp.columns - 1)
    selected_weights = _solve_linear(transposed, target, curve_order())
    weights = [0] * msp.rows
    for row, weight in zip(selected, selected_weights):
        weights[row] = weight
    return tuple(weights)


def reconstructs_target(msp: MSP, weights: Iterable[int]) -> bool:
    values = tuple(weights)
    if len(values) != msp.rows:
        return False
    order = curve_order()
    result = [0] * msp.columns
    for weight, row in zip(values, msp.matrix):
        for column, coefficient in enumerate(row):
            result[column] = (result[column] + weight * coefficient) % order
    return result == [1] + [0] * (msp.columns - 1)
