"""Authorization witness preparation and the fixed complete PPE layout."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .groups import g1_add, g1_identity, g1_mul, g2_identity
from .gs import (
    PPEEquation,
    PPETerm,
    hidden_g1,
    hidden_g2,
    public_g1,
    public_g2,
)
from .hashing import encode_attribute
from .lsss import compile_policy as compile_msp, reconstruction_weights
from .models import CompiledPolicy, IssuerSecretKey, PublicParams
from .policy import Attribute, Policy


@dataclass(frozen=True, repr=False)
class RowWitness:
    R: Any
    Rhat: Any
    S: Any
    G: Any
    tau: Any
    P: Any
    W: tuple[Any, Any, Any]
    B1: Any
    B2: Any
    V: Any

    def __repr__(self) -> str:
        return "RowWitness(<redacted>)"


@dataclass(frozen=True, repr=False)
class PreparedAuthorization:
    compiled_policy: CompiledPolicy
    witness_g1: dict[str, Any]
    witness_g2: dict[str, Any]

    def __repr__(self) -> str:
        return "PreparedAuthorization(<redacted>)"


def compile_policy(policy: Policy) -> CompiledPolicy:
    msp = compile_msp(policy)
    return CompiledPolicy(policy, msp.matrix, msp.labels, msp.rows, msp.columns)


def variable_order(compiled: CompiledPolicy) -> tuple[str, ...]:
    names: list[str] = ["X1", "X2", "X3", "Z", "Y"]
    for row in range(compiled.k):
        prefix = f"row:{row}"
        names.extend((
            f"{prefix}:R", f"{prefix}:Rhat", f"{prefix}:S", f"{prefix}:G",
            f"{prefix}:P", f"{prefix}:tau", f"{prefix}:W1", f"{prefix}:W2",
            f"{prefix}:W3", f"{prefix}:B1", f"{prefix}:B2", f"{prefix}:V",
        ))
    return tuple(names)


def prepare_authorization(
    pp: PublicParams,
    issuer_secret: IssuerSecretKey,
    compiled: CompiledPolicy,
    epoch: int,
) -> PreparedAuthorization:
    credentials = {
        (credential.attribute, credential.epoch): credential
        for credential in issuer_secret.credentials
        if credential.issuer_public_key == issuer_secret.public_key
        # Attribute certificates in this fixture were issued by the RA and
        # installed before timing; the published paper_core run treats them as
        # the issuer's trusted local credentials.
    }
    available = {attribute for attribute, credential_epoch in credentials if credential_epoch == epoch}
    msp = compile_msp(compiled.policy)
    weights = reconstruction_weights(msp, available)
    witness_g1: dict[str, Any] = {}
    witness_g2: dict[str, Any] = {
        f"X{index}": point
        for index, point in enumerate(issuer_secret.public_key.components, 1)
    }
    for row, (attribute, weight) in enumerate(zip(compiled.row_labels, weights)):
        prefix = f"row:{row}"
        selected = weight != 0
        if selected:
            credential = credentials.get((attribute, epoch))
            if credential is None:
                raise ValueError("a nonzero reconstruction row lacks a valid credential")
            R, Rhat, S, G, tau, P = credential.certificate
            W = issuer_secret.public_key.components
            B1, B2 = pp.g1, pp.g2
        else:
            R = Rhat = S = G = P = g2_identity()
            tau = g1_identity()
            W = (g2_identity(), g2_identity(), g2_identity())
            B1, B2 = g1_identity(), g2_identity()
        V = g1_mul(pp.g1, weight)
        witness_g1.update({f"{prefix}:tau": tau, f"{prefix}:B1": B1, f"{prefix}:V": V})
        witness_g2.update({
            f"{prefix}:R": R, f"{prefix}:Rhat": Rhat, f"{prefix}:S": S,
            f"{prefix}:G": G, f"{prefix}:P": P,
            f"{prefix}:W1": W[0], f"{prefix}:W2": W[1], f"{prefix}:W3": W[2],
            f"{prefix}:B2": B2,
        })
    return PreparedAuthorization(compiled, witness_g1, witness_g2)


def build_equations(
    pp: PublicParams,
    compiled: CompiledPolicy,
    representative: tuple[Any, Any, Any],
    gamma: Any,
    epoch: int,
) -> tuple[PPEEquation, ...]:
    q = pp.jr_public_key.elements
    equations: list[PPEEquation] = []
    for row, attribute in enumerate(compiled.row_labels):
        prefix = f"row:{row}"
        for coordinate in range(1, 4):
            equations.append(PPEEquation(
                f"row:{row}:common-X{coordinate}",
                (
                    PPETerm(public_g1(f"row:{row}:common:{coordinate}:g1", pp.g1), hidden_g2(f"{prefix}:W{coordinate}"), 1),
                    PPETerm(hidden_g1(f"{prefix}:B1"), hidden_g2(f"X{coordinate}"), -1),
                ),
            ))
        encoded_attribute = encode_attribute(attribute, epoch)
        q4a_q0 = g1_add(g1_mul(q[3], encoded_attribute), q[8])
        equations.append(PPEEquation(
            f"row:{row}:jr-main",
            tuple(
                PPETerm(public_g1(f"row:{row}:Q{coordinate}", q[coordinate - 1]), hidden_g2(f"{prefix}:W{coordinate}"), 1)
                for coordinate in range(1, 4)
            ) + (
                PPETerm(public_g1(f"row:{row}:Q4aQ0", q4a_q0), hidden_g2(f"{prefix}:B2"), 1),
                PPETerm(public_g1(f"row:{row}:Q5", q[4]), hidden_g2(f"{prefix}:R"), 1),
                PPETerm(public_g1(f"row:{row}:Q6", q[5]), hidden_g2(f"{prefix}:Rhat"), 1),
                PPETerm(public_g1(f"row:{row}:Q7", q[6]), hidden_g2(f"{prefix}:S"), 1),
                PPETerm(public_g1(f"row:{row}:Q8", q[7]), hidden_g2(f"{prefix}:G"), 1),
                PPETerm(public_g1(f"row:{row}:QA", q[9]), hidden_g2(f"{prefix}:P"), -1),
            ),
        ))
        equations.append(PPEEquation(
            f"row:{row}:jr-tag",
            (
                PPETerm(hidden_g1(f"{prefix}:tau"), hidden_g2(f"{prefix}:R"), 1),
                PPETerm(public_g1(f"row:{row}:tag:g1", pp.g1), hidden_g2(f"{prefix}:S"), -1),
            ),
        ))
        equations.append(PPEEquation(
            f"row:{row}:bit-equality",
            (
                PPETerm(hidden_g1(f"{prefix}:B1"), public_g2(f"row:{row}:bit:g2", pp.g2), 1),
                PPETerm(public_g1(f"row:{row}:bit:g1", pp.g1), hidden_g2(f"{prefix}:B2"), -1),
            ),
        ))
        equations.append(PPEEquation(
            f"row:{row}:bit-binary",
            (
                PPETerm(hidden_g1(f"{prefix}:B1"), public_g2(f"row:{row}:binary:g2", pp.g2), 1),
                PPETerm(hidden_g1(f"{prefix}:B1"), hidden_g2(f"{prefix}:B2"), -1),
            ),
        ))
        equations.append(PPEEquation(
            f"row:{row}:support",
            (
                PPETerm(hidden_g1(f"{prefix}:V"), public_g2(f"row:{row}:support:g2", pp.g2), 1),
                PPETerm(hidden_g1(f"{prefix}:V"), hidden_g2(f"{prefix}:B2"), -1),
            ),
        ))
    for column in range(compiled.ell):
        terms = [
            PPETerm(hidden_g1(f"row:{row}:V"), public_g2(f"reconstruct:{column}:g2", pp.g2), compiled.matrix[row][column])
            for row in range(compiled.k)
            if compiled.matrix[row][column]
        ]
        if column == 0:
            terms.append(PPETerm(public_g1("reconstruct:target:g1", pp.g1), public_g2("reconstruct:target:g2", pp.g2), -1))
        equations.append(PPEEquation(f"reconstruct:{column}", tuple(terms)))
    equations.append(PPEEquation(
        "message",
        (
            PPETerm(public_g1("message:N1", representative[0]), hidden_g2("X1"), 1),
            PPETerm(public_g1("message:N2", representative[1]), hidden_g2("X2"), 1),
            PPETerm(public_g1("message:N3", representative[2]), hidden_g2("X3"), 1),
            PPETerm(hidden_g1("Z"), public_g2("message:gamma", gamma), -1),
        ),
    ))
    equations.append(PPEEquation(
        "consistency",
        (
            PPETerm(hidden_g1("Y"), public_g2("consistency:g2", pp.g2), 1),
            PPETerm(public_g1("consistency:g1", pp.g1), public_g2("consistency:gamma", gamma), -1),
        ),
    ))
    return tuple(equations)
