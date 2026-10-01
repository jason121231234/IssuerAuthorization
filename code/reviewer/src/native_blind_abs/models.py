"""Immutable data models for the native blind ABS protocol.

This module defines protocol containers only.  Group elements and policy
objects are deliberately typed as ``Any``; validation of their mathematics,
encodings, and authorization relations belongs to protocol operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class ModelError(ValueError):
    """Raised when a native blind ABS model has an invalid shape or label."""


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ModelError(f"{name} must be non-empty NUL-free text")
    return value


def _bytes(value: object, name: str) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise ModelError(f"{name} must be non-empty bytes")
    return value


def _tuple(value: object, name: str) -> tuple[Any, ...]:
    if not isinstance(value, tuple):
        raise ModelError(f"{name} must be a tuple")
    return value


def _integer(value: object, name: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ModelError(f"{name} must be an integer >= {minimum}")
    return value


def _purpose(value: object, expected: str | None = None) -> str:
    if value not in ("VC", "VP"):
        raise ModelError("purpose must be 'VC' or 'VP'")
    if expected is not None and value != expected:
        raise ModelError(f"purpose must be {expected!r}")
    return value


def _private_tuple(value: object, name: str, *, nonempty: bool = True) -> tuple[Any, ...]:
    result = _tuple(value, name)
    if nonempty and not result:
        raise ModelError(f"{name} must not be empty")
    return result


class _PrivateModel:
    """Base repr for secret-bearing containers."""

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


@dataclass(frozen=True)
class Schema:
    schema_id: str
    field_names: tuple[str, ...]
    encoding_version: str
    bases: tuple[Any, ...]

    def __post_init__(self) -> None:
        _text(self.schema_id, "schema_id")
        _text(self.encoding_version, "encoding_version")
        fields = _tuple(self.field_names, "field_names")
        bases = _tuple(self.bases, "bases")
        if not fields or len(fields) != len(bases):
            raise ModelError("schema must have one basis for each non-empty field list")
        for field in fields:
            _text(field, "field name")
        if len(set(fields)) != len(fields):
            raise ModelError("schema field names must be unique")

    @property
    def L(self) -> int:
        return len(self.field_names)


@dataclass(frozen=True)
class G1Vec:
    first: Any
    second: Any


@dataclass(frozen=True)
class G2Vec:
    first: Any
    second: Any


@dataclass(frozen=True)
class JRPublicKey:
    """JR public elements in order Q1,...,Q8,Q0,QA."""

    elements: tuple[Any, ...]

    def __post_init__(self) -> None:
        elements = _tuple(self.elements, "JR public elements")
        if len(elements) != 10:
            raise ModelError("JR public key must contain ten elements")


@dataclass(frozen=True, repr=False)
class RASecretKey(_PrivateModel):
    material: tuple[Any, ...]

    def __post_init__(self) -> None:
        _private_tuple(self.material, "RA secret material")


@dataclass(frozen=True)
class GSPublicKey:
    v1: G1Vec
    w1: G1Vec
    u1: G1Vec
    v2: G2Vec
    w2: G2Vec
    u2: G2Vec

    def __post_init__(self) -> None:
        for name in ("v1", "w1", "u1"):
            if not isinstance(getattr(self, name), G1Vec):
                raise ModelError(f"{name} must be a G1Vec")
        for name in ("v2", "w2", "u2"):
            if not isinstance(getattr(self, name), G2Vec):
                raise ModelError(f"{name} must be a G2Vec")


@dataclass(frozen=True, repr=False)
class GSExtractionKey(_PrivateModel):
    material: tuple[Any, ...]

    def __post_init__(self) -> None:
        _private_tuple(self.material, "GS extraction material")


@dataclass(frozen=True)
class PublicParams:
    group_id: str
    g1: Any
    g2: Any
    schema: Schema
    jr_public_key: JRPublicKey
    gs_public_key: GSPublicKey
    pp_id: bytes

    def __post_init__(self) -> None:
        _text(self.group_id, "group_id")
        _bytes(self.pp_id, "pp_id")
        if not isinstance(self.schema, Schema):
            raise ModelError("schema must be a Schema")
        if not isinstance(self.jr_public_key, JRPublicKey):
            raise ModelError("jr_public_key must be a JRPublicKey")
        if not isinstance(self.gs_public_key, GSPublicKey):
            raise ModelError("gs_public_key must be a GSPublicKey")


@dataclass(frozen=True)
class IssuerPublicKey:
    components: tuple[Any, ...]

    def __post_init__(self) -> None:
        components = _tuple(self.components, "issuer public key components")
        if len(components) != 3:
            raise ModelError("issuer public key must contain three components")


@dataclass(frozen=True, repr=False)
class AttributeCredential(_PrivateModel):
    issuer_public_key: IssuerPublicKey
    attribute: Any
    epoch: int
    certificate: tuple[Any, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.issuer_public_key, IssuerPublicKey):
            raise ModelError("issuer_public_key must be an IssuerPublicKey")
        _integer(self.epoch, "epoch")
        certificate = _tuple(self.certificate, "attribute certificate")
        if len(certificate) != 6:
            raise ModelError("attribute certificate must contain six elements")


@dataclass(frozen=True, repr=False)
class IssuerSecretKey(_PrivateModel):
    public_key: IssuerPublicKey
    secret_exponents: tuple[int, int, int]
    credentials: tuple[AttributeCredential, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.public_key, IssuerPublicKey):
            raise ModelError("public_key must be an IssuerPublicKey")
        exponents = _tuple(self.secret_exponents, "issuer secret exponents")
        if len(exponents) != 3:
            raise ModelError("issuer secret key must contain three exponents")
        for exponent in exponents:
            _integer(exponent, "issuer secret exponent", minimum=1)
        credentials = _tuple(self.credentials, "issuer credentials")
        if any(not isinstance(item, AttributeCredential) for item in credentials):
            raise ModelError("issuer credentials must contain AttributeCredential values")


@dataclass(frozen=True)
class CompiledPolicy:
    policy: Any
    matrix: tuple[tuple[int, ...], ...]
    row_labels: tuple[Any, ...]
    k: int
    ell: int

    def __post_init__(self) -> None:
        matrix = _tuple(self.matrix, "policy matrix")
        labels = _tuple(self.row_labels, "policy row labels")
        k = _integer(self.k, "k", minimum=1)
        ell = _integer(self.ell, "ell", minimum=1)
        if len(matrix) != k or len(labels) != k:
            raise ModelError("policy row count must match k and row labels")
        for row in matrix:
            row = _tuple(row, "policy matrix row")
            if len(row) != ell:
                raise ModelError("each policy matrix row must have ell entries")
            for entry in row:
                if not isinstance(entry, int) or isinstance(entry, bool):
                    raise ModelError("policy matrix entries must be integers")


@dataclass(frozen=True, repr=False)
class CommitmentOpening(_PrivateModel):
    schema_id: str
    r: int
    message: tuple[int, ...]

    def __post_init__(self) -> None:
        _text(self.schema_id, "schema_id")
        _integer(self.r, "commitment randomness")
        message = _tuple(self.message, "message vector")
        if not message:
            raise ModelError("message vector must not be empty")
        for coordinate in message:
            _integer(coordinate, "message coordinate")


@dataclass(frozen=True)
class GSCommitment:
    variable_name: str
    value: G1Vec | G2Vec

    def __post_init__(self) -> None:
        _text(self.variable_name, "GS variable name")
        if not isinstance(self.value, (G1Vec, G2Vec)):
            raise ModelError("GS commitment value must be a G1Vec or G2Vec")


@dataclass(frozen=True)
class GSPublicCommitments:
    items: tuple[GSCommitment, ...]

    def __post_init__(self) -> None:
        items = _tuple(self.items, "GS commitments")
        if any(not isinstance(item, GSCommitment) for item in items):
            raise ModelError("GS commitments must contain GSCommitment values")
        names = tuple(item.variable_name for item in items)
        if len(set(names)) != len(names):
            raise ModelError("GS variable names must be unique")


@dataclass(frozen=True)
class GSPPEProof:
    pi1: G2Vec
    pi2: G2Vec
    theta1: G1Vec
    theta2: G1Vec

    def __post_init__(self) -> None:
        if not isinstance(self.pi1, G2Vec) or not isinstance(self.pi2, G2Vec):
            raise ModelError("pi1 and pi2 must be G2Vec values")
        if not isinstance(self.theta1, G1Vec) or not isinstance(self.theta2, G1Vec):
            raise ModelError("theta1 and theta2 must be G1Vec values")


@dataclass(frozen=True)
class ABSSignature:
    gamma: Any
    commitments: GSPublicCommitments
    proofs: tuple[GSPPEProof, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.commitments, GSPublicCommitments):
            raise ModelError("commitments must be GSPublicCommitments")
        proofs = _tuple(self.proofs, "PPE proofs")
        if not proofs:
            raise ModelError("PPE proof tuple must not be empty")
        if any(not isinstance(proof, GSPPEProof) for proof in proofs):
            raise ModelError("PPE proofs must contain GSPPEProof values")


@dataclass(frozen=True)
class Credential:
    schema_id: str
    pp_id: bytes
    commitment: Any
    source_policy: Any
    epoch: int
    signature: ABSSignature
    purpose: str = "VC"

    def __post_init__(self) -> None:
        _text(self.schema_id, "schema_id")
        _bytes(self.pp_id, "pp_id")
        _integer(self.epoch, "epoch")
        _purpose(self.purpose, "VC")
        if not isinstance(self.signature, ABSSignature):
            raise ModelError("signature must be an ABSSignature")


@dataclass(frozen=True)
class RequestProof:
    schema_id: str
    message_length: int
    A0: Any
    A1: Any
    A2: Any
    z_r: int
    z_message: tuple[int, ...]
    z_s: int
    z_t: int

    def __post_init__(self) -> None:
        _text(self.schema_id, "schema_id")
        length = _integer(self.message_length, "message_length", minimum=1)
        _integer(self.z_r, "z_r")
        _integer(self.z_s, "z_s")
        _integer(self.z_t, "z_t")
        responses = _tuple(self.z_message, "z_message")
        if len(responses) != length:
            raise ModelError("request proof response count must match message_length")
        for response in responses:
            _integer(response, "message response")


@dataclass(frozen=True)
class BlindRequest:
    source_credential: Credential
    target_policy: Any
    epoch: int
    schema_id: str
    pp_id: bytes
    U: Any
    V: Any
    W: Any
    proof: RequestProof
    purpose: str = "VP"

    def __post_init__(self) -> None:
        if not isinstance(self.source_credential, Credential):
            raise ModelError("source_credential must be a Credential")
        if not isinstance(self.proof, RequestProof):
            raise ModelError("proof must be a RequestProof")
        _text(self.schema_id, "schema_id")
        _bytes(self.pp_id, "pp_id")
        _integer(self.epoch, "epoch")
        _purpose(self.purpose, "VP")
        if self.source_credential.schema_id != self.schema_id:
            raise ModelError("source and target schema identifiers must match")
        if self.source_credential.pp_id != self.pp_id:
            raise ModelError("source and target parameter identifiers must match")
        if self.source_credential.epoch != self.epoch:
            raise ModelError("source and target epochs must match")
        if self.proof.schema_id != self.schema_id:
            raise ModelError("request proof schema identifier must match")


@dataclass(frozen=True, repr=False)
class HolderRequestState(_PrivateModel):
    source_opening: CommitmentOpening
    target_commitment: Any
    target_opening: CommitmentOpening
    s: int
    delta: int
    t: int
    request_binding: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.source_opening, CommitmentOpening):
            raise ModelError("source_opening must be a CommitmentOpening")
        if not isinstance(self.target_opening, CommitmentOpening):
            raise ModelError("target_opening must be a CommitmentOpening")
        if self.source_opening.schema_id != self.target_opening.schema_id:
            raise ModelError("source and target openings must use the same schema")
        if len(self.source_opening.message) != len(self.target_opening.message):
            raise ModelError("source and target opening lengths must match")
        _integer(self.s, "s", minimum=1)
        _integer(self.delta, "delta")
        _integer(self.t, "t")
        _bytes(self.request_binding, "request_binding")


@dataclass(frozen=True, repr=False)
class CheckedBlindRequest(_PrivateModel):
    request: BlindRequest
    compiled_policy: CompiledPolicy
    issuer_public_key: IssuerPublicKey

    def __post_init__(self) -> None:
        if not isinstance(self.request, BlindRequest):
            raise ModelError("request must be a BlindRequest")
        if not isinstance(self.compiled_policy, CompiledPolicy):
            raise ModelError("compiled_policy must be a CompiledPolicy")
        if not isinstance(self.issuer_public_key, IssuerPublicKey):
            raise ModelError("issuer_public_key must be an IssuerPublicKey")


@dataclass(frozen=True)
class BlindResponse:
    signature: ABSSignature
    schema_id: str
    pp_id: bytes
    epoch: int
    purpose: str = "VP"

    def __post_init__(self) -> None:
        if not isinstance(self.signature, ABSSignature):
            raise ModelError("signature must be an ABSSignature")
        _text(self.schema_id, "schema_id")
        _bytes(self.pp_id, "pp_id")
        _integer(self.epoch, "epoch")
        _purpose(self.purpose, "VP")


@dataclass(frozen=True)
class OpeningProof:
    schema_id: str
    message_length: int
    B: Any
    z_r: int
    z_message: tuple[int, ...]

    def __post_init__(self) -> None:
        _text(self.schema_id, "schema_id")
        length = _integer(self.message_length, "message_length", minimum=1)
        _integer(self.z_r, "z_r")
        responses = _tuple(self.z_message, "z_message")
        if len(responses) != length:
            raise ModelError("opening proof response count must match message_length")
        for response in responses:
            _integer(response, "message response")


@dataclass(frozen=True)
class Presentation:
    commitment: Any
    target_policy: Any
    epoch: int
    signature: ABSSignature
    schema_id: str
    pp_id: bytes
    nonce: bytes
    opening_proof: OpeningProof
    purpose: str = "VP"

    def __post_init__(self) -> None:
        _integer(self.epoch, "epoch")
        _text(self.schema_id, "schema_id")
        _bytes(self.pp_id, "pp_id")
        _bytes(self.nonce, "nonce")
        _purpose(self.purpose, "VP")
        if not isinstance(self.signature, ABSSignature):
            raise ModelError("signature must be an ABSSignature")
        if not isinstance(self.opening_proof, OpeningProof):
            raise ModelError("opening_proof must be an OpeningProof")
        if self.opening_proof.schema_id != self.schema_id:
            raise ModelError("opening proof schema identifier must match")


@dataclass(frozen=True, repr=False)
class AuthorizationWitness(_PrivateModel):
    compiled_policy: CompiledPolicy
    issuer_public_key: IssuerPublicKey
    epoch: int
    row_witnesses: tuple[Any, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.compiled_policy, CompiledPolicy):
            raise ModelError("compiled_policy must be a CompiledPolicy")
        if not isinstance(self.issuer_public_key, IssuerPublicKey):
            raise ModelError("issuer_public_key must be an IssuerPublicKey")
        _integer(self.epoch, "epoch")
        witnesses = _tuple(self.row_witnesses, "row_witnesses")
        if len(witnesses) != self.compiled_policy.k:
            raise ModelError("row witness count must match the policy row count")
