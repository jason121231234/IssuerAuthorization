"""Canonical public wire encoder for Native Blind ABS v3.

This reviewer copy intentionally retains only the encoding direction. Public
tags and canonical byte layouts are unchanged; the full prototype retains the
validated decoder for receiving untrusted wire objects.
"""

from __future__ import annotations

from typing import Any, Callable

from .encoding import EncodingError, encode_bytes, encode_sequence, encode_text, encode_u32, encode_u64
from .groups import encode_g1, encode_g2, scalar_bytes
from .models import (
    ABSSignature, BlindRequest, BlindResponse, Credential, G1Vec, G2Vec,
    GSCommitment, GSPPEProof, GSPublicCommitments, GSPublicKey,
    IssuerPublicKey, JRPublicKey, OpeningProof, Presentation, PublicParams,
    RequestProof, Schema,
)
from .policy import And, Attr, Attribute, Or, Policy


MAGIC = b"ABS-NATIVE-BLIND-PUBLIC-v3"
MAX_WIRE_BYTES = 32 * 1024 * 1024
MAX_BLOB_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 1 * 1024 * 1024
MAX_ITEMS = 1 << 16
MAX_POLICY_NODES = 1 << 14
MAX_POLICY_DEPTH = 128
MAX_NONCE_BYTES = 4096
PP_ID_BYTES = 32

_SCHEMA, _JR_PUBLIC_KEY, _GS_PUBLIC_KEY, _PUBLIC_PARAMS = 1, 2, 3, 4
_ISSUER_PUBLIC_KEY = 5
_CREDENTIAL, _BLIND_REQUEST, _BLIND_RESPONSE, _PRESENTATION = 10, 11, 12, 13

_TAGS: dict[type[Any], int] = {
    Schema: _SCHEMA,
    JRPublicKey: _JR_PUBLIC_KEY,
    GSPublicKey: _GS_PUBLIC_KEY,
    PublicParams: _PUBLIC_PARAMS,
    IssuerPublicKey: _ISSUER_PUBLIC_KEY,
    Credential: _CREDENTIAL,
    BlindRequest: _BLIND_REQUEST,
    BlindResponse: _BLIND_RESPONSE,
    Presentation: _PRESENTATION,
}
PUBLIC_TYPES = tuple(_TAGS)


def _bounded_text(value: str) -> bytes:
    raw = encode_text(value)
    if len(raw) - 4 > MAX_TEXT_BYTES:
        raise EncodingError("text field exceeds the public wire limit")
    return raw


def _bounded_blob(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("wire blob must be bytes")
    if len(value) > MAX_BLOB_BYTES:
        raise EncodingError("byte field exceeds the public wire limit")
    return encode_bytes(value)


def _encode_ppid(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != PP_ID_BYTES:
        raise EncodingError("parameter identifier must be exactly 32 bytes")
    return _bounded_blob(value)


def _encode_sequence(items: tuple[Any, ...], encoder: Callable[[Any], bytes]) -> bytes:
    if not isinstance(items, tuple):
        raise TypeError("sequence fields must be tuples")
    if len(items) > MAX_ITEMS:
        raise EncodingError("sequence item count exceeds the public wire limit")
    parts = []
    for item in items:
        encoded = encoder(item)
        if len(encoded) > MAX_BLOB_BYTES:
            raise EncodingError("sequence item exceeds the public wire limit")
        parts.append(encode_bytes(encoded))
    return encode_u32(len(parts)) + b"".join(parts)


def _encode_g1(point: Any, *, allow_identity: bool = False) -> bytes:
    return encode_g1(point, allow_identity=allow_identity)


def _encode_g2(point: Any, *, allow_identity: bool = False) -> bytes:
    return encode_g2(point, allow_identity=allow_identity)


def _g1_vec(value: G1Vec, *, allow_identity: bool) -> bytes:
    if not isinstance(value, G1Vec):
        raise TypeError("expected a G1Vec")
    return _encode_g1(value.first, allow_identity=allow_identity) + _encode_g1(value.second, allow_identity=allow_identity)


def _g2_vec(value: G2Vec, *, allow_identity: bool) -> bytes:
    if not isinstance(value, G2Vec):
        raise TypeError("expected a G2Vec")
    return _encode_g2(value.first, allow_identity=allow_identity) + _encode_g2(value.second, allow_identity=allow_identity)


def _encode_policy(policy: Policy, *, _depth: int = 0, _budget: list[int] | None = None) -> bytes:
    if _budget is None:
        _budget = [0]
    if _depth > MAX_POLICY_DEPTH:
        raise EncodingError("policy nesting exceeds the public wire limit")
    _budget[0] += 1
    if _budget[0] > MAX_POLICY_NODES:
        raise EncodingError("policy node count exceeds the public wire limit")
    if type(policy) is Attr:
        attr = policy.attribute
        if type(attr) is not Attribute:
            raise TypeError("policy leaf must contain an Attribute")
        return b"\x01" + _bounded_text(attr.namespace) + _bounded_text(attr.kind) + _bounded_text(attr.value)
    if type(policy) in (And, Or):
        tag = b"\x02" if type(policy) is And else b"\x03"
        left = _encode_policy(policy.left, _depth=_depth + 1, _budget=_budget)
        right = _encode_policy(policy.right, _depth=_depth + 1, _budget=_budget)
        return tag + _bounded_blob(left) + _bounded_blob(right)
    raise TypeError("policy must be an Attr, And, or Or node")


def _encode_nested(value: Any) -> bytes:
    return _bounded_blob(serialize_public(value))


def _schema_body(value: Schema) -> bytes:
    return (_bounded_text(value.schema_id) + _encode_sequence(value.field_names, _bounded_text)
            + _bounded_text(value.encoding_version)
            + _encode_sequence(value.bases, lambda point: _encode_g1(point)))


def _jr_body(value: JRPublicKey) -> bytes:
    return _encode_sequence(value.elements, lambda point: _encode_g1(point))


def _gs_public_body(value: GSPublicKey) -> bytes:
    return (_g1_vec(value.v1, allow_identity=False) + _g1_vec(value.w1, allow_identity=True)
            + _g1_vec(value.u1, allow_identity=True) + _g2_vec(value.v2, allow_identity=False)
            + _g2_vec(value.w2, allow_identity=True) + _g2_vec(value.u2, allow_identity=True))






def _public_params_body(value: PublicParams) -> bytes:
    return (_bounded_text(value.group_id) + _encode_g1(value.g1) + _encode_g2(value.g2)
            + _encode_nested(value.schema) + _encode_nested(value.jr_public_key)
            + _encode_nested(value.gs_public_key) + _encode_ppid(value.pp_id))


def _issuer_public_body(value: IssuerPublicKey) -> bytes:
    return _encode_sequence(value.components, lambda point: _encode_g2(point))






def _gs_commitment_body(value: GSCommitment) -> bytes:
    if type(value.value) is G1Vec:
        return _bounded_text(value.variable_name) + b"\x01" + _g1_vec(value.value, allow_identity=True)
    if type(value.value) is G2Vec:
        return _bounded_text(value.variable_name) + b"\x02" + _g2_vec(value.value, allow_identity=True)
    raise TypeError("GS commitment has an unsupported group direction")


def _gs_proof_body(value: GSPPEProof) -> bytes:
    return (_g2_vec(value.pi1, allow_identity=True) + _g2_vec(value.pi2, allow_identity=True)
            + _g1_vec(value.theta1, allow_identity=True) + _g1_vec(value.theta2, allow_identity=True))


def _signature_body(value: ABSSignature) -> bytes:
    commitments = _encode_sequence(value.commitments.items, _gs_commitment_body)
    proofs = _encode_sequence(value.proofs, _gs_proof_body)
    return _encode_g2(value.gamma) + commitments + proofs


def _credential_body(value: Credential) -> bytes:
    return (_encode_ppid(value.pp_id) + _bounded_text(value.schema_id) + _encode_g1(value.commitment)
            + _bounded_blob(_encode_policy(value.source_policy)) + encode_u64(value.epoch)
            + _bounded_text(value.purpose) + _encode_nested_signature(value.signature))


def _encode_nested_signature(value: ABSSignature) -> bytes:
    return _bounded_blob(_signature_body(value))


def _request_proof_body(value: RequestProof) -> bytes:
    return (_bounded_text(value.schema_id) + _encode_g1(value.A0, allow_identity=True)
            + _encode_g1(value.A1, allow_identity=True) + _encode_g1(value.A2, allow_identity=True)
            + scalar_bytes(value.z_r) + _encode_sequence(value.z_message, scalar_bytes)
            + scalar_bytes(value.z_s) + scalar_bytes(value.z_t))


def _blind_request_body(value: BlindRequest) -> bytes:
    return (_encode_ppid(value.pp_id) + _bounded_text(value.schema_id)
            + _encode_nested(value.source_credential) + _bounded_blob(_encode_policy(value.target_policy))
            + encode_u64(value.epoch) + _bounded_text(value.purpose) + _encode_g1(value.U)
            + _encode_g1(value.V) + _encode_g1(value.W) + _bounded_blob(_request_proof_body(value.proof)))


def _blind_response_body(value: BlindResponse) -> bytes:
    return (_bounded_text(value.schema_id) + _encode_ppid(value.pp_id) + encode_u64(value.epoch)
            + _bounded_text(value.purpose) + _encode_nested_signature(value.signature))


def _opening_proof_body(value: OpeningProof) -> bytes:
    return (_bounded_text(value.schema_id) + _encode_g1(value.B, allow_identity=True)
            + scalar_bytes(value.z_r) + _encode_sequence(value.z_message, scalar_bytes))


def _presentation_body(value: Presentation) -> bytes:
    if len(value.nonce) > MAX_NONCE_BYTES:
        raise EncodingError("presentation nonce exceeds the public wire limit")
    return (_encode_ppid(value.pp_id) + _bounded_text(value.schema_id) + _encode_g1(value.commitment)
            + _bounded_blob(_encode_policy(value.target_policy)) + encode_u64(value.epoch)
            + _bounded_text(value.purpose) + _encode_nested_signature(value.signature)
            + _bounded_blob(value.nonce) + _bounded_blob(_opening_proof_body(value.opening_proof)))


_BODY_ENCODERS: dict[type[Any], Callable[[Any], bytes]] = {
    Schema: _schema_body, JRPublicKey: _jr_body, GSPublicKey: _gs_public_body,
    PublicParams: _public_params_body, IssuerPublicKey: _issuer_public_body,
    Credential: _credential_body, BlindRequest: _blind_request_body,
    BlindResponse: _blind_response_body, Presentation: _presentation_body,
}


def serialize_public(value: Any) -> bytes:
    """Serialize one whitelisted public model using the v3 canonical format."""
    cls = type(value)
    tag = _TAGS.get(cls)
    if tag is None:
        raise TypeError(f"{cls.__name__} is not an approved public wire type")
    body = _BODY_ENCODERS[cls](value)
    if len(body) > MAX_BLOB_BYTES:
        raise EncodingError("public object exceeds the wire size limit")
    wire = MAGIC + bytes((tag,)) + encode_u32(len(body)) + body
    if len(wire) > MAX_WIRE_BYTES:
        raise EncodingError("public object exceeds the wire size limit")
    return wire

