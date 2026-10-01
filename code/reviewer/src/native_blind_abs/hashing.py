"""Domain-separated scalar encodings for protocol statements."""

from __future__ import annotations

import hashlib

from .encoding import encode_bytes, encode_sequence, encode_text, encode_u64
from .groups import curve_order
from .policy import Attribute, Policy


ATTR_DOMAIN = b"ABS-NATIVE-BLIND-v3/attr"
POLICY_DOMAIN = b"ABS-NATIVE-BLIND-v3/policy"
REQUEST_DOMAIN = b"ABS-NATIVE-BLIND-v3/request"
SHOW_DOMAIN = b"ABS-NATIVE-BLIND-v3/show"
PP_ID_DOMAIN = b"ABS-NATIVE-BLIND-v3/pp-id"


def hash_to_scalar_wide(domain: bytes, *parts: bytes, nonzero: bool = False) -> int:
    if not isinstance(domain, bytes) or not domain or len(domain) > 255:
        raise ValueError("domain must contain 1..255 bytes")
    if any(not isinstance(part, bytes) for part in parts):
        raise TypeError("hash transcript parts must be bytes")
    transcript = bytes((len(domain),)) + domain + encode_sequence(parts)
    value = int.from_bytes(hashlib.sha512(transcript).digest(), "big") % curve_order()
    if nonzero and value == 0:
        return 1
    return value


def encode_attribute(attribute: Attribute, epoch: int) -> int:
    if not isinstance(epoch, int) or isinstance(epoch, bool) or not 0 <= epoch < 1 << 64:
        raise ValueError("epoch must be an unsigned 64-bit integer")
    return hash_to_scalar_wide(
        ATTR_DOMAIN,
        encode_text(attribute.namespace),
        encode_text(attribute.kind),
        encode_text(attribute.value),
        encode_u64(epoch),
        nonzero=True,
    )


def encode_policy(policy: Policy, epoch: int, purpose: str, schema_id: str) -> int:
    if purpose not in {"VC", "VP"}:
        raise ValueError("purpose must be VC or VP")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or not 0 <= epoch < 1 << 64:
        raise ValueError("epoch must be an unsigned 64-bit integer")
    return hash_to_scalar_wide(
        POLICY_DOMAIN,
        policy.canonical_bytes(),
        encode_u64(epoch),
        encode_text(purpose),
        encode_text(schema_id),
        nonzero=True,
    )


def parameter_identifier(payload: bytes) -> bytes:
    if not isinstance(payload, bytes):
        raise TypeError("parameter payload must be bytes")
    return hashlib.sha256(bytes((len(PP_ID_DOMAIN),)) + PP_ID_DOMAIN + encode_bytes(payload)).digest()
