"""Canonical, length-delimited encodings used by the S2R public API."""

from __future__ import annotations

import hashlib
import struct
from typing import Iterable


class EncodingError(ValueError):
    """Raised when an encoding is malformed or non-canonical."""


def _check_bytes(value: bytes, *, name: str = "value") -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    return value


def encode_u8(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFF:
        raise EncodingError("u8 out of range")
    return bytes((value,))


def encode_u16(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF:
        raise EncodingError("u16 out of range")
    return struct.pack(">H", value)


def encode_u32(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise EncodingError("u32 out of range")
    return struct.pack(">I", value)


def encode_u64(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise EncodingError("u64 out of range")
    return struct.pack(">Q", value)


def encode_int(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("integer value required")
    if not -(1 << 63) <= value < (1 << 63):
        raise EncodingError("signed integer out of range")
    return b"I" + struct.pack(">q", value)


def encode_bytes(value: bytes) -> bytes:
    value = _check_bytes(value)
    return encode_u32(len(value)) + value


def encode_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("text value required")
    raw = value.encode("utf-8")
    if "\x00" in value:
        raise EncodingError("NUL is not permitted in text fields")
    return encode_bytes(raw)


def encode_optional_bytes(value: bytes | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + encode_bytes(_check_bytes(value))


def encode_optional_text(value: str | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + encode_text(value)


def encode_sequence(values: Iterable[bytes]) -> bytes:
    items = tuple(values)
    return encode_u32(len(items)) + b"".join(encode_bytes(item) for item in items)


def encode_attr_value(value: str | int | bytes) -> bytes:
    """Encode one context attribute with an explicit value type tag."""

    if isinstance(value, bool):
        raise TypeError("bool is not a protocol attribute type")
    if isinstance(value, str):
        return b"S" + encode_text(value)
    if isinstance(value, int):
        return encode_int(value)
    if isinstance(value, bytes):
        return b"B" + encode_bytes(value)
    raise TypeError("attribute values must be str, int, or bytes")


def sha256_domain(domain: bytes, payload: bytes) -> bytes:
    domain = _check_bytes(domain, name="domain")
    payload = _check_bytes(payload, name="payload")
    if not domain or len(domain) > 255:
        raise EncodingError("domain must contain 1..255 bytes")
    return hashlib.sha256(bytes((len(domain),)) + domain + payload).digest()
