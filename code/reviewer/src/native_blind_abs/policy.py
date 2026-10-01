"""Canonical monotone policies for the native blind ABS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .encoding import encode_sequence, encode_text


class PolicyError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Attribute:
    namespace: str
    kind: str
    value: str

    def __post_init__(self) -> None:
        for name, item in (
            ("namespace", self.namespace), ("kind", self.kind), ("value", self.value)
        ):
            if not isinstance(item, str) or not item or "\x00" in item:
                raise PolicyError(f"{name} must be nonempty NUL-free text")

    def canonical_bytes(self) -> bytes:
        return b"A" + encode_text(self.namespace) + encode_text(self.kind) + encode_text(self.value)


@dataclass(frozen=True)
class Attr:
    attribute: Attribute

    def canonical_bytes(self) -> bytes:
        return b"L" + self.attribute.canonical_bytes()


@dataclass(frozen=True)
class And:
    left: "Policy"
    right: "Policy"

    def canonical_bytes(self) -> bytes:
        return b"&" + encode_sequence((self.left.canonical_bytes(), self.right.canonical_bytes()))


@dataclass(frozen=True)
class Or:
    left: "Policy"
    right: "Policy"

    def canonical_bytes(self) -> bytes:
        return b"|" + encode_sequence((self.left.canonical_bytes(), self.right.canonical_bytes()))


Policy = Attr | And | Or


def _fold(nodes: Iterable[Policy], cls: type[And] | type[Or]) -> Policy:
    items = tuple(nodes)
    if not items:
        raise PolicyError("a policy connective needs at least one child")
    result = items[0]
    for item in items[1:]:
        result = cls(result, item)
    return result


def and_all(*nodes: Policy) -> Policy:
    return _fold(nodes, And)


def or_all(*nodes: Policy) -> Policy:
    return _fold(nodes, Or)


def evaluate(policy: Policy, available: Iterable[Attribute]) -> bool:
    have = set(available)
    if isinstance(policy, Attr):
        return policy.attribute in have
    if isinstance(policy, And):
        return evaluate(policy.left, have) and evaluate(policy.right, have)
    if isinstance(policy, Or):
        return evaluate(policy.left, have) or evaluate(policy.right, have)
    raise TypeError("unsupported policy node")


def replace_values(policy: Policy, replacements: Mapping[Attribute, Attribute]) -> Policy:
    """Return a policy with exact leaf substitutions; useful for fixed profiles."""

    if isinstance(policy, Attr):
        return Attr(replacements.get(policy.attribute, policy.attribute))
    if isinstance(policy, And):
        return And(replace_values(policy.left, replacements), replace_values(policy.right, replacements))
    if isinstance(policy, Or):
        return Or(replace_values(policy.left, replacements), replace_values(policy.right, replacements))
    raise TypeError("unsupported policy node")
