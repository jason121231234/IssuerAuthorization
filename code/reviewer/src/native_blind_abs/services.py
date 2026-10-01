"""Thin role services that compose the native blind ABS primitives."""

from __future__ import annotations

import hashlib
from typing import Iterable

from .blind import abs_blind_sign, abs_unblind, vp_check_request, vp_request, vp_show, vp_verify
from .commitment import commit, verify_opening
from .core import abs_sign, abs_verify, representative_for
from .encoding import encode_sequence
from .groups import encode_g2, scalar
from .jr import add_credentials, authorize as issue_attribute_credential
from .models import (
    AttributeCredential,
    BlindRequest,
    BlindResponse,
    CommitmentOpening,
    Credential,
    HolderRequestState,
    IssuerPublicKey,
    IssuerSecretKey,
    Presentation,
    PublicParams,
    RASecretKey,
)
from .policy import Attribute, Policy
from .setup import setup
from .transcript import encode_blind_request, encode_credential


def _key_id(public_key: IssuerPublicKey) -> bytes:
    return encode_sequence(encode_g2(point) for point in public_key.components)


def _credential_id(credential: Credential) -> bytes:
    return hashlib.sha256(encode_credential(credential)).digest()


def _transition_id(source: Policy, target: Policy) -> tuple[bytes, bytes]:
    return source.canonical_bytes(), target.canonical_bytes()


class RAService:
    """Owns setup, issuer registration, and attribute authorization."""

    def __init__(
        self,
        field_names: tuple[str, ...],
        *,
        schema_id: str = "credential-vector-v1",
        encoding_version: str = "scalar-vector-v1",
    ) -> None:
        self.pp, self.__secret = setup(
            field_names,
            schema_id=schema_id,
            encoding_version=encoding_version,
        )
        self.__issuers: dict[bytes, IssuerPublicKey] = {}
        self.__certificates: dict[bytes, dict[tuple[Attribute, int], AttributeCredential]] = {}

    def __repr__(self) -> str:
        return "RAService(<secret state redacted>)"

    def register_issuer(self, public_key: IssuerPublicKey) -> IssuerPublicKey:
        """Register an issuer's public key; duplicate keys are rejected."""
        if not isinstance(public_key, IssuerPublicKey):
            raise TypeError("public_key must be an IssuerPublicKey")
        key_id = _key_id(public_key)
        if key_id in self.__issuers:
            raise ValueError("issuer public key is already registered")
        self.__issuers[key_id] = public_key
        self.__certificates[key_id] = {}
        return public_key

    def authorize(
        self,
        issuer: IssuerPublicKey,
        attributes: Iterable[Attribute],
        epoch: int,
    ) -> tuple[AttributeCredential, ...]:
        """Issue or reuse one RA certificate for each requested attribute."""
        if not isinstance(issuer, IssuerPublicKey):
            raise TypeError("issuer must be a registered IssuerPublicKey")
        key_id = _key_id(issuer)
        if self.__issuers.get(key_id) != issuer:
            raise ValueError("issuer is not registered")
        attrs = tuple(attributes)
        if not attrs or any(not isinstance(attribute, Attribute) for attribute in attrs):
            raise ValueError("attributes must be a nonempty sequence of Attribute values")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            raise ValueError("epoch must be a nonnegative integer")
        requested = tuple(dict.fromkeys(attrs))
        registry = self.__certificates[key_id]
        for attribute in requested:
            cert_key = (attribute, epoch)
            if cert_key not in registry:
                registry[cert_key] = issue_attribute_credential(
                    self.pp, self.__secret, issuer, attribute, epoch
                )
        return tuple(registry[(attribute, epoch)] for attribute in requested)


class IssuerService:
    """Issues source VCs and answers permitted, proof-checked VP requests."""

    def __init__(
        self,
        pp: PublicParams,
        issuer_secret: IssuerSecretKey,
        attribute_credentials: Iterable[AttributeCredential] = (),
        *,
        allowed_transitions: Iterable[tuple[Policy, Policy]] | None = None,
    ) -> None:
        self.pp = pp
        self.__issuer_secret = add_credentials(issuer_secret, tuple(attribute_credentials))
        if allowed_transitions is None:
            self.__allowed_transitions = None
        else:
            self.__allowed_transitions = frozenset(
                _transition_id(source, target)
                for source, target in allowed_transitions
            )
        self.__source_records: dict[bytes, Credential] = {}

    def __repr__(self) -> str:
        return "IssuerService(<secret state redacted>)"

    @property
    def public_key(self) -> IssuerPublicKey:
        return self.__issuer_secret.public_key

    @property
    def source_record_count(self) -> int:
        return len(self.__source_records)

    def install_credentials(self, credentials: Iterable[AttributeCredential]) -> None:
        self.__issuer_secret = add_credentials(self.__issuer_secret, tuple(credentials))

    def approve_vector(self, message_vector: Iterable[int]) -> tuple[int, ...]:
        """Check vector shape and canonical scalars before VC issuance."""
        vector = tuple(message_vector)
        if len(vector) != self.pp.schema.L:
            raise ValueError("message vector length must match the credential schema")
        return tuple(scalar(value) for value in vector)

    def issue_vc(
        self,
        message_vector: Iterable[int],
        source_policy: Policy,
        epoch: int,
    ) -> tuple[Credential, CommitmentOpening]:
        approved = self.approve_vector(message_vector)
        commitment, opening = commit(self.pp, approved)
        representative = representative_for(
            self.pp, commitment, source_policy, epoch, "VC"
        )
        signature = abs_sign(
            self.pp,
            self.__issuer_secret,
            representative,
            source_policy,
            epoch,
        )
        credential = Credential(
            self.pp.schema.schema_id,
            self.pp.pp_id,
            commitment,
            source_policy,
            epoch,
            signature,
        )
        self.__source_records[_credential_id(credential)] = credential
        return credential, opening

    def blind_sign(self, request: BlindRequest) -> BlindResponse:
        request_id = _credential_id(request.source_credential)
        recorded = self.__source_records.get(request_id)
        if recorded is None:
            raise ValueError("source VC is absent from this issuer's records")
        if encode_credential(recorded) != encode_credential(request.source_credential):
            raise ValueError("source VC does not match the issuer record")

        def transition_allowed(source: Policy, target: Policy) -> bool:
            if self.__allowed_transitions is None:
                return source == target
            return _transition_id(source, target) in self.__allowed_transitions

        checked = vp_check_request(
            self.pp,
            self.__issuer_secret,
            request,
            expected_source=recorded,
            transition_allowed=transition_allowed,
        )
        return abs_blind_sign(self.pp, self.__issuer_secret, checked)


class HolderService:
    """Stores VC openings privately and manages blind VP requests."""

    def __init__(self, pp: PublicParams) -> None:
        self.pp = pp
        self.__openings: dict[bytes, CommitmentOpening] = {}
        self.__request_states: dict[bytes, HolderRequestState] = {}

    def __repr__(self) -> str:
        return "HolderService(<secret state redacted>)"

    def receive_vc(self, credential: Credential, opening: CommitmentOpening) -> None:
        if credential.pp_id != self.pp.pp_id or credential.schema_id != self.pp.schema.schema_id:
            raise ValueError("VC uses different public parameters or schema")
        if not verify_opening(self.pp, credential.commitment, opening):
            raise ValueError("VC opening is invalid")
        representative = representative_for(
            self.pp,
            credential.commitment,
            credential.source_policy,
            credential.epoch,
            "VC",
        )
        if not abs_verify(
            self.pp,
            representative,
            credential.source_policy,
            credential.epoch,
            credential.signature,
        ):
            raise ValueError("VC signature is invalid")
        self.__openings[_credential_id(credential)] = opening

    def request_vp(self, credential: Credential, target_policy: Policy) -> BlindRequest:
        opening = self.__openings.get(_credential_id(credential))
        if opening is None:
            raise ValueError("holder has not received this VC and opening")
        request, state = vp_request(self.pp, credential, opening, target_policy)
        self.__request_states[state.request_binding] = state
        return request

    def complete_vp(
        self,
        request: BlindRequest,
        response: BlindResponse,
        nonce: bytes,
    ) -> Presentation:
        request_id = hashlib.sha256(encode_blind_request(request)).digest()
        state = self.__request_states.get(request_id)
        if state is None:
            raise ValueError("holder has no pending state for this request")
        signature = abs_unblind(self.pp, request, state, response)
        presentation = vp_show(self.pp, request, state, signature, nonce)
        del self.__request_states[request_id]
        return presentation


class VerifierService:
    """Verifies a presentation against independently supplied requirements."""

    def __init__(self, pp: PublicParams) -> None:
        self.pp = pp

    def verify(
        self,
        presentation: Presentation,
        *,
        required_policy: Policy,
        required_epoch: int,
        expected_nonce: bytes,
    ) -> bool:
        return vp_verify(
            self.pp,
            presentation,
            required_policy=required_policy,
            required_epoch=required_epoch,
            expected_nonce=expected_nonce,
        )
