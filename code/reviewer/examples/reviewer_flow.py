"""Run one identified-VC to anonymous-VP protocol instance."""

from native_blind_abs.policy import Attr, Attribute, and_all
from native_blind_abs.jr import issuer_keygen
from native_blind_abs.services import HolderService, IssuerService, RAService, VerifierService


EPOCH = 7
N = 3
NAMESPACE = "ra:reviewer-example"
NONCE = b"reviewer-example-nonce"


def run_flow() -> dict[str, object]:
    permissions = tuple(
        Attribute(NAMESPACE, "permission", f"permission-{i}")
        for i in range(1, N + 1)
    )
    identity = Attribute(NAMESPACE, "identity", "issuer-A")
    time_attribute = Attribute(NAMESPACE, "time", f"epoch-{EPOCH}")
    source_policy = and_all(
        *(Attr(attribute) for attribute in permissions),
        Attr(identity),
        Attr(time_attribute),
    )
    target_policy = and_all(
        *(Attr(attribute) for attribute in permissions),
        Attr(time_attribute),
    )

    ra = RAService(
        ("content-0", "content-1", "content-2"),
        schema_id="reviewer-code-v1",
    )
    issuer_secret = issuer_keygen(ra.pp)
    issuer_key = issuer_secret.public_key
    ra.register_issuer(issuer_key)
    attributes = (*permissions, identity, time_attribute)
    certificates = ra.authorize(issuer_key, attributes, EPOCH)
    issuer = IssuerService(
        ra.pp,
        issuer_secret,
        certificates,
        allowed_transitions=((source_policy, target_policy),),
    )

    holder = HolderService(ra.pp)
    verifier = VerifierService(ra.pp)
    message = (17, 29, 41)
    credential, opening = issuer.issue_vc(message, source_policy, EPOCH)
    holder.receive_vc(credential, opening)
    request = holder.request_vp(credential, target_policy)
    response = issuer.blind_sign(request)
    presentation = holder.complete_vp(request, response, NONCE)
    verified = verifier.verify(
        presentation,
        required_policy=target_policy,
        required_epoch=EPOCH,
        expected_nonce=NONCE,
    )
    return {
        "issuer": issuer,
        "holder": holder,
        "verifier": verifier,
        "credential": credential,
        "request": request,
        "response": response,
        "presentation": presentation,
        "target_policy": target_policy,
        "verified": verified,
    }


if __name__ == "__main__":
    result = run_flow()
    print(f"VP verification: {result['verified']}")
