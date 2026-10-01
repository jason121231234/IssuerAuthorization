"""JR group-message credentials in the group-swapped project orientation."""

from __future__ import annotations

from .groups import (
    curve_order,
    g1_equal,
    g1_generator,
    g1_mul,
    g2_add,
    g2_generator,
    g2_mul,
    gt_equal,
    gt_identity,
    gt_inv,
    gt_mul,
    pairing_g1_g2,
    random_scalar,
)
from .hashing import encode_attribute
from .models import AttributeCredential, IssuerPublicKey, IssuerSecretKey, PublicParams, RASecretKey
from .policy import Attribute


def issuer_keygen(pp: PublicParams) -> IssuerSecretKey:
    exponents = tuple(random_scalar(nonzero=True) for _ in range(3))
    public = IssuerPublicKey(tuple(g2_mul(pp.g2, value) for value in exponents))
    return IssuerSecretKey(public, exponents, ())


def _ra_material(secret: RASecretKey):
    if len(secret.material) != 8:
        raise ValueError("unexpected RA secret-key layout")
    kappas, kappa0, a_qa, b_ra, k0, ks, d_ra, f_ra = secret.material
    if len(kappas) != 8 or len(ks) != 4:
        raise ValueError("unexpected RA coefficient layout")
    return kappas, kappa0, a_qa, b_ra, k0, ks, d_ra, f_ra


def authorize(
    pp: PublicParams,
    ra_secret: RASecretKey,
    issuer_public_key: IssuerPublicKey,
    attribute: Attribute,
    epoch: int,
) -> AttributeCredential:
    kappas, kappa0, _a_qa, b_ra, k0, ks, d_ra, f_ra = _ra_material(ra_secret)
    order = curve_order()
    a = encode_attribute(attribute, epoch)
    attr_point = g2_mul(pp.g2, a)
    r = random_scalar()
    tag = random_scalar()
    R = g2_mul(pp.g2, r)
    Rhat = g2_mul(pp.g2, b_ra * r % order)
    S = g2_mul(pp.g2, tag * r % order)
    tau = g1_mul(pp.g1, tag)

    message = issuer_public_key.components + (attr_point,)
    G = g2_mul(pp.g2, (k0 + d_ra * r + f_ra * tag * r) % order)
    for point, coefficient in zip(message, ks):
        G = g2_add(G, g2_mul(point, coefficient))

    q_values = message + (R, Rhat, S, G)
    P = g2_mul(pp.g2, kappa0)
    for point, coefficient in zip(q_values, kappas):
        P = g2_add(P, g2_mul(point, coefficient))
    return AttributeCredential(
        issuer_public_key,
        attribute,
        epoch,
        (R, Rhat, S, G, tau, P),
    )


def add_credentials(
    issuer_secret: IssuerSecretKey,
    credentials: tuple[AttributeCredential, ...],
) -> IssuerSecretKey:
    for credential in credentials:
        if credential.issuer_public_key != issuer_secret.public_key:
            raise ValueError("credential belongs to a different issuer key")
    merged: dict[tuple[Attribute, int], AttributeCredential] = {
        (item.attribute, item.epoch): item for item in issuer_secret.credentials
    }
    for item in credentials:
        merged[(item.attribute, item.epoch)] = item
    ordered = tuple(merged[key] for key in sorted(merged, key=lambda x: (x[1], x[0])))
    return IssuerSecretKey(issuer_secret.public_key, issuer_secret.secret_exponents, ordered)


def verify_credential(pp: PublicParams, credential: AttributeCredential) -> bool:
    try:
        q = pp.jr_public_key.elements
        X1, X2, X3 = credential.issuer_public_key.components
        R, Rhat, S, G, tau, P = credential.certificate
        attr_point = g2_mul(pp.g2, encode_attribute(credential.attribute, credential.epoch))
        g2_values = (X1, X2, X3, attr_point, R, Rhat, S, G, pp.g2)
        g1_values = q[:8] + (q[8],)
        left = gt_identity()
        for g1_point, g2_point in zip(g1_values, g2_values):
            left = gt_mul(left, pairing_g1_g2(g1_point, g2_point))
        right = pairing_g1_g2(q[9], P)
        if not gt_equal(left, right):
            return False
        return gt_equal(pairing_g1_g2(tau, R), pairing_g1_g2(pp.g1, S))
    except (TypeError, ValueError):
        return False
