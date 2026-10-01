"""Trusted setup for the native blind ABS v3 prototype."""

from __future__ import annotations

from .encoding import encode_sequence, encode_text
from .groups import (
    GROUP_ID,
    curve_order,
    encode_g1,
    encode_g2,
    g1_add,
    g1_generator,
    g1_mul,
    g2_add,
    g2_generator,
    g2_mul,
    random_g1,
    random_scalar,
)
from .hashing import parameter_identifier
from .models import G1Vec, G2Vec, GSPublicKey, JRPublicKey, PublicParams, RASecretKey, Schema


def _g1v_add(left: G1Vec, right: G1Vec) -> G1Vec:
    return G1Vec(g1_add(left.first, right.first), g1_add(left.second, right.second))


def _g1v_mul(value: G1Vec, exponent: int) -> G1Vec:
    return G1Vec(g1_mul(value.first, exponent), g1_mul(value.second, exponent))


def _g2v_add(left: G2Vec, right: G2Vec) -> G2Vec:
    return G2Vec(g2_add(left.first, right.first), g2_add(left.second, right.second))


def _g2v_mul(value: G2Vec, exponent: int) -> G2Vec:
    return G2Vec(g2_mul(value.first, exponent), g2_mul(value.second, exponent))


def _parameter_payload(
    schema_id: str,
    field_names: tuple[str, ...],
    encoding_version: str,
    bases: tuple[object, ...],
    jr: JRPublicKey,
    gs: GSPublicKey,
) -> bytes:
    return encode_sequence(
        (
            encode_text(GROUP_ID),
            encode_text(schema_id),
            encode_sequence(encode_text(name) for name in field_names),
            encode_text(encoding_version),
            encode_sequence(encode_g1(base) for base in bases),
            encode_sequence(encode_g1(point) for point in jr.elements),
            encode_sequence(
                (
                    encode_g1(gs.v1.first, allow_identity=True),
                    encode_g1(gs.v1.second, allow_identity=True),
                    encode_g1(gs.w1.first, allow_identity=True),
                    encode_g1(gs.w1.second, allow_identity=True),
                    encode_g1(gs.u1.first, allow_identity=True),
                    encode_g1(gs.u1.second, allow_identity=True),
                    encode_g2(gs.v2.first, allow_identity=True),
                    encode_g2(gs.v2.second, allow_identity=True),
                    encode_g2(gs.w2.first, allow_identity=True),
                    encode_g2(gs.w2.second, allow_identity=True),
                    encode_g2(gs.u2.first, allow_identity=True),
                    encode_g2(gs.u2.second, allow_identity=True),
                )
            ),
        )
    )


def setup(
    field_names: tuple[str, ...],
    *,
    schema_id: str = "credential-vector-v1",
    encoding_version: str = "scalar-vector-v1",
) -> tuple[PublicParams, RASecretKey]:
    """Generate authenticated public parameters and the JR signing secret.

    The caller stores ``pp.pp_id`` in its trusted parameter registry. Temporary
    exponents used for the Pedersen bases and GS key are not returned.
    """

    if not isinstance(field_names, tuple) or not field_names:
        raise ValueError("field_names must be a nonempty tuple")
    bases = tuple(random_g1() for _ in field_names)

    # JR Figure-2 parameters in the group-swapped orientation used by the spec.
    kappas = tuple(random_scalar(nonzero=True) for _ in range(8))
    kappa0 = random_scalar(nonzero=True)
    a_qa = random_scalar(nonzero=True)
    order = curve_order()
    q_values = tuple(g1_mul(g1_generator(), a_qa * value % order) for value in kappas)
    q0 = g1_mul(g1_generator(), a_qa * kappa0 % order)
    qa = g1_mul(g1_generator(), a_qa)
    jr_public = JRPublicKey(q_values + (q0, qa))
    ra_secret = RASecretKey((
        kappas,
        kappa0,
        a_qa,
        random_scalar(nonzero=True),  # b_RA
        random_scalar(nonzero=True),  # k0
        tuple(random_scalar(nonzero=True) for _ in range(4)),
        random_scalar(nonzero=True),  # d_RA
        random_scalar(nonzero=True),  # f_RA
    ))

    xi = random_scalar(nonzero=True)
    zeta = random_scalar(nonzero=True)
    rho = random_scalar()
    sigma = random_scalar()
    v1 = G1Vec(g1_mul(g1_generator(), xi), g1_generator())
    w1 = _g1v_mul(v1, rho)
    u1 = _g1v_add(w1, G1Vec(g1_mul(g1_generator(), 0), g1_generator()))
    v2 = G2Vec(g2_mul(g2_generator(), zeta), g2_generator())
    w2 = _g2v_mul(v2, sigma)
    u2 = _g2v_add(w2, G2Vec(g2_mul(g2_generator(), 0), g2_generator()))
    gs_public = GSPublicKey(v1, w1, u1, v2, w2, u2)

    provisional_schema = Schema(schema_id, field_names, encoding_version, bases)
    payload = _parameter_payload(schema_id, field_names, encoding_version, bases, jr_public, gs_public)
    pp = PublicParams(
        GROUP_ID,
        g1_generator(),
        g2_generator(),
        provisional_schema,
        jr_public,
        gs_public,
        parameter_identifier(payload),
    )
    return pp, ra_secret
