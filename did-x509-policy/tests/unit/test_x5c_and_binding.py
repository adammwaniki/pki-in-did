"""Checks 7, 8 and 9: the chain must be present, identified, and actually bound to the key.

Tab C: "Confirm the leaf certificate's SubjectPublicKeyInfo matches the x/y in the JWK.
Without this binding check the chain is decorative."
"""

from __future__ import annotations

import copy

import pytest

from tests import fixtures as fx
from tests.conftest import assert_accepted, assert_rejected

pytestmark = pytest.mark.unit


def _with_jwk(world, issuer, jwk):
    document = fx.build_did_document(issuer.did, jwk=jwk, fragment=issuer.fragment)
    return document


def test_a_jwk_with_no_x5c_is_rejected(verify, world, policy, store, online):
    """Brief verifier rule 2, stated directly."""
    jwk = {k: v for k, v in world.issuer_a.jwk.items() if k not in ("x5c", "x5t#S256")}
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "x5c_missing")


def test_an_empty_x5c_array_is_rejected(verify, world, policy, store, online):
    jwk = copy.deepcopy(world.issuer_a.jwk)
    jwk["x5c"] = []
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "x5c_missing")


def test_an_x5c_entry_that_is_not_a_certificate_is_rejected(verify, world, policy, store, online):
    jwk = copy.deepcopy(world.issuer_a.jwk)
    jwk["x5c"] = ["bm90IGEgY2VydGlmaWNhdGU="]
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "x5c_malformed")


def test_x5c_must_be_standard_base64_not_base64url(verify, world, policy, store, online):
    """RFC 7517 §4.7 specifies base64, not base64url. A base64url chain is malformed."""
    jwk = copy.deepcopy(world.issuer_a.jwk)
    jwk["x5c"] = [fx.b64u(fx.der(world.issuer_a.cert))]
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert not result.accepted
    assert result.reason == "x5c_malformed"


def test_a_decorative_chain_is_rejected(verify, world, policy, store, online):
    """A genuine national chain pasted beside a key it does not certify.

    This is the attack tab C names: anyone can paste a national CA chain into their
    own did.json. Only the SPKI-to-JWK binding check catches it.
    """
    impostor = fx.ec_key()
    jwk = fx.ec_public_jwk(impostor, kid=world.issuer_a.fragment,
                           x5c=[world.issuer_a.cert, world.issuing.cert])
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    credential = fx.sign_jws_compact(
        fx.vc_payload(world.issuer_a.did), impostor, kid=world.issuer_a.vm_id,
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "spki_jwk_mismatch")


def test_a_swapped_y_coordinate_is_rejected(verify, world, policy, store, online):
    jwk = copy.deepcopy(world.issuer_a.jwk)
    jwk["y"] = fx.b64u(bytes(32))
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "spki_jwk_mismatch")


def test_an_x5t_s256_that_does_not_match_the_leaf_is_rejected(verify, world, policy, store, online):
    jwk = copy.deepcopy(world.issuer_a.jwk)
    jwk["x5t#S256"] = fx.b64u(b"\x00" * 32)
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "x5t_mismatch")


def test_a_missing_x5t_is_permitted(verify, world, policy, store, online):
    """RFC 7517 makes x5t#S256 optional; the policy only checks it when present."""
    jwk = fx.ec_public_jwk(world.issuer_a.key, kid=world.issuer_a.fragment,
                           x5c=[world.issuer_a.cert, world.issuing.cert], include_x5t=False)
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    assert result.check("x5t_matches_leaf").status == "skip"


def test_the_root_may_be_included_in_x5c_and_is_still_not_trusted_on_that_basis(
    verify, world, policy, store, online
):
    """A chain ending in an untrusted self-signed root must fail even though it is complete."""
    rogue_leaf_key = fx.ec_key()
    rogue_leaf = world.rogue_root.issue(
        subject=fx.dn("Impostor Issuer"),
        public_key=rogue_leaf_key.public_key(),
        extensions=fx.leaf_extensions(rogue_leaf_key, world.rogue_root.cert,
                                      did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
    )
    jwk = fx.ec_public_jwk(rogue_leaf_key, kid="rogue-1",
                           x5c=[rogue_leaf, world.rogue_root.cert])
    document = fx.build_did_document(world.issuer_a.did, jwk=jwk, fragment="rogue-1")
    online.serve(world.issuer_a.did_url, document)
    credential = fx.sign_jws_compact(
        fx.vc_payload(world.issuer_a.did), rogue_leaf_key,
        kid=f"{world.issuer_a.did}#rogue-1",
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "chain_untrusted_root")


def test_the_trusted_root_may_also_appear_inside_x5c_without_breaking_validation(
    verify, world, policy, store, online
):
    jwk = fx.ec_public_jwk(world.issuer_a.key, kid=world.issuer_a.fragment,
                           x5c=[world.issuer_a.cert, world.issuing.cert, world.root.cert])
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online))


def test_x5u_is_refused_by_default(verify, world, policy, store, online):
    jwk = fx.ec_public_jwk(world.issuer_a.key, kid=world.issuer_a.fragment, x5u=fx.CHAIN_URL_A)
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "x5u_not_allowed")


def test_x5u_works_online_when_policy_allows_it(verify, world, policy, store, online):
    jwk = fx.ec_public_jwk(world.issuer_a.key, kid=world.issuer_a.fragment, x5u=fx.CHAIN_URL_A)
    online.serve(world.issuer_a.did_url, _with_jwk(world, world.issuer_a, jwk))
    online.serve(fx.CHAIN_URL_A, fx.pem(world.issuer_a.cert) + fx.pem(world.issuing.cert))
    assert_accepted(verify(world.issuer_a.credential_jose,
                           policy=policy.replace(allow_x5u=True), store=store, transport=online))
