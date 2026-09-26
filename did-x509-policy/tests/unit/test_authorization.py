"""Checks 11, 12 and 14: the profile rules that turn a valid chain into an accreditation."""

from __future__ import annotations

import pytest
from cryptography import x509

from tests import fixtures as fx
from tests.conftest import assert_accepted, assert_rejected

pytestmark = pytest.mark.unit


def _issue_leaf(world, online, *, extensions, fragment="profile-key", did=None):
    did = did or world.issuer_a.did
    key = fx.ec_key()
    leaf = world.issuing.issue(
        subject=fx.dn("Profile Test Issuer"), public_key=key.public_key(),
        extensions=extensions(key),
    )
    jwk = fx.ec_public_jwk(key, kid=fragment, x5c=[leaf, world.issuing.cert])
    online.serve(world.issuer_a.did_url, fx.build_did_document(did, jwk=jwk, fragment=fragment))
    online.serve(fx.OCSP_URL, lambda body: fx.build_ocsp_response(
        subject_cert=leaf, issuer_cert=world.issuing.cert,
        responder_cert=world.ocsp_signer_cert, responder_key=world.ocsp_signer_key,
    ))
    credential = fx.sign_jws_compact(fx.vc_payload(did), key, kid=f"{did}#{fragment}")
    return credential, leaf


def test_a_san_uri_that_does_not_equal_the_did_is_rejected(verify, world, policy, store, online):
    credential, _ = _issue_leaf(
        world, online,
        extensions=lambda key: fx.leaf_extensions(
            key, world.issuing.cert, did=world.issuer_b.did, ocsp_url=fx.OCSP_URL),
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "san_uri_mismatch")


def test_a_leaf_with_no_san_at_all_is_rejected(verify, world, policy, store, online):
    credential, _ = _issue_leaf(
        world, online,
        extensions=lambda key: [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (fx.digital_signature_key_usage(), True),
            (fx.accreditation_policy(), False),
            (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
            (x509.AuthorityInformationAccess([
                x509.AccessDescription(x509.AuthorityInformationAccessOID.OCSP,
                                       x509.UniformResourceIdentifier(fx.OCSP_URL))]), False),
        ],
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "san_uri_mismatch")


def test_a_dns_san_is_not_accepted_in_place_of_the_uri_san(verify, world, policy, store, online):
    credential, _ = _issue_leaf(
        world, online,
        extensions=lambda key: fx.leaf_extensions(
            key, world.issuing.cert, did=world.issuer_a.did, ocsp_url=fx.OCSP_URL,
            san=x509.SubjectAlternativeName([x509.DNSName(fx.ISSUER_A_DOMAIN)]),
        ),
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "san_uri_mismatch")


def test_a_leaf_without_digital_signature_key_usage_is_rejected(verify, world, policy, store, online):
    key_agreement_only = x509.KeyUsage(
        digital_signature=False, content_commitment=True, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    )
    credential, _ = _issue_leaf(
        world, online,
        extensions=lambda key: fx.leaf_extensions(
            key, world.issuing.cert, did=world.issuer_a.did, ocsp_url=fx.OCSP_URL,
            key_usage=key_agreement_only,
        ),
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "key_usage_missing_digital_signature")


def test_a_leaf_without_the_accreditation_policy_oid_is_rejected(verify, world, policy, store, online):
    """Tab C verifier step 5: a valid chain proves who certified the key, not what it may issue."""
    credential, _ = _issue_leaf(
        world, online,
        extensions=lambda key: fx.leaf_extensions(
            key, world.issuing.cert, did=world.issuer_a.did, ocsp_url=fx.OCSP_URL,
            policy_oid=None),
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "issuer_not_authorized_for_type")


def test_a_leaf_carrying_an_unrelated_policy_oid_is_rejected(verify, world, policy, store, online):
    credential, _ = _issue_leaf(
        world, online,
        extensions=lambda key: fx.leaf_extensions(
            key, world.issuing.cert, did=world.issuer_a.did, ocsp_url=fx.OCSP_URL,
            policy_oid="1.3.6.1.4.1.99999.9.9"),
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "issuer_not_authorized_for_type")


def test_a_credential_type_outside_the_accreditation_is_rejected(verify, world, policy, store, online):
    """The certificate is accredited for AccreditedOperatorCredential, not for this one."""
    payload = fx.vc_payload(world.issuer_a.did, types=("VerifiableCredential", "PassportCredential"))
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "issuer_not_authorized_for_type")


def test_authorization_can_be_switched_off_by_policy(verify, world, policy, store, online):
    payload = fx.vc_payload(world.issuer_a.did, types=("VerifiableCredential", "PassportCredential"))
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    result = verify(credential, policy=policy.replace(require_issuer_authorization=False),
                    store=store, transport=online)
    assert_accepted(result)
    assert result.check("issuer_authorization").status == "skip"
