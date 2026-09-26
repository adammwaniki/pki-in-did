"""Check 13: RFC 5280 path validation to the National Root CA, and nothing else."""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509

from tests import fixtures as fx
from tests.conftest import assert_accepted, assert_rejected

pytestmark = pytest.mark.unit


def _publish(world, online, *, key, cert, chain, did=None, fragment="test-key"):
    """Publish a JWK for `cert` at issuer A's DID and return a credential signed by `key`."""
    did = did or world.issuer_a.did
    jwk = fx.ec_public_jwk(key, kid=fragment, x5c=chain)
    online.serve(world.issuer_a.did_url,
                 fx.build_did_document(did, jwk=jwk, fragment=fragment))
    return fx.sign_jws_compact(fx.vc_payload(did), key, kid=f"{did}#{fragment}")


def test_an_unknown_root_is_rejected(verify, world, policy, store, online):
    key = fx.ec_key()
    leaf = world.rogue_root.issue(
        subject=fx.dn("Impostor"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, world.rogue_root.cert,
                                      did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
    )
    credential = _publish(world, online, key=key, cert=leaf,
                          chain=[leaf, world.rogue_root.cert])
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "chain_untrusted_root")


def test_a_chain_missing_its_intermediate_is_rejected(verify, world, policy, store, online):
    """The leaf alone cannot reach the root: the Issuing CA must be in x5c."""
    credential = _publish(world, online, key=world.issuer_a.key, cert=world.issuer_a.cert,
                          chain=[world.issuer_a.cert], fragment=world.issuer_a.fragment)
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "chain_incomplete")


def test_an_expired_leaf_is_rejected(verify, world, policy, store, online):
    key = fx.ec_key()
    leaf = world.issuing.issue(
        subject=fx.dn("Expired Issuer"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, world.issuing.cert,
                                      did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
        not_before=fx.now() - dt.timedelta(days=800),
        not_after=fx.now() - dt.timedelta(days=1),
    )
    credential = _publish(world, online, key=key, cert=leaf, chain=[leaf, world.issuing.cert])
    online.serve(fx.OCSP_URL, lambda body: fx.build_ocsp_response(
        subject_cert=leaf, issuer_cert=world.issuing.cert,
        responder_cert=world.ocsp_signer_cert, responder_key=world.ocsp_signer_key,
    ))
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "certificate_expired")


def test_a_not_yet_valid_leaf_is_rejected(verify, world, policy, store, online):
    key = fx.ec_key()
    leaf = world.issuing.issue(
        subject=fx.dn("Future Issuer"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, world.issuing.cert,
                                      did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
        not_before=fx.now() + dt.timedelta(days=1),
        not_after=fx.now() + dt.timedelta(days=400),
    )
    credential = _publish(world, online, key=key, cert=leaf, chain=[leaf, world.issuing.cert])
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "certificate_not_yet_valid")


def test_a_leaf_signed_by_a_certificate_that_is_not_a_ca_is_rejected(
    verify, world, policy, store, online
):
    """basicConstraints CA:FALSE means it may not issue, however well it signs."""
    fake_ca_key = fx.ec_key()
    fake_ca = fx.Authority(key=fake_ca_key, cert=world.issuer_a.cert)
    key = fx.ec_key()
    leaf = fake_ca.issue(
        subject=fx.dn("Child Of A Leaf"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, world.issuer_a.cert,
                                      did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
        issuer_name=world.issuer_a.cert.subject,
        signing_key=world.issuer_a.key,
    )
    credential = _publish(world, online, key=key, cert=leaf,
                          chain=[leaf, world.issuer_a.cert, world.issuing.cert])
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "chain_not_a_ca")


def test_a_path_longer_than_path_len_zero_is_rejected(verify, world, policy, store, online):
    """The Issuing CA carries pathlen:0, so it may not certify another CA."""
    sub_ca_key = fx.rsa_key()
    sub_ca = world.issuing.issue(
        subject=fx.dn("Unauthorised Sub CA"), public_key=sub_ca_key.public_key(),
        extensions=fx.ca_extensions(sub_ca_key, world.issuing.cert, path_length=None),
    )
    sub = fx.Authority(key=sub_ca_key, cert=sub_ca)
    key = fx.ec_key()
    leaf = sub.issue(
        subject=fx.dn("Issuer Under Sub CA"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, sub_ca, did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
    )
    credential = _publish(world, online, key=key, cert=leaf,
                          chain=[leaf, sub_ca, world.issuing.cert])
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "chain_path_len_exceeded")


def test_a_ca_without_key_cert_sign_is_rejected(verify, world, policy, store, online):
    bad_ca_key = fx.rsa_key()
    bad_ca = world.root.issue(
        subject=fx.dn("CA Without KeyCertSign"), public_key=bad_ca_key.public_key(),
        extensions=[
            (x509.BasicConstraints(ca=True, path_length=0), True),
            (fx.digital_signature_key_usage(), True),
            (x509.SubjectKeyIdentifier.from_public_key(bad_ca_key.public_key()), False),
        ],
    )
    authority = fx.Authority(key=bad_ca_key, cert=bad_ca)
    key = fx.ec_key()
    leaf = authority.issue(
        subject=fx.dn("Issuer Under Bad CA"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, bad_ca, did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
    )
    credential = _publish(world, online, key=key, cert=leaf, chain=[leaf, bad_ca])
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "chain_ca_cannot_sign_certificates")


def test_a_forged_signature_in_the_chain_is_rejected(verify, world, policy, store, online):
    """A certificate that names the Issuing CA as issuer but was signed by someone else."""
    key = fx.ec_key()
    forger = fx.Authority(key=world.rogue_root.key, cert=world.issuing.cert)
    leaf = forger.issue(
        subject=fx.dn("Forged Issuer"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, world.issuing.cert,
                                      did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
        issuer_name=world.issuing.cert.subject,
        signing_key=world.rogue_root.key,
    )
    credential = _publish(world, online, key=key, cert=leaf, chain=[leaf, world.issuing.cert])
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "chain_signature_invalid")


def test_a_chain_whose_names_do_not_link_up_is_rejected(verify, world, policy, store, online):
    """Leaf's issuer DN names an authority that is not the next certificate in x5c."""
    key = fx.ec_key()
    leaf = world.issuing.issue(
        subject=fx.dn("Mislinked Issuer"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, world.issuing.cert,
                                      did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
        issuer_name=fx.dn("Some Other Authority"),
    )
    credential = _publish(world, online, key=key, cert=leaf, chain=[leaf, world.issuing.cert])
    result = verify(credential, policy=policy, store=store, transport=online)
    assert not result.accepted
    assert result.reason in ("chain_name_mismatch", "chain_incomplete")


def test_a_chain_deeper_than_the_policy_allows_is_rejected(verify, world, policy, store, online):
    credential = _publish(world, online, key=world.issuer_a.key, cert=world.issuer_a.cert,
                          chain=[world.issuer_a.cert, world.issuing.cert],
                          fragment=world.issuer_a.fragment)
    assert_rejected(
        verify(credential, policy=policy.replace(max_chain_depth=1), store=store, transport=online),
        "chain_too_long",
    )


def test_the_web_tls_root_is_not_a_credential_trust_anchor(verify, world, policy, store, online, tmp_path):
    """The two PKI layers must not be interchangeable.

    A certificate chaining to the Web-TLS root is rejected even though that root is
    perfectly trusted for TLS, because it is not in the credential trust anchor store.
    """
    tls_root_key = fx.rsa_key()
    tls_root = fx.Authority(key=tls_root_key, cert=fx.self_signed_root("DemoWebTLS Root", tls_root_key))
    key = fx.ec_key()
    leaf = tls_root.issue(
        subject=fx.dn("Issuer Certified By The TLS Root"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, tls_root.cert,
                                      did=world.issuer_a.did, ocsp_url=fx.OCSP_URL),
    )
    credential = _publish(world, online, key=key, cert=leaf, chain=[leaf, tls_root.cert])
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "chain_untrusted_root")


def test_the_happy_chain_reports_the_anchor_it_reached(verify, world, policy, store, online):
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    detail = result.check("certification_path").detail
    assert fx.NRCA_CN in detail
