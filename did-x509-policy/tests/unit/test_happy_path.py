"""The two credentials the verifier must accept, and the shape of a verification."""

from __future__ import annotations

import datetime as dt

import pytest

from tests import fixtures as fx
from tests.conftest import assert_accepted, assert_rejected

pytestmark = pytest.mark.unit

EXPECTED_CHECKS = [
    "credential_parsed",
    "alg_allowed",
    "issuer_matches_key_reference",
    "did_document_resolved",
    "did_document_id",
    "verification_method_authorized",
    "x5c_present",
    "x5t_matches_leaf",
    "jwk_matches_leaf_spki",
    "credential_signature",
    "san_uri_matches_did",
    "key_usage_digital_signature",
    "certification_path",
    "issuer_authorization",
    "revocation_status",
]


def test_issuer_a_credential_is_accepted_with_ocsp_good(verify, world, policy, store, online):
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    assert result.revocation.method == "ocsp"
    assert result.revocation.status == "good"
    assert result.revocation.source == "network"


def test_issuer_b_credential_is_accepted_when_serial_absent_from_crl(
    verify, world, policy, store, online
):
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    assert result.revocation.method == "crl"
    assert result.revocation.status == "good"
    assert result.revocation.source == "network"


def test_data_integrity_credential_is_accepted(verify, world, policy, store, online):
    """The source document's §4 proof shape: proof.jws + proof.verificationMethod."""
    result = verify(world.issuer_a.credential_di, policy=policy, store=store, transport=online)
    assert_accepted(result)


def test_every_check_runs_in_the_documented_order(verify, world, policy, store, online):
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert [c.key for c in result.checks] == EXPECTED_CHECKS
    assert [c.number for c in result.checks] == list(range(1, len(EXPECTED_CHECKS) + 1))
    assert all(c.status == "pass" for c in result.checks), result.reason


def test_accepted_result_has_no_reason_and_rejected_result_names_the_failing_check(
    verify, world, policy, store, online
):
    ok = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert ok.reason is None
    assert ok.failed_check is None

    tampered = world.issuer_a.credential_jose[:-4] + "AAAA"
    bad = verify(tampered, policy=policy, store=store, transport=online)
    assert not bad.accepted
    assert bad.failed_check.key == "credential_signature"
    assert bad.reason == "signature_invalid"


def test_resolution_writes_through_to_the_cache(verify, world, policy, store, online):
    assert store.get_did_document(world.issuer_a.did) is None
    verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    cached = store.get_did_document(world.issuer_a.did)
    assert cached is not None
    assert cached.document == world.issuer_a.did_document
    assert store.get_ocsp(world.issuer_a.cert, world.issuing.cert) is not None


def test_the_did_url_is_derived_per_the_did_web_read_algorithm(verify, world, policy, store, online):
    verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert f"https://{fx.ISSUER_A_DOMAIN}/.well-known/did.json" in online.gets


def test_a_credential_not_yet_valid_is_rejected(verify, world, policy, store, online):
    payload = fx.vc_payload(world.issuer_a.did, valid_from=fx.now() + dt.timedelta(hours=1))
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert_rejected(
        verify(credential, policy=policy, store=store, transport=online),
        "credential_not_yet_valid",
    )


def test_an_expired_credential_is_rejected(verify, world, policy, store, online):
    payload = fx.vc_payload(
        world.issuer_a.did,
        valid_from=fx.now() - dt.timedelta(days=2),
        valid_until=fx.now() - dt.timedelta(days=1),
    )
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert_rejected(
        verify(credential, policy=policy, store=store, transport=online),
        "credential_expired",
    )
