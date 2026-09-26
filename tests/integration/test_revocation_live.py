"""Parts 3 and 4 of the recording, against the live stack.

These tests mutate the CA database and the published CRL, so each is written as one
ordered sequence and each restores the stack with `00-reset.sh` afterwards.
"""

from __future__ import annotations

import time

import pytest

from .conftest import REVOCATION_REASON, script, verify_json

pytestmark = [pytest.mark.integration, pytest.mark.slow]


@pytest.fixture
def fresh_stack():
    """Put revocation status back, without reissuing anything.

    A full reset regenerates every key and credential and takes minutes; nothing about a
    revocation needs that, since the certificates themselves do not change. The full reset
    is exercised by test_reproducibility.py instead.
    """
    script("90-restore-revocations.sh")
    yield
    script("90-restore-revocations.sh")


def test_ocsp_revocation_is_visible_at_the_next_verification(fresh_stack):
    """Part 3, OCSP: revoke, show did.json unchanged, verify again.

    The reason asserted is whatever config/domains.env sets, so this test follows the
    demonstration's choice rather than pinning one of its own.
    """
    before = verify_json("issuer-a-vc-jose.jwt")
    assert before["accepted"] is True

    document_before = (script("30-did-documents.sh", "--print", "a").stdout)

    script("60-revoke.sh", "a")

    document_after = (script("30-did-documents.sh", "--print", "a").stdout)
    assert document_before == document_after, \
        "the DID document must not change when the CA withdraws accreditation"

    after = verify_json("issuer-a-vc-jose.jwt")
    assert after["accepted"] is False
    assert after["reason"] == "revocation_revoked"
    assert after["revocation"]["status"] == "revoked"
    assert after["revocation"]["reason"] == REVOCATION_REASON


def test_a_stopped_responder_produces_unknown_and_a_rejection(fresh_stack):
    """Part 3 optional step: stop the OCSP responder.

    Two behaviours, both correct. A verifier holding a fresh cached answer uses it -- the
    brief's own comparison table says as much. A verifier with nothing to fall back on
    cannot establish a status, and unknown is a rejection.
    """
    assert verify_json("issuer-a-vc-jose.jwt")["accepted"] is True
    script("responder.sh", "stop")
    try:
        using_cache = verify_json("issuer-a-vc-jose.jwt")
        assert using_cache["accepted"] is True
        assert using_cache["revocation"]["source"] == "cache"

        no_cache = verify_json("issuer-a-vc-jose.jwt", no_cached_revocation=True)
        assert no_cache["accepted"] is False
        assert no_cache["reason"] == "revocation_unknown"
        assert no_cache["revocation"]["status"] == "unknown"
    finally:
        script("responder.sh", "start")


def test_the_crl_revocation_window_then_its_closure(fresh_stack):
    """Part 3, CRL: the three-step story the brief asks for."""
    assert verify_json("issuer-b-vc-jose.jwt")["accepted"] is True

    # 1. Revoke in the CA database, publish nothing.
    script("60-revoke.sh", "b", "--no-publish")

    # 2. The published CRL is unchanged and not yet expired, so the verifier accepts.
    during = verify_json("issuer-b-vc-jose.jwt")
    assert during["accepted"] is True, "this is the revocation period, and accepting is correct"
    assert during["revocation"]["status"] == "good"

    # 3. Publish the new CRL. The serial is now listed.
    script("50-publish-crl.sh")
    after = verify_json("issuer-b-vc-jose.jwt")
    assert after["accepted"] is False
    assert after["reason"] == "revocation_revoked"
    assert after["revocation"]["reason"] == REVOCATION_REASON


def test_an_expired_crl_is_rejected_even_though_it_lists_nothing(fresh_stack):
    """Part 3 optional step 5."""
    script("expire-crl.sh")
    result = verify_json("issuer-b-vc-jose.jwt")
    assert result["accepted"] is False
    assert result["reason"] == "revocation_expired"


def test_offline_learns_of_an_ocsp_revocation_only_after_the_cache_is_refreshed(fresh_stack):
    """Part 4, OCSP half: what a disconnected laptop can and cannot know."""
    script("80-seed-offline-cache.sh")
    assert verify_json("issuer-a-vc-jose.jwt", offline=True)["accepted"] is True

    script("60-revoke.sh", "a")

    # Still offline with the old cached response: the laptop cannot know yet.
    stale = verify_json("issuer-a-vc-jose.jwt", offline=True)
    assert stale["accepted"] is True
    assert stale["revocation"]["source"] == "cache"

    # One online verification refreshes the cache, and the rejection then persists offline.
    online = verify_json("issuer-a-vc-jose.jwt")
    assert online["accepted"] is False and online["reason"] == "revocation_revoked"

    refreshed = verify_json("issuer-a-vc-jose.jwt", offline=True)
    assert refreshed["accepted"] is False
    assert refreshed["reason"] == "revocation_revoked"
    assert refreshed["revocation"]["source"] == "cache"


def test_offline_learns_of_a_crl_revocation_only_after_a_new_crl_is_cached(fresh_stack):
    """Part 4, CRL half."""
    script("80-seed-offline-cache.sh")
    assert verify_json("issuer-b-vc-jose.jwt", offline=True)["accepted"] is True

    script("60-revoke.sh", "b")  # revokes and publishes a new CRL

    stale = verify_json("issuer-b-vc-jose.jwt", offline=True)
    assert stale["accepted"] is True, "the cached CRL predates the revocation and has not expired"

    script("80-seed-offline-cache.sh")  # the laptop gets the new CRL
    refreshed = verify_json("issuer-b-vc-jose.jwt", offline=True)
    assert refreshed["accepted"] is False
    assert refreshed["reason"] == "revocation_revoked"


def test_a_cached_answer_goes_stale_under_a_narrower_policy(fresh_stack):
    """How long a cached answer counts is a policy decision, not a property of the credential.

    The same cache is fresh enough for one policy and too old for another, at the same
    instant. A verifier that cannot date its evidence must refuse rather than guess.
    """
    script("80-seed-offline-cache.sh")

    strict = "/laptop/policy-strict.json"
    fresh = verify_json("issuer-a-vc-jose.jwt", offline=True, policy=strict)
    assert fresh["accepted"] is True, fresh["reason"]
    assert fresh["revocation"]["source"] == "cache"

    # The strict policy trusts a cached answer for 30 seconds rather than the default's
    # five minutes, so the window can be waited out without a long test.
    time.sleep(33)
    stale = verify_json("issuer-a-vc-jose.jwt", offline=True, policy=strict)
    assert stale["accepted"] is False
    assert stale["reason"] in ("revocation_expired", "revocation_stale")

    # Nothing was revoked and nothing expired at the authority: the default policy still
    # accepts the very same cache.
    assert verify_json("issuer-a-vc-jose.jwt", offline=True)["accepted"] is True
