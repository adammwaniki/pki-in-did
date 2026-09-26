"""Check 15, OCSP half. Issuer A's certificate carries an AIA OCSP URI."""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp

from tests import pkifixtures as fx
from tests.conftest import assert_accepted, assert_rejected

pytestmark = pytest.mark.unit


def _serve(online, payload):
    online.serve(fx.OCSP_URL, lambda body: payload)
    return online


def test_status_good_is_accepted(verify, world, policy, store, online):
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    assert result.revocation.status == "good"


def test_status_revoked_is_rejected(verify, world, policy, store, online):
    """Part 2 of the demonstration: the CA withdrew the accreditation."""
    _serve(online, world.ocsp_revoked(world.issuer_a))
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_rejected(result, "revocation_revoked")
    assert result.revocation.status == "revoked"
    assert result.revocation.reason == "privilegeWithdrawn"


def test_status_unknown_is_rejected(verify, world, policy, store, online):
    _serve(online, world.ocsp_unknown(world.issuer_a))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_unknown")


def test_a_responder_that_cannot_be_reached_is_rejected(verify, world, policy, store, online):
    """Part 2 optional step: stop the responder. Unknown status, so reject."""
    online.withdraw(fx.OCSP_URL)
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_rejected(result, "revocation_unknown")
    assert result.revocation.status == "unknown"


def test_an_unsuccessful_ocsp_response_is_rejected(verify, world, policy, store, online):
    _serve(online, fx.build_unauthorized_ocsp_response())
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_unknown")


def test_a_response_that_is_not_der_is_rejected(verify, world, policy, store, online):
    _serve(online, b"<html>502 Bad Gateway</html>")
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_unknown")


def test_a_response_signed_by_a_rogue_certificate_is_rejected(verify, world, policy, store, online):
    """A convincing 'good' from an authority the Issuing CA never delegated to."""
    rogue_signer_key = fx.rsa_key()
    rogue_signer = world.rogue_root.issue(
        subject=fx.dn("Rogue OCSP Responder"), public_key=rogue_signer_key.public_key(),
        extensions=fx.ocsp_signer_extensions(rogue_signer_key, world.rogue_root.cert),
    )
    _serve(online, fx.build_ocsp_response(
        subject_cert=world.issuer_a.cert, issuer_cert=world.issuing.cert,
        responder_cert=rogue_signer, responder_key=rogue_signer_key,
    ))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_response_untrusted")


def test_a_responder_certificate_without_ocsp_signing_eku_is_rejected(
    verify, world, policy, store, online
):
    """Delegation to a responder is only valid with EKU id-kp-OCSPSigning."""
    key = fx.rsa_key()
    cert = world.issuing.issue(
        subject=fx.dn("Issuing CA Employee Without OCSPSigning"), public_key=key.public_key(),
        extensions=[
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (fx.digital_signature_key_usage(), True),
            (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
        ],
    )
    _serve(online, fx.build_ocsp_response(
        subject_cert=world.issuer_a.cert, issuer_cert=world.issuing.cert,
        responder_cert=cert, responder_key=key,
    ))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_response_untrusted")


def test_a_response_signed_directly_by_the_issuing_ca_is_accepted(
    verify, world, policy, store, online
):
    """RFC 6960 permits the issuing CA to sign its own OCSP responses."""
    _serve(online, fx.build_ocsp_response(
        subject_cert=world.issuer_a.cert, issuer_cert=world.issuing.cert,
        responder_cert=world.issuing.cert, responder_key=world.issuing.key,
        include_responder_chain=False,
    ))
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online))


def test_a_response_about_a_different_certificate_is_rejected(verify, world, policy, store, online):
    """A 'good' response for issuer B replayed at issuer A."""
    _serve(online, fx.build_ocsp_response(
        subject_cert=world.issuer_b.cert, issuer_cert=world.issuing.cert,
        responder_cert=world.ocsp_signer_cert, responder_key=world.ocsp_signer_key,
    ))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_response_mismatch")


def test_a_response_whose_next_update_has_passed_is_rejected(verify, world, policy, store, online):
    _serve(online, world.ocsp_good(
        world.issuer_a,
        this_update=fx.now() - dt.timedelta(minutes=30),
        next_update=fx.now() - dt.timedelta(minutes=25),
    ))
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_rejected(result, "revocation_expired")
    assert result.revocation.status == "expired"


def test_a_response_dated_in_the_future_beyond_clock_skew_is_rejected(
    verify, world, policy, store, online
):
    _serve(online, world.ocsp_good(
        world.issuer_a,
        this_update=fx.now() + dt.timedelta(minutes=10),
        next_update=fx.now() + dt.timedelta(minutes=20),
    ))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_response_not_yet_valid")


def test_a_response_within_clock_skew_is_tolerated(verify, world, policy, store, online):
    _serve(online, world.ocsp_good(
        world.issuer_a,
        this_update=fx.now() + dt.timedelta(seconds=10),
        next_update=fx.now() + dt.timedelta(minutes=5),
    ))
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online))


def test_the_selected_five_minute_response_life_is_what_the_verifier_reports(
    verify, world, policy, store, online
):
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    life = result.revocation.next_update - result.revocation.this_update
    assert life == dt.timedelta(minutes=5)


def test_a_leaf_with_no_revocation_source_at_all_is_rejected(verify, world, policy, store, online):
    key = fx.ec_key()
    leaf = world.issuing.issue(
        subject=fx.dn("Issuer With No Revocation Source"), public_key=key.public_key(),
        extensions=fx.leaf_extensions(key, world.issuing.cert, did=world.issuer_a.did),
    )
    jwk = fx.ec_public_jwk(key, kid="no-rev", x5c=[leaf, world.issuing.cert])
    online.serve(world.issuer_a.did_url,
                 fx.build_did_document(world.issuer_a.did, jwk=jwk, fragment="no-rev"))
    credential = fx.sign_jws_compact(fx.vc_payload(world.issuer_a.did), key,
                                     kid=f"{world.issuer_a.did}#no-rev")
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "revocation_source_missing")


def test_revocation_can_be_switched_off_by_policy(verify, world, policy, store, online):
    _serve(online, world.ocsp_revoked(world.issuer_a))
    result = verify(world.issuer_a.credential_jose,
                    policy=policy.replace(revocation_required=False), store=store, transport=online)
    assert_accepted(result)
    assert result.check("revocation_status").status == "skip"


def test_a_fresh_response_replaces_a_stale_cached_one(verify, world, policy, store, online):
    """Online, the network is authoritative: a cached 'good' does not mask a fresh 'revoked'."""
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(world.issuer_a))
    _serve(online, world.ocsp_revoked(world.issuer_a))
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_rejected(result, "revocation_revoked")
    assert result.revocation.source == "network"


def test_a_verifier_that_refuses_cached_data_reports_unknown_when_the_responder_is_down(
    verify, world, policy, store, online
):
    """Brief, part 2, optional step: stop the responder and the status is unknown.

    A verifier holding a fresh cached response would legitimately use it -- the brief's own
    comparison table says as much. This is the case where there is nothing usable to fall
    back on, which is what that step is really showing.
    """
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(world.issuer_a))
    online.withdraw(fx.OCSP_URL)

    using_cache = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(using_cache)
    assert using_cache.revocation.source == "cache"

    refusing_cache = verify(world.issuer_a.credential_jose,
                            policy=policy.replace(allow_cached_revocation=False),
                            store=store, transport=online)
    assert_rejected(refusing_cache, "revocation_unknown")


# ------------------------------------------------------- the nonce (RFC 6960 §4.4.1)

def test_a_nonce_is_sent_and_the_echo_is_accepted(verify, world, policy, store, online):
    """The happy path already relies on this: the fake responder echoes what it was sent."""
    captured: list[bytes | None] = []

    def responder(body):
        captured.append(fx.nonce_of_request(body))
        return world.ocsp_good(world.issuer_a, nonce=captured[-1])

    online.serve(fx.OCSP_URL, responder)
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=online))
    assert captured and captured[0] is not None, "the verifier sent no nonce"
    assert len(captured[0]) >= 16


def test_a_nonce_is_different_on_every_request(verify, world, policy, store, online):
    seen: list[bytes] = []

    def responder(body):
        seen.append(fx.nonce_of_request(body))
        return world.ocsp_good(world.issuer_a, nonce=seen[-1])

    online.serve(fx.OCSP_URL, responder)
    for _ in range(3):
        verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert len(set(seen)) == 3, "a reused nonce would not detect a replay"


def test_a_response_echoing_the_wrong_nonce_is_rejected(verify, world, policy, store, online):
    """A captured response replayed against a new question."""
    _serve(online, world.ocsp_good(world.issuer_a, nonce=b"\x01" * 16))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=online),
                    "revocation_response_nonce_mismatch")


def test_a_responder_that_omits_the_nonce_is_still_accepted(verify, world, policy, store, online):
    """Many responders pre-sign answers and cannot echo a nonce.

    An absent nonce is not a failure; freshness then rests on thisUpdate and nextUpdate.
    """
    _serve(online, world.ocsp_good(world.issuer_a))
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=online))


def test_a_cached_response_is_not_failed_for_its_old_nonce(
    verify, world, policy, store, offline
):
    """The nonce in a cached response answers a request we no longer hold."""
    store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert,
                   world.ocsp_good(world.issuer_a, nonce=b"\x02" * 16))
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=offline)
    assert_accepted(result)
    assert result.revocation.source == "cache"


# ------------------------------------------ the delegated responder, wherever it sits

def test_the_delegated_responder_is_found_even_if_it_is_not_first(
    verify, world, policy, store, online
):
    """A responder may ship several certificates, in any order."""
    from cryptography.hazmat.primitives import serialization

    # A decoy the CA also issued, without OCSPSigning, placed ahead of the real signer.
    decoy_key = fx.rsa_key()
    decoy = world.issuing.issue(
        subject=fx.dn("Some Other Certificate From The Same CA"),
        public_key=decoy_key.public_key(),
        extensions=[
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (fx.digital_signature_key_usage(), True),
        ],
    )
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=world.issuer_a.cert, issuer=world.issuing.cert, algorithm=hashes.SHA256(),
        cert_status=ocsp.OCSPCertStatus.GOOD, this_update=fx.now(),
        next_update=fx.now() + dt.timedelta(minutes=5),
        revocation_time=None, revocation_reason=None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, world.ocsp_signer_cert) \
     .certificates([decoy, world.ocsp_signer_cert])
    _serve(online, builder.sign(world.ocsp_signer_key, hashes.SHA256())
           .public_bytes(serialization.Encoding.DER))

    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=online))
