"""Check 15, CRL half. Issuer B's certificate carries a CRL distribution point.

The revocation window -- a CRL that is still inside its own nextUpdate but predates a
revocation -- is asserted here as intended behaviour, because it is the whole point of
part 3 of the demonstration.
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509

from tests import pkifixtures as fx
from tests.conftest import assert_accepted, assert_rejected

pytestmark = pytest.mark.unit


def _serve(online, payload):
    online.serve(fx.CRL_URL, payload)
    return online


def test_a_serial_absent_from_the_crl_is_accepted(verify, world, policy, store, online):
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    assert result.revocation.method == "crl"
    assert result.revocation.status == "good"


def test_a_serial_present_in_the_crl_is_rejected(verify, world, policy, store, online):
    _serve(online, world.crl(revoked_serials=[world.issuer_b.cert.serial_number]))
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online)
    assert_rejected(result, "revocation_revoked")
    assert result.revocation.reason == "privilegeWithdrawn"


def test_another_issuers_serial_on_the_crl_does_not_affect_this_one(
    verify, world, policy, store, online
):
    _serve(online, world.crl(revoked_serials=[world.issuer_a.cert.serial_number]))
    assert_accepted(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online))


def test_a_crl_whose_next_update_has_passed_is_rejected(verify, world, policy, store, online):
    """Brief verifier rule 3: reject if the revocation status is expired."""
    _serve(online, world.crl(
        last_update=fx.now() - dt.timedelta(hours=3),
        next_update=fx.now() - dt.timedelta(hours=2),
    ))
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online)
    assert_rejected(result, "revocation_expired")
    assert result.revocation.status == "expired"


def test_a_crl_signed_by_the_wrong_authority_is_rejected(verify, world, policy, store, online):
    _serve(online, fx.build_crl(issuer_cert=world.rogue_root.cert, issuer_key=world.rogue_root.key))
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_response_untrusted")


def test_a_crl_whose_issuer_name_matches_but_signature_does_not_is_rejected(
    verify, world, policy, store, online
):
    _serve(online, fx.build_crl(issuer_cert=world.issuing.cert, issuer_key=world.rogue_root.key))
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_response_untrusted")


def test_a_crl_that_is_not_der_is_rejected(verify, world, policy, store, online):
    _serve(online, b"404 not found")
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_unknown")


def test_an_unreachable_crl_with_no_cache_is_rejected(verify, world, policy, store, online):
    online.withdraw(fx.CRL_URL)
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_unknown")


def test_the_revocation_window_a_stale_but_unexpired_crl_still_accepts(
    verify, world, policy, store, online
):
    """Part 3 step 3, stated as a test.

    The certificate has been revoked in the CA's database, but the CRL on the server
    was published before that and has not yet reached its nextUpdate. The verifier
    accepts, and it is correct to accept. This is the revocation period.
    """
    published_before_revocation = world.crl(
        revoked_serials=[],
        last_update=fx.now() - dt.timedelta(minutes=30),
        next_update=fx.now() + dt.timedelta(minutes=30),
        crl_number=7,
    )
    _serve(online, published_before_revocation)
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    assert result.revocation.status == "good"


def test_publishing_the_new_crl_closes_the_window(verify, world, policy, store, online):
    _serve(online, world.crl(revoked_serials=[world.issuer_b.cert.serial_number], crl_number=8))
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_revoked")


def test_the_selected_one_hour_next_update_is_what_the_verifier_reports(
    verify, world, policy, store, online
):
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result)
    life = result.revocation.next_update - result.revocation.this_update
    assert life == dt.timedelta(hours=1)


def test_a_crl_older_than_the_policy_maximum_age_is_rejected_even_if_unexpired(
    verify, world, policy, store, online
):
    """Defence in depth: a CA that publishes a CRL with an absurd nextUpdate does not
    get to extend the verifier's own staleness tolerance."""
    _serve(online, world.crl(
        last_update=fx.now() - dt.timedelta(days=10),
        next_update=fx.now() + dt.timedelta(days=10),
    ))
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_stale")


def test_an_expired_crl_is_rejected_for_being_expired_even_when_it_lists_the_serial(
    verify, world, policy, store, online
):
    """Expiry is decided before the list is consulted.

    An expired CRL is not evidence about anything, so the verifier must say so rather than
    report a revocation it cannot currently stand behind.
    """
    _serve(online, world.crl(
        revoked_serials=[world.issuer_b.cert.serial_number],
        last_update=fx.now() - dt.timedelta(hours=3),
        next_update=fx.now() - dt.timedelta(hours=2),
    ))
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online),
                    "revocation_expired")


def test_a_crl_inside_the_clock_skew_tolerance_is_not_yet_expired(
    verify, world, policy, store, online
):
    """Why the expired-CRL scene dates the CRL in the past rather than waiting one out."""
    _serve(online, world.crl(
        last_update=fx.now() - dt.timedelta(seconds=10),
        next_update=fx.now() - dt.timedelta(seconds=5),
    ))
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online)
    assert_accepted(result), "5s past nextUpdate is inside the 30s skew the policy allows"


@pytest.mark.parametrize("flag,name", [
    (x509.ReasonFlags.privilege_withdrawn, "privilegeWithdrawn"),
    (x509.ReasonFlags.cessation_of_operation, "cessationOfOperation"),
    (x509.ReasonFlags.key_compromise, "keyCompromise"),
    (x509.ReasonFlags.ca_compromise, "cACompromise"),
    (x509.ReasonFlags.affiliation_changed, "affiliationChanged"),
    (x509.ReasonFlags.superseded, "superseded"),
    (x509.ReasonFlags.certificate_hold, "certificateHold"),
    (x509.ReasonFlags.unspecified, "unspecified"),
])
def test_every_reason_code_is_reported_by_its_x509_name(
    verify, world, policy, store, online, flag, name
):
    """The demonstration uses cessationOfOperation because openssl cannot express
    privilegeWithdrawn, but the verifier must report whatever a CA actually sends."""
    import datetime as _dt

    _serve(online, fx.build_crl(
        issuer_cert=world.issuing.cert, issuer_key=world.issuing.key,
        revoked=[(world.issuer_b.cert.serial_number, fx.now() - _dt.timedelta(minutes=1), flag)],
    ))
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=online)
    assert_rejected(result, "revocation_revoked")
    assert result.revocation.reason == name
