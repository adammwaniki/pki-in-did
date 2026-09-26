"""Offline verification -- the capability this demonstration exists to show.

The transport here raises on every call, which is what `docker run --network none`
looks like from inside the container. Nothing but the laptop's own store is available.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tests import pkifixtures as fx
from tests.conftest import DeadTransport, assert_accepted, assert_rejected

pytestmark = [pytest.mark.unit, pytest.mark.offline]


def test_both_credentials_verify_offline_from_a_primed_cache(
    verify, world, policy, seeded_store, offline
):
    """Part 2 of the recording: happy path with no network at all."""
    a = verify(world.issuer_a.credential_jose, policy=policy, store=seeded_store, transport=offline)
    assert_accepted(a)
    assert a.revocation.method == "ocsp"
    assert a.revocation.source == "cache"

    b = verify(world.issuer_b.credential_jose, policy=policy, store=seeded_store, transport=offline)
    assert_accepted(b)
    assert b.revocation.method == "crl"
    assert b.revocation.source == "cache"


def test_the_did_document_comes_from_the_cache_offline(verify, world, policy, seeded_store, offline):
    result = verify(world.issuer_a.credential_jose, policy=policy, store=seeded_store, transport=offline)
    assert_accepted(result)
    assert result.check("did_document_resolved").detail.lower().count("cache") == 1


def test_offline_with_no_cached_did_document_is_rejected(verify, world, policy, store, offline):
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=offline),
                    "did_resolution_failed")


def test_offline_with_a_cached_did_document_but_no_revocation_data_is_rejected(
    verify, world, policy, store, offline
):
    """Brief verifier rule 3: unknown revocation status is a rejection, offline included."""
    store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=offline)
    assert_rejected(result, "revocation_unknown")
    assert result.revocation.status == "unknown"


def test_a_cached_ocsp_response_past_its_next_update_is_rejected_offline(
    verify, world, policy, store, offline
):
    store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(
        world.issuer_a,
        this_update=fx.now() - dt.timedelta(minutes=20),
        next_update=fx.now() - dt.timedelta(minutes=15),
    ))
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=offline)
    assert_rejected(result, "revocation_expired")
    assert result.revocation.source == "cache"


def test_a_cached_crl_past_its_next_update_is_rejected_offline(verify, world, policy, store, offline):
    store.put_did_document(world.issuer_b.did, world.issuer_b.did_document)
    store.put_crl(world.issuing.cert, world.crl(
        last_update=fx.now() - dt.timedelta(hours=3),
        next_update=fx.now() - dt.timedelta(hours=2),
    ))
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=offline),
                    "revocation_expired")


def test_a_cached_revoked_ocsp_response_rejects_offline(verify, world, policy, store, offline):
    """Part 4 of the recording: the laptop learned of the revocation, then went offline."""
    store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_revoked(world.issuer_a))
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=offline)
    assert_rejected(result, "revocation_revoked")
    assert result.revocation.source == "cache"


def test_a_cached_crl_predating_the_revocation_still_accepts_offline(
    verify, world, policy, store, offline
):
    """The offline revocation window: the laptop cannot know yet, and says so honestly."""
    store.put_did_document(world.issuer_b.did, world.issuer_b.did_document)
    store.put_crl(world.issuing.cert, world.crl(
        revoked_serials=[],
        last_update=fx.now() - dt.timedelta(minutes=10),
        next_update=fx.now() + dt.timedelta(minutes=50),
    ))
    result = verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=offline)
    assert_accepted(result)
    assert result.revocation.source == "cache"


def test_a_cached_crl_naming_the_serial_rejects_offline(verify, world, policy, store, offline):
    store.put_did_document(world.issuer_b.did, world.issuer_b.did_document)
    store.put_crl(world.issuing.cert, world.crl(
        revoked_serials=[world.issuer_b.cert.serial_number], crl_number=9))
    assert_rejected(verify(world.issuer_b.credential_jose, policy=policy, store=store, transport=offline),
                    "revocation_revoked")


def test_offline_never_opens_a_socket(verify, world, policy, seeded_store, monkeypatch):
    """The verifier must not reach the network when the transport says there is none.

    Asserted by making any socket construction an error, not by trusting our own code.
    """
    import socket

    def explode(*args, **kwargs):  # pragma: no cover - only runs on failure
        raise AssertionError("the verifier tried to open a socket while offline")

    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    assert_accepted(
        verify(world.issuer_a.credential_jose, policy=policy, store=seeded_store,
               transport=DeadTransport())
    )


def test_x5c_verifies_offline_where_x5u_cannot(verify, world, policy, store, offline):
    """The reason this demonstration puts the chain inside the DID document.

    Tab C: the x5c-in-did.json approach is best where relying parties are offline-capable.
    An x5u reference is a network dependency by construction.
    """
    x5u_jwk = fx.ec_public_jwk(world.issuer_a.key, kid=world.issuer_a.fragment, x5u=fx.CHAIN_URL_A)
    x5u_document = fx.build_did_document(
        world.issuer_a.did, jwk=x5u_jwk, fragment=world.issuer_a.fragment)

    store.put_did_document(world.issuer_a.did, x5u_document)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(world.issuer_a))
    assert_rejected(
        verify(world.issuer_a.credential_jose, policy=policy.replace(allow_x5u=True),
               store=store, transport=offline),
        "x5u_fetch_failed",
    )

    store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    assert_accepted(
        verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=offline)
    )


def test_a_cached_did_document_is_still_checked_not_merely_trusted(
    verify, world, policy, store, offline
):
    """Cache is a copy of evidence, not a verdict. Every check runs against it again."""
    tampered = fx.build_did_document(
        world.issuer_a.did,
        jwk=fx.ec_public_jwk(fx.ec_key(), kid=world.issuer_a.fragment,
                             x5c=[world.issuer_a.cert, world.issuing.cert]),
        fragment=world.issuer_a.fragment,
    )
    store.put_did_document(world.issuer_a.did, tampered)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(world.issuer_a))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=offline),
                    "spki_jwk_mismatch")


def test_the_root_certificate_is_the_only_trust_anchor_offline_too(
    verify, world, policy, store, offline, tmp_path
):
    from verifier.store import LaptopStore

    empty = tmp_path / "no-anchors"
    (empty / "trust").mkdir(parents=True)
    bare = LaptopStore(empty)
    bare.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    bare.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(world.issuer_a))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=bare, transport=offline),
                    "no_trust_anchors")
