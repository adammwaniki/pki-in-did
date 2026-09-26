"""Checks 4, 5 and 6: did:web resolution and the DID Core authorization relationship."""

from __future__ import annotations

import copy

import pytest

from tests import pkifixtures as fx
from tests.conftest import assert_accepted, assert_rejected

pytestmark = pytest.mark.unit


def _serve_document(online, issuer, document):
    online.serve(issuer.did_url, document)
    return online


def test_resolution_failure_with_no_cache_is_rejected(verify, world, policy, store, online):
    online.withdraw(world.issuer_a.did_url)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "did_resolution_failed")


def test_a_document_that_is_not_json_is_rejected(verify, world, policy, store, online):
    _serve_document(online, world.issuer_a, b"<html>404</html>")
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "did_document_malformed")


def test_a_document_whose_id_does_not_match_the_did_is_rejected(
    verify, world, policy, store, online
):
    """did:web Read step 2, and DID Core resolution: the document's id must equal the DID."""
    document = copy.deepcopy(world.issuer_a.did_document)
    document["id"] = world.issuer_b.did
    _serve_document(online, world.issuer_a, document)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "did_document_id_mismatch")


def test_a_document_with_no_matching_verification_method_is_rejected(
    verify, world, policy, store, online
):
    """DID Core §5.3: a method absent from the latest document is revoked.

    This is DID-layer revocation -- independent of the PKI layer, and the reason the
    demonstration shows the DID document staying unchanged when the CA revokes.
    """
    document = copy.deepcopy(world.issuer_a.did_document)
    document["verificationMethod"] = []
    document["assertionMethod"] = []
    _serve_document(online, world.issuer_a, document)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "verification_method_not_found")


def test_a_key_listed_only_under_authentication_is_rejected(verify, world, policy, store, online):
    """Tab C: a key listed only under authentication is not valid for signing a VC."""
    document = fx.build_did_document(
        world.issuer_a.did, jwk=world.issuer_a.jwk, fragment=world.issuer_a.fragment,
        relationships=("authentication",),
    )
    _serve_document(online, world.issuer_a, document)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "not_in_assertion_method")


def test_an_assertion_method_entry_may_be_an_embedded_verification_method(
    verify, world, policy, store, online
):
    """DID Core permits embedding rather than referencing. Both must work."""
    document = {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/suites/jws-2020/v1"],
        "id": world.issuer_a.did,
        "assertionMethod": [{
            "id": world.issuer_a.vm_id,
            "type": "JsonWebKey2020",
            "controller": world.issuer_a.did,
            "publicKeyJwk": world.issuer_a.jwk,
        }],
    }
    _serve_document(online, world.issuer_a, document)
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online))


def test_a_relative_verification_method_id_inside_the_document_is_rejected(
    verify, world, policy, store, online
):
    """did:web's Key Material section: DID URLs in the document must be absolute."""
    document = fx.build_did_document(
        world.issuer_a.did, jwk=world.issuer_a.jwk, fragment=world.issuer_a.fragment,
        absolute_urls=False,
    )
    _serve_document(online, world.issuer_a, document)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "did_url_not_absolute")


def test_a_verification_method_controlled_by_another_did_is_rejected(
    verify, world, policy, store, online
):
    document = copy.deepcopy(world.issuer_a.did_document)
    document["verificationMethod"][0]["controller"] = world.issuer_b.did
    _serve_document(online, world.issuer_a, document)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "controller_mismatch")


def test_a_verification_method_without_public_key_jwk_is_rejected(
    verify, world, policy, store, online
):
    """DID Core §5.2.1 limits verification material; publicKeyMultibase carries no chain."""
    document = copy.deepcopy(world.issuer_a.did_document)
    del document["verificationMethod"][0]["publicKeyJwk"]
    document["verificationMethod"][0]["publicKeyMultibase"] = "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
    _serve_document(online, world.issuer_a, document)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "public_key_jwk_missing")


def test_a_jwk_carrying_private_key_material_is_rejected(verify, world, policy, store, online):
    """DID Core forbids private-class members such as `d` in publicKeyJwk."""
    document = copy.deepcopy(world.issuer_a.did_document)
    document["verificationMethod"][0]["publicKeyJwk"]["d"] = "AAAA"
    _serve_document(online, world.issuer_a, document)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online),
                    "jwk_contains_private_material")


def test_the_did_to_url_transformation_handles_a_path_based_did(verify, world, policy, store, online):
    """did:web:host:agency:health -> https://host/agency/health/did.json (no .well-known)."""
    from verifier.didweb import did_to_url

    assert did_to_url("did:web:example.gov") == "https://example.gov/.well-known/did.json"
    assert did_to_url("did:web:example.gov:agency:health") == "https://example.gov/agency/health/did.json"
    assert did_to_url("did:web:example.gov%3A8443") == "https://example.gov:8443/.well-known/did.json"


def test_an_ip_address_did_is_refused(verify, policy, store, online):
    """did:web forbids IP addresses as the method-specific identifier."""
    from verifier.didweb import did_to_url, DidWebError

    with pytest.raises(DidWebError):
        did_to_url("did:web:192.0.2.10")
