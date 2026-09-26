"""Check 1 and 2: parsing, algorithm allow-listing, and the issuer/kid linkage."""

from __future__ import annotations

import json

import pytest

from tests import fixtures as fx
from tests.conftest import assert_rejected

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "credential",
    [
        pytest.param("", id="empty"),
        pytest.param("not-a-credential", id="not-jws"),
        pytest.param("a.b", id="two-segments"),
        pytest.param("a.b.c.d", id="four-segments"),
        pytest.param("!!!.!!!.!!!", id="not-base64url"),
        pytest.param("e30.e30.AAAA", id="header-without-alg"),
        pytest.param("{}", id="bare-json-object"),
        pytest.param('{"type":["VerifiableCredential"]}', id="vc-without-proof"),
    ],
)
def test_unparseable_credentials_are_rejected(verify, policy, store, online, credential):
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "malformed_credential")


def test_alg_none_is_rejected(verify, world, policy, store, online):
    credential = fx.sign_jws_compact(
        fx.vc_payload(world.issuer_a.did), world.issuer_a.key,
        kid=world.issuer_a.vm_id, alg="none",
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "alg_not_allowed")


def test_an_algorithm_outside_the_allow_list_is_rejected(verify, world, policy, store, online):
    """An RSA key and RS256 are perfectly valid JOSE. Policy still says ES256 only."""
    rsa = fx.rsa_key()
    credential = fx.sign_jws_compact(
        fx.vc_payload(world.issuer_a.did), rsa, kid=world.issuer_a.vm_id, alg="RS256",
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "alg_not_allowed")


def test_algorithm_substitution_does_not_get_past_the_signature_check(
    verify, world, policy, store, online
):
    """Header claims ES256; the bytes were actually signed with a different key."""
    other = fx.ec_key()
    credential = fx.sign_jws_compact(
        fx.vc_payload(world.issuer_a.did), other, kid=world.issuer_a.vm_id,
    )
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "signature_invalid")


def test_a_credential_without_a_key_reference_is_rejected(verify, world, policy, store, online):
    header = {"alg": "ES256", "typ": "vc+jwt"}
    payload = fx.vc_payload(world.issuer_a.did)
    signing_input = f"{fx.b64u(fx.jcs(header))}.{fx.b64u(fx.jcs(payload))}"
    assert_rejected(
        verify(f"{signing_input}.{fx.b64u(b'x' * 64)}", policy=policy, store=store, transport=online),
        "key_reference_missing",
    )


def test_a_credential_without_an_issuer_is_rejected(verify, world, policy, store, online):
    payload = fx.vc_payload(world.issuer_a.did)
    del payload["issuer"]
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "malformed_credential")


def test_kid_pointing_at_a_different_did_than_the_issuer_is_rejected(
    verify, world, policy, store, online
):
    """Issuer A's key signing a credential that claims issuer B."""
    payload = fx.vc_payload(world.issuer_b.did)
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "kid_issuer_mismatch")


def test_a_relative_key_reference_is_rejected(verify, world, policy, store, online):
    """did:web requires every DID URL inside the document to be absolute."""
    payload = fx.vc_payload(world.issuer_a.did)
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=f"#{world.issuer_a.fragment}")
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "key_reference_not_absolute")


def test_an_unsupported_did_method_is_rejected(verify, world, policy, store, online):
    payload = fx.vc_payload("did:example:not-web")
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid="did:example:not-web#k1")
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "did_method_unsupported")


def test_both_a_json_string_and_bytes_are_accepted_as_input(verify, world, policy, store, online):
    as_dict = world.issuer_a.credential_di
    as_text = json.dumps(as_dict)
    for form in (as_dict, as_text, as_text.encode("utf-8")):
        assert verify(form, policy=policy, store=store, transport=online).accepted


def test_data_integrity_proof_purpose_must_be_assertion_method(
    verify, world, policy, store, online
):
    credential = fx.sign_data_integrity(
        fx.vc_payload(world.issuer_a.did), world.issuer_a.key,
        verification_method=world.issuer_a.vm_id,
    )
    credential["proof"]["proofPurpose"] = "authentication"
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "proof_purpose_invalid")


# ------------------------------- the shapes walt.id issuer-api2 actually produces
# Measured in record/NOTES-waltid.md. These are regression tests against a real issuer's
# output, not against our own fixture conventions.

def test_the_waltid_payload_shape_is_accepted(verify, world, policy, store, online):
    payload = fx.waltid_vc_payload(world.issuer_a.did)
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    result = verify(credential, policy=policy, store=store, transport=online)
    assert result.accepted, result.reason


def test_an_issuer_object_is_read_through_its_id(verify, world, policy, store, online):
    """VC 2.0 allows `issuer` to be an object; walt.id emits one."""
    payload = fx.vc_payload(world.issuer_a.did)
    payload["issuer"] = {"id": world.issuer_a.did, "type": ["Profile"], "name": "Registry"}
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert verify(credential, policy=policy, store=store, transport=online).accepted


def test_iss_disagreeing_with_the_issuer_object_is_rejected(verify, world, policy, store, online):
    """Two statements of the issuer must not be allowed to differ."""
    payload = fx.waltid_vc_payload(world.issuer_a.did)
    payload["iss"] = world.issuer_b.did
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "issuer_inconsistent")


def test_nanosecond_precision_timestamps_are_parsed(verify, world, policy, store, online):
    """walt.id emits validFrom as 2026-09-26T12:26:57.207818928Z -- nine fractional digits,
    which datetime.fromisoformat rejects outright."""
    payload = fx.waltid_vc_payload(world.issuer_a.did)
    payload["validFrom"] = "2026-09-26T12:26:57.207818928Z"
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    result = verify(credential, policy=policy, store=store, transport=online)
    assert result.accepted, result.reason


def test_the_jwt_exp_claim_is_honoured(verify, world, policy, store, online):
    import datetime as dt

    payload = fx.waltid_vc_payload(
        world.issuer_a.did,
        issued_at=fx.now() - dt.timedelta(days=2),
        expires_at=fx.now() - dt.timedelta(days=1),
    )
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "credential_expired")


def test_the_jwt_nbf_claim_is_honoured(verify, world, policy, store, online):
    import datetime as dt

    payload = fx.waltid_vc_payload(world.issuer_a.did, issued_at=fx.now() + dt.timedelta(hours=2))
    credential = fx.sign_jws_compact(payload, world.issuer_a.key, kid=world.issuer_a.vm_id)
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "credential_not_yet_valid")


def test_the_key_reference_fragment_is_the_rfc7638_thumbprint(world):
    """The contract between walt.id's `kid` and our DID document's fragment."""
    expected = fx.jwk_thumbprint(world.issuer_a.jwk)
    assert world.issuer_a.fragment == expected
    assert world.issuer_a.vm_id == f"{world.issuer_a.did}#{expected}"
