"""Part 1 and part 2 of the recording, run against the live stack."""

from __future__ import annotations

import pytest

from .conftest import ISSUER_A_DID, ISSUER_B_DID, verify_json, verifier

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("credential,did,method", [
    ("issuer-a-vc-jose.jwt", ISSUER_A_DID, "ocsp"),
    ("issuer-b-vc-jose.jwt", ISSUER_B_DID, "crl"),
])
def test_online_happy_path(credential, did, method):
    result = verify_json(credential)
    assert result["accepted"] is True, result["reason"]
    assert result["credential"]["issuer"] == did
    assert result["revocation"]["method"] == method
    assert result["revocation"]["status"] == "good"
    assert result["revocation"]["source"] == "network"
    assert len(result["checks"]) == 15
    assert all(c["status"] in ("pass", "skip") for c in result["checks"])


@pytest.mark.parametrize("credential,method", [
    ("issuer-a-vc-jose.jwt", "ocsp"),
    ("issuer-b-vc-jose.jwt", "crl"),
])
def test_offline_happy_path_from_the_primed_cache(credential, method):
    """Part 2: `docker run --network none`, decided entirely from the laptop's own store."""
    result = verify_json(credential, offline=True)
    assert result["accepted"] is True, result["reason"]
    assert result["revocation"]["method"] == method
    assert result["revocation"]["source"] == "cache"


def test_the_human_report_names_the_trust_anchor_and_every_check():
    done = verifier("--credential", "/credentials/issuer-a-vc-jose.jwt")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "Demo National Root CA" in done.stdout
    assert "ACCEPTED" in done.stdout
    for line in ("x5c_present", "jwk_matches_leaf_spki", "certification_path", "revocation_status"):
        assert line in done.stdout


def test_the_exit_code_is_the_verdict():
    assert verifier("--credential", "/credentials/issuer-a-vc-jose.jwt").returncode == 0


def test_each_credential_came_from_waltid_issuer_api2():
    """The header walt.id emits: typ vc+jwt, an absolute did:web kid, and x5c beside it.

    Recorded in record/NOTES-waltid.md. Data Integrity proofs are not checked here --
    issuer-api2 is OpenID4VCI/JOSE only, so the live stack issues vc+jwt exclusively.
    """
    import base64
    import json
    from pathlib import Path

    from .conftest import STATE

    for name, did in (("issuer-a-vc-jose.jwt", ISSUER_A_DID),
                      ("issuer-b-vc-jose.jwt", ISSUER_B_DID)):
        token = (STATE / "credentials" / name).read_text().strip()
        raw = token.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        assert header["typ"] == "vc+jwt"
        assert header["alg"] == "ES256"
        assert header["kid"].startswith(f"{did}#")
        assert len(header["x5c"]) == 2, "leaf and Issuing CA, root omitted"


def test_the_issuer_management_api_is_not_reachable_through_nginx():
    """GET /issuer2/profiles returns the private key. It must never be published."""
    from .conftest import ISSUER_A_DOMAIN, curl_in_network

    for path in ("issuer2/profiles", "issuer2/credential-offers", "issuer2/sessions"):
        done = curl_in_network(f"https://{ISSUER_A_DOMAIN}/{path}", check=False)
        assert done.returncode != 0, f"/{path} is publicly reachable"
