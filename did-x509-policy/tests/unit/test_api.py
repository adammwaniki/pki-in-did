"""The HTTP service.

The service is a thin shell over the library, so these tests are about the shell: status codes,
configuration from the environment, and the two things a caller needs to be able to read back
before trusting a verdict -- the policy in force and the trust anchors.
"""

from __future__ import annotations

import json

import pytest

from did_x509_policy.api import Configuration, create_app
from tests import fixtures as fx

pytestmark = pytest.mark.unit

starlette_testclient = pytest.importorskip("starlette.testclient")
TestClient = starlette_testclient.TestClient


@pytest.fixture
def env(tmp_path, world):
    """A deployment configured the way the README describes, with no files but the anchor."""
    kit = tmp_path / "kit"
    (kit / "trust").mkdir(parents=True)
    (kit / "trust" / "nrca.pem").write_bytes(world.root_pem)

    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({
        "trust_anchors": ["trust/nrca.pem"],
        "require_issuer_authorization": True,
        "accreditation_policy_oids": {fx.ACCREDITATION_POLICY_OID: [fx.ACCREDITED_TYPE]},
    }))
    return {
        "DID_X509_TRUST_ANCHOR_FILE": str(kit / "trust" / "nrca.pem"),
        "DID_X509_POLICY_FILE": str(policy_file),
        "DID_X509_CACHE_DIR": str(kit),
    }


@pytest.fixture
def client(env):
    return TestClient(create_app(Configuration(env)))


@pytest.fixture
def seeded(env, world):
    """The cache primed as one online verification would leave it."""
    from did_x509_policy import FileStore

    store = FileStore(env["DID_X509_CACHE_DIR"])
    store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(world.issuer_a))
    return store


# ------------------------------------------------------------------------- readiness

def test_healthz_reports_the_trust_anchors_and_their_fingerprints(client, world):
    from did_x509_policy import sha256_fingerprint

    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert [a["fingerprintSha256"] for a in body["trustAnchors"]] == [
        sha256_fingerprint(world.root.cert)]
    assert len(body["checks"]) == 15


def test_a_service_with_no_trust_anchor_is_not_ready(tmp_path):
    """It could only ever reject. Safe, useless, and a deployment should learn it here."""
    response = TestClient(create_app(Configuration({}))).get("/healthz")
    assert response.status_code == 503
    assert response.json()["trustAnchors"] == []


def test_the_policy_in_force_can_be_read_back(client):
    policy = client.get("/policy").json()
    assert policy["require_spki_jwk_binding"] is True
    assert policy["revocation_required"] is True
    assert "_comment" not in policy


def test_the_root_page_names_the_endpoints(client):
    body = client.get("/").text
    for path in ("/verify", "/policy", "/healthz"):
        assert path in body


# --------------------------------------------------------------------------- verify

def test_a_rejection_is_422_with_the_whole_report(client, world, seeded):
    """422, not 200-with-a-flag: the request was fine, the credential was not."""
    impostor = fx.ec_key()
    jwk = fx.ec_public_jwk(impostor, kid=world.issuer_a.fragment,
                           x5c=[world.issuer_a.cert, world.issuing.cert])
    seeded.put_did_document(world.issuer_a.did,
                            fx.build_did_document(world.issuer_a.did, jwk=jwk,
                                                  fragment=world.issuer_a.fragment))
    credential = fx.sign_jws_compact(fx.vc_payload(world.issuer_a.did), impostor,
                                     kid=world.issuer_a.vm_id)

    response = client.post("/verify", json={"credential": credential})
    assert response.status_code == 422
    body = response.json()
    assert body["accepted"] is False
    assert body["reason"] == "spki_jwk_mismatch"
    assert len(body["checks"]) == 15
    assert body["checks"][8]["status"] == "fail"


def test_an_offline_service_rejects_when_nothing_is_cached(env, world):
    client = TestClient(create_app(Configuration({**env, "DID_X509_OFFLINE": "1"})))
    response = client.post("/verify", json={"credential": world.issuer_a.credential_jose})
    assert response.status_code == 422
    assert response.json()["reason"] == "did_resolution_failed"


def test_an_offline_service_accepts_from_a_primed_cache(env, world, seeded):
    seeded.put_crl(world.issuing.cert, world.crl())
    client = TestClient(create_app(Configuration({**env, "DID_X509_OFFLINE": "1"})))
    response = client.post("/verify", json={"credential": world.issuer_a.credential_jose})
    assert response.status_code == 200, response.json().get("reason")
    body = response.json()
    assert body["accepted"] is True
    assert body["revocation"]["source"] == "cache"
    assert body["offline"] is True


def test_a_per_request_policy_override_is_honoured(env, world, seeded):
    """Useful for staging a rule before making it the default."""
    client = TestClient(create_app(Configuration({**env, "DID_X509_OFFLINE": "1"})))
    strict = client.post("/verify", json={
        "credential": world.issuer_a.credential_jose,
        "policy": {"clock_skew_seconds": 0, "ocsp_max_age_seconds": 0},
    })
    assert strict.status_code == 422
    assert strict.json()["reason"] in ("revocation_expired", "revocation_stale")


def test_an_unknown_policy_override_is_refused_rather_than_ignored(client, world):
    response = client.post("/verify", json={
        "credential": world.issuer_a.credential_jose,
        "policy": {"no_such_setting": True},
    })
    assert response.status_code == 400
    assert "no_such_setting" in response.json()["error"]


@pytest.mark.parametrize("body,expected", [
    ({}, 400),
    ({"credential": ""}, 400),
    ({"credential": "not a credential"}, 422),
    ({"credential": None}, 400),
])
def test_bad_requests_are_distinguished_from_bad_credentials(client, body, expected):
    """A missing credential is the caller's mistake; a malformed one is an answer."""
    assert client.post("/verify", json=body).status_code == expected


def test_a_non_json_body_is_a_400(client):
    response = client.post("/verify", content=b"not json",
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 400


def test_an_invalid_at_is_a_400(client, world):
    response = client.post("/verify", json={"credential": world.issuer_a.credential_jose,
                                           "at": "the day before yesterday"})
    assert response.status_code == 400


# ------------------------------------------------------------------- configuration

def test_an_inline_pem_anchor_is_accepted(world):
    config = Configuration({"DID_X509_TRUST_ANCHOR_PEM": world.root_pem.decode()})
    assert [a.subject for a in config.anchors] == [world.root.cert.subject]


def test_the_cache_backend_is_reported(env):
    assert Configuration(env).describe()["cache"] == "file"
    assert Configuration({}).describe()["cache"] == "memory"


def test_a_single_policy_setting_can_come_from_the_environment():
    config = Configuration({"DID_X509_POLICY_CLOCK_SKEW_SECONDS": "0",
                            "DID_X509_POLICY_ALLOW_X5U": "true"})
    assert config.policy.clock_skew_seconds == 0
    assert config.policy.allow_x5u is True


def test_the_shipped_default_policy_is_used_when_nothing_is_configured():
    from did_x509_policy import Policy

    assert Configuration({}).policy == Policy.default()
