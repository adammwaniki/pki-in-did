"""The gap between a conformant verifier and a national-PKI policy layer.

These tests run the same credentials through walt.id verifier-api2 -- a production OpenID4VP
1.0 verifier -- and through src/verifier, and assert that the two disagree in exactly the way
the source document says they will.

If these ever start agreeing, either walt.id has begun validating x5c (in which case the
demonstration's premise needs revisiting) or the policy layer has stopped.
"""

from __future__ import annotations

import json

import pytest

from .conftest import NETWORK, REPO, VERIFIER_IMAGE, as_current_user, run, script, verify_json

pytestmark = [pytest.mark.integration, pytest.mark.slow]

WALTID_VERIFIER = "http://verifier-api:7004"


def present(credential: str) -> dict:
    """Present a credential to walt.id verifier-api2 and return its session record."""
    done = run(
        "docker", "run", "--rm", "--network", NETWORK, *as_current_user(),
        "-v", f"{REPO}:{REPO}", "-w", str(REPO),
        "--entrypoint", "python", VERIFIER_IMAGE,
        "src/holder/wallet.py", "present",
        "--verifier", WALTID_VERIFIER,
        "--credential", f"state/credentials/{credential}",
        "--quiet", "--json",
        check=False, timeout=300,
    )
    assert done.stdout.strip(), f"the wallet printed nothing\n{done.stderr}"
    return json.loads(done.stdout)


def policy_names(session: dict) -> set[str]:
    """Every policy name walt.id reported running."""
    names: set[str] = set()

    def walk(node, path=""):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("policy_executed", "results"):
                    continue
                if isinstance(value, dict) and "success" in value:
                    names.add(key)
                walk(value, f"{path}{key}.")

    walk(session.get("policy_results") or {})
    return names


@pytest.fixture(scope="module")
def restored():
    """Nothing revoked, so these tests are about the binding check alone."""
    script("90-restore-revocations.sh")
    script("95-impostor.sh")
    yield


# ---------------------------------------------------- what walt.id's verifier does

def test_a_genuine_credential_is_successful_at_waltid(restored):
    session = present("issuer-a-vc-jose.jwt")
    assert session["status"] == "SUCCESSFUL", json.dumps(session.get("policy_results"))[:500]


def test_waltid_checks_the_presentation_and_the_signatures(restored):
    """What it does check is real work, and worth naming."""
    names = policy_names(present("issuer-a-vc-jose.jwt"))
    for expected in ("jwt_vc_json/envelope_signature", "jwt_vc_json/nonce-check",
                     "jwt_vc_json/audience-check"):
        assert expected in names, f"{expected} not among {sorted(names)}"


def test_waltid_runs_no_certificate_chain_policy(restored):
    """The claim, asserted against a third-party implementation.

    A conformant verifier treats x5c as opaque metadata. If this ever fails, the premise of
    the whole demonstration has changed and the documents need revisiting.
    """
    names = policy_names(present("issuer-a-vc-jose.jwt"))
    chainish = [n for n in names
                if any(word in n.lower() for word in ("x5c", "x5u", "chain", "x509", "pkix"))]
    assert not chainish, f"walt.id now runs a chain policy: {chainish}"


# --------------------------------------------------------------- the impostor

def test_the_impostor_is_also_successful_at_waltid(restored):
    """The whole argument, in one assertion.

    This credential is signed by a key nobody certified, beside a genuine national chain that
    does not certify it. A conformant verifier accepts it, correctly.
    """
    session = present("impostor-vc-jose.jwt")
    assert session["status"] == "SUCCESSFUL", (
        "if this fails, walt.id has started checking something it did not before: "
        + json.dumps(session.get("policy_results"))[:500]
    )


def test_the_policy_layer_rejects_the_impostor(restored):
    result = verify_json("impostor-vc-jose.jwt")
    assert result["accepted"] is False
    assert result["reason"] == "spki_jwk_mismatch"


def test_the_policy_layer_still_accepts_the_genuine_credential(restored):
    """A policy layer that rejected everything would prove nothing."""
    result = verify_json("issuer-a-vc-jose.jwt")
    assert result["accepted"] is True, result["reason"]


def test_the_impostors_borrowed_chain_is_genuine(restored):
    """The chain really does validate to the National Root CA; only the binding fails.

    Otherwise the rejection could be dismissed as catching a forged certificate, which is a
    much easier problem and not the one being demonstrated.
    """
    result = verify_json("impostor-vc-jose.jwt")
    checks = {c["key"]: c for c in result["checks"]}
    assert checks["x5c_present"]["status"] == "pass"
    assert checks["x5t_matches_leaf"]["status"] == "pass", \
        "the borrowed leaf is exactly the certificate the JWK's own x5t#S256 names"
    assert checks["jwk_matches_leaf_spki"]["status"] == "fail"


def test_the_two_verdicts_disagree_on_the_impostor_and_agree_otherwise(restored):
    """The table part 5 prints, as a test."""
    genuine_waltid = present("issuer-a-vc-jose.jwt")["status"]
    genuine_policy = verify_json("issuer-a-vc-jose.jwt")["accepted"]
    impostor_waltid = present("impostor-vc-jose.jwt")["status"]
    impostor_policy = verify_json("impostor-vc-jose.jwt")["accepted"]

    assert (genuine_waltid, genuine_policy) == ("SUCCESSFUL", True)
    assert (impostor_waltid, impostor_policy) == ("SUCCESSFUL", False)
