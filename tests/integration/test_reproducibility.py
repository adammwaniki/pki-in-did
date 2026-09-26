"""The reset script, and the alternative procedure the brief asks for.

A full reset reissues every key, certificate and credential and takes minutes, so the
assertions about it are gathered into one test that resets twice rather than five tests
that reset five times. The lighter restore used between revocation tests is
scripts/90-restore-revocations.sh.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .conftest import STATE, load_cert, script, verify_json

pytestmark = [pytest.mark.integration, pytest.mark.slow]


@pytest.mark.timeout(1800)
def test_reset_reissues_everything_is_idempotent_and_keeps_the_root():
    """Brief, tests and alternative procedure step 1."""
    before_leaf = load_cert(STATE / "ca" / "certs" / "issuer-a.pem").serial_number
    before_root = load_cert(STATE / "offline" / "nrca" / "nrca.pem").fingerprint(hashes.SHA256())
    before_credential = (STATE / "credentials" / "issuer-a-vc-jose.jwt").read_text()

    script("00-reset.sh")

    # Everything below the root is new.
    after_leaf = load_cert(STATE / "ca" / "certs" / "issuer-a.pem").serial_number
    assert after_leaf != before_leaf, "reset must issue a new issuer certificate"
    assert (STATE / "credentials" / "issuer-a-vc-jose.jwt").read_text() != before_credential

    # The root is not re-keyed. A national root is not regenerated on a whim, and keeping it
    # means a fingerprint someone wrote down stays correct across resets.
    after_root = load_cert(STATE / "offline" / "nrca" / "nrca.pem").fingerprint(hashes.SHA256())
    assert after_root == before_root

    # The root private key stays on the offline machine and appears nowhere a service can reach.
    assert (STATE / "offline" / "nrca" / "private" / "nrca.key").exists()
    assert not (STATE / "ca" / "private" / "nrca.key").exists()
    assert not (STATE / "web" / "nrca" / "nrca.key").exists()
    assert not any(
        b"PRIVATE KEY" in path.read_bytes()[:400]
        for path in (STATE / "web").rglob("*") if path.is_file()
    )

    # The stack verifies again immediately afterwards, online and offline.
    for credential in ("issuer-a-vc-jose.jwt", "issuer-b-vc-jose.jwt"):
        online = verify_json(credential)
        assert online["accepted"] is True, f"{credential}: {online['reason']}"
        offline = verify_json(credential, offline=True)
        assert offline["accepted"] is True, f"{credential} offline: {offline['reason']}"

    # And running it a second time is safe.
    script("00-reset.sh")
    assert verify_json("issuer-a-vc-jose.jwt")["accepted"] is True
    assert load_cert(STATE / "offline" / "nrca" / "nrca.pem").fingerprint(hashes.SHA256()) \
        == before_root


@pytest.mark.timeout(600)
def test_the_offline_kit_contains_everything_the_brief_lists():
    """Brief, alternative procedure step 2: the root certificate, the DID documents, an
    OCSP response and the CRLs, all held on the laptop."""
    script("80-seed-offline-cache.sh")
    laptop = STATE / "laptop"

    assert (laptop / "trust" / "nrca.pem").exists(), "the root certificate"
    assert (laptop / "trust" / "webtls-root.pem").exists(), "the transport trust store"
    assert (laptop / "policy.json").exists(), "the verifier policy in force"
    assert len(list((laptop / "cache" / "did").glob("*.json"))) >= 2, "both DID documents"
    assert list((laptop / "cache" / "ocsp").glob("*")), "an OCSP response"
    assert list((laptop / "cache" / "crl").glob("*")), "the CRL"

    # Nothing in the kit is secret.
    for path in laptop.rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes()[:400], f"{path} holds a private key"
