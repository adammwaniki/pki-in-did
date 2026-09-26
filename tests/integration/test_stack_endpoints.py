"""What each of the four domains serves, checked from inside the demo network."""

from __future__ import annotations

import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .conftest import (ISSUER_A_DID, ISSUER_B_DID, ISSUER_A_DOMAIN, ISSUER_B_DOMAIN,
                       ISSUING_CA_DOMAIN, NETWORK, NRCA_DOMAIN, STATE, VERIFIER_IMAGE,
                       as_current_user, curl_in_network, run)

pytestmark = pytest.mark.integration


def test_domain1_serves_the_root_certificate_over_https(root_cert):
    body = curl_in_network(f"https://{NRCA_DOMAIN}/nrca.pem").stdout
    served = x509.load_pem_x509_certificate(body.encode())
    assert served.fingerprint(hashes.SHA256()) == root_cert.fingerprint(hashes.SHA256())


def test_domain1_does_not_serve_the_root_private_key():
    """Brief step 6: do not put the root private key on the server."""
    body = curl_in_network(f"https://{NRCA_DOMAIN}/nrca.pem").stdout
    assert "PRIVATE KEY" not in body

    for path in ("nrca.key", "private/nrca.key", "nrca.p12", "index.txt"):
        done = curl_in_network(f"https://{NRCA_DOMAIN}/{path}", check=False)
        assert done.returncode != 0, f"{path} should not be served, but it was"


@pytest.mark.parametrize("domain,did", [(ISSUER_A_DOMAIN, ISSUER_A_DID),
                                        (ISSUER_B_DOMAIN, ISSUER_B_DID)])
def test_did_web_resolves_to_the_well_known_document(domain, did):
    """did:web Read algorithm, and its step 2: the document's id must equal the DID."""
    body = curl_in_network(f"https://{domain}/.well-known/did.json").stdout
    document = json.loads(body)
    assert document["id"] == did


@pytest.mark.parametrize("domain", [ISSUER_A_DOMAIN, ISSUER_B_DOMAIN])
def test_each_did_document_carries_a_jwk_with_x5c_and_assertion_method(domain):
    document = json.loads(curl_in_network(f"https://{domain}/.well-known/did.json").stdout)
    method = document["verificationMethod"][0]
    assert method["type"] == "JsonWebKey2020"
    jwk = method["publicKeyJwk"]
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256" and jwk["alg"] == "ES256"
    assert len(jwk["x5c"]) == 2, "leaf and Issuing CA; the root is a trust anchor, not a chain link"
    assert "x5t#S256" in jwk
    assert "d" not in jwk, "a DID document must never carry private key material"
    assert document["assertionMethod"] == [method["id"]]
    assert method["id"].startswith("did:web:"), "did:web requires absolute DID URLs"


@pytest.mark.parametrize("domain", [ISSUER_A_DOMAIN, ISSUER_B_DOMAIN])
def test_no_issuer_serves_its_private_key(domain):
    for path in (".well-known/issuer.key", "private/issuer.key", "issuer-a.key", "issuer-b.key"):
        done = curl_in_network(f"https://{domain}/{path}", check=False)
        assert done.returncode != 0, f"{domain}/{path} should not be served"


def test_the_did_document_is_served_as_json():
    done = curl_in_network("-D", "-", "-o", "/dev/null",
                           f"https://{ISSUER_A_DOMAIN}/.well-known/did.json")
    assert "application/did+json" in done.stdout.lower() or \
           "application/json" in done.stdout.lower()


def test_domain2_serves_the_crl_over_http(issuing_cert):
    """The CRL is DER, so it is fetched to a file rather than through a text pipe.

    The destination is under the repository, not pytest's tmp_path: tmp_path lives in the
    test runner's own filesystem, which the Docker daemon on the host does not share, so a
    bind mount of it would silently write nowhere.
    """
    scratch = STATE / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    out = scratch / "fetched.crl"
    out.unlink(missing_ok=True)
    run(
        "docker", "run", "--rm", "--network", NETWORK, *as_current_user(),
        "-v", f"{scratch}:/out", "--entrypoint", "curl", VERIFIER_IMAGE,
        "--silent", "--show-error", "--fail",
        "-o", "/out/fetched.crl", f"http://{ISSUING_CA_DOMAIN}/issuing-ca.crl",
    )
    crl = x509.load_der_x509_crl(out.read_bytes())
    assert crl.issuer == issuing_cert.subject
    assert crl.is_signature_valid(issuing_cert.public_key())


def test_domain2_answers_an_ocsp_request(issuer_a_cert, issuing_cert):
    """The responder is reachable and says `good` before any revocation."""
    done = run(
        "docker", "run", "--rm", "--network", NETWORK,
        "-v", f"{STATE}/ca:/ca:ro", "--entrypoint", "openssl", VERIFIER_IMAGE,
        "ocsp", "-issuer", "/ca/issuing-ca.pem", "-cert", "/ca/certs/issuer-a.pem",
        "-url", f"http://{ISSUING_CA_DOMAIN}/ocsp", "-resp_text", "-noverify",
    )
    assert "issuer-a.pem: good" in done.stdout or ": good" in done.stdout


def test_the_issuer_chain_is_published_for_the_x5u_variant():
    body = curl_in_network(f"https://{ISSUER_A_DOMAIN}/.well-known/pki/issuer-chain.pem").stdout
    assert body.count("BEGIN CERTIFICATE") == 2
