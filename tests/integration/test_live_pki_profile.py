"""The certificate profile the brief specifies, asserted against the certificates the
live scripts actually produced."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .conftest import ISSUER_A_DID, ISSUER_B_DID, STATE, load_cert

pytestmark = pytest.mark.integration

POLICY_OID = "1.3.6.1.4.1.99999.1.1"


def ext(cert, oid):
    return cert.extensions.get_extension_for_oid(oid).value


# ------------------------------------------------------------------ National Root CA

def test_the_root_is_self_signed_and_a_ca(root_cert):
    assert root_cert.subject == root_cert.issuer
    bc = ext(root_cert, ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.ca is True


def test_the_root_uses_rsa_4096(root_cert):
    key = root_cert.public_key()
    assert isinstance(key, rsa.RSAPublicKey)
    assert key.key_size == 4096


def test_the_root_may_sign_certificates_and_crls(root_cert):
    ku = ext(root_cert, ExtensionOID.KEY_USAGE)
    assert ku.key_cert_sign and ku.crl_sign


def test_the_root_private_key_lives_only_on_the_offline_machine():
    """The one property the demonstration must never get wrong."""
    offline_dir = STATE / "offline"
    offline_key = offline_dir / "nrca" / "private" / "nrca.key"
    assert offline_key.exists(), "the offline root key is missing"
    secret = offline_key.read_bytes()

    leaked = [
        str(path.relative_to(STATE))
        for path in STATE.rglob("*")
        if path.is_file()
        and not path.is_relative_to(offline_dir)
        and path.stat().st_size == len(secret)
        and path.read_bytes() == secret
    ]
    assert not leaked, f"the root private key appears outside the offline machine: {leaked}"


def test_no_directory_served_by_a_web_container_holds_any_private_key():
    """Whatever nginx can reach, nginx can be tricked into serving."""
    leaked = [
        str(path.relative_to(STATE))
        for path in (STATE / "web").rglob("*")
        if path.is_file() and b"PRIVATE KEY" in path.read_bytes()[:400]
    ]
    assert not leaked, f"private key material inside a web root: {leaked}"


# --------------------------------------------------------------------- Issuing CA

def test_the_issuing_ca_is_signed_by_the_root(issuing_cert, root_cert):
    assert issuing_cert.issuer == root_cert.subject
    root_cert.public_key().verify(
        issuing_cert.signature,
        issuing_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        issuing_cert.signature_hash_algorithm,
    )


def test_the_issuing_ca_carries_path_len_zero(issuing_cert):
    bc = ext(issuing_cert, ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.ca is True
    assert bc.path_length == 0, "the Issuing CA must not be able to certify another CA"


def test_the_issuing_ca_key_is_not_the_root_key(issuing_cert, root_cert):
    assert issuing_cert.public_key().public_numbers() != root_cert.public_key().public_numbers()


# --------------------------------------------------------- credential issuer leaves

@pytest.mark.parametrize("which,did", [("a", ISSUER_A_DID), ("b", ISSUER_B_DID)])
def test_each_issuer_leaf_names_its_did_in_a_san_uri(request, which, did):
    cert = request.getfixturevalue(f"issuer_{which}_cert")
    san = ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [did]


@pytest.mark.parametrize("which", ["a", "b"])
def test_each_issuer_leaf_has_digital_signature_and_nothing_else(request, which):
    cert = request.getfixturevalue(f"issuer_{which}_cert")
    ku = ext(cert, ExtensionOID.KEY_USAGE)
    assert ku.digital_signature is True
    assert ku.key_cert_sign is False
    assert ku.crl_sign is False
    assert ku.key_encipherment is False


@pytest.mark.parametrize("which", ["a", "b"])
def test_each_issuer_leaf_is_an_end_entity(request, which):
    cert = request.getfixturevalue(f"issuer_{which}_cert")
    assert ext(cert, ExtensionOID.BASIC_CONSTRAINTS).ca is False


@pytest.mark.parametrize("which", ["a", "b"])
def test_each_issuer_leaf_uses_ec_p256_for_es256(request, which):
    cert = request.getfixturevalue(f"issuer_{which}_cert")
    key = cert.public_key()
    assert isinstance(key, ec.EllipticCurvePublicKey)
    assert key.curve.name == "secp256r1"


@pytest.mark.parametrize("which", ["a", "b"])
def test_each_issuer_leaf_is_signed_by_the_issuing_ca(request, which, issuing_cert):
    cert = request.getfixturevalue(f"issuer_{which}_cert")
    assert cert.issuer == issuing_cert.subject


@pytest.mark.parametrize("which", ["a", "b"])
def test_each_issuer_leaf_carries_the_accreditation_policy_oid(request, which):
    cert = request.getfixturevalue(f"issuer_{which}_cert")
    policies = ext(cert, ExtensionOID.CERTIFICATE_POLICIES)
    assert POLICY_OID in [p.policy_identifier.dotted_string for p in policies]


def test_issuer_a_points_at_ocsp_and_not_at_a_crl(issuer_a_cert):
    aia = ext(issuer_a_cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    urls = [d.access_location.value for d in aia
            if d.access_method == x509.AuthorityInformationAccessOID.OCSP]
    assert urls == ["http://mwaniki.dev/ocsp"]
    with pytest.raises(x509.ExtensionNotFound):
        ext(issuer_a_cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)


def test_issuer_b_points_at_a_crl_and_not_at_ocsp(issuer_b_cert):
    cdp = ext(issuer_b_cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    urls = [n.value for point in cdp for n in point.full_name]
    assert urls == ["http://mwaniki.dev/issuing-ca.crl"]
    with pytest.raises(x509.ExtensionNotFound):
        ext(issuer_b_cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)


# -------------------------------------------------------------------- OCSP signer

def test_the_ocsp_signer_has_the_ocsp_signing_extended_key_usage(ocsp_signer_cert):
    eku = ext(ocsp_signer_cert, ExtensionOID.EXTENDED_KEY_USAGE)
    assert ExtendedKeyUsageOID.OCSP_SIGNING in eku


def test_the_ocsp_signer_is_issued_by_the_issuing_ca(ocsp_signer_cert, issuing_cert):
    assert ocsp_signer_cert.issuer == issuing_cert.subject


def test_the_ocsp_signer_is_not_a_ca(ocsp_signer_cert):
    assert ext(ocsp_signer_cert, ExtensionOID.BASIC_CONSTRAINTS).ca is False


# ----------------------------------------------------------- the two PKI layers

def test_the_web_tls_hierarchy_is_a_separate_root(root_cert):
    tls_root = load_cert(STATE / "tls" / "root" / "webtls-root.pem")
    assert tls_root.subject != root_cert.subject
    assert tls_root.public_key().public_numbers() != root_cert.public_key().public_numbers()


def test_the_laptop_keeps_the_two_trust_stores_apart():
    credential_anchor = (STATE / "laptop" / "trust" / "nrca.pem").read_bytes()
    tls_anchor = (STATE / "laptop" / "trust" / "webtls-root.pem").read_bytes()
    assert credential_anchor != tls_anchor
    assert b"PRIVATE KEY" not in credential_anchor
    assert b"PRIVATE KEY" not in tls_anchor
