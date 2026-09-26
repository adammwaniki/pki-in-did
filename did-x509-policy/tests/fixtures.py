"""Synthetic PKI, DID document and credential builders for the unit tests.

Everything the live stack produces with openssl and nginx is reproduced here in
process, so that adverse cases the demonstration cannot easily stage -- an expired
leaf, a rogue OCSP signer, a JWK whose key does not match its own certificate --
are all reachable from a test.

This module is test scaffolding. It deliberately does not import from `verifier`.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils as asym_utils
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

UTC = dt.timezone.utc

ACCREDITATION_POLICY_OID = "1.3.6.1.4.1.99999.1.1"
ACCREDITED_TYPE = "AccreditedOperatorCredential"

NRCA_CN = "Demo National Root CA"
ISSUING_CA_CN = "Demo National Issuing CA"
OCSP_SIGNER_CN = "Demo National Issuing CA OCSP Responder"

ISSUER_A_DOMAIN = "jacarandapropaganda.com"
ISSUER_B_DOMAIN = "lawnbull.com"
ISSUER_A_DID = f"did:web:{ISSUER_A_DOMAIN}"
ISSUER_B_DID = f"did:web:{ISSUER_B_DOMAIN}"
NRCA_DOMAIN = "adamndegwa.com"
ISSUING_CA_DOMAIN = "mwaniki.dev"

OCSP_URL = f"http://{ISSUING_CA_DOMAIN}/ocsp"
CRL_URL = f"http://{ISSUING_CA_DOMAIN}/issuing-ca.crl"
CHAIN_URL_A = f"https://{ISSUER_A_DOMAIN}/.well-known/pki/issuer-chain.pem"


# --------------------------------------------------------------------------- utils

def now() -> dt.datetime:
    return dt.datetime.now(tz=UTC)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64(raw: bytes) -> str:
    """Standard base64, which is what RFC 7517 x5c uses (not base64url)."""
    return base64.b64encode(raw).decode("ascii")


def jcs(obj) -> bytes:
    """Canonical JSON.

    RFC 8785 for the subset this demonstration uses: objects with string keys,
    string/bool/int values, arrays. Sorted keys, no insignificant whitespace.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def dn(cn: str, *, country: str = "KE", org: str = "Demo National PKI") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    # 2048 in tests: a 4096-bit key per test run makes the suite needlessly slow.
    # The live stack uses 4096 for both CAs; tests/unit/test_pki_structure.py asserts that.
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _hash_for(key) -> hashes.HashAlgorithm:
    return hashes.SHA384() if isinstance(key, rsa.RSAPrivateKey) else hashes.SHA256()


# ------------------------------------------------------------------- certificates

@dataclass
class Authority:
    """A signing authority: its private key and its own certificate."""

    key: object
    cert: x509.Certificate
    next_serial: int = 0x1000

    @property
    def name(self) -> x509.Name:
        return self.cert.subject

    def take_serial(self) -> int:
        self.next_serial += 1
        return self.next_serial

    def issue(
        self,
        *,
        subject: x509.Name,
        public_key,
        extensions: Sequence[tuple[x509.ExtensionType, bool]],
        not_before: dt.datetime | None = None,
        not_after: dt.datetime | None = None,
        serial: int | None = None,
        signing_key=None,
        issuer_name: x509.Name | None = None,
    ) -> x509.Certificate:
        nb = not_before or (now() - dt.timedelta(minutes=5))
        na = not_after or (now() + dt.timedelta(days=730))
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name or self.name)
            .public_key(public_key)
            .serial_number(serial if serial is not None else self.take_serial())
            .not_valid_before(nb)
            .not_valid_after(na)
        )
        for ext, critical in extensions:
            builder = builder.add_extension(ext, critical=critical)
        key = signing_key or self.key
        return builder.sign(key, _hash_for(key))


def self_signed_root(
    cn: str,
    key,
    *,
    days: int = 7300,
    path_length: int | None = None,
) -> x509.Certificate:
    subject = dn(cn)
    pub = key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - dt.timedelta(days=1))
        .not_valid_after(now() + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    )
    return builder.sign(key, _hash_for(key))


def ca_extensions(ca_key, issuer_cert: x509.Certificate, *, path_length: int | None = 0):
    pub = ca_key.public_key()
    return [
        (x509.BasicConstraints(ca=True, path_length=path_length), True),
        (
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            True,
        ),
        (x509.SubjectKeyIdentifier.from_public_key(pub), False),
        (
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            False,
        ),
    ]


def digital_signature_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    )


def accreditation_policy(oid: str = ACCREDITATION_POLICY_OID) -> x509.CertificatePolicies:
    return x509.CertificatePolicies([
        x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=None)
    ])


def leaf_extensions(
    leaf_key,
    issuer_cert: x509.Certificate,
    *,
    did: str,
    ocsp_url: str | None = None,
    crl_url: str | None = None,
    key_usage: x509.KeyUsage | None = None,
    san: x509.SubjectAlternativeName | None = None,
    policy_oid: str | None = ACCREDITATION_POLICY_OID,
):
    pub = leaf_key.public_key()
    exts: list[tuple[x509.ExtensionType, bool]] = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (key_usage or digital_signature_key_usage(), True),
        (san or x509.SubjectAlternativeName([x509.UniformResourceIdentifier(did)]), False),
        (x509.SubjectKeyIdentifier.from_public_key(pub), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), False),
    ]
    if policy_oid:
        exts.append((accreditation_policy(policy_oid), False))
    if ocsp_url:
        exts.append((
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            False,
        ))
    if crl_url:
        exts.append((
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None,
                )
            ]),
            False,
        ))
    return exts


def ocsp_signer_extensions(signer_key, issuer_cert: x509.Certificate):
    pub = signer_key.public_key()
    return [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (digital_signature_key_usage(), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False),
        (x509.OCSPNoCheck(), False),
        (x509.SubjectKeyIdentifier.from_public_key(pub), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), False),
    ]


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def x5t_s256(cert: x509.Certificate) -> str:
    return b64u(hashlib.sha256(der(cert)).digest())


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an EC public JWK.

    walt.id issuer-api2 uses exactly this as the `kid` fragment, and DID Core
    recommends it, so the fixtures use it too. See record/NOTES-waltid.md.
    """
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(canonical).digest())


# ---------------------------------------------------------------------- JWK / JWS

def ec_public_jwk(
    key,
    *,
    kid: str,
    x5c: Iterable[x509.Certificate] | None = None,
    x5u: str | None = None,
    include_x5t: bool = True,
) -> dict:
    pub = key.public_key() if hasattr(key, "public_key") else key
    numbers = pub.public_numbers()
    size = (pub.curve.key_size + 7) // 8
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(numbers.x.to_bytes(size, "big")),
        "y": b64u(numbers.y.to_bytes(size, "big")),
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
    }
    chain = list(x5c or [])
    if chain:
        jwk["x5c"] = [b64(der(c)) for c in chain]
        if include_x5t:
            jwk["x5t#S256"] = x5t_s256(chain[0])
    if x5u:
        jwk["x5u"] = x5u
    return jwk


def build_did_document(
    did: str,
    *,
    jwk: dict,
    fragment: str,
    relationships: Sequence[str] = ("assertionMethod",),
    vm_type: str = "JsonWebKey2020",
    absolute_urls: bool = True,
    doc_id: str | None = None,
) -> dict:
    vm_id = f"{did}#{fragment}" if absolute_urls else f"#{fragment}"
    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": doc_id or did,
        "verificationMethod": [
            {"id": vm_id, "type": vm_type, "controller": did, "publicKeyJwk": jwk}
        ],
    }
    for rel in relationships:
        document[rel] = [vm_id]
    return document


def vc_payload(
    issuer_did: str,
    *,
    types: Sequence[str] = ("VerifiableCredential", ACCREDITED_TYPE),
    subject: dict | None = None,
    valid_from: dt.datetime | None = None,
    valid_until: dt.datetime | None = None,
    credential_id: str = "urn:uuid:11111111-2222-3333-4444-555555555555",
) -> dict:
    payload = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": credential_id,
        "type": list(types),
        "issuer": issuer_did,
        "validFrom": (valid_from or now()).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "credentialSubject": subject or {
            "id": "did:example:holder-1",
            "name": "Demonstration Holder",
            "licenceNumber": "OP-2026-0001",
        },
    }
    if valid_until:
        payload["validUntil"] = valid_until.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return payload


def waltid_vc_payload(
    issuer_did: str,
    *,
    types: Sequence[str] = ("VerifiableCredential", ACCREDITED_TYPE),
    subject_did: str = "did:jwk:eyJjcnYiOiJQLTI1NiJ9",
    issued_at: dt.datetime | None = None,
    expires_at: dt.datetime | None = None,
) -> dict:
    """The payload walt.id issuer-api2 actually emits.

    Differs from `vc_payload` in three ways the verifier must cope with: `iss` sits
    beside an `issuer` *object*, JWT `iat`/`nbf`/`jti` are present, and `validFrom`
    carries nanosecond precision. See record/NOTES-waltid.md.
    """
    at = issued_at or now()
    epoch = int(at.timestamp())
    credential_id = "urn:uuid:8415268f-bd9d-43f0-83ea-7693033f452a"
    payload = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": credential_id,
        "jti": credential_id,
        "type": list(types),
        "iss": issuer_did,
        "issuer": {"id": issuer_did, "type": ["Profile"], "name": "Demo National Operator Registry"},
        "sub": subject_did,
        "iat": epoch,
        "nbf": epoch,
        "validFrom": at.strftime("%Y-%m-%dT%H:%M:%S") + f".{at.microsecond:06d}207Z",
        "credentialSubject": {"id": subject_did, "licenceNumber": "OP-2026-0001"},
    }
    if expires_at:
        payload["exp"] = int(expires_at.timestamp())
    return payload


def sign_jws_compact(payload: dict, key, *, kid: str, alg: str = "ES256", typ: str = "vc+jwt") -> str:
    """VC-JOSE-COSE: the credential is the JWS payload, kid is the absolute DID URL."""
    header = {"alg": alg, "typ": typ, "kid": kid}
    signing_input = f"{b64u(jcs(header))}.{b64u(jcs(payload))}".encode("ascii")
    if alg == "none":
        return f"{signing_input.decode()}."
    signature = _raw_signature(key, signing_input, alg)
    return f"{signing_input.decode()}.{b64u(signature)}"


def _raw_signature(key, signing_input: bytes, alg: str) -> bytes:
    if alg == "ES256":
        der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der_sig)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    if alg in ("RS256", "PS256"):
        if alg == "RS256":
            return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    raise ValueError(f"unsupported alg for the fixture builder: {alg}")


def sign_data_integrity(vc: dict, key, *, verification_method: str, created: dt.datetime | None = None) -> dict:
    """JsonWebSignature2020 with a detached payload.

    Canonicalization here is JCS (RFC 8785), not URDNA2015 -- the demonstration
    deliberately carries no JSON-LD processor. Both ends of this demo agree on it,
    and README.md records the deviation.
    """
    header = {"alg": "ES256", "b64": False, "crit": ["b64"]}
    proof = {
        "type": "JsonWebSignature2020",
        "created": (created or now()).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "proofPurpose": "assertionMethod",
        "verificationMethod": verification_method,
    }
    document = {k: v for k, v in vc.items() if k != "proof"}
    signing_input = b64u(jcs(header)).encode("ascii") + b"." + jcs({**document, "proof": proof})
    signature = _raw_signature(key, signing_input, "ES256")
    proof["jws"] = f"{b64u(jcs(header))}..{b64u(signature)}"
    return {**document, "proof": proof}


# ----------------------------------------------------------------- OCSP and CRLs

def build_ocsp_response(
    *,
    subject_cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key,
    status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD,
    revocation_time: dt.datetime | None = None,
    revocation_reason: x509.ReasonFlags | None = None,
    this_update: dt.datetime | None = None,
    next_update: dt.datetime | None = None,
    produced_at: dt.datetime | None = None,
    include_responder_chain: bool = True,
    nonce: bytes | None = None,
) -> bytes:
    ti = this_update or now()
    tn = next_update or (now() + dt.timedelta(minutes=5))
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=subject_cert,
        issuer=issuer_cert,
        algorithm=hashes.SHA256(),
        cert_status=status,
        this_update=ti,
        next_update=tn,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    if include_responder_chain:
        builder = builder.certificates([responder_cert])
    return builder.sign(responder_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def nonce_of_request(der: bytes) -> bytes | None:
    """The nonce a verifier put in its request, so a fixture can echo it."""
    request = ocsp.load_der_ocsp_request(der)
    try:
        return request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound:
        return None


def build_unauthorized_ocsp_response() -> bytes:
    return ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED
    ).public_bytes(serialization.Encoding.DER)


def build_crl(
    *,
    issuer_cert: x509.Certificate,
    issuer_key,
    revoked: Sequence[tuple[int, dt.datetime, x509.ReasonFlags | None]] = (),
    last_update: dt.datetime | None = None,
    next_update: dt.datetime | None = None,
    crl_number: int = 1,
) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(last_update or now())
        .next_update(next_update or (now() + dt.timedelta(hours=1)))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
    )
    for serial, when, reason in revoked:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(when)
        )
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(issuer_key, _hash_for(issuer_key)).public_bytes(serialization.Encoding.DER)


# -------------------------------------------------------------------- whole world

@dataclass
class IssuerFixture:
    domain: str
    did: str
    key: object
    cert: x509.Certificate
    fragment: str
    jwk: dict
    did_document: dict
    credential_jose: str
    credential_di: dict

    @property
    def vm_id(self) -> str:
        return f"{self.did}#{self.fragment}"

    @property
    def did_url(self) -> str:
        return f"https://{self.domain}/.well-known/did.json"


@dataclass
class DemoWorld:
    """The whole demonstration, in memory."""

    root: Authority
    issuing: Authority
    ocsp_signer_cert: x509.Certificate
    ocsp_signer_key: object
    issuer_a: IssuerFixture
    issuer_b: IssuerFixture
    rogue_root: Authority = field(default=None)  # type: ignore[assignment]

    @property
    def root_pem(self) -> bytes:
        return pem(self.root.cert)

    def chain_for(self, issuer: IssuerFixture) -> list[x509.Certificate]:
        return [issuer.cert, self.issuing.cert]

    def ocsp_good(self, issuer: IssuerFixture, **kw) -> bytes:
        return build_ocsp_response(
            subject_cert=issuer.cert, issuer_cert=self.issuing.cert,
            responder_cert=self.ocsp_signer_cert, responder_key=self.ocsp_signer_key,
            status=ocsp.OCSPCertStatus.GOOD, **kw,
        )

    def ocsp_revoked(self, issuer: IssuerFixture, *, when: dt.datetime | None = None, **kw) -> bytes:
        return build_ocsp_response(
            subject_cert=issuer.cert, issuer_cert=self.issuing.cert,
            responder_cert=self.ocsp_signer_cert, responder_key=self.ocsp_signer_key,
            status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=(when or now() - dt.timedelta(minutes=1)).replace(tzinfo=None),
            revocation_reason=x509.ReasonFlags.privilege_withdrawn,
            **kw,
        )

    def ocsp_unknown(self, issuer: IssuerFixture, **kw) -> bytes:
        return build_ocsp_response(
            subject_cert=issuer.cert, issuer_cert=self.issuing.cert,
            responder_cert=self.ocsp_signer_cert, responder_key=self.ocsp_signer_key,
            status=ocsp.OCSPCertStatus.UNKNOWN, **kw,
        )

    def crl(self, *, revoked_serials: Sequence[int] = (), **kw) -> bytes:
        entries = [
            (s, now() - dt.timedelta(minutes=1), x509.ReasonFlags.privilege_withdrawn)
            for s in revoked_serials
        ]
        return build_crl(issuer_cert=self.issuing.cert, issuer_key=self.issuing.key,
                         revoked=entries, **kw)


def _make_issuer(
    issuing: Authority,
    *,
    domain: str,
    cn: str,
    ocsp_url: str | None,
    crl_url: str | None,
    chain_extra: Sequence[x509.Certificate] = (),
) -> IssuerFixture:
    did = f"did:web:{domain}"
    key = ec_key()
    cert = issuing.issue(
        subject=dn(cn),
        public_key=key.public_key(),
        extensions=leaf_extensions(
            key, issuing.cert, did=did, ocsp_url=ocsp_url, crl_url=crl_url
        ),
    )
    chain = [cert, issuing.cert, *chain_extra]
    fragment = jwk_thumbprint(ec_public_jwk(key, kid="tmp"))
    jwk = ec_public_jwk(key, kid=fragment, x5c=chain)
    document = build_did_document(did, jwk=jwk, fragment=fragment)
    payload = vc_payload(did)
    return IssuerFixture(
        domain=domain,
        did=did,
        key=key,
        cert=cert,
        fragment=fragment,
        jwk=jwk,
        did_document=document,
        credential_jose=sign_jws_compact(payload, key, kid=f"{did}#{fragment}"),
        credential_di=sign_data_integrity(
            vc_payload(did, credential_id="urn:uuid:66666666-7777-8888-9999-aaaaaaaaaaaa"),
            key,
            verification_method=f"{did}#{fragment}",
        ),
    )


def build_world() -> DemoWorld:
    root_key = rsa_key()
    root_cert = self_signed_root(NRCA_CN, root_key)
    root = Authority(key=root_key, cert=root_cert)

    issuing_key = rsa_key()
    issuing_cert = root.issue(
        subject=dn(ISSUING_CA_CN),
        public_key=issuing_key.public_key(),
        extensions=ca_extensions(issuing_key, root.cert, path_length=0),
        not_after=now() + dt.timedelta(days=3650),
    )
    issuing = Authority(key=issuing_key, cert=issuing_cert)

    signer_key = rsa_key()
    signer_cert = issuing.issue(
        subject=dn(OCSP_SIGNER_CN),
        public_key=signer_key.public_key(),
        extensions=ocsp_signer_extensions(signer_key, issuing.cert),
        not_after=now() + dt.timedelta(days=365),
    )

    rogue_key = rsa_key()
    rogue = Authority(key=rogue_key, cert=self_signed_root("Rogue Root CA", rogue_key))

    return DemoWorld(
        root=root,
        issuing=issuing,
        ocsp_signer_cert=signer_cert,
        ocsp_signer_key=signer_key,
        issuer_a=_make_issuer(
            issuing, domain=ISSUER_A_DOMAIN, cn="Jacaranda Propaganda Credential Issuer",
            ocsp_url=OCSP_URL, crl_url=None,
        ),
        issuer_b=_make_issuer(
            issuing, domain=ISSUER_B_DOMAIN, cn="Lawnbull Credential Issuer",
            ocsp_url=None, crl_url=CRL_URL,
        ),
        rogue_root=rogue,
    )
