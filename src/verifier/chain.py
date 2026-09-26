"""RFC 5280 path validation to the National Root CA, and nothing else.

Written out by hand rather than delegated to a library, for two reasons. The leaf is a
signing-only certificate identified by a URI SAN, which the web-PKI validators in most
libraries will not accept; and the demonstration needs each step to be nameable on camera.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .reasons import (CERTIFICATE_EXPIRED, CERTIFICATE_NOT_YET_VALID,
                      CHAIN_CA_CANNOT_SIGN_CERTIFICATES, CHAIN_INCOMPLETE,
                      CHAIN_NAME_MISMATCH, CHAIN_NOT_A_CA, CHAIN_PATH_LEN_EXCEEDED,
                      CHAIN_SIGNATURE_INVALID, CHAIN_TOO_LONG, CHAIN_UNTRUSTED_ROOT,
                      NO_TRUST_ANCHORS, X5C_MALFORMED, X5C_MISSING, X5U_FETCH_FAILED,
                      X5U_NOT_ALLOWED, Rejected)
from .transport import NetworkUnavailable, fetch

UTC = dt.timezone.utc


@dataclass
class Path:
    """A validated certification path, leaf first, plus the anchor it reached."""

    certificates: list[x509.Certificate]
    anchor: x509.Certificate

    @property
    def leaf(self) -> x509.Certificate:
        return self.certificates[0]

    @property
    def issuing_ca(self) -> x509.Certificate:
        """Whatever certified the leaf: the next certificate up, or the anchor itself."""
        return self.certificates[1] if len(self.certificates) > 1 else self.anchor

    def describe(self) -> str:
        names = [_cn(c) for c in self.certificates] + [f"{_cn(self.anchor)} (trust anchor)"]
        return " -> ".join(names)


# ---------------------------------------------------------------- loading x5c

def load_chain(jwk: dict, *, policy, transport) -> list[x509.Certificate]:
    """Get the certificate chain out of the JWK, by x5c or, if policy allows, x5u.

    A JWK with no chain at all is rejected unconditionally: that is the brief's second
    verifier rule, and it is a premise rather than a setting, because with no chain there
    is nothing to validate against the National Root CA. Whether a chain held by *reference*
    will do is the setting -- `allow_x5u`.
    """
    raw = jwk.get("x5c")
    if raw:
        if not isinstance(raw, list):
            raise Rejected(X5C_MALFORMED, "x5c is not an array")
        return [_load_x5c_entry(entry, position) for position, entry in enumerate(raw)]

    x5u = jwk.get("x5u")
    if x5u:
        if not policy.allow_x5u:
            raise Rejected(
                X5U_NOT_ALLOWED,
                f"the JWK carries x5u ({x5u}) rather than x5c, and policy does not allow it; "
                "an x5u reference cannot be followed without a network",
            )
        return _fetch_x5u(x5u, policy=policy, transport=transport)

    raise Rejected(
        X5C_MISSING,
        "the verification method's publicKeyJwk has no x5c, so there is no certificate "
        "chain to validate against the National Root CA",
    )


def _load_x5c_entry(entry, position: int) -> x509.Certificate:
    if not isinstance(entry, str) or not entry:
        raise Rejected(X5C_MALFORMED, f"x5c[{position}] is not a string")
    try:
        # RFC 7517 §4.7: standard base64 of the DER certificate, not base64url.
        der = base64.b64decode(entry, validate=True)
    except (ValueError, TypeError) as exc:
        raise Rejected(
            X5C_MALFORMED,
            f"x5c[{position}] is not standard base64 as RFC 7517 requires: {exc}",
        ) from exc
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise Rejected(X5C_MALFORMED, f"x5c[{position}] is not a DER certificate: {exc}") from exc


def _fetch_x5u(url: str, *, policy, transport) -> list[x509.Certificate]:
    try:
        body = fetch(transport, url, timeout=policy.http_timeout_seconds)
    except NetworkUnavailable as exc:
        raise Rejected(
            X5U_FETCH_FAILED,
            f"the chain lives at {url} and could not be fetched ({exc}); "
            "this is exactly what x5c avoids",
        ) from exc
    try:
        certificates = x509.load_pem_x509_certificates(body)
    except ValueError as exc:
        raise Rejected(X5C_MALFORMED, f"the chain at {url} is not PEM certificates: {exc}") from exc
    if not certificates:
        raise Rejected(X5C_MALFORMED, f"the chain at {url} contains no certificates")
    return certificates


# --------------------------------------------------------------- path building

def validate(
    chain: list[x509.Certificate],
    anchors: list[x509.Certificate],
    *,
    at: dt.datetime,
    policy,
) -> Path:
    if not anchors:
        raise Rejected(
            NO_TRUST_ANCHORS,
            "no trust anchor is configured; the National Root CA certificate is missing "
            "from the laptop's trust store",
        )
    if not chain:
        raise Rejected(CHAIN_INCOMPLETE, "the certificate chain is empty")
    if len(chain) > policy.max_chain_depth:
        raise Rejected(
            CHAIN_TOO_LONG,
            f"the chain has {len(chain)} certificates, policy allows {policy.max_chain_depth}",
        )

    skew = dt.timedelta(seconds=policy.clock_skew_seconds)
    path: list[x509.Certificate] = [chain[0]]
    _check_validity(chain[0], at=at, skew=skew)

    index = 0
    while True:
        current = path[-1]
        anchor = _anchor_for(current, anchors, at=at, skew=skew)
        if anchor is not None:
            _check_path_lengths(path, anchor)
            return Path(certificates=path, anchor=anchor)

        index += 1
        if index >= len(chain):
            if current.subject == current.issuer:
                raise Rejected(
                    CHAIN_UNTRUSTED_ROOT,
                    f"the chain ends at the self-signed {_cn(current)!r}, which is not a "
                    "configured trust anchor",
                )
            raise Rejected(
                CHAIN_INCOMPLETE,
                f"{_cn(current)!r} was issued by {_cn_of_name(current.issuer)!r}, which is "
                "neither in x5c nor a configured trust anchor",
            )

        issuer = chain[index]
        if issuer.subject != current.issuer:
            raise Rejected(
                CHAIN_NAME_MISMATCH,
                f"{_cn(current)!r} names issuer {_cn_of_name(current.issuer)!r}, but the next "
                f"certificate in x5c is {_cn(issuer)!r}",
            )
        _check_validity(issuer, at=at, skew=skew)
        _require_ca(issuer)
        _verify_signature(current, issuer)
        path.append(issuer)


def _anchor_for(cert, anchors, *, at, skew):
    for anchor in anchors:
        if anchor.subject != cert.issuer:
            continue
        try:
            _verify_signature(cert, anchor)
        except Rejected:
            continue
        _check_validity(anchor, at=at, skew=skew)
        if cert is not anchor:
            _require_ca(anchor)
        return anchor
    return None


def _check_validity(cert: x509.Certificate, *, at: dt.datetime, skew: dt.timedelta) -> None:
    not_before = _aware(cert.not_valid_before_utc)
    not_after = _aware(cert.not_valid_after_utc)
    if at + skew < not_before:
        raise Rejected(
            CERTIFICATE_NOT_YET_VALID,
            f"{_cn(cert)!r} is not valid before {not_before.isoformat()}",
        )
    if at - skew > not_after:
        raise Rejected(
            CERTIFICATE_EXPIRED,
            f"{_cn(cert)!r} expired at {not_after.isoformat()}",
        )


def _require_ca(cert: x509.Certificate) -> None:
    try:
        basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        raise Rejected(
            CHAIN_NOT_A_CA,
            f"{_cn(cert)!r} has no basicConstraints, so it may not certify other certificates",
        ) from None
    if not basic.ca:
        raise Rejected(
            CHAIN_NOT_A_CA,
            f"{_cn(cert)!r} is basicConstraints CA:FALSE and may not issue certificates",
        )
    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return
    if not usage.key_cert_sign:
        raise Rejected(
            CHAIN_CA_CANNOT_SIGN_CERTIFICATES,
            f"{_cn(cert)!r} is a CA but its keyUsage lacks keyCertSign",
        )


def _check_path_lengths(path: list[x509.Certificate], anchor: x509.Certificate) -> None:
    """A CA's pathLenConstraint bounds how many CAs may sit below it."""
    for position, cert in enumerate(list(path) + [anchor]):
        if position == 0:
            continue  # the leaf constrains nothing
        limit = _path_length_of(cert)
        if limit is None:
            continue
        intermediates_below = position - 1
        if intermediates_below > limit:
            raise Rejected(
                CHAIN_PATH_LEN_EXCEEDED,
                f"{_cn(cert)!r} carries pathlen:{limit} but {intermediates_below} "
                "intermediate CA(s) sit below it in this path",
            )


def _path_length_of(cert: x509.Certificate) -> int | None:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.path_length
    except x509.ExtensionNotFound:
        return None


def _verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes,
                       padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes,
                       ec.ECDSA(cert.signature_hash_algorithm))
        else:
            raise Rejected(
                CHAIN_SIGNATURE_INVALID,
                f"{_cn(issuer)!r} uses an unsupported key type {type(key).__name__}",
            )
    except InvalidSignature as exc:
        raise Rejected(
            CHAIN_SIGNATURE_INVALID,
            f"{_cn(cert)!r} was not signed by {_cn(issuer)!r}",
        ) from exc
    except Rejected:
        raise
    except Exception as exc:  # noqa: BLE001 -- unsupported padding, bad parameters, ...
        raise Rejected(
            CHAIN_SIGNATURE_INVALID,
            f"could not verify {_cn(cert)!r} against {_cn(issuer)!r}: {exc}",
        ) from exc


# ------------------------------------------------------------------- helpers

def spki(cert_or_key) -> bytes:
    key = cert_or_key.public_key() if hasattr(cert_or_key, "public_key") else cert_or_key
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def sha256_of_der(cert: x509.Certificate) -> bytes:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _cn(cert: x509.Certificate) -> str:
    return _cn_of_name(cert.subject)


def _cn_of_name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()
