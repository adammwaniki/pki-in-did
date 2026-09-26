"""Revocation: OCSP through the AIA extension, CRL through the distribution point.

The brief's third verifier rule is the whole of this module's purpose: reject a credential
if the revocation status is unknown or expired. Cached data is honoured only while inside
its own `nextUpdate`, which is precisely what creates the CRL revocation window the
demonstration shows.
"""

from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import (AuthorityInformationAccessOID, CRLEntryExtensionOID,
                                   ExtendedKeyUsageOID, ExtensionOID)

from .reasons import (REVOCATION_EXPIRED, REVOCATION_RESPONSE_MISMATCH,
                      REVOCATION_RESPONSE_NONCE_MISMATCH,
                      REVOCATION_RESPONSE_NOT_YET_VALID, REVOCATION_RESPONSE_UNTRUSTED,
                      REVOCATION_REVOKED, REVOCATION_SOURCE_MISSING, REVOCATION_STALE,
                      REVOCATION_UNKNOWN, Rejected)
from .transport import NetworkUnavailable, fetch, post

UTC = dt.timezone.utc

#: cryptography spells the reason codes in snake_case; X.509 and the brief use camelCase.
REASON_NAMES = {
    x509.ReasonFlags.unspecified: "unspecified",
    x509.ReasonFlags.key_compromise: "keyCompromise",
    x509.ReasonFlags.ca_compromise: "cACompromise",
    x509.ReasonFlags.affiliation_changed: "affiliationChanged",
    x509.ReasonFlags.superseded: "superseded",
    x509.ReasonFlags.cessation_of_operation: "cessationOfOperation",
    x509.ReasonFlags.certificate_hold: "certificateHold",
    x509.ReasonFlags.privilege_withdrawn: "privilegeWithdrawn",
    x509.ReasonFlags.aa_compromise: "aACompromise",
    x509.ReasonFlags.remove_from_crl: "removeFromCRL",
}


@dataclass
class Outcome:
    method: str | None                 # "ocsp" | "crl" | None
    status: str                        # "good" | "revoked" | "unknown" | "expired"
    source: str | None = None          # "network" | "cache"
    reason: str | None = None          # the X.509 reason code, when revoked
    reason_code: str | None = None     # the verifier reason string, when rejecting
    detail: str = ""
    url: str | None = None
    this_update: dt.datetime | None = None
    next_update: dt.datetime | None = None
    produced_at: dt.datetime | None = None
    revoked_at: dt.datetime | None = None

    @property
    def accepted(self) -> bool:
        return self.status == "good"

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "status": self.status,
            "source": self.source,
            "reason": self.reason,
            "url": self.url,
            "thisUpdate": _iso(self.this_update),
            "nextUpdate": _iso(self.next_update),
            "producedAt": _iso(self.produced_at),
            "revokedAt": _iso(self.revoked_at),
            "detail": self.detail,
        }


# ----------------------------------------------------------------- entry point

def check(leaf, issuer, *, policy, store, transport, at: dt.datetime) -> Outcome:
    ocsp_urls = _ocsp_urls(leaf)
    crl_urls = _crl_urls(leaf)

    if ocsp_urls:
        return _via_ocsp(leaf, issuer, ocsp_urls[0],
                         policy=policy, store=store, transport=transport, at=at)
    if crl_urls:
        return _via_crl(leaf, issuer, crl_urls[0],
                        policy=policy, store=store, transport=transport, at=at)
    return Outcome(
        method=None, status="unknown", reason_code=REVOCATION_SOURCE_MISSING,
        detail="the certificate carries neither an AIA OCSP URI nor a CRL distribution point, "
               "so its revocation status cannot be established",
    )


def _ocsp_urls(cert) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in aia
            if d.access_method == AuthorityInformationAccessOID.OCSP
            and isinstance(d.access_location, x509.UniformResourceIdentifier)]


def _crl_urls(cert) -> list[str]:
    try:
        points = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for point in points:
        for name in point.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return urls


# ------------------------------------------------------------------------ OCSP

def _via_ocsp(leaf, issuer, url, *, policy, store, transport, at) -> Outcome:
    fresh = None
    # RFC 6960 §4.4.1: a nonce binds the answer to this question. Without it a captured
    # "good" response can be replayed for as long as it remains fresh.
    nonce = secrets.token_bytes(16)
    try:
        fresh = post(transport, url, _ocsp_request(leaf, issuer, nonce=nonce),
                     content_type="application/ocsp-request",
                     timeout=policy.http_timeout_seconds)
    except NetworkUnavailable as network_error:
        network_detail = str(network_error)
    else:
        network_detail = None

    if fresh is not None:
        outcome = _evaluate_ocsp(fresh, leaf, issuer, policy=policy, at=at, source="network",
                                 expected_nonce=nonce)
        outcome.url = url
        if outcome.status in ("good", "revoked"):
            store.put_ocsp(leaf, issuer, fresh, url=url)
        return outcome

    if not policy.allow_cached_revocation:
        return Outcome(method="ocsp", status="unknown", url=url,
                       reason_code=REVOCATION_UNKNOWN,
                       detail=f"the OCSP responder at {url} could not be reached "
                              f"({network_detail}) and cached responses are not allowed")

    cached = store.get_ocsp(leaf, issuer)
    if cached is None:
        return Outcome(method="ocsp", status="unknown", url=url,
                       reason_code=REVOCATION_UNKNOWN,
                       detail=f"the OCSP responder at {url} could not be reached "
                              f"({network_detail}) and nothing is cached for this certificate")
    outcome = _evaluate_ocsp(cached.der, leaf, issuer, policy=policy, at=at, source="cache")
    outcome.url = url
    return outcome


def _ocsp_request(leaf, issuer, *, nonce: bytes | None = None) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    builder = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA256())
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(Encoding.DER)


def _evaluate_ocsp(der: bytes, leaf, issuer, *, policy, at, source: str,
                   expected_nonce: bytes | None = None) -> Outcome:
    try:
        response = ocsp.load_der_ocsp_response(der)
    except ValueError as exc:
        return Outcome(method="ocsp", status="unknown", source=source,
                       reason_code=REVOCATION_UNKNOWN,
                       detail=f"the OCSP response could not be parsed: {exc}")

    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return Outcome(method="ocsp", status="unknown", source=source,
                       reason_code=REVOCATION_UNKNOWN,
                       detail=f"the responder returned {response.response_status.name}")

    if response.serial_number != leaf.serial_number:
        return Outcome(method="ocsp", status="unknown", source=source,
                       reason_code=REVOCATION_RESPONSE_MISMATCH,
                       detail=f"the response is about serial {response.serial_number:x}, "
                              f"not {leaf.serial_number:x}")

    if not _request_matches_issuer(response, leaf, issuer):
        return Outcome(method="ocsp", status="unknown", source=source,
                       reason_code=REVOCATION_RESPONSE_MISMATCH,
                       detail="the response names a different certificate issuer")

    untrusted = _check_ocsp_signature(response, issuer)
    if untrusted:
        return Outcome(method="ocsp", status="unknown", source=source,
                       reason_code=REVOCATION_RESPONSE_UNTRUSTED, detail=untrusted)

    # A nonce is only checkable when we asked the question ourselves. A cached response
    # carries the nonce of a request we no longer hold, and many responders omit nonces
    # entirely so that they can pre-sign answers, so an absent nonce is not a failure --
    # freshness then rests on thisUpdate and nextUpdate.
    if expected_nonce is not None:
        returned = _nonce_of(response)
        if returned is not None and returned != expected_nonce:
            return Outcome(method="ocsp", status="unknown", source=source,
                           reason_code=REVOCATION_RESPONSE_NONCE_MISMATCH,
                           detail="the OCSP response answers a different request: its nonce "
                                  "does not match the one just sent")

    this_update = _aware(response.this_update_utc)
    next_update = _aware(response.next_update_utc) if response.next_update_utc else None
    produced_at = _aware(response.produced_at_utc)
    skew = dt.timedelta(seconds=policy.clock_skew_seconds)

    base = dict(method="ocsp", source=source, this_update=this_update,
                next_update=next_update, produced_at=produced_at)

    if this_update - skew > at:
        return Outcome(status="unknown", reason_code=REVOCATION_RESPONSE_NOT_YET_VALID,
                       detail=f"the response is dated {this_update.isoformat()}, in the future",
                       **base)

    effective_next = next_update or (produced_at + dt.timedelta(seconds=policy.ocsp_max_age_seconds))
    if effective_next + skew < at:
        return Outcome(status="expired", reason_code=REVOCATION_EXPIRED,
                       detail=f"the response expired at {effective_next.isoformat()}", **base)

    if at - this_update > dt.timedelta(seconds=policy.ocsp_max_age_seconds) + skew:
        return Outcome(status="expired", reason_code=REVOCATION_STALE,
                       detail=f"the response is {_age(at, this_update)} old, beyond the "
                              f"{policy.ocsp_max_age_seconds}s the policy tolerates", **base)

    if response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        reason = REASON_NAMES.get(response.revocation_reason, "unspecified")
        revoked_at = _aware(response.revocation_time_utc) if response.revocation_time_utc else None
        return Outcome(status="revoked", reason=reason, reason_code=REVOCATION_REVOKED,
                       revoked_at=revoked_at,
                       detail=f"the Issuing CA reports this certificate revoked ({reason})"
                              + (f" at {revoked_at.isoformat()}" if revoked_at else ""),
                       **base)

    if response.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
        return Outcome(status="unknown", reason_code=REVOCATION_UNKNOWN,
                       detail="the responder does not know this certificate", **base)

    return Outcome(status="good", detail="the Issuing CA reports status good", **base)


def _request_matches_issuer(response, leaf, issuer) -> bool:
    """Confirm the response's issuer hashes describe the CA we think issued the leaf."""
    try:
        expected = ocsp.OCSPRequestBuilder().add_certificate(
            leaf, issuer, response.hash_algorithm
        ).build()
    except Exception:  # noqa: BLE001 -- an unsupported hash algorithm
        return False
    return (response.issuer_key_hash == expected.issuer_key_hash
            and response.issuer_name_hash == expected.issuer_name_hash)


def _check_ocsp_signature(response, issuer) -> str | None:
    """RFC 6960: the CA signs, or a certificate it issued bearing EKU id-kp-OCSPSigning does.

    Returns a description of the problem, or None when the response is properly signed.
    """
    delegates = list(response.certificates)
    if delegates:
        # A responder may ship more than one certificate, in any order. Find one the CA
        # actually issued AND delegated to, rather than assuming the first is it.
        responder = None
        issued_by_ca = []
        for candidate in delegates:
            try:
                _verify(candidate.signature, candidate.tbs_certificate_bytes,
                        issuer.public_key(), candidate.signature_hash_algorithm)
            except Exception:  # noqa: BLE001 -- not issued by this CA; try the next
                continue
            issued_by_ca.append(candidate)
            if _has_ocsp_signing(candidate):
                responder = candidate
                break

        if responder is None:
            if not issued_by_ca:
                return (f"the OCSP response carries {len(delegates)} certificate(s), none "
                        f"issued by {_cn(issuer)!r}")
            return (f"the responder certificate {_cn(issued_by_ca[0])!r} lacks the "
                    "OCSPSigning extended key usage, so the Issuing CA never delegated to it")
        verifier_key = responder.public_key()
        signer = _cn(responder)
    else:
        verifier_key = issuer.public_key()
        signer = _cn(issuer)

    try:
        _verify(response.signature, response.tbs_response_bytes,
                verifier_key, response.signature_hash_algorithm)
    except InvalidSignature:
        return f"the OCSP response signature does not verify against {signer!r}"
    except Exception as exc:  # noqa: BLE001
        return f"the OCSP response signature could not be checked: {exc}"
    return None


def _nonce_of(response) -> bytes | None:
    try:
        return response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound:
        return None
    except Exception:  # noqa: BLE001 -- a malformed extension is the same as none
        return None


def _has_ocsp_signing(cert) -> bool:
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in eku


# ------------------------------------------------------------------------- CRL

def _via_crl(leaf, issuer, url, *, policy, store, transport, at) -> Outcome:
    fresh = None
    try:
        fresh = fetch(transport, url, timeout=policy.http_timeout_seconds)
    except NetworkUnavailable as network_error:
        network_detail = str(network_error)
    else:
        network_detail = None

    if fresh is not None:
        outcome = _evaluate_crl(fresh, leaf, issuer, policy=policy, at=at, source="network")
        outcome.url = url
        if outcome.status in ("good", "revoked"):
            store.put_crl(issuer, fresh, url=url)
        return outcome

    if not policy.allow_cached_revocation:
        return Outcome(method="crl", status="unknown", url=url, reason_code=REVOCATION_UNKNOWN,
                       detail=f"the CRL at {url} could not be fetched ({network_detail}) "
                              "and cached CRLs are not allowed")

    cached = store.get_crl(issuer)
    if cached is None:
        return Outcome(method="crl", status="unknown", url=url, reason_code=REVOCATION_UNKNOWN,
                       detail=f"the CRL at {url} could not be fetched ({network_detail}) "
                              "and no CRL is cached for this Issuing CA")
    outcome = _evaluate_crl(cached.der, leaf, issuer, policy=policy, at=at, source="cache")
    outcome.url = url
    return outcome


def _evaluate_crl(body: bytes, leaf, issuer, *, policy, at, source: str) -> Outcome:
    crl = _load_crl(body)
    if crl is None:
        return Outcome(method="crl", status="unknown", source=source,
                       reason_code=REVOCATION_UNKNOWN,
                       detail="the CRL could not be parsed as DER or PEM")

    if crl.issuer != issuer.subject:
        return Outcome(method="crl", status="unknown", source=source,
                       reason_code=REVOCATION_RESPONSE_UNTRUSTED,
                       detail=f"the CRL was issued by {_cn_of_name(crl.issuer)!r}, "
                              f"not by {_cn(issuer)!r}")
    if not crl.is_signature_valid(issuer.public_key()):
        return Outcome(method="crl", status="unknown", source=source,
                       reason_code=REVOCATION_RESPONSE_UNTRUSTED,
                       detail=f"the CRL signature does not verify against {_cn(issuer)!r}")

    this_update = _aware(crl.last_update_utc)
    next_update = _aware(crl.next_update_utc) if crl.next_update_utc else None
    skew = dt.timedelta(seconds=policy.clock_skew_seconds)
    base = dict(method="crl", source=source, this_update=this_update, next_update=next_update)

    if this_update - skew > at:
        return Outcome(status="unknown", reason_code=REVOCATION_RESPONSE_NOT_YET_VALID,
                       detail=f"the CRL is dated {this_update.isoformat()}, in the future", **base)

    if next_update is None:
        return Outcome(status="expired", reason_code=REVOCATION_EXPIRED,
                       detail="the CRL has no nextUpdate, so its freshness cannot be judged",
                       **base)
    if next_update + skew < at:
        return Outcome(status="expired", reason_code=REVOCATION_EXPIRED,
                       detail=f"the CRL expired at {next_update.isoformat()}", **base)

    if at - this_update > dt.timedelta(seconds=policy.crl_max_age_seconds) + skew:
        return Outcome(status="expired", reason_code=REVOCATION_STALE,
                       detail=f"the CRL is {_age(at, this_update)} old, beyond the "
                              f"{policy.crl_max_age_seconds}s the policy tolerates", **base)

    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if entry is not None:
        reason = "unspecified"
        try:
            reason = REASON_NAMES.get(
                entry.extensions.get_extension_for_oid(CRLEntryExtensionOID.CRL_REASON).value.reason,
                "unspecified",
            )
        except x509.ExtensionNotFound:
            pass
        revoked_at = _aware(entry.revocation_date_utc)
        return Outcome(status="revoked", reason=reason, reason_code=REVOCATION_REVOKED,
                       revoked_at=revoked_at,
                       detail=f"serial {leaf.serial_number:x} is listed on the CRL "
                              f"({reason}, {revoked_at.isoformat()})", **base)

    return Outcome(status="good",
                   detail=f"serial {leaf.serial_number:x} is absent from a CRL valid until "
                          f"{next_update.isoformat()}", **base)


def _load_crl(body: bytes):
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            return loader(body)
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------- helpers

def _verify(signature: bytes, data: bytes, key, algorithm) -> None:
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, data, padding.PKCS1v15(), algorithm)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, data, ec.ECDSA(algorithm))
    else:
        raise InvalidSignature(f"unsupported key type {type(key).__name__}")


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _age(at: dt.datetime, then: dt.datetime) -> str:
    seconds = int((at - then).total_seconds())
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def _cn(cert) -> str:
    return _cn_of_name(cert.subject)


def _cn_of_name(name) -> str:
    from cryptography.x509.oid import NameOID

    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()
