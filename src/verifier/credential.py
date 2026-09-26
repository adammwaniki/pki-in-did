"""Parsing the two securing mechanisms the source document describes.

* **VC-JOSE-COSE** -- a compact JWS whose payload is the credential and whose `kid` header
  is the absolute DID URL of the verification method. This is what walt.id issuer-api2
  emits (`typ: vc+jwt`).
* **Data Integrity / JsonWebSignature2020** -- the shape in the source document's §4
  example: a detached JWS in `proof.jws` with `proof.verificationMethod`.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field

from .jose import b64u_decode, b64u_encode, jcs
from .reasons import (CREDENTIAL_EXPIRED, CREDENTIAL_NOT_YET_VALID, ISSUER_INCONSISTENT,
                      KEY_REFERENCE_MISSING, KEY_REFERENCE_NOT_ABSOLUTE,
                      MALFORMED_CREDENTIAL, PROOF_PURPOSE_INVALID, Rejected)

UTC = dt.timezone.utc


@dataclass
class ParsedCredential:
    form: str                      # "vc-jose-cose" or "data-integrity"
    alg: str
    key_reference: str             # absolute DID URL of the verification method
    issuer: str
    types: list[str]
    signing_input: bytes
    signature: bytes
    payload: dict
    proof_purpose: str | None = None
    valid_from: dt.datetime | None = None
    valid_until: dt.datetime | None = None
    header: dict = field(default_factory=dict)

    @property
    def key_reference_did(self) -> str:
        return self.key_reference.split("#", 1)[0]


def parse(credential) -> ParsedCredential:
    if isinstance(credential, dict):
        return _parse_data_integrity(credential)
    if isinstance(credential, bytes):
        credential = credential.decode("utf-8", errors="replace")
    if not isinstance(credential, str):
        raise Rejected(MALFORMED_CREDENTIAL, f"cannot read a credential from {type(credential).__name__}")

    text = credential.strip()
    if not text:
        raise Rejected(MALFORMED_CREDENTIAL, "the credential is empty")
    if text.startswith("{"):
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise Rejected(MALFORMED_CREDENTIAL, f"not valid JSON: {exc}") from exc
        return _parse_data_integrity(document)
    return _parse_compact_jws(text)


# --------------------------------------------------------------- VC-JOSE-COSE

def _parse_compact_jws(token: str) -> ParsedCredential:
    parts = token.split(".")
    if len(parts) != 3:
        raise Rejected(
            MALFORMED_CREDENTIAL,
            f"a compact JWS has three dot-separated parts, this has {len(parts)}",
        )
    raw_header, raw_payload, raw_signature = parts
    header = _decode_json_segment(raw_header, "JOSE header")
    payload = _decode_json_segment(raw_payload, "credential payload")

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise Rejected(MALFORMED_CREDENTIAL, "the JOSE header has no alg")

    try:
        signature = b64u_decode(raw_signature) if raw_signature else b""
    except ValueError as exc:
        raise Rejected(MALFORMED_CREDENTIAL, f"the signature is not base64url: {exc}") from exc

    issuer = _issuer_of(payload)
    parsed = ParsedCredential(
        form="vc-jose-cose",
        alg=alg,
        key_reference=_key_reference(header.get("kid")),
        issuer=issuer,
        types=_types_of(payload),
        signing_input=f"{raw_header}.{raw_payload}".encode("ascii"),
        signature=signature,
        payload=payload,
        header=header,
        valid_from=_valid_from(payload),
        valid_until=_valid_until(payload),
    )
    return parsed


# ------------------------------------------------------------- Data Integrity

def _parse_data_integrity(document: dict) -> ParsedCredential:
    if not isinstance(document, dict):
        raise Rejected(MALFORMED_CREDENTIAL, "the credential is not a JSON object")
    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise Rejected(MALFORMED_CREDENTIAL, "the credential has no proof object")

    jws = proof.get("jws")
    if not isinstance(jws, str) or jws.count(".") != 2:
        raise Rejected(MALFORMED_CREDENTIAL, "proof.jws is not a detached compact JWS")
    raw_header, detached, raw_signature = jws.split(".")
    if detached:
        raise Rejected(MALFORMED_CREDENTIAL, "proof.jws must have a detached payload")
    header = _decode_json_segment(raw_header, "proof header")

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise Rejected(MALFORMED_CREDENTIAL, "the proof header has no alg")
    try:
        signature = b64u_decode(raw_signature) if raw_signature else b""
    except ValueError as exc:
        raise Rejected(MALFORMED_CREDENTIAL, f"the signature is not base64url: {exc}") from exc

    body = {k: v for k, v in document.items() if k != "proof"}
    proof_without_jws = {k: v for k, v in proof.items() if k != "jws"}
    signing_input = b64u_encode(jcs(header)).encode("ascii") + b"." + jcs(
        {**body, "proof": proof_without_jws}
    )

    parsed = ParsedCredential(
        form="data-integrity",
        alg=alg,
        key_reference=_key_reference(proof.get("verificationMethod")),
        issuer=_issuer_of(document),
        types=_types_of(document),
        signing_input=signing_input,
        signature=signature,
        payload=document,
        header=header,
        proof_purpose=proof.get("proofPurpose"),
        valid_from=_valid_from(document),
        valid_until=_valid_until(document),
    )
    return parsed


def check_proof_purpose(parsed: ParsedCredential) -> None:
    """DID Core §5.3.2: issuing a credential is an assertionMethod relationship."""
    if parsed.form != "data-integrity":
        return
    if parsed.proof_purpose != "assertionMethod":
        raise Rejected(
            PROOF_PURPOSE_INVALID,
            f"proof.proofPurpose is {parsed.proof_purpose!r}, not 'assertionMethod'",
        )


# ------------------------------------------------------------------ internals

def _decode_json_segment(segment: str, what: str) -> dict:
    try:
        decoded = json.loads(b64u_decode(segment))
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise Rejected(MALFORMED_CREDENTIAL, f"the {what} is not base64url JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise Rejected(MALFORMED_CREDENTIAL, f"the {what} is not a JSON object")
    return decoded


def _key_reference(value) -> str:
    if not value:
        raise Rejected(
            KEY_REFERENCE_MISSING,
            "the credential does not say which verification method signed it "
            "(no JOSE kid, no proof.verificationMethod)",
        )
    if not isinstance(value, str):
        raise Rejected(KEY_REFERENCE_MISSING, "the key reference is not a string")
    if not value.startswith("did:"):
        raise Rejected(
            KEY_REFERENCE_NOT_ABSOLUTE,
            f"the key reference {value!r} is relative; did:web requires absolute DID URLs",
        )
    return value


def _issuer_of(payload: dict) -> str:
    """`iss`, `issuer` as a string, or `issuer` as an object with an `id`.

    When both `iss` and `issuer` are present they must agree; walt.id emits both.
    """
    issuer = payload.get("issuer")
    if isinstance(issuer, dict):
        issuer = issuer.get("id")
    iss = payload.get("iss")

    if isinstance(issuer, str) and isinstance(iss, str) and issuer != iss:
        raise Rejected(
            ISSUER_INCONSISTENT,
            f"the credential names two different issuers: iss={iss!r} and issuer={issuer!r}",
        )
    found = issuer if isinstance(issuer, str) else iss
    if not isinstance(found, str) or not found:
        raise Rejected(MALFORMED_CREDENTIAL, "the credential does not name an issuer")
    return found


def _types_of(payload: dict) -> list[str]:
    types = payload.get("type") or payload.get("types") or []
    if isinstance(types, str):
        return [types]
    return [t for t in types if isinstance(t, str)]


def _valid_from(payload: dict) -> dt.datetime | None:
    for key in ("validFrom", "issuanceDate"):
        parsed = _parse_timestamp(payload.get(key))
        if parsed:
            return parsed
    return _from_epoch(payload.get("nbf"))


def _valid_until(payload: dict) -> dt.datetime | None:
    for key in ("validUntil", "expirationDate"):
        parsed = _parse_timestamp(payload.get(key))
        if parsed:
            return parsed
    return _from_epoch(payload.get("exp"))


def _from_epoch(value) -> dt.datetime | None:
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value, tz=UTC)
    return None


def _parse_timestamp(value) -> dt.datetime | None:
    """Parse an XSD dateTime, tolerating more fractional digits than Python accepts.

    walt.id issuer-api2 emits nanoseconds (2026-09-26T12:26:57.207818928Z), which
    datetime.fromisoformat rejects; the fraction is truncated to microseconds.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    if "." in text:
        head, _, tail = text.partition(".")
        digits = ""
        for char in tail:
            if char.isdigit():
                digits += char
            else:
                break
        rest = tail[len(digits):]
        text = f"{head}.{digits[:6].ljust(6, '0')}{rest}"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def check_validity_window(parsed: ParsedCredential, *, at: dt.datetime, skew: int) -> None:
    """Is the credential within its own validity window?

    Takes `at` and the policy's skew like every other time check, rather than reading the
    clock itself: a verifier's tolerances should be stated in one place, and a test needs to
    be able to fix the moment of verification.
    """
    now = at
    margin = dt.timedelta(seconds=skew)
    if parsed.valid_from and parsed.valid_from - margin > now:
        raise Rejected(
            CREDENTIAL_NOT_YET_VALID,
            f"the credential is valid from {parsed.valid_from.isoformat()}",
        )
    if parsed.valid_until and parsed.valid_until + margin < now:
        raise Rejected(
            CREDENTIAL_EXPIRED,
            f"the credential expired at {parsed.valid_until.isoformat()}",
        )
