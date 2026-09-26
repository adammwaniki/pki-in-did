"""The fifteen checks, in order.

Checks 1-6 and 10 come from DID Core and the `did:web` Read algorithm. Checks 7-9 and
11-15 are *verifier policy*: `did:web` and DID Core do not define them, and a conformant
DID resolver treats `x5c` as opaque metadata. That gap is the point of the demonstration.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from . import chain as chainmod
from . import credential as credmod
from . import didweb, jose, revocation
from .policy import Policy
from .reasons import (ALG_NOT_ALLOWED, ISSUER_NOT_AUTHORIZED_FOR_TYPE,
                      KEY_USAGE_MISSING_DIGITAL_SIGNATURE, KID_ISSUER_MISMATCH,
                      NOT_IN_ASSERTION_METHOD, PUBLIC_KEY_JWK_MISSING, SAN_URI_MISMATCH,
                      SPKI_JWK_MISMATCH, VERIFICATION_METHOD_NOT_FOUND, X5T_MISMATCH,
                      CONTROLLER_MISMATCH, DID_URL_NOT_ABSOLUTE, VERIFIER_ERROR, Rejected)
from .store import LaptopStore, sha256_fingerprint

UTC = dt.timezone.utc

PASS, FAIL, SKIP, NOT_RUN = "pass", "fail", "skip", "not-run"

#: (key, title) in the order they run. The report and the tests both rely on this order.
CHECKS: list[tuple[str, str]] = [
    ("credential_parsed", "Credential parses and is within its validity window"),
    ("alg_allowed", "Signature algorithm is allowed by policy"),
    ("issuer_matches_key_reference", "Issuer and key reference name the same DID"),
    ("did_document_resolved", "did:web resolves to a DID document"),
    ("did_document_id", "DID document id equals the DID resolved"),
    ("verification_method_authorized", "Verification method is listed under assertionMethod"),
    ("x5c_present", "publicKeyJwk carries an x5c certificate chain"),
    ("x5t_matches_leaf", "x5t#S256 matches the leaf certificate"),
    ("jwk_matches_leaf_spki", "JWK public key equals the leaf certificate's public key"),
    ("credential_signature", "Credential signature verifies under that key"),
    ("san_uri_matches_did", "Leaf certificate names the DID in a SAN URI"),
    ("key_usage_digital_signature", "Leaf keyUsage includes digitalSignature"),
    ("certification_path", "Path validates to the National Root CA"),
    ("issuer_authorization", "Certificate accredits this credential type"),
    ("revocation_status", "Revocation status is good and fresh"),
]


@dataclass
class Check:
    number: int
    key: str
    title: str
    status: str = NOT_RUN
    detail: str = ""

    def as_dict(self) -> dict:
        return {"number": self.number, "key": self.key, "title": self.title,
                "status": self.status, "detail": self.detail}


@dataclass
class Result:
    checks: list[Check]
    accepted: bool = False
    reason: str | None = None
    credential: credmod.ParsedCredential | None = None
    did_document_source: str | None = None
    did_document_url: str | None = None
    revocation: revocation.Outcome | None = None
    path: chainmod.Path | None = None
    policy: Policy | None = None
    offline: bool = False
    checked_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(tz=UTC))

    def check(self, key: str) -> Check:
        for item in self.checks:
            if item.key == key:
                return item
        raise KeyError(key)

    @property
    def failed_check(self) -> Check | None:
        for item in self.checks:
            if item.status == FAIL:
                return item
        return None

    def to_dict(self) -> dict:
        parsed = self.credential
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "checkedAt": self.checked_at.isoformat().replace("+00:00", "Z"),
            "offline": self.offline,
            "credential": {
                "form": parsed.form if parsed else None,
                "alg": parsed.alg if parsed else None,
                "issuer": parsed.issuer if parsed else None,
                "keyReference": parsed.key_reference if parsed else None,
                "types": parsed.types if parsed else [],
                "validFrom": _iso(parsed.valid_from) if parsed else None,
                "validUntil": _iso(parsed.valid_until) if parsed else None,
            },
            "didDocument": {"source": self.did_document_source, "url": self.did_document_url},
            "trustAnchor": (
                {"subject": self.path.anchor.subject.rfc4514_string(),
                 "fingerprintSha256": sha256_fingerprint(self.path.anchor)}
                if self.path else None
            ),
            "certificationPath": self.path.describe() if self.path else None,
            "revocation": self.revocation.as_dict() if self.revocation else None,
            "checks": [c.as_dict() for c in self.checks],
        }


def verify(
    credential,
    *,
    policy: Policy | None = None,
    store: LaptopStore | None = None,
    transport=None,
    at: dt.datetime | None = None,
) -> Result:
    policy = policy or Policy()
    at = at or dt.datetime.now(tz=UTC)
    checks = [Check(number=i + 1, key=key, title=title)
              for i, (key, title) in enumerate(CHECKS)]
    result = Result(checks=checks, policy=policy, checked_at=at,
                    offline=bool(getattr(transport, "offline", False)))
    state: dict = {}

    for check in checks:
        runner = _RUNNERS[check.key]
        try:
            status, detail = runner(credential, state, result, policy, store, transport, at)
        except Rejected as rejected:
            check.status = FAIL
            check.detail = rejected.detail
            result.reason = rejected.reason
            result.accepted = False
            return result
        except Exception as unexpected:  # noqa: BLE001
            # A verifier that crashes has not accepted anything. Fail closed, and say so
            # plainly rather than printing a stack trace during a demonstration.
            check.status = FAIL
            check.detail = f"{type(unexpected).__name__}: {unexpected}"
            result.reason = VERIFIER_ERROR
            result.accepted = False
            return result
        check.status = status
        check.detail = detail

    result.accepted = True
    return result


# ----------------------------------------------------------------- the checks

def _check_credential_parsed(credential, state, result, policy, store, transport, at):
    parsed = credmod.parse(credential)
    state["credential"] = parsed
    result.credential = parsed
    credmod.check_validity_window(parsed, at=at, skew=policy.clock_skew_seconds)
    window = []
    if parsed.valid_from:
        window.append(f"from {_iso(parsed.valid_from)}")
    if parsed.valid_until:
        window.append(f"until {_iso(parsed.valid_until)}")
    return PASS, (f"{parsed.form}, {parsed.alg}"
                  + (f", valid {' '.join(window)}" if window else ", no validity window stated"))


def _check_alg_allowed(credential, state, result, policy, store, transport, at):
    parsed = state["credential"]
    if parsed.alg not in policy.allowed_algs:
        raise Rejected(
            ALG_NOT_ALLOWED,
            f"alg {parsed.alg!r} is not in the allow-list {policy.allowed_algs}",
        )
    return PASS, f"alg {parsed.alg}"


def _check_issuer_matches_key_reference(credential, state, result, policy, store, transport, at):
    parsed = state["credential"]
    if parsed.key_reference_did != parsed.issuer:
        raise Rejected(
            KID_ISSUER_MISMATCH,
            f"the credential claims issuer {parsed.issuer} but is signed by a key belonging "
            f"to {parsed.key_reference_did}",
        )
    return PASS, f"{parsed.issuer} signed with {parsed.key_reference}"


def _check_did_document_resolved(credential, state, result, policy, store, transport, at):
    parsed = state["credential"]
    document, source, url = didweb.resolve(parsed.issuer, transport=transport,
                                           store=store, policy=policy)
    state["document"] = document
    result.did_document_source = source
    result.did_document_url = url
    where = "the network" if source == "network" else "the local cache"
    return PASS, f"{url} from {where}"


def _check_did_document_id(credential, state, result, policy, store, transport, at):
    # didweb.resolve already enforced this; the check exists so the report names it.
    return PASS, f"id equals {state['credential'].issuer}"


def _check_verification_method_authorized(credential, state, result, policy, store, transport, at):
    parsed = state["credential"]
    document = state["document"]
    methods = _collect_methods(document, policy)

    method = methods.get(parsed.key_reference)
    if method is None:
        raise Rejected(
            VERIFICATION_METHOD_NOT_FOUND,
            f"the DID document lists no verification method {parsed.key_reference}; "
            "at the DID layer that means the key is revoked",
        )

    if policy.require_assertion_method:
        if parsed.key_reference not in _assertion_method_ids(document):
            raise Rejected(
                NOT_IN_ASSERTION_METHOD,
                f"{parsed.key_reference} is not associated with assertionMethod, so it may "
                "not be used to issue a credential",
            )

    controller = method.get("controller")
    if controller and controller != parsed.issuer:
        raise Rejected(
            CONTROLLER_MISMATCH,
            f"the verification method is controlled by {controller}, not {parsed.issuer}",
        )

    jwk = method.get("publicKeyJwk")
    if not isinstance(jwk, dict) or not jwk:
        raise Rejected(
            PUBLIC_KEY_JWK_MISSING,
            "the verification method has no publicKeyJwk, so it carries no certificate chain "
            "(DID Core's publicKeyMultibase cannot carry one)",
        )
    jose.check_public_only(jwk)
    state["jwk"] = jwk

    credmod.check_proof_purpose(parsed)
    return PASS, f"{parsed.key_reference} is an assertionMethod of {parsed.issuer}"


def _check_x5c_present(credential, state, result, policy, store, transport, at):
    jwk = state["jwk"]
    certificates = chainmod.load_chain(jwk, policy=policy, transport=transport)
    state["chain"] = certificates
    origin = "x5c" if jwk.get("x5c") else "x5u"
    return PASS, f"{len(certificates)} certificate(s) from {origin}"


def _check_x5t_matches_leaf(credential, state, result, policy, store, transport, at):
    jwk = state["jwk"]
    declared = jwk.get("x5t#S256")
    if not declared:
        return SKIP, "the JWK declares no x5t#S256 (RFC 7517 makes it optional)"
    if not policy.require_x5t_match_when_present:
        return SKIP, "policy does not check x5t#S256"
    expected = jose.b64u_encode(chainmod.sha256_of_der(state["chain"][0]))
    if declared != expected:
        raise Rejected(
            X5T_MISMATCH,
            f"x5t#S256 is {declared} but the leaf certificate hashes to {expected}",
        )
    return PASS, f"x5t#S256 {declared[:16]}… matches the leaf"


def _check_jwk_matches_leaf_spki(credential, state, result, policy, store, transport, at):
    if not policy.require_spki_jwk_binding:
        return SKIP, "policy does not check the JWK-to-certificate binding"
    jwk = state["jwk"]
    leaf = state["chain"][0]
    public_key = jose.jwk_to_public_key(jwk)
    state["public_key"] = public_key
    if chainmod.spki(public_key) != chainmod.spki(leaf):
        raise Rejected(
            SPKI_JWK_MISMATCH,
            "the JWK's public key is not the public key in the leaf certificate; without "
            "this binding the certificate chain is decorative",
        )
    return PASS, "the JWK is the leaf certificate's own public key"


def _check_credential_signature(credential, state, result, policy, store, transport, at):
    parsed = state["credential"]
    public_key = state.get("public_key") or jose.jwk_to_public_key(state["jwk"])
    jose.verify_es256(public_key, parsed.signing_input, parsed.signature)
    return PASS, f"{parsed.alg} signature verifies over the {parsed.form} credential"


def _check_san_uri_matches_did(credential, state, result, policy, store, transport, at):
    if not policy.require_san_uri_equals_did:
        return SKIP, "policy does not require the DID in a SAN URI"
    parsed = state["credential"]
    leaf = state["chain"][0]
    uris = _san_uris(leaf)
    if parsed.issuer not in uris:
        raise Rejected(
            SAN_URI_MISMATCH,
            f"the leaf certificate's SAN URIs are {uris or 'absent'}, which do not include "
            f"{parsed.issuer}",
        )
    return PASS, f"SAN URI {parsed.issuer}"


def _check_key_usage_digital_signature(credential, state, result, policy, store, transport, at):
    if not policy.require_key_usage_digital_signature:
        return SKIP, "policy does not check keyUsage"
    leaf = state["chain"][0]
    try:
        usage = leaf.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        raise Rejected(
            KEY_USAGE_MISSING_DIGITAL_SIGNATURE,
            "the leaf certificate has no keyUsage extension",
        ) from None
    if not usage.digital_signature:
        raise Rejected(
            KEY_USAGE_MISSING_DIGITAL_SIGNATURE,
            "the leaf certificate's keyUsage does not include digitalSignature",
        )
    return PASS, "keyUsage digitalSignature"


def _check_certification_path(credential, state, result, policy, store, transport, at):
    anchors = store.trust_anchors(policy.trust_anchors)
    path = chainmod.validate(state["chain"], anchors, at=at, policy=policy)
    state["path"] = path
    result.path = path
    return PASS, path.describe()


def _check_issuer_authorization(credential, state, result, policy, store, transport, at):
    if not policy.require_issuer_authorization:
        return SKIP, "policy does not check issuer accreditation"
    parsed = state["credential"]
    leaf = state["chain"][0]
    oids = _policy_oids(leaf)
    allowed = policy.types_allowed_by(oids)
    subject_types = [t for t in parsed.types if t != "VerifiableCredential"]

    unauthorized = [t for t in subject_types if t not in allowed]
    if not subject_types or unauthorized:
        raise Rejected(
            ISSUER_NOT_AUTHORIZED_FOR_TYPE,
            f"the certificate's policy OIDs {sorted(oids) or '[]'} accredit "
            f"{sorted(allowed) or '[]'}, which does not cover {subject_types or '[]'}; "
            "a valid chain proves who certified the key, not what it may issue",
        )
    return PASS, f"accredited for {', '.join(subject_types)} by policy OID {sorted(oids)[0]}"


def _check_revocation_status(credential, state, result, policy, store, transport, at):
    if not policy.revocation_required:
        return SKIP, "policy does not require a revocation check"
    path = state["path"]
    outcome = revocation.check(path.leaf, path.issuing_ca, policy=policy,
                               store=store, transport=transport, at=at)
    result.revocation = outcome
    if not outcome.accepted:
        raise Rejected(outcome.reason_code or "revocation_unknown", outcome.detail)
    where = "the responder" if outcome.source == "network" else "the local cache"
    return PASS, f"{outcome.method.upper()} says good, from {where}; {outcome.detail}"


_RUNNERS = {
    "credential_parsed": _check_credential_parsed,
    "alg_allowed": _check_alg_allowed,
    "issuer_matches_key_reference": _check_issuer_matches_key_reference,
    "did_document_resolved": _check_did_document_resolved,
    "did_document_id": _check_did_document_id,
    "verification_method_authorized": _check_verification_method_authorized,
    "x5c_present": _check_x5c_present,
    "x5t_matches_leaf": _check_x5t_matches_leaf,
    "jwk_matches_leaf_spki": _check_jwk_matches_leaf_spki,
    "credential_signature": _check_credential_signature,
    "san_uri_matches_did": _check_san_uri_matches_did,
    "key_usage_digital_signature": _check_key_usage_digital_signature,
    "certification_path": _check_certification_path,
    "issuer_authorization": _check_issuer_authorization,
    "revocation_status": _check_revocation_status,
}


# ---------------------------------------------------------- DID document reading

def _collect_methods(document: dict, policy) -> dict[str, dict]:
    """Every verification method in the document, by id.

    DID Core allows a relationship to reference a method by id or to embed it, so both
    are gathered. `did:web` additionally requires every DID URL inside the document to
    be absolute, which is checked here because it prevents key confusion.
    """
    methods: dict[str, dict] = {}
    relationships = ("verificationMethod", "assertionMethod", "authentication",
                     "capabilityInvocation", "capabilityDelegation", "keyAgreement")
    for name in relationships:
        for entry in document.get(name) or []:
            if isinstance(entry, dict):
                identifier = entry.get("id")
                if isinstance(identifier, str):
                    _require_absolute(identifier, policy)
                    methods.setdefault(identifier, entry)
            elif isinstance(entry, str):
                _require_absolute(entry, policy)
    return methods


def _assertion_method_ids(document: dict) -> set[str]:
    ids = set()
    for entry in document.get("assertionMethod") or []:
        if isinstance(entry, str):
            ids.add(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("id"), str):
            ids.add(entry["id"])
    return ids


def _require_absolute(did_url: str, policy) -> None:
    if policy.require_absolute_did_urls and not did_url.startswith("did:"):
        raise Rejected(
            DID_URL_NOT_ABSOLUTE,
            f"the DID document contains the relative DID URL {did_url!r}; did:web requires "
            "absolute DID URLs, which prevents key confusion",
        )


def _san_uris(cert) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []
    return san.get_values_for_type(x509.UniformResourceIdentifier)


def _policy_oids(cert) -> set[str]:
    try:
        policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
    except x509.ExtensionNotFound:
        return set()
    return {p.policy_identifier.dotted_string for p in policies}


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None
