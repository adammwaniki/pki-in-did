"""The laptop's own store: one trust anchor and a cache.

Everything the verifier needs when there is no network lives here:

    trust/nrca.pem          the National Root CA -- the only credential trust anchor
    trust/webtls-root.pem   the TLS trust store, deliberately a separate file
    cache/did/<key>.json    resolved DID documents
    cache/ocsp/<key>.json   OCSP responses, with the time they were stored
    cache/crl/<key>.json    certificate revocation lists
    policy.json             the verifier policy in force on this laptop
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

UTC = dt.timezone.utc


def sha256_fingerprint(cert: x509.Certificate) -> str:
    """The form a person compares by eye against the offline machine."""
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _key_for_certificate(cert: x509.Certificate) -> str:
    """A stable cache key for a certificate's public key."""
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).hexdigest()[:32]


@dataclass(frozen=True)
class CachedDocument:
    document: dict
    fetched_at: dt.datetime
    url: str | None
    path: Path


@dataclass(frozen=True)
class CachedBytes:
    der: bytes
    stored_at: dt.datetime
    source_url: str | None
    path: Path


class LaptopStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    # ------------------------------------------------------------ trust anchors

    def trust_anchors(self, relative_paths) -> list[x509.Certificate]:
        anchors: list[x509.Certificate] = []
        for relative in relative_paths:
            path = self.root / relative
            if not path.exists():
                continue
            anchors.extend(_load_pem_certificates(path.read_bytes()))
        return anchors

    def put_trust_anchor_pem(self, pem: bytes, name: str = "nrca.pem") -> Path:
        if b"PRIVATE KEY" in pem:
            raise ValueError(
                "refusing to store private key material in the laptop trust store"
            )
        if not _load_pem_certificates(pem):
            raise ValueError("no certificate found in the supplied PEM")
        path = self.root / "trust" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)
        return path

    def tls_bundle(self) -> str | None:
        path = self.root / "trust" / "webtls-root.pem"
        return str(path) if path.exists() else None

    def policy_path(self) -> Path | None:
        path = self.root / "policy.json"
        return path if path.exists() else None

    # ----------------------------------------------------------- DID documents

    def _did_path(self, did: str) -> Path:
        # A DID contains colons, so the filename is a digest rather than the DID itself.
        return self.root / "cache" / "did" / f"{hashlib.sha256(did.encode()).hexdigest()[:32]}.json"

    def put_did_document(self, did: str, document: dict, *, url: str | None = None) -> Path:
        return _write_json(
            self._did_path(did),
            {"did": did, "url": url, "fetchedAt": _now_iso(), "document": document},
        )

    def get_did_document(self, did: str) -> CachedDocument | None:
        path = self._did_path(did)
        raw = _read_json(path)
        if raw is None:
            return None
        return CachedDocument(
            document=raw["document"],
            fetched_at=_parse_iso(raw.get("fetchedAt")),
            url=raw.get("url"),
            path=path,
        )

    # -------------------------------------------------------------------- OCSP

    def _ocsp_path(self, cert: x509.Certificate, issuer: x509.Certificate) -> Path:
        key = f"{_key_for_certificate(issuer)}-{cert.serial_number:x}"
        return self.root / "cache" / "ocsp" / f"{key}.json"

    def put_ocsp(self, cert, issuer, der: bytes, *, url: str | None = None) -> Path:
        return _write_json(
            self._ocsp_path(cert, issuer),
            {"storedAt": _now_iso(), "url": url,
             "subjectSerial": f"{cert.serial_number:x}",
             "der": base64.b64encode(der).decode("ascii")},
        )

    def get_ocsp(self, cert, issuer) -> CachedBytes | None:
        return _read_der(self._ocsp_path(cert, issuer))

    # --------------------------------------------------------------------- CRL

    def _crl_path(self, issuer: x509.Certificate) -> Path:
        return self.root / "cache" / "crl" / f"{_key_for_certificate(issuer)}.json"

    def put_crl(self, issuer, der: bytes, *, url: str | None = None) -> Path:
        return _write_json(
            self._crl_path(issuer),
            {"storedAt": _now_iso(), "url": url,
             "issuer": issuer.subject.rfc4514_string(),
             "der": base64.b64encode(der).decode("ascii")},
        )

    def get_crl(self, issuer) -> CachedBytes | None:
        return _read_der(self._crl_path(issuer))


# ------------------------------------------------------------------- internals

def _load_pem_certificates(pem: bytes) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(pem)
    except AttributeError:  # pragma: no cover -- cryptography < 39
        return [x509.load_pem_x509_certificate(pem)]
    except ValueError:
        return []


def _now_iso() -> str:
    return dt.datetime.now(tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str | None) -> dt.datetime:
    if not value:
        return dt.datetime.now(tz=UTC)
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return dt.datetime.now(tz=UTC)


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
    tmp.replace(path)
    return path


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except ValueError:
        return None


def _read_der(path: Path) -> CachedBytes | None:
    raw = _read_json(path)
    if raw is None:
        return None
    try:
        der = base64.b64decode(raw["der"])
    except (KeyError, ValueError):
        return None
    return CachedBytes(der=der, stored_at=_parse_iso(raw.get("storedAt")),
                       source_url=raw.get("url"), path=path)
