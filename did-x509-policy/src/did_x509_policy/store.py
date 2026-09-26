"""Where the verifier keeps what it has already seen -- and how to plug in your own.

The verifier needs somewhere to read trust anchors from, and somewhere to keep resolved DID
documents, OCSP responses and CRLs so that it can decide again without a network. Nothing
about *where* that is belongs in the verification logic, so it is a protocol with three
implementations supplied and no assumption that yours is one of them.

    MemoryStore   nothing survives the process. Good for a request-scoped service, a test,
                  or a stateless worker behind a shared cache you manage yourself.
    FileStore     a directory. Good for a device that must work disconnected, and the
                  reference layout for an "offline kit".
    NullStore     no cache at all. Every check goes to the network, and offline always
                  fails. Good when freshness matters more than availability.

To use Redis, S3, a database or anything else, implement `Store`. The six cache methods and
`trust_anchors` are the whole contract; see `tests/unit/test_store_backends.py`, which runs
the same suite against every backend, including a deliberately hostile one.

A cached document is a **copy of evidence, never a stored verdict**. Every check runs again
against whatever comes back, so a compromised cache cannot turn a rejection into an
acceptance -- only make the verifier's information stale, which it then reports.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

UTC = dt.timezone.utc


def sha256_fingerprint(cert: x509.Certificate) -> str:
    """The form a person compares by eye against an authority's published value."""
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def load_pem_certificates(pem: bytes) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(pem)
    except AttributeError:  # pragma: no cover -- cryptography < 39
        return [x509.load_pem_x509_certificate(pem)]
    except ValueError:
        return []


def _key_for_certificate(cert: x509.Certificate) -> str:
    """A stable cache key for a certificate's public key."""
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).hexdigest()[:32]


def _ocsp_key(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    return f"{_key_for_certificate(issuer)}-{cert.serial_number:x}"


@dataclass(frozen=True)
class CachedDocument:
    document: dict
    fetched_at: dt.datetime
    url: str | None = None
    path: Path | None = None


@dataclass(frozen=True)
class CachedBytes:
    der: bytes
    stored_at: dt.datetime
    source_url: str | None = None
    path: Path | None = None


@runtime_checkable
class Store(Protocol):
    """The whole storage contract. Implement this to use any backend you like.

    Every `get_*` may return None; the verifier treats a miss as "no information", which is a
    rejection when there is also no network. Every `put_*` may be a no-op; the verifier never
    requires that what it stored can be read back.
    """

    def trust_anchors(self, refs: Iterable[str]) -> list[x509.Certificate]:
        """The certificates that may terminate a certification path, and nothing else."""

    def get_did_document(self, did: str) -> CachedDocument | None: ...
    def put_did_document(self, did: str, document: dict, *, url: str | None = None) -> None: ...

    def get_ocsp(self, cert: x509.Certificate,
                 issuer: x509.Certificate) -> CachedBytes | None: ...
    def put_ocsp(self, cert: x509.Certificate, issuer: x509.Certificate, der: bytes, *,
                 url: str | None = None) -> None: ...

    def get_crl(self, issuer: x509.Certificate) -> CachedBytes | None: ...
    def put_crl(self, issuer: x509.Certificate, der: bytes, *,
                url: str | None = None) -> None: ...


class MemoryStore:
    """Everything in process memory. Trust anchors are given up front.

    `refs` passed to `trust_anchors` are ignored: the anchors are whatever this store was
    constructed with. That is deliberate -- in a service, trust anchors come from deployment
    configuration, not from a path named in a request.
    """

    def __init__(self, anchors: Iterable[x509.Certificate] | None = None):
        self._anchors = list(anchors or [])
        self._dids: dict[str, CachedDocument] = {}
        self._ocsp: dict[str, CachedBytes] = {}
        self._crl: dict[str, CachedBytes] = {}

    @classmethod
    def from_pem(cls, pem: bytes) -> "MemoryStore":
        anchors = load_pem_certificates(pem)
        if not anchors:
            raise ValueError("no certificate found in the supplied PEM")
        return cls(anchors)

    def trust_anchors(self, refs: Iterable[str] = ()) -> list[x509.Certificate]:
        return list(self._anchors)

    def get_did_document(self, did):
        return self._dids.get(did)

    def put_did_document(self, did, document, *, url=None):
        self._dids[did] = CachedDocument(document=document, fetched_at=_now(), url=url)

    def get_ocsp(self, cert, issuer):
        return self._ocsp.get(_ocsp_key(cert, issuer))

    def put_ocsp(self, cert, issuer, der, *, url=None):
        self._ocsp[_ocsp_key(cert, issuer)] = CachedBytes(der=der, stored_at=_now(),
                                                          source_url=url)

    def get_crl(self, issuer):
        return self._crl.get(_key_for_certificate(issuer))

    def put_crl(self, issuer, der, *, url=None):
        self._crl[_key_for_certificate(issuer)] = CachedBytes(der=der, stored_at=_now(),
                                                              source_url=url)


class NullStore:
    """No cache. Anchors are given up front; nothing is ever remembered.

    Use when a stale answer is worse than no answer. Offline verification is impossible with
    this store, by design: with no cached revocation data the status is unknown, and unknown
    is a rejection.
    """

    def __init__(self, anchors: Iterable[x509.Certificate] | None = None):
        self._anchors = list(anchors or [])

    @classmethod
    def from_pem(cls, pem: bytes) -> "NullStore":
        return cls(load_pem_certificates(pem))

    def trust_anchors(self, refs: Iterable[str] = ()) -> list[x509.Certificate]:
        return list(self._anchors)

    def get_did_document(self, did): return None
    def put_did_document(self, did, document, *, url=None): return None
    def get_ocsp(self, cert, issuer): return None
    def put_ocsp(self, cert, issuer, der, *, url=None): return None
    def get_crl(self, issuer): return None
    def put_crl(self, issuer, der, *, url=None): return None


class FileStore:
    """A directory on disk. The reference layout for a device that works disconnected.

        trust/<name>.pem        trust anchors, named by `Policy.trust_anchors`
        cache/did/<key>.json    resolved DID documents
        cache/ocsp/<key>.json   OCSP responses, base64 DER plus the time stored
        cache/crl/<key>.json    certificate revocation lists

    Cache filenames are digests, not identifiers: a DID contains colons and a path is not a
    safe place to put user-controlled text.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)

    # -- trust anchors

    def trust_anchors(self, refs: Iterable[str]) -> list[x509.Certificate]:
        anchors: list[x509.Certificate] = []
        for ref in refs:
            path = self.root / ref
            if path.exists():
                anchors.extend(load_pem_certificates(path.read_bytes()))
        return anchors

    def put_trust_anchor_pem(self, pem: bytes, name: str = "anchor.pem") -> Path:
        """Refuses private key material outright: a trust store holds certificates."""
        if b"PRIVATE KEY" in pem:
            raise ValueError("refusing to store private key material in a trust store")
        if not load_pem_certificates(pem):
            raise ValueError("no certificate found in the supplied PEM")
        path = self.root / "trust" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)
        return path

    def tls_bundle(self) -> str | None:
        """A separate trust store, for transport. Never consulted for credentials."""
        path = self.root / "trust" / "webtls-root.pem"
        return str(path) if path.exists() else None

    def policy_path(self) -> Path | None:
        path = self.root / "policy.json"
        return path if path.exists() else None

    # -- DID documents

    def _did_path(self, did: str) -> Path:
        return self.root / "cache" / "did" / f"{_digest(did)}.json"

    def put_did_document(self, did, document, *, url=None) -> Path:
        return _write_json(self._did_path(did), {
            "did": did, "url": url, "fetchedAt": _now_iso(), "document": document})

    def get_did_document(self, did) -> CachedDocument | None:
        path = self._did_path(did)
        raw = _read_json(path)
        if raw is None:
            return None
        return CachedDocument(document=raw["document"],
                              fetched_at=_parse_iso(raw.get("fetchedAt")),
                              url=raw.get("url"), path=path)

    # -- OCSP

    def _ocsp_path(self, cert, issuer) -> Path:
        return self.root / "cache" / "ocsp" / f"{_ocsp_key(cert, issuer)}.json"

    def put_ocsp(self, cert, issuer, der, *, url=None) -> Path:
        return _write_json(self._ocsp_path(cert, issuer), {
            "storedAt": _now_iso(), "url": url,
            "subjectSerial": f"{cert.serial_number:x}",
            "der": base64.b64encode(der).decode("ascii")})

    def get_ocsp(self, cert, issuer) -> CachedBytes | None:
        return _read_der(self._ocsp_path(cert, issuer))

    # -- CRLs

    def _crl_path(self, issuer) -> Path:
        return self.root / "cache" / "crl" / f"{_key_for_certificate(issuer)}.json"

    def put_crl(self, issuer, der, *, url=None) -> Path:
        return _write_json(self._crl_path(issuer), {
            "storedAt": _now_iso(), "url": url,
            "issuer": issuer.subject.rfc4514_string(),
            "der": base64.b64encode(der).decode("ascii")})

    def get_crl(self, issuer) -> CachedBytes | None:
        return _read_der(self._crl_path(issuer))


#: Kept so existing deployments and the demonstration that this was extracted from keep working.
LaptopStore = FileStore


# ------------------------------------------------------------------------- internals

def _now() -> dt.datetime:
    return dt.datetime.now(tz=UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str | None) -> dt.datetime:
    if not value:
        return _now()
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return _now()


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
