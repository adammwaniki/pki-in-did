"""Verifier policy.

Every rule the brief and the source document impose is a setting here rather than a
constant in the code, because the point of the demonstration is that these are *verifier
policy* -- `did:web` and DID Core do not define them.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

#: The policy shipped with the package. A starting point, not a recommendation: the freshness
#: limits and the accreditation OIDs in particular belong to whoever runs the verifier.
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent / "default-policy.json"


@dataclasses.dataclass(frozen=True)
class Policy:
    #: How the store should find trust anchors. A FileStore reads these as paths under its
    #: root; a MemoryStore ignores them because it was given certificates directly. Empty by
    #: default: a verifier with no configured anchor rejects everything with `no_trust_anchors`,
    #: which is the right behaviour for something nobody has configured yet.
    trust_anchors: list[str] = dataclasses.field(default_factory=list)

    allow_x5u: bool = False
    require_spki_jwk_binding: bool = True
    require_x5t_match_when_present: bool = True
    require_san_uri_equals_did: bool = True
    require_key_usage_digital_signature: bool = True
    require_assertion_method: bool = True
    require_absolute_did_urls: bool = True

    require_issuer_authorization: bool = True
    accreditation_policy_oids: dict[str, list[str]] = dataclasses.field(default_factory=dict)

    allowed_algs: list[str] = dataclasses.field(default_factory=lambda: ["ES256"])

    revocation_required: bool = True
    allow_cached_revocation: bool = True
    ocsp_max_age_seconds: int = 300
    crl_max_age_seconds: int = 3600
    clock_skew_seconds: int = 30

    http_timeout_seconds: int = 5
    max_chain_depth: int = 5

    # ------------------------------------------------------------------ loading

    @classmethod
    def field_names(cls) -> set[str]:
        return {f.name for f in dataclasses.fields(cls)}

    @classmethod
    def from_dict(cls, raw: dict) -> "Policy":
        known = cls.field_names()
        # keys beginning with "_" are the notes in the shipped policy file
        settings = {k: v for k, v in raw.items() if not k.startswith("_")}
        unknown = sorted(set(settings) - known)
        if unknown:
            raise ValueError(f"unknown policy setting(s): {', '.join(unknown)}")
        return cls(**settings)

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "Policy":
        return cls.from_dict(json.loads(Path(path or DEFAULT_POLICY_PATH).read_text()))

    @classmethod
    def default(cls) -> "Policy":
        """The policy shipped with the package."""
        return cls.from_file(DEFAULT_POLICY_PATH)

    @classmethod
    def from_env(cls, prefix: str = "DID_X509_POLICY_", env=None) -> "Policy":
        """Overlay environment variables onto the shipped policy.

        `DID_X509_POLICY_OCSP_MAX_AGE_SECONDS=60` sets `ocsp_max_age_seconds`. Booleans accept
        true/false/1/0/yes/no; lists are comma-separated; the accreditation map is JSON. Used
        by the HTTP service so a deployment needs no policy file if it only changes a setting
        or two.

        `env` takes any mapping, so a caller can supply configuration explicitly rather than
        through the process environment -- which is what makes the service testable.
        """
        import os

        env = os.environ if env is None else env
        changes: dict = {}
        for field in dataclasses.fields(cls):
            raw = env.get(prefix + field.name.upper())
            if raw is None:
                continue
            changes[field.name] = _coerce(field, raw)
        return cls.default().replace(**changes) if changes else cls.default()

    # ------------------------------------------------------------------- using

    def replace(self, **changes) -> "Policy":
        unknown = sorted(set(changes) - self.field_names())
        if unknown:
            raise ValueError(f"unknown policy setting(s): {', '.join(unknown)}")
        return dataclasses.replace(self, **changes)

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)

    def to_json(self, **kwargs) -> str:
        return json.dumps(self.as_dict(), **kwargs)

    def types_allowed_by(self, oids: set[str]) -> set[str]:
        """Credential types the given certificate policy OIDs accredit an issuer for."""
        allowed: set[str] = set()
        for oid in oids:
            allowed.update(self.accreditation_policy_oids.get(oid, []))
        return allowed


def _coerce(field, raw: str):
    """Turn an environment string into the type a policy field expects."""
    if field.type in ("bool", bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if field.type in ("int", int):
        return int(raw)
    if "dict" in str(field.type):
        return json.loads(raw)
    if "list" in str(field.type):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw
