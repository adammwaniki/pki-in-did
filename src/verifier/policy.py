"""Verifier policy.

Every rule the brief and the source document impose is a setting here rather than a
constant in the code, because the point of the demonstration is that these are *verifier
policy* -- `did:web` and DID Core do not define them.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "verifier-policy.json"


@dataclasses.dataclass(frozen=True)
class Policy:
    trust_anchors: list[str] = dataclasses.field(default_factory=lambda: ["trust/nrca.pem"])

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

    # ------------------------------------------------------------------- using

    def replace(self, **changes) -> "Policy":
        unknown = sorted(set(changes) - self.field_names())
        if unknown:
            raise ValueError(f"unknown policy setting(s): {', '.join(unknown)}")
        return dataclasses.replace(self, **changes)

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)

    def types_allowed_by(self, oids: set[str]) -> set[str]:
        """Credential types the given certificate policy OIDs accredit an issuer for."""
        allowed: set[str] = set()
        for oid in oids:
            allowed.update(self.accreditation_policy_oids.get(oid, []))
        return allowed
