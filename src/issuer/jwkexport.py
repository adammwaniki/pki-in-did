"""Export an issuer's key material in the shapes the two consumers need.

* walt.id `issuer-api2` needs the **private** JWK (with `d`) in its profile `issuerKey`.
* The DID document needs the **public** JWK plus `x5c` and `x5t#S256`.

Both come from the same EC P-256 key that the Issuing CA certified, which is what makes the
DID document and the credential agree.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

COORDINATE_BYTES = 32


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64(raw: bytes) -> str:
    """RFC 7517 §4.7 x5c is standard base64, not base64url."""
    return base64.b64encode(raw).decode("ascii")


def load_private_key(path: str | Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SystemExit(f"{path}: expected an EC private key, got {type(key).__name__}")
    if key.curve.name != "secp256r1":
        raise SystemExit(f"{path}: expected P-256 for ES256, got {key.curve.name}")
    return key


def public_members(key) -> dict:
    numbers = (key.public_key() if hasattr(key, "public_key") else key).public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(numbers.x.to_bytes(COORDINATE_BYTES, "big")),
        "y": b64u(numbers.y.to_bytes(COORDINATE_BYTES, "big")),
    }


def thumbprint(jwk: dict) -> str:
    """RFC 7638. walt.id issuer-api2 uses this as the `kid` fragment; see record/NOTES-waltid.md."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(canonical).digest())


def private_jwk(key) -> dict:
    """The profile's issuerKey. Contains `d`; must never reach a DID document."""
    members = public_members(key)
    d = key.private_numbers().private_value.to_bytes(COORDINATE_BYTES, "big")
    return {**members, "d": b64u(d)}


def public_jwk_with_chain(key, chain: list[x509.Certificate], *, kid: str) -> dict:
    """The DID document's publicKeyJwk: the public key, the chain, and its thumbprint."""
    leaf_der = chain[0].public_bytes(serialization.Encoding.DER)
    return {
        **public_members(key),
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x5c": [b64(c.public_bytes(serialization.Encoding.DER)) for c in chain],
        "x5t#S256": b64u(hashlib.sha256(leaf_der).digest()),
    }


def load_chain(*paths: str | Path) -> list[x509.Certificate]:
    chain: list[x509.Certificate] = []
    for path in paths:
        chain.extend(x509.load_pem_x509_certificates(Path(path).read_bytes()))
    return chain
