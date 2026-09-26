"""JWK handling, canonical JSON, and JWS verification."""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

from .reasons import (ALG_NOT_ALLOWED, JWK_CONTAINS_PRIVATE_MATERIAL, SPKI_JWK_MISMATCH,
                      SIGNATURE_INVALID, Rejected)

#: JWK members that carry private key material. DID Core forbids them in publicKeyJwk.
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k", "oth")

CURVES = {"P-256": (ec.SECP256R1, 32, hashes.SHA256)}


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not a string")
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def jcs(obj) -> bytes:
    """Canonical JSON: sorted keys, no insignificant whitespace.

    RFC 8785 for the subset used here (objects with string keys, strings, numbers,
    booleans, arrays). The demonstration carries no JSON-LD processor, so Data Integrity
    proofs use this rather than URDNA2015; README.md records the deviation.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint. walt.id issuer-api2 uses this as the `kid` fragment."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    return b64u_encode(hashlib.sha256(jcs(required)).digest())


def check_public_only(jwk: dict) -> None:
    present = [m for m in PRIVATE_JWK_MEMBERS if m in jwk]
    if present:
        raise Rejected(
            JWK_CONTAINS_PRIVATE_MATERIAL,
            f"publicKeyJwk carries private key material: {', '.join(present)}",
        )


def jwk_to_public_key(jwk: dict):
    """Turn an EC public JWK into a key object, rejecting anything unsupported."""
    if jwk.get("kty") != "EC":
        raise Rejected(ALG_NOT_ALLOWED, f"unsupported JWK key type {jwk.get('kty')!r}")
    curve = CURVES.get(jwk.get("crv"))
    if curve is None:
        raise Rejected(ALG_NOT_ALLOWED, f"unsupported JWK curve {jwk.get('crv')!r}")
    curve_cls, size, _ = curve
    try:
        x = int.from_bytes(b64u_decode(jwk["x"]), "big")
        y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    except (KeyError, ValueError, TypeError) as exc:
        raise Rejected(ALG_NOT_ALLOWED, f"malformed JWK coordinates: {exc}") from exc
    try:
        return ec.EllipticCurvePublicNumbers(x, y, curve_cls()).public_key()
    except ValueError as exc:
        # A point that is not on the curve cannot be any certificate's public key, so this
        # is a binding failure rather than a signature failure.
        raise Rejected(
            SPKI_JWK_MISMATCH,
            f"the JWK's point is not on {jwk['crv']}, so it cannot be the leaf "
            f"certificate's public key: {exc}",
        ) from exc


def public_numbers_of(jwk: dict) -> tuple[int, int]:
    return (int.from_bytes(b64u_decode(jwk["x"]), "big"),
            int.from_bytes(b64u_decode(jwk["y"]), "big"))


def verify_es256(public_key, signing_input: bytes, signature: bytes) -> None:
    """Verify an ES256 signature given as raw R||S, as JOSE requires."""
    if len(signature) != 64:
        raise Rejected(SIGNATURE_INVALID, f"ES256 signature must be 64 bytes, got {len(signature)}")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        public_key.verify(
            asym_utils.encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as exc:
        raise Rejected(SIGNATURE_INVALID, "the credential signature does not verify") from exc
