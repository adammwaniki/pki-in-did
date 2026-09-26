"""Write a did:web DID document that publishes a nationally certified signing key.

The verification method fragment is the RFC 7638 thumbprint of the public JWK, because that
is what walt.id issuer-api2 puts after the `#` in the credential's `kid`. The two are
computed the same way from the same key, so they agree by construction rather than by
convention -- see record/NOTES-waltid.md.

DID Core recommends exactly this (fragment = JWK `kid` = RFC 7638 thumbprint).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jwkexport import load_chain, load_private_key, public_jwk_with_chain, thumbprint

CONTEXT = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
]


def build(did: str, jwk: dict, *, fragment: str) -> dict:
    # did:web requires every DID URL inside the document to be absolute, which is what
    # prevents key confusion. Nothing here is written as a bare fragment.
    method_id = f"{did}#{fragment}"
    return {
        "@context": CONTEXT,
        "id": did,
        "verificationMethod": [
            {
                "id": method_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        # assertionMethod, not authentication: DID Core §5.3.2 makes this the relationship
        # for expressing claims, which is what issuing a credential is.
        "assertionMethod": [method_id],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--did", required=True)
    parser.add_argument("--key", required=True, help="the issuer's EC P-256 private key")
    parser.add_argument("--leaf", required=True, help="the issuer's certificate")
    parser.add_argument("--issuing-ca", required=True, help="the Issuing CA certificate")
    parser.add_argument("--out", required=True, help="where to write did.json")
    parser.add_argument("--x5u", default=None,
                        help="also write an x5u variant document to this path, "
                             "given the URL the chain is published at")
    parser.add_argument("--x5u-url", default=None)
    args = parser.parse_args()

    key = load_private_key(args.key)
    # The root is deliberately absent: the verifier holds it as a trust anchor, and a chain
    # is not made trustworthy by including its own root.
    chain = load_chain(args.leaf, args.issuing_ca)

    fragment = thumbprint(public_jwk_with_chain(key, chain, kid="unused"))
    jwk = public_jwk_with_chain(key, chain, kid=fragment)
    document = build(args.did, jwk, fragment=fragment)

    for member in ("d", "p", "q", "dp", "dq", "qi", "k"):
        if member in jwk:
            raise SystemExit(f"refusing to publish a DID document containing {member!r}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2) + "\n")

    if args.x5u and args.x5u_url:
        # The same key published by reference instead of by value. Used only to show that
        # x5u cannot be followed with no network, while x5c can.
        variant_jwk = {k: v for k, v in jwk.items() if k not in ("x5c", "x5t#S256")}
        variant_jwk["x5u"] = args.x5u_url
        variant = build(args.did, variant_jwk, fragment=fragment)
        path = Path(args.x5u)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(variant, indent=2) + "\n")

    print(fragment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
