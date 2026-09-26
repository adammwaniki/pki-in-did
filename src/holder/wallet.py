"""A minimal OpenID4VCI 1.0 holder -- the wallet side of issuance.

walt.id `issuer-api2` only issues over OpenID4VCI, so a credential is obtained the way a
wallet obtains one: create an offer, redeem the pre-authorized code for an access token,
prove possession of a holder key, collect the credential.

The flow, and the two things that are easy to get wrong, are recorded in
record/NOTES-waltid.md.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

PRE_AUTHORIZED = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def compact(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


class Wallet:
    """A holder with one freshly generated key, which is all a pre-authorized offer needs."""

    def __init__(self, base_url: str, *, timeout: float = 20.0, verbose: bool = True):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verbose = verbose
        self.key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.jwk = {
            "crv": "P-256", "kty": "EC",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }
        # did:jwk, so the issuer's `<subjectDid>` mapping has something to resolve. A proof
        # carrying a bare `jwk` header instead fails with "Cannot find in context: subjectDid".
        self.did = "did:jwk:" + b64u(compact(self.jwk))

    # ------------------------------------------------------------------ plumbing

    def _request(self, method: str, url: str, *, body=None, form=False, bearer=None):
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            if form:
                data = urllib.parse.urlencode(body).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()
        except urllib.error.URLError as error:
            raise SystemExit(f"wallet: cannot reach {url}: {error}") from error

    def _step(self, number: int, what: str, status: int, detail: str = "") -> None:
        if self.verbose:
            mark = "ok" if 200 <= status < 300 else "!!"
            print(f"  {number}. [{mark}] {what} -> {status}{'  ' + detail if detail else ''}")

    def _json(self, status: int, body: str, what: str) -> dict:
        if not 200 <= status < 300:
            raise SystemExit(f"wallet: {what} failed with {status}: {body}")
        try:
            return json.loads(body)
        except ValueError as exc:
            raise SystemExit(f"wallet: {what} returned non-JSON: {body[:200]}") from exc

    def _local(self, url: str) -> str:
        """Rewrite an advertised URL onto the base we can actually reach.

        The issuer advertises whatever `baseUrl` says; inside the demo network the wallet
        may be reaching it by a different name.
        """
        parsed = urllib.parse.urlparse(url)
        base = urllib.parse.urlparse(self.base_url)
        return urllib.parse.urlunparse(parsed._replace(scheme=base.scheme, netloc=base.netloc))

    def _sign(self, header: dict, payload: dict) -> str:
        signing_input = f"{b64u(compact(header))}.{b64u(compact(payload))}".encode()
        der = self.key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        return f"{signing_input.decode()}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    # ---------------------------------------------------------------- the flow

    def collect(self, profile_id: str, *, subject: dict | None = None) -> str:
        metadata = self._json(
            *self._request("GET", f"{self.base_url}/.well-known/openid-credential-issuer/openid4vci"),
            "fetching issuer metadata",
        )
        audience = metadata["credential_issuer"]
        self._step(0, "issuer metadata", 200, audience)

        overrides = {"credentialData": {"credentialSubject": subject}} if subject else {}
        status, body = self._request(
            "POST", f"{self.base_url}/issuer2/credential-offers",
            body={"profileId": profile_id, "authMethod": "PRE_AUTHORIZED", **({"runtimeOverrides": overrides} if overrides else {})},
        )
        created = self._json(status, body, "creating the credential offer")
        self._step(1, "credential offer created", status, created["offerId"])

        offer_uri = urllib.parse.parse_qs(
            urllib.parse.urlparse(created["credentialOffer"]).query
        )["credential_offer_uri"][0]
        status, body = self._request("GET", self._local(offer_uri))
        offer = self._json(status, body, "retrieving the credential offer")
        code = offer["grants"][PRE_AUTHORIZED]["pre-authorized_code"]
        configuration_id = offer["credential_configuration_ids"][0]
        self._step(2, "offer retrieved", status, configuration_id)

        status, body = self._request(
            "POST", f"{self.base_url}/openid4vci/token",
            body={"grant_type": PRE_AUTHORIZED, "pre-authorized_code": code}, form=True,
        )
        token = self._json(status, body, "redeeming the pre-authorized code")
        self._step(3, "access token issued", status)

        status, body = self._request("POST", f"{self.base_url}/openid4vci/nonce")
        nonce = self._json(status, body, "fetching a nonce")["c_nonce"]
        self._step(4, "nonce issued", status)

        proof = self._sign(
            {"typ": "openid4vci-proof+jwt", "alg": "ES256", "kid": f"{self.did}#0"},
            {"aud": audience, "iat": int(time.time()), "nonce": nonce},
        )
        status, body = self._request(
            "POST", f"{self.base_url}/openid4vci/credential",
            body={"credential_configuration_id": configuration_id, "proofs": {"jwt": [proof]}},
            bearer=token["access_token"],
        )
        issued = self._json(status, body, "requesting the credential")
        credential = issued["credentials"][0]["credential"]
        self._step(5, "credential issued", status, f"{len(credential)} characters")
        return credential


def describe(credential: str) -> str:
    header_segment = credential.split(".", 1)[0]
    header = json.loads(base64.urlsafe_b64decode(
        header_segment + "=" * (-len(header_segment) % 4)
    ))
    chain = header.get("x5c", [])
    return (f"      typ {header.get('typ')}   alg {header.get('alg')}\n"
            f"      kid {header.get('kid')}\n"
            f"      x5c {len(chain)} certificate(s) in the JOSE header")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", required=True, help="base URL of the issuer-api2 instance")
    parser.add_argument("--profile", default="accreditedOperatorCredential")
    parser.add_argument("--out", required=True, help="where to write the credential")
    parser.add_argument("--operator-name", default="Demonstration Holder")
    parser.add_argument("--licence", default="OP-2026-0001")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    wallet = Wallet(args.issuer, verbose=not args.quiet)
    if not args.quiet:
        print(f"  holder {wallet.did[:48]}…")
    credential = wallet.collect(
        args.profile,
        subject={"operatorName": args.operator_name, "licenceNumber": args.licence},
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(credential)
    if not args.quiet:
        print(describe(credential))
        print(f"      saved to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
