"""Drive walt.id `wallet-api2` -- the holder in this demonstration.

This file is a *client*. The wallet is a real service: it generates and holds the holder key,
creates the DID, performs the OpenID4VCI 1.0 issuance flow (with DPoP-bound access tokens),
stores credentials, and performs the OpenID4VP 1.0 presentation flow with DCQL. None of that
protocol work happens here.

    collect  ask the issuer for an offer, then have the wallet redeem it
    present  create a verification session, then have the wallet present to it
    import   put a credential the wallet did not receive into its store

A handle is written beside each credential (`<credential>.wallet.json`) recording which wallet
holds it, under which DID, with which credential id. Presenting needs all three.

The endpoint shapes were established by a spike; record/NOTES-waltid.md records them, and the
two that cost time.
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

PRE_AUTHORIZED = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


def _call(method: str, url: str, *, body=None, timeout: float = 120.0):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode()
            return response.status, (json.loads(text) if text.strip() else {})
    except urllib.error.HTTPError as error:
        text = error.read().decode()
        try:
            return error.code, json.loads(text)
        except ValueError:
            return error.code, {"raw": text}
    except urllib.error.URLError as error:
        raise SystemExit(f"wallet: cannot reach {url}: {error}") from error


def _need(status: int, payload, what: str):
    if not 200 <= status < 300:
        raise SystemExit(f"wallet: {what} failed ({status}): {json.dumps(payload)[:400]}")
    return payload


class Wallet:
    """A wallet held by walt.id wallet-api2, addressed over HTTP."""

    def __init__(self, base_url: str, *, verbose: bool = True):
        self.base = base_url.rstrip("/")
        self.verbose = verbose

    def _step(self, number: int, what: str, detail: str = "") -> None:
        if self.verbose:
            print(f"  {number}. [ok] {what}{'  ' + detail if detail else ''}")

    def create(self) -> tuple[str, str]:
        """A fresh wallet with exactly one key, and a did:jwk over it.

        Exactly one key matters: the wallet binds its access token to a key with DPoP, and
        signs the issuance proof with the key behind the DID it is given. In a wallet holding
        several keys those can differ, and the issuer then rejects the proof as invalid_proof.
        """
        wallet_id = _need(*_call("POST", f"{self.base}/wallet", body={}), "creating a wallet")["walletId"]
        self._step(1, "wallet created", wallet_id)

        key = _need(*_call("POST", f"{self.base}/wallet/{wallet_id}/keys/generate",
                           body={"backend": "jwk", "keyType": "secp256r1"}),
                    "generating a holder key")
        self._step(2, "holder key generated", f"{key['keyType']} {key['keyId'][:16]}…")

        did = _need(*_call("POST", f"{self.base}/wallet/{wallet_id}/dids/create",
                           body={"method": "jwk", "keyId": key["keyId"]}),
                    "creating a holder DID")["did"]
        self._step(3, "holder DID created", f"{did[:44]}…")
        return wallet_id, did

    def receive(self, wallet_id: str, did: str, offer_url: str) -> str:
        received = _need(*_call("POST", f"{self.base}/wallet/{wallet_id}/credentials/receive",
                                body={"offerUrl": offer_url, "did": did}),
                         "redeeming the credential offer")
        ids = received.get("credentialIds") or []
        if not ids:
            raise SystemExit(f"wallet: no credential was issued: {json.dumps(received)[:300]}")
        self._step(5, "credential received and stored", ids[0])
        return ids[0]

    def import_raw(self, wallet_id: str, raw: str) -> str:
        stored = _need(*_call("POST", f"{self.base}/wallet/{wallet_id}/credentials/import",
                              body={"rawCredential": raw}),
                       "importing a credential")
        return stored["id"]

    def raw_credential(self, wallet_id: str, credential_id: str) -> str:
        held = _need(*_call("GET", f"{self.base}/wallet/{wallet_id}/credentials/{credential_id}"),
                     "reading the stored credential")
        signed = (held.get("credential") or {}).get("signed")
        if not signed:
            raise SystemExit("wallet: the stored credential has no signed form")
        return signed

    def present(self, wallet_id: str, did: str, request_url: str) -> dict:
        return _need(*_call("POST", f"{self.base}/wallet/{wallet_id}/credentials/present",
                            body={"requestUrl": request_url, "did": did}),
                     "presenting the credential")


def request_offer(issuer_base: str, profile: str, *, subject: dict | None = None) -> str:
    """Ask the issuer for a pre-authorized offer. This is the issuer's side, not the wallet's."""
    body: dict = {"profileId": profile, "authMethod": "PRE_AUTHORIZED"}
    if subject:
        body["runtimeOverrides"] = {"credentialData": {"credentialSubject": subject}}
    created = _need(*_call("POST", f"{issuer_base.rstrip('/')}/issuer2/credential-offers",
                           body=body), "creating a credential offer")
    return created["credentialOffer"]


def open_verification_session(verifier_base: str, credential_type: str,
                              *, query_id: str = "c1") -> tuple[str, str]:
    """Ask the verifier for a session, and return its id and the wallet-facing request URL."""
    setup = {
        "flow_type": "cross_device",
        "core_flow": {
            "dcql_query": {
                "credentials": [{
                    "id": query_id,
                    "format": "jwt_vc_json",
                    "meta": {"type_values": [["VerifiableCredential", credential_type]]},
                }]
            }
        },
    }
    created = _need(*_call("POST", f"{verifier_base.rstrip('/')}/verification-session/create",
                           body=setup), "creating a verification session")
    return created["sessionId"], created["fullAuthorizationRequestUrl"]


def verification_result(verifier_base: str, session_id: str, *, tries: int = 12) -> dict:
    for _ in range(tries):
        status, session = _call(
            "GET", f"{verifier_base.rstrip('/')}/verification-session/{session_id}/info")
        if 200 <= status < 300 and session.get("status") in (
                "SUCCESSFUL", "FAILED", "UNSUCCESSFUL"):
            return session
        time.sleep(1)
    raise SystemExit("wallet: the verifier never reached a terminal status")


def summarise_policies(session: dict) -> list[str]:
    """The verifier's own policy results, flattened."""
    lines: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("policy_executed", "results"):
                    continue
                if isinstance(value, dict) and isinstance(value.get("success"), bool):
                    lines.append(f"{'pass' if value['success'] else 'FAIL'}  {key}")
                walk(value)

    walk(session.get("policy_results") or {})
    return sorted(set(lines))


def describe(credential: str) -> str:
    raw = credential.split(".", 1)[0]
    header = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    return (f"      typ {header.get('typ')}   alg {header.get('alg')}\n"
            f"      kid {header.get('kid')}\n"
            f"      x5c {len(header.get('x5c', []))} certificate(s) in the JOSE header")


def _handle_path(credential_path: str) -> Path:
    return Path(credential_path).with_suffix(".wallet.json")


def _save_handle(credential_path: str, wallet_base: str, wallet_id: str, did: str,
                 credential_id: str) -> Path:
    path = _handle_path(credential_path)
    path.write_text(json.dumps({
        "wallet": wallet_base, "walletId": wallet_id,
        "did": did, "credentialId": credential_id,
    }, indent=2))
    return path


def _load_handle(credential_path: str) -> dict:
    path = _handle_path(credential_path)
    if not path.exists():
        raise SystemExit(
            f"wallet: no handle at {path}. A credential can only be presented by the wallet "
            "holding it; run `collect` or `import` first."
        )
    return json.loads(path.read_text())


# ------------------------------------------------------------------------ commands

def _collect(args) -> int:
    wallet = Wallet(args.wallet, verbose=not args.quiet)
    wallet_id, did = wallet.create()

    offer = request_offer(args.issuer, args.profile,
                          subject={"operatorName": args.operator_name,
                                   "licenceNumber": args.licence})
    if not args.quiet:
        print(f"  4. [ok] offer received from the issuer  {offer[:58]}…")

    credential_id = wallet.receive(wallet_id, did, offer)
    raw = wallet.raw_credential(wallet_id, credential_id)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(raw)
    handle = _save_handle(args.out, args.wallet, wallet_id, did, credential_id)

    if not args.quiet:
        print(describe(raw))
        print(f"      exported to {out}")
        print(f"      held by wallet {wallet_id} ({handle.name})")
    return 0


def _import(args) -> int:
    wallet = Wallet(args.wallet, verbose=not args.quiet)
    wallet_id, did = wallet.create()
    raw = Path(args.credential).read_text().strip()
    credential_id = wallet.import_raw(wallet_id, raw)
    handle = _save_handle(args.credential, args.wallet, wallet_id, did, credential_id)
    if not args.quiet:
        print(f"  imported into wallet {wallet_id} as {credential_id}")
        print(f"  handle {handle}")
    return 0


def _present(args) -> int:
    handle = _load_handle(args.credential)
    wallet = Wallet(handle.get("wallet", args.wallet), verbose=not args.quiet)

    session_id, request_url = open_verification_session(args.verifier, args.type)
    if not args.quiet:
        print(f"  1. [ok] verification session created  {session_id}")

    wallet.present(handle["walletId"], handle["did"], request_url)
    if not args.quiet:
        print("  2. [ok] wallet presented the credential over OpenID4VP")

    session = verification_result(args.verifier, session_id)
    if args.json:
        print(json.dumps(session, indent=2))
    elif not args.quiet:
        print(f"\n  the verifier's own verdict: {session.get('status')}")
        for line in summarise_policies(session):
            print(f"      {line}")
    return 0 if session.get("status") == "SUCCESSFUL" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet", default="http://wallet-api:7006",
                        help="base URL of the walt.id wallet-api2 instance")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="have the wallet obtain a credential over OpenID4VCI")
    c.add_argument("--issuer", required=True)
    c.add_argument("--profile", default="accreditedOperatorCredential")
    c.add_argument("--out", required=True, help="where to export the raw credential")
    c.add_argument("--operator-name", default="Demonstration Holder")
    c.add_argument("--licence", default="OP-2026-0001")
    c.add_argument("--quiet", action="store_true")

    i = sub.add_parser("import", help="put a credential into a wallet's store directly")
    i.add_argument("--credential", required=True)
    i.add_argument("--quiet", action="store_true")

    p = sub.add_parser("present", help="have the wallet present a credential over OpenID4VP")
    p.add_argument("--verifier", required=True)
    p.add_argument("--credential", required=True)
    p.add_argument("--type", default="AccreditedOperatorCredential")
    p.add_argument("--json", action="store_true")
    p.add_argument("--quiet", action="store_true")

    args = parser.parse_args()
    return {"collect": _collect, "import": _import, "present": _present}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
