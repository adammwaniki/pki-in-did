# did-x509-policy

**The PKI policy layer a conformant DID verifier leaves to you.**

`did:web` resolution ends at a JWK. DID Core says nothing about validating the X.509 chain that
RFC 7517 lets you carry beside it in `x5c`, and a conformant verifier treats that chain as
opaque metadata. So a credential whose chain is **genuine but certifies a different key** passes
a standards-compliant verifier, and something else has to catch it.

This is that something else. Give it a Verifiable Credential and it answers one question:

> Does the key that signed this chain up to an authority I trust, and is it still allowed to?

Measured against a production verifier — walt.id `verifier-api2` — on the same two credentials:

|  | walt.id `verifier-api2` | did-x509-policy |
|---|---|---|
| accredited issuer | `SUCCESSFUL` | **accepted** |
| impostor presenting a genuine chain that certifies a different key | `SUCCESSFUL` | **rejected** `spki_jwk_mismatch` |

Both are behaving correctly. Validating `x5c` is not part of `did:web` or DID Core, which is
exactly why this exists.

## What this is not

- **Not a credential verifier.** It does not do OpenID4VP, presentation exchange, holder
  binding, selective disclosure, or status lists. Run it *alongside* whatever does.
- **Not a trust framework.** It enforces rules you configure. Which OIDs accredit which
  credential types, how fresh revocation data must be, what algorithms are acceptable — those
  are yours.
- **Not an opinion about whether you should use `did:web` with a national PKI.** It makes that
  arrangement checkable if you have chosen it.

## Prerequisites

| To run it as | You need |
|---|---|
| a service | Docker, and a trust anchor certificate in PEM |
| a library | Python ≥ 3.11 and `cryptography` |
| offline | a populated cache, or a `Store` implementation that has one |

You must also have, or be given:

- **one or more trust anchor certificates** — the root(s) that may terminate a certification
  path. With none configured, everything is rejected `no_trust_anchors`, and `/healthz` returns
  503. That is deliberate: a verifier nobody has configured should not look healthy.
- **reachable revocation endpoints**, if `revocation_required` is on (it is by default). A leaf
  with neither an AIA OCSP URI nor a CRL distribution point is rejected
  `revocation_source_missing` — the verifier will not treat "no way to check" as "fine".
- **credentials as `vc+jwt` (VC-JOSE-COSE) or W3C Data Integrity** with the chain in
  `publicKeyJwk.x5c`. Data Integrity proofs are canonicalised with JCS (RFC 8785), not
  URDNA2015; see [Limitations](#limitations).

## Quick start

### As a service

```bash
docker run --rm -p 8080:8080 \
  -e DID_X509_TRUST_ANCHOR_PEM="$(cat national-root.pem)" \
  ghcr.io/adammwaniki/did-x509-policy:1.0.0
```

```bash
curl -sS localhost:8080/healthz | jq '{status, trustAnchors}'

curl -sS -X POST localhost:8080/verify \
  -H 'Content-Type: application/json' \
  -d "{\"credential\": \"$(cat credential.jwt)\"}" | jq '{accepted, reason}'
```

`POST /verify` returns **200** when accepted and **422** when rejected, with the full report
either way — every check, not a boolean. A rejection is 422 because the request was well-formed
but did not pass, and because your monitoring should see it.

| Endpoint | |
|---|---|
| `POST /verify` | `{"credential": "…"}`, optionally `{"policy": {…}, "at": "…"}` |
| `GET /policy` | the policy in force, so a verdict can be read in context |
| `GET /healthz` | readiness, trust anchors and their fingerprints, and the check list |

### As a library

```python
from did_x509_policy import HttpTransport, MemoryStore, Policy, verify, render_text

store = MemoryStore.from_pem(open("national-root.pem", "rb").read())
policy = Policy.default().replace(
    require_issuer_authorization=True,
    accreditation_policy_oids={"1.3.6.1.4.1.99999.1.1": ["AccreditedOperatorCredential"]},
)

result = verify(credential, policy=policy, store=store, transport=HttpTransport())

if result.accepted:
    print("accepted")
else:
    print(result.reason, "-", result.failed_check.detail)
    print(render_text(result))      # the numbered report, for a human
```

`result.to_dict()` is the same JSON the service returns.

### As a CLI

```bash
pip install 'did-x509-policy[http]'
did-x509-policy verify --credential credential.jwt --store ./kit
did-x509-policy verify --credential credential.jwt --store ./kit --offline
did-x509-policy fingerprint --store ./kit
```

## What it checks

Fifteen checks, in order. It stops at the first failure and tells you which.

| # | Check | Whose rule |
|---|---|---|
| 1 | Credential parses and is inside its validity window | — |
| 2 | Algorithm is allow-listed (never `none`) | yours |
| 3 | Issuer and key reference name the same DID | DID Core |
| 4 | `did:web` resolves to a DID document | `did:web` Read |
| 5 | The document's `id` equals the DID resolved | `did:web` Read step 2 |
| 6 | The verification method is listed under `assertionMethod` | DID Core §5.3.2 |
| 7 | `publicKeyJwk` carries an `x5c` chain | **yours** |
| 8 | `x5t#S256` matches the leaf, when present | RFC 7517 |
| 9 | **Leaf SubjectPublicKeyInfo equals the JWK** | **yours** |
| 10 | The credential signature verifies under that key | DID Core |
| 11 | The leaf names the DID in a SAN URI | **yours** |
| 12 | Leaf `keyUsage` includes `digitalSignature` | **yours** |
| 13 | Path validates to a configured trust anchor, and only that | RFC 5280 |
| 14 | The certificate accredits this credential *type* | **yours** |
| 15 | Revocation is good and fresh (OCSP via AIA, CRL via CDP) | **yours** |

Checks 1–6 and 10 are what the specifications give you. The rest is policy — which is the point.

**Check 9 is the one people leave out.** Without it, anyone can paste a national CA chain beside
their own key and the chain becomes decorative. `tests/unit/test_x5c_and_binding.py::test_a_decorative_chain_is_rejected`
is that attack, and it is why this library exists.

Check 15 verifies the OCSP responder's own delegation (a certificate the CA issued bearing EKU
`OCSPSigning`), sends a nonce to prevent replay, and rejects on `unknown`, `expired` or `stale`
as well as `revoked`. A missing answer is never treated as a good one.

## Working offline

The chain travels **inside** the credential's key material, so with a populated cache no network
is needed:

```bash
did-x509-policy verify --credential credential.jwt --store ./kit --offline
```

A cached document is a **copy of evidence, never a stored verdict** — all fifteen checks run
again against it, so a tampered cache cannot turn a rejection into an acceptance, only make the
verifier's information stale, which it then says.

What offline costs you is honesty about freshness, and the library is explicit about it:

| Situation | Answer |
|---|---|
| cached revocation data still inside its own `nextUpdate` | accepted, `source: cache` |
| cached data past `nextUpdate` | rejected `revocation_expired` |
| cached data older than your `*_max_age_seconds` | rejected `revocation_stale` |
| nothing cached | rejected `revocation_unknown` |

`x5u` is refused by default (`allow_x5u: false`) precisely because a chain held by reference
cannot be followed without a network.

## Configuration

Environment only, so the image is useful with nothing mounted:

| Variable | |
|---|---|
| `DID_X509_TRUST_ANCHOR_PEM` | trust anchors inline, as PEM |
| `DID_X509_TRUST_ANCHOR_FILE` | …or read them from a path |
| `DID_X509_POLICY_FILE` | a policy JSON file; the shipped default is used otherwise |
| `DID_X509_POLICY_<SETTING>` | override one setting, e.g. `DID_X509_POLICY_CLOCK_SKEW_SECONDS=0` |
| `DID_X509_CACHE_DIR` | use a directory-backed cache instead of memory |
| `DID_X509_TLS_BUNDLE` | CA bundle for TLS when resolving `did:web` |
| `DID_X509_OFFLINE` | `1` to forbid the network entirely |
| `DID_X509_PORT` | listen port, default 8080 |

Every rule is a setting: see the shipped
[`default-policy.json`](src/did_x509_policy/default-policy.json). Two are empty on purpose —
`trust_anchors` and `accreditation_policy_oids` — because only you can supply them.

### Two trust stores, kept apart

The anchors here are for **credential signing**. The CA bundle used to fetch a `did:web`
document over TLS is a *different* store (`DID_X509_TLS_BUNDLE`), and this library never
consults one for the other. A national signing root is not a web PKI root; conflating them is a
real deployment mistake and the test suite asserts they are not interchangeable.

## Backend-agnostic

Nothing about *where* data lives is in the verification logic. Two protocols are the whole
contract:

```python
class Store(Protocol):
    def trust_anchors(self, refs) -> list[Certificate]: ...
    def get_did_document(self, did) -> CachedDocument | None: ...
    def put_did_document(self, did, document, *, url=None) -> None: ...
    def get_ocsp(self, cert, issuer) -> CachedBytes | None: ...
    def put_ocsp(self, cert, issuer, der, *, url=None) -> None: ...
    def get_crl(self, issuer) -> CachedBytes | None: ...
    def put_crl(self, issuer, der, *, url=None) -> None: ...

class Transport(Protocol):
    offline: bool
    def get(self, url, *, timeout=None) -> bytes: ...
    def post(self, url, body, *, content_type, timeout=None) -> bytes: ...
```

Supplied: `MemoryStore`, `FileStore`, `NullStore`; `HttpTransport`, `OfflineTransport`. For
Redis, S3, a database or a queue, implement `Store` — `tests/unit/test_store_backends.py` runs
the same suite against every backend, including a deliberately hostile one, so you can check
yours the same way.

Any exception from a `Transport` is treated as "no answer". The library never distinguishes a
refused connection from a timeout from a 500, because the decision is the same.

## Reason codes

A rejection always names one. The full list is in
[`reasons.py`](src/did_x509_policy/reasons.py); the ones worth knowing:

| Reason | Means |
|---|---|
| `spki_jwk_mismatch` | the chain does not certify the key beside it — the decorative-chain case |
| `chain_untrusted_root` | the chain is complete but ends somewhere you do not trust |
| `chain_incomplete` | the chain cannot reach any configured anchor |
| `san_uri_mismatch` | the leaf does not name the DID in a SAN URI |
| `issuer_not_authorized_for_type` | valid chain, but not accredited for *this* credential type |
| `revocation_revoked` / `_unknown` / `_expired` / `_stale` | status, or the absence of one |
| `x5u_not_allowed` / `x5u_fetch_failed` | a chain by reference, which offline cannot follow |
| `verifier_error` | the verifier itself failed. It fails closed: never an acceptance |

## Testing

```bash
pip install -e '.[http,service,test]'
pytest -q
```

The suite builds its own PKI in process, so every adverse path is reachable without fixtures on
disk: a decorative chain, an expired leaf, a rogue OCSP signer, a responder without
`OCSPSigning`, a CRL signed by the wrong CA, `alg: none`, a key listed only under
`authentication`, a relative DID URL, a JWK carrying private material, a `pathlen:0` violation,
a replayed OCSP nonce.

## Versioning

Published to GHCR on every tag matching `did-x509-policy-v*`:

```
ghcr.io/adammwaniki/did-x509-policy:1.0.0
ghcr.io/adammwaniki/did-x509-policy:1.0
ghcr.io/adammwaniki/did-x509-policy:latest
```

Images are built for `linux/amd64` and `linux/arm64`, with provenance attestation. Reason codes
and the fifteen check keys are the public contract: changing one is a breaking change.

## Limitations

Worth knowing before you adopt it.

- **Data Integrity canonicalisation is JCS (RFC 8785), not URDNA2015.** There is no JSON-LD
  processor here. It matches the `*-jcs-*` cryptosuites, but a `JsonWebSignature2020` proof from
  a URDNA2015 implementation will not verify.
- **Only the leaf's revocation is checked.** Intermediates are not, so a compromised issuing CA
  would not be caught. That needs your root to publish revocation data, and an explicit choice
  about what to do when it does not.
- **Path validation does not compare AKI to SKI.** Name chaining plus signature verification is
  sound, but a certificate re-keyed under the same subject name is not distinguished by AKI.
- **No certificate policy *mapping* or name constraints.** Policy OIDs are matched exactly.
- **ES256 only**, out of the box. Other algorithms need the allow-list widened and the
  corresponding verification path added.

## Where this came from

Extracted from a working demonstration of national PKI inside `did:web`, which records the whole
argument on video: [pki-in-did](https://github.com/adammwaniki/pki-in-did). Read that if you want
to see the problem before the solution.

It still lives in that repository as a subdirectory, which has one visible consequence: GitHub
Packages renders the *repository's* root README on the package page, not this file. There is no
setting for that. Giving the package its own repository fixes it, and `git subtree split` moves it
with its history intact:

```bash
# in the pki-in-did checkout
git subtree split --prefix=did-x509-policy -b did-x509-policy-only

# then, with an empty github.com/<owner>/did-x509-policy created
git push git@github.com:<owner>/did-x509-policy.git did-x509-policy-only:main
```

Two things change in the new repository: `.github/workflows/did-x509-policy.yml` loses its
`working-directory`, `paths` filter and `context: did-x509-policy`, and the release tag becomes
`v1.0.0` rather than `did-x509-policy-v1.0.0`. The image name is unchanged — GHCR names a package
by owner, not by repository — so anything already pinned to
`ghcr.io/<owner>/did-x509-policy:1.0.0` keeps working.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
