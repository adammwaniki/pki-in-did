# PKI in DIDs — the system as built

Status: built and verified (2026-09-26). This document was first written before the build
and has been redrafted from the code, the tests and `record/NOTES-waltid.md` so that every
statement describes what now exists. Where the build departed from the original plan, section
17 says so.

Source material: `PKI in DID.md` (tabs **K** and **C**) and the demonstration script supplied
in the session brief. `README.md` is the reader's introduction; this file is the record of
design decisions and of what was learned.

---

## 1. Objective

The demonstration proves four claims, on camera and under test:

1. A `did:web` DID document can publish an issuer's national-PKI-certified signing key as a
   DID Core verification method, using RFC 7517 `x5c` inside `publicKeyJwk`.
2. A verifier whose only trust anchor is the National Root CA certificate can decide accept or
   reject on a Verifiable Credential: PKIX path validation plus DID Core `assertionMethod`.
3. Accreditation can be withdrawn by the Issuing CA alone, with the DID document untouched,
   once with OCSP and once with a CRL.
4. Because the chain travels inside the key material (`x5c`, not `x5u`), verification works
   with no network at all, enforced by `docker run --network none`.

Claim 4 is the differentiator. It is why `x5c`-in-`did.json` is worth the DNS and TLS
dependency the source document flags (tab C, "Whether you should").

## 2. The recordings

| Recording | Script | Network | Outcome shown |
|---|---|---|---|
| `part0-setup` | `demo/part0-setup.sh` | demo network | the offline machine and the root it holds, then everything below it rebuilt |
| `part1-happy-online` | `demo/part1-happy-online.sh` | demo network | A accepted via OCSP `good`; B accepted, serial absent from the CRL |
| `part2-happy-offline` | `demo/part2-happy-offline.sh` | `--network none` | isolation proved; A and B accepted from cache; the `x5u` variant fails |
| `part3-revocation-online` | `demo/part3-revocation-online.sh` | demo network | A rejected by OCSP; responder stopped gives `unknown`; B accepted in the CRL window, then rejected; expired CRL rejected |
| `part4-revocation-offline` | `demo/part4-revocation-offline.sh` | `--network none` | a stale cache still accepts; `--no-cached-revocation` rejects; one reconnection makes the rejection persist; a cached answer goes stale under the strict policy |

`demo/part0-setup.sh` runs `10-offline-root.sh` before `00-reset.sh`. The reset deliberately
keeps the root, so on its own it would never show the offline machine that holds the root
private key -- which is the first thing a viewer needs to see. `10-offline-root.sh` is safe to
re-run: it reports and displays the existing root rather than re-keying it.

Each part produces a `.cast`, a `.gif` and an `.mp4` in `recordings/`, via `record/record.sh`.

## 3. Environment findings that shaped the design

Verified on this host on 2026-09-26:

- **Ports 80 and 443 are held by Caddy**, fronting an existing multi-container VCA stack
  (`admin-*`, `verifier-*`, `inji-*`). The demonstration must not bind them, and binds no host
  port at all.
- **The four bare domains are proxied and already serve unrelated content**, so they cannot
  resolve to this stack. Public Let's Encrypt certificates for all four, as brief step 10
  assumes, is not the current state of the world. The `labs.*` names used by the public profile
  do resolve here directly, which is what makes that profile possible.
- No `asciinema`, `agg`, `ffmpeg` or `certbot` on the host. Recording tooling ships in a
  container.
- Docker 29.8.1 and Compose v5.5.1 on the host. The host's own OpenSSL is not used: every CA
  operation runs inside `images/ca-tools`, which is Alpine 3.22 with OpenSSL 3.5.8 LTS.

**Consequence.** The demonstration is a self-contained Docker stack. The four real domain names
are Docker-network DNS aliases, and a Web-TLS CA inside the stack provides the HTTPS layer.
This makes the run reproducible, makes `--network none` meaningful, and lets a recording be
re-shot identically.

## 4. Component and domain map

| Brief | Real domain | Compose service(s) | Serves | Transport |
|---|---|---|---|---|
| NRCA, public | `adamndegwa.com` | `nrca-web` (nginx) | `/nrca.pem` | HTTPS |
| NRCA, private | — | none; a `ca-tools` container run with `--network none` | the root private key | no network |
| Issuing CA | `mwaniki.dev` | `issuing-ca` (nginx), `ocsp-responder` (Python) | `/ocsp`, `/issuing-ca.crl`, `/issuing-ca.pem` | HTTP |
| Credential issuer A | `jacarandapropaganda.com` | `issuer-a-web` (nginx), `issuer-a-api` (walt.id) | `/.well-known/did.json`; OpenID4VCI | HTTPS; internal |
| Credential issuer B | `lawnbull.com` | `issuer-b-web` (nginx), `issuer-b-api` (walt.id) | `/.well-known/did.json`; OpenID4VCI | HTTPS; internal |
| Verifier, "the laptop" | — | none; `pki-in-did/verifier` run on demand | the root certificate and a cache | demo network or none |

Seven compose services, one bridge network named `pki-in-did_demo`. The offline machine is
deliberately not a service: `images/offline-ca/README.md` explains that the isolation comes
from `--network none` and from mounting the key nowhere else, not from an image.

Issuer A's certificate carries an AIA OCSP URI. Issuer B's carries a CRL distribution point.
That is the only difference between them, the controlled variable of the experiment.

The walt.id management API (`/issuer2/`) is reachable only on the internal network. `GET
/issuer2/profiles` returns the issuer's private key, and nginx does not proxy that path;
`tests/integration/test_live_verification.py` asserts it.

### Two PKI layers, kept apart

| | Certifies | Root | Held by the laptop in |
|---|---|---|---|
| Web-TLS CA | the HTTPS endpoints, so `did:web` can be resolved | `DemoWebTLS Root` | `trust/webtls-root.pem`, the TLS store |
| National Root CA | the credential-signing keys | `Demo National Root CA` | `trust/nrca.pem`, the only credential trust anchor |

The two never mix. `tests/unit/test_chain_validation.py::test_the_web_tls_root_is_not_a_credential_trust_anchor`
and `tests/integration/test_live_pki_profile.py::test_the_laptop_keeps_the_two_trust_stores_apart`
assert it.

## 5. Cryptographic choices

| Object | Key | Signature | Life | Constraints |
|---|---|---|---|---|
| National Root CA | RSA 4096 | `sha384WithRSA`, self-signed | 7300 days | `CA:TRUE`; KU `digitalSignature, cRLSign, keyCertSign` |
| Issuing CA | RSA 4096 | by the root, SHA-384 | 3650 days | `CA:TRUE, pathlen:0` |
| OCSP signer | RSA 2048 | by the Issuing CA, SHA-384 | 365 days | EKU `OCSPSigning`, critical; `noCheck` |
| Issuer A and B leaves | EC P-256 | by the Issuing CA, SHA-384 | 730 days | KU `digitalSignature` only |
| Web-TLS root | RSA 4096 | self-signed, SHA-384 | 3650 days | separate hierarchy |
| Web-TLS server certificates | RSA 2048 | by the Web-TLS root, SHA-256 | 825 days | EKU `serverAuth`, DNS SAN |

Leaf extensions, from `config/openssl/ext/issuer-{a,b}.ext`:

- `subjectAltName = URI:did:web:<domain>`. A profile rule, not a `did:web` requirement.
- `keyUsage = critical, digitalSignature`. No `extendedKeyUsage`: a signing-only certificate,
  which is exactly why a Web PKI validator would not accept it.
- Issuer A: `authorityInfoAccess = OCSP;URI:http://mwaniki.dev/ocsp`.
- Issuer B: `crlDistributionPoints = URI:http://mwaniki.dev/issuing-ca.crl`.
- Both: `certificatePolicies = 1.3.6.1.4.1.99999.1.1`, an invented OID under a
  private-enterprise arc meaning "accredited to issue `AccreditedOperatorCredential`". It backs
  verifier check 14.

Freshness values, from `config/domains.env`:

- OCSP response life: **5 minutes** (`OCSP_RESPONSE_MINUTES`). Short enough that a cache
  expiring can be shown on camera.
- CRL `nextUpdate`: **1 hour** (`CRL_NEXTUPDATE_HOURS`). Long enough that the revocation
  window is a real window.
- An expired CRL is produced by `scripts/expire-crl.sh`, which dates the CRL wholly in the
  past (`--expired-by`, default 600 s). A five-second CRL cannot be waited out inside the
  verifier's 30-second clock-skew tolerance, so no wait is used and no clock is faked.

The `openssl ca` configurations set `copy_extensions = none`: the authority decides what it
certifies, never the requester.

## 6. DID document shape

Built by `src/issuer/build_did_document.py`, published at `https://<domain>/.well-known/did.json`:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1",
               "https://w3id.org/security/suites/jws-2020/v1"],
  "id": "did:web:jacarandapropaganda.com",
  "verificationMethod": [{
    "id": "did:web:jacarandapropaganda.com#<RFC 7638 thumbprint>",
    "type": "JsonWebKey2020",
    "controller": "did:web:jacarandapropaganda.com",
    "publicKeyJwk": {
      "kty": "EC", "crv": "P-256", "x": "...", "y": "...",
      "use": "sig", "alg": "ES256", "kid": "<RFC 7638 thumbprint>",
      "x5c": ["<leaf DER, standard base64>", "<Issuing CA DER, standard base64>"],
      "x5t#S256": "<base64url SHA-256 of the leaf DER>"
    }
  }],
  "assertionMethod": ["did:web:jacarandapropaganda.com#<RFC 7638 thumbprint>"]
}
```

- The fragment is the RFC 7638 thumbprint of the public JWK. walt.id `issuer-api2` emits
  `<issuerDid>#<thumbprint>` as the credential `kid`, so the two agree by construction.
- `x5c` is standard base64 DER, leaf first, root omitted. The verifier holds the root as a
  trust anchor, and a chain is not made trustworthy by carrying its own root.
- Every DID URL in the document is absolute, as `did:web` requires and as the verifier
  checks.
- The key is under `assertionMethod`, not `authentication`. A key listed only under
  `authentication` is rejected (`tests/unit/test_didweb_resolution.py`).
- A second document, `did.x5u.json`, publishes the same key with `x5u` pointing at
  `/.well-known/pki/issuer-chain.pem`. It exists only to show `x5u` failing offline.
- The builder refuses to write a document containing any private JWK member, and
  `scripts/30-did-documents.sh` greps the output for private material before publishing.

## 7. Credential issuance: walt.id `issuer-api2` over OpenID4VCI

Credentials are issued by `waltid/issuer-api2:1.0.0`, one instance per issuer. Every fact
about it below was measured, not inferred; `record/NOTES-waltid.md` holds the evidence.

`scripts/25-waltid-config.sh` renders, per issuer, `issuer2-profiles.conf`,
`credential-issuer-metadata.conf`, `issuer-service.conf`, `web.conf`, `_features.conf` and
`persistence.conf` into `state/waltid/issuer-<x>/`. The profile carries the issuer's private
JWK (with `d`), `issuerDid`, and `x5Chain` holding the leaf and the Issuing CA. The directory
is `chmod go-rwx` and is never served.

Key material flows one way:

```
EC P-256 key + CSR (ours)
  -> the Issuing CA signs the leaf                 scripts/20-issuer-certs.sh
  -> private JWK (with d)                          issuer-api2 profile issuerKey
  -> leaf + Issuing CA PEM                         issuer-api2 profile x5Chain
  -> public JWK + x5c + x5t#S256                   our did.json, scripts/30-did-documents.sh
```

`src/holder/wallet.py` is a minimal OpenID4VCI 1.0 holder. It performs the pre-authorized-code
flow: create offer, retrieve offer, token, nonce, proof, credential. The holder proof must
bind through a `kid` holding a DID (`did:jwk:...#0`) and use `aud` equal to the metadata's
`credential_issuer`; both were learned the hard way and are recorded.

Measured facts the verifier depends on:

1. `kid` is `<issuerDid>#<RFC 7638 thumbprint>`.
2. The JOSE header also carries `x5c`, leaf first, root omitted. The verifier ignores it and
   takes the chain from the DID document, because chain-in-header is the *other* design in
   the source document.
3. The payload carries both `iss` and an `issuer` object; the verifier requires them to agree.
4. `validFrom` has nanosecond precision, which `datetime.fromisoformat` rejects; the verifier
   truncates to microseconds.
5. Issuance never resolves `did:web`, so the issuer needs no TLS trust in the JVM.
6. Startup takes about 21 seconds; scripts poll the port rather than sleep.

### Credential shapes

**VC-JOSE-COSE** (`typ: vc+jwt`) is the only shape issued live. Both credentials in
`state/credentials/` are this shape.

**Data Integrity / `JsonWebSignature2020`**, the shape in the source document's §4 example,
is *not* issued live: `issuer-api2` is OpenID4VCI/JOSE only. The verifier still parses and
verifies it, and `tests/unit/test_happy_path.py::test_data_integrity_credential_is_accepted`
covers it with an in-process fixture. Canonicalisation for that shape is JCS (RFC 8785), not
URDNA2015, because the demonstration carries no JSON-LD processor.

## 8. The verifier

`did-x509-policy`'s `verify.py` runs fifteen checks in a fixed order and stops at the first failure.
Checks 1–6 and 10 come from DID Core and the `did:web` Read algorithm. The rest are verifier
policy: a conformant resolver treats `x5c` as opaque metadata, and that gap is the point.

| # | Key | Check | Origin |
|---|---|---|---|
| 1 | `credential_parsed` | credential parses and is within its validity window | — |
| 2 | `alg_allowed` | `alg` is allow-listed (`ES256`; never `none`) | policy |
| 3 | `issuer_matches_key_reference` | the `kid` DID equals `issuer` | DID Core |
| 4 | `did_document_resolved` | `did:web` resolves, from the network or the cache | `did:web` Read |
| 5 | `did_document_id` | the document's `id` equals the DID | `did:web` Read step 2 |
| 6 | `verification_method_authorized` | the method exists, is under `assertionMethod`, is controlled by the issuer, has a public-only JWK, and every DID URL is absolute | DID Core §5.3.2 |
| 7 | `x5c_present` | `publicKeyJwk` carries `x5c` (or `x5u`, if policy allows) | policy, brief rule 2 |
| 8 | `x5t_matches_leaf` | `x5t#S256` matches the leaf when present | RFC 7517 |
| 9 | `jwk_matches_leaf_spki` | the JWK equals the leaf's SubjectPublicKeyInfo | policy, tab C |
| 10 | `credential_signature` | ES256 verifies under that key | DID Core |
| 11 | `san_uri_matches_did` | the leaf names the DID in a SAN URI | policy, profile rule |
| 12 | `key_usage_digital_signature` | leaf `keyUsage` includes `digitalSignature` | policy |
| 13 | `certification_path` | path validates to the National Root CA, and only it | RFC 5280 |
| 14 | `issuer_authorization` | the leaf's policy OID accredits this credential type | policy, tab C step 5 |
| 15 | `revocation_status` | OCSP via AIA or CRL via CDP says good, and the answer is fresh | policy, brief rule 3 |

Check 9 is the one people omit. Without it anyone can paste a national chain into their own
`did.json`; `tests/unit/test_x5c_and_binding.py::test_a_decorative_chain_is_rejected` is that
attack.

Check 13, in `chain.py`, is written by hand: signatures, validity windows with clock skew,
`basicConstraints` CA and `pathlen`, `keyCertSign` on CAs, issuer/subject name chaining, and a
maximum depth. It does not compare AKI to SKI. A self-signed certificate inside `x5c` that is
not a configured anchor is rejected.

Check 15, in `revocation.py`:

- Only the leaf is checked, against the certificate that issued it. The Issuing CA's own
  status is not queried; it carries neither AIA nor CDP.
- **OCSP**: POST to the AIA URI, no nonce. The response must name the same serial and issuer
  hashes, and be signed by the Issuing CA or by a certificate it issued bearing EKU
  `OCSPSigning`. `thisUpdate`, `nextUpdate` and `producedAt` are checked against
  `clock_skew_seconds` and `ocsp_max_age_seconds`.
- **CRL**: fetched from the CDP, issuer name and signature checked against the Issuing CA,
  `nextUpdate` required and in the future, age bounded by `crl_max_age_seconds`.
- **Cache**: a fresh answer is stored only when it says `good` or `revoked`. When the network
  fails and `allow_cached_revocation` is true, the cached answer is re-evaluated under the same
  rules. `--no-cached-revocation` turns the fallback off.
- `unknown`, `expired`, `stale`, untrusted and mismatched answers all reject.

A check that raises an unexpected exception fails closed with reason `verifier_error`.

### Reason codes

`did-x509-policy`'s `reasons.py` defines the stable reason strings. They are the verifier's public
contract: the tests assert on them, the demo scripts print them, and `--json` emits them.

### Policy

`config/verifier-policy.json` carries 19 settings and is loaded into a frozen dataclass;
unknown keys are refused. Underscore-prefixed keys are notes. The settings are:
`trust_anchors`, `require_x5c`, `allow_x5u`, `require_spki_jwk_binding`,
`require_x5t_match_when_present`, `require_san_uri_equals_did`,
`require_key_usage_digital_signature`, `require_assertion_method`,
`require_absolute_did_urls`, `require_issuer_authorization`, `accreditation_policy_oids`,
`allowed_algs`, `revocation_required`, `allow_cached_revocation`, `ocsp_max_age_seconds`
(300), `crl_max_age_seconds` (3600), `clock_skew_seconds` (30), `http_timeout_seconds`,
`max_chain_depth`.

`config/verifier-policy-strict.json` is the same policy with `clock_skew_seconds` 0 and
both freshness windows at 30 seconds. It exists because a 30-second skew tolerance makes a
short expiry window unobservable; this bit the build three times before the second policy
was introduced. A unit test asserts the strict policy differs from the default only in those
three settings. `scripts/70-fingerprint.sh` installs both on the laptop.

### Command line

`python -m verifier.cli`, the image's entrypoint. Exit 0 accepted, 1 rejected, 2 could not run.

| Subcommand | Does |
|---|---|
| `verify --credential <path\|->` | decide; `--offline`, `--json`, `--no-cached-revocation`, `--allow-x5u`, `--no-colour` |
| `fingerprint` | print each trust anchor's SHA-256 fingerprint |
| `resolve <did>` | resolve a `did:web` DID; `--offline` uses the cache |
| `cache-document --did --file` | place a DID document in the cache without resolving it |
| `seed-cache --credential ...` | verify online to fill the cache (the scripts use `verify --json` instead) |
| `inspect --credential` | print header and payload without deciding |

`--store` and `--policy` are accepted before or after the subcommand. The policy defaults to
`<store>/policy.json`, then the shipped file. The text report is the default output, capped at
100 columns wide; there is no `--explain` flag.

## 9. The laptop store

`did-x509-policy`'s `FileStore`, rooted at `/laptop` in the container (`state/laptop/` on the host):

```
trust/nrca.pem            the National Root CA, the only credential trust anchor
trust/webtls-root.pem     the TLS store, deliberately a separate file
cache/did/<sha256>.json   {did, url, fetchedAt, document}
cache/ocsp/<key>.json     {storedAt, url, subjectSerial, der (base64)}
cache/crl/<key>.json      {storedAt, url, issuer, der (base64)}
policy.json               the default policy
policy-strict.json        the strict policy, for the freshness scenes
```

Cache keys are digests, because a DID contains colons. Writes go through a temporary file and
`replace`. The store refuses to hold a PEM containing `PRIVATE KEY`.

A cached document is a copy of evidence, never a stored verdict: all fifteen checks run again
against it. `tests/unit/test_offline.py::test_offline_never_opens_a_socket` makes any socket
construction an assertion failure while verifying offline.

## 10. The Issuing CA's revocation services

`src/ca/revocation_service.py` replaces `openssl ocsp` and `openssl ca -gencrl`. The brief's
reason code is `privilegeWithdrawn`. The `openssl ca` application cannot express it, measured
against OpenSSL 3.5.8 LTS, not merely an old build: `-crl_reason privilegeWithdrawn` is
rejected, and a reason written into `index.txt` by hand makes `-gencrl` fail. The table is
hard-coded in the `ca` application; libcrypto supports the full RFC 5280 set.

What stays as the brief intends: `openssl ca -revoke` still maintains `index.txt`, the
responder still sits behind nginx on domain2, the response life is still ours to choose, and a
CRL is published only when someone publishes it. What moves: the OCSP response and the CRL,
the two artefacts that must carry the reason, are built by this module. The reason per serial
lives in `state/ca/revocations.json`, written by `record-reason`, because `index.txt` cannot
hold it.

| Subcommand | Does |
|---|---|
| `serve --port 2560 --response-minutes 5` | the OCSP responder; re-reads `index.txt` on every request |
| `crl --out --hours [--seconds] [--expired-by]` | generate a CRL; increments `crlnumber` |
| `record-reason --serial --reason` | record the reason for a revoked serial |
| `status` | print the revocation database |

The responder signs with the delegated OCSP signer certificate and includes it in the
response. A request about a serial it never issued gets `unauthorized`, which the verifier
treats as `unknown`. The responder runs in the verifier image, read-only, with `state/ca`
mounted read-only.

## 11. Repository layout

```
config/            domains.env · verifier-policy.json · verifier-policy-strict.json
                   openssl/{nrca,issuing-ca}.cnf · openssl/ext/*.ext · nginx/*
images/            ca-tools (Alpine 3.22, OpenSSL 3.5.8) · web (nginx) · verifier (python:3.12)
                   tester (verifier deps + docker-cli + compose plugin) · recorder (tester + asciinema, agg, ffmpeg)
                   offline-ca/README.md — no image; ca-tools run with --network none
(the policy layer is its own repository now: adammwaniki/did-x509-policy)
src/ca/            revocation_service.py
src/issuer/        jwkexport.py · build_did_document.py · render_profile.py
src/holder/        wallet.py
scripts/           the build, revocation and restore steps; lib/common.sh
demo/              part1 … part4 · lib/present.sh
tests/unit/        hermetic; in-process PKI fixtures (tests/pkifixtures.py)
tests/integration/ against the live stack, driven through docker as a person would
record/            record.sh · RECORDING.md · NOTES-waltid.md · spike-wallet.py
state/             generated; offline/ holds the root key and is mounted nowhere else
recordings/        .cast, .gif, .mp4 per part
```

`state/offline/` is mounted only into the `offline()` helper's container, which has no
network. `state/transfer/` is the sneakernet: the CSR goes in, the certificate comes out. The
root private key never appears in a container that has a network, and
`tests/integration/test_live_pki_profile.py` searches all of `state/` for its bytes.

### The images

- **verifier**: `python:3.12-slim` with `cryptography`, `requests`, `pytest`; copies `src/`,
  `config/` and `tests/`. Also runs the OCSP responder and every Python helper in the scripts.
- **ca-tools**: Alpine 3.22 with OpenSSL 3.5.8, nginx, curl, jq. Used as the offline machine,
  as the Issuing CA workspace, and as domain2's web server.
- **tester**: the verifier's Python dependencies plus a Docker client and the compose plugin.
  Integration tests run in it with the socket mounted, and with the repository mounted at
  its own absolute host path so that a path computed inside the container is the same string
  on the host.
- **recorder**: built on the tester image, adding `asciinema`, `agg` and `ffmpeg`.

## 12. Scripts, in the order `make setup` runs them

| Script | Does |
|---|---|
| `10-offline-root.sh` | root key and certificate, on the offline machine; skipped if the root exists |
| `11-issuing-ca-csr.sh` | Issuing CA key and CSR, on the server |
| `12-offline-sign-ca.sh` | the root signs the Issuing CA; the CSR and certificate cross as files |
| `05-publish-root.sh` | copy the root certificate to domain1's web root; refuse if any private key is under `state/web` |
| `15-web-tls.sh` | the separate Web-TLS CA and three server certificates |
| `20-issuer-certs.sh` | issuer A (AIA OCSP), issuer B (CRL DP), the OCSP signer; publish the chain file for the `x5u` variant |
| `25-waltid-config.sh` | render the `issuer-api2` configuration for both issuers |
| `30-did-documents.sh` | build and publish both `did.json` and the `x5u` variants |
| `50-publish-crl.sh` | publish a CRL: a deliberate, separate act |
| *(compose up)* | start the seven services |
| `40-issue-credentials.sh` | issue one credential per issuer over OpenID4VCI |
| `70-fingerprint.sh` | fetch the root over HTTPS, compare its fingerprint with the offline machine's, install it and both policies |
| `80-seed-offline-cache.sh` | one online verification per credential, to fill the cache |

Other scripts:

| Script | Does |
|---|---|
| `60-revoke.sh a\|b [--no-publish]` | `openssl ca -revoke`, then `record-reason privilegeWithdrawn`; for B, publish a CRL unless told not to |
| `expire-crl.sh [seconds]` | publish a CRL already past `nextUpdate` |
| `responder.sh stop\|start` | stop and start domain2's nginx |
| `90-restore-revocations.sh` | mark every certificate valid, drop `revocations.json`, publish a clean CRL, re-prime the cache (about 25 s) |
| `00-reset.sh` | stop the dependent services, empty the state directories below the root, run 11 through 50, recreate the services, run 40, 70 and 80 |
| `pytest.sh` | unit tests in the verifier image; with `PKI_DEMO_STACK=1`, integration tests in the tester image |

`scripts/lib/common.sh` pre-creates every state directory, defines the `offline`, `ca`,
`laptop` and `laptop_offline` container helpers, and the polling helpers that run one
container per wait rather than one per attempt.

## 13. Tests

Collected on 2026-09-26 with `pytest --collect-only`: **180 unit tests** and **66 integration
tests**. `README.md` states 165 and 69; the collected figures are the ones from the code.

### Unit (`tests/unit`, hermetic)

`tests/pkifixtures.py` builds the whole world in process: root, Issuing CA, OCSP signer, both
issuers, a rogue root, DID documents, both credential shapes, OCSP responses and CRLs. The
`world` fixture is session-scoped because RSA key generation is the slow part. Adverse cases
covered include:

- **Binding and chain**: decorative chain, swapped coordinate, off-curve point, `x5t`
  mismatch, `x5c` in base64url, unknown root, missing intermediate, expired and not-yet-valid
  leaf, non-CA issuer, `pathlen:0` violation, CA without `keyCertSign`, forged signature,
  broken name chaining, chain deeper than policy, a root inside `x5c` that is not trusted.
- **DID document and authorisation**: resolution failure, non-JSON, `id` mismatch, method
  absent, key only under `authentication`, relative DID URL, foreign controller, missing
  `publicKeyJwk`, JWK carrying `d`, SAN mismatch or absent, DNS SAN instead of URI, missing
  `digitalSignature`, missing or unrelated policy OID, type outside the accreditation.
- **Credential**: unparseable inputs, `alg: none`, algorithm outside the allow-list,
  algorithm substitution, missing key reference or issuer, `kid` DID not the issuer, relative
  `kid`, unsupported DID method, `iss` disagreeing with `issuer`, nanosecond timestamps,
  `exp` and `nbf`, Data Integrity `proofPurpose`.
- **Revocation**: `good`, `revoked`, `unknown`, unreachable, unsuccessful, non-DER, rogue
  signer, signer without `OCSPSigning`, response about another serial, expired, future-dated,
  inside skew, wrong-CA CRL, expired CRL, stale-but-unexpired CRL accepting (the window),
  CRL older than policy, expired CRL rejected for being expired even when it lists the serial.
- **Offline**: primed cache accepts; absent document, absent revocation data, expired cached
  answers and cached `revoked` all reject; `x5c` verifies where `x5u` cannot; no socket is
  opened; the Web-TLS root is not an anchor offline either.
- **Revocation service**: `good`, `privilegeWithdrawn`, delegated signer, response life,
  refusing unknown serials and malformed requests, database re-read per request, CRL
  signature and contents, `crlnumber` increment, every RFC 5280 reason, unknown reason
  refused, `index.txt` parsing including a reason suffix.
- **Policy, store, report, CLI**: the shipped and strict policies, cache round-trips, the
  private-key refusal, the report layout, exit codes, stdin, `cache-document`, `--allow-x5u`.

### Integration (`tests/integration`, live stack)

Skipped unless `PKI_DEMO_STACK=1`. Fixtures that load certificates are function-scoped,
because session-scoped ones went stale after a test ran a full reset.

- **Endpoints**: domain1 serves the root over HTTPS and nothing private; both DIDs resolve
  and their `id` matches; the documents carry `x5c` and `assertionMethod`; no issuer serves
  a key; the CRL and OCSP are answered on domain2; the `x5u` chain file is published.
- **Certificate profile**: every constraint in section 5, on the real certificates; the root
  private key's bytes appear nowhere outside `state/offline`; no web root holds a private key;
  the two hierarchies have different roots.
- **Verification**: both credentials accepted online and offline; the report names the
  anchor and every check; the exit code is the verdict; each credential has the walt.id
  header shape; `/issuer2/` is not reachable through nginx.
- **Isolation**: inside `--network none`, no domain resolves, no endpoint answers, and the
  routing table has nothing beyond loopback; verification still succeeds; only
  `state/laptop` is consulted.
- **Revocation** (each test restored by `90-restore-revocations.sh`): OCSP revocation visible
  at the next verification with `did.json` unchanged; a stopped responder gives `unknown`
  without cache and the cached answer with it; the CRL window then its closure; an expired
  CRL; both offline stories; a cached answer going stale under the strict policy after 33 s.
- **Reproducibility**: `00-reset.sh` reissues everything below the root, keeps the root's
  fingerprint, leaves the root key only on the offline machine, verifies immediately after,
  and is safe to run twice; the offline kit holds what the brief's alternative procedure lists.

## 14. Recording

`record/record.sh <setup|part1|part2|part3|part4|all>` runs the named script under
`asciinema` inside the recorder container, with the Docker socket mounted and the repository
at its own host path, then renders `.cast` to `.gif` with `agg` and to `.mp4` with `ffmpeg`.
Terminal size is fixed at 104 by 34.

`demo/lib/present.sh` numbers each scene, prints narration lines in quotes as they come up,
and pauses on `[enter to continue]` unless `PAUSE=0`. `verdict` captures the verifier's JSON
first and renders afterwards, so a rejection (exit 1) is an answer rather than a failure.

## 15. Build order, as it happened

1. Environment findings and the original plan.
2. `config/`, `Makefile`, compose skeleton.
3. Unit tests and in-process fixtures first; the verifier until they passed.
4. Images, nginx, the CA scripts, DID documents.
5. A spike against `issuer-api2`, recorded in `record/NOTES-waltid.md`; then the profile
   renderer, the holder client and issuance.
6. `openssl ocsp` abandoned for `revocation_service.py` when `privilegeWithdrawn` was found
   to be unrepresentable; unit tests for the service.
7. The tester image and integration tests; the strict policy after the freshness scenes
   failed three times.
8. Demo scripts, `90-restore-revocations.sh`, reset and idempotence.
9. The recorder image and the recordings.

## 16. Deliberate deviations from the brief

| The brief says | Built | Why |
|---|---|---|
| Let's Encrypt on three real domains | a Web-TLS CA inside the stack | section 3 |
| an offline machine or VM for the root | a `ca-tools` container run with `--network none`, the key mounted nowhere else | the same isolation property, reproducible, enforced by Docker |
| (superseded) a bespoke responder | `openssl ocsp` behind nginx, as step 16 says | `openssl ca` cannot express `privilegeWithdrawn` on OpenSSL 3.5.8 LTS; section 10 |
| one credential per issuer | one per issuer, `vc+jwt` only | `issuer-api2` is OpenID4VCI/JOSE only; the Data Integrity shape is unit-tested |
| `x5c` | `x5c`, plus an `x5u` variant document | needed to show why `x5c` is the offline-capable choice |
| three verifier rules | fifteen checks | the brief's three plus everything tab C §5 requires, notably the SPKI-to-JWK binding |
| an expired CRL by short life and a wait | a CRL dated in the past | a short life cannot be waited out inside the skew tolerance |

## 16a. A real verifier, and the gap it leaves

The plan had the demonstration's own code doing all verification. That was a weakness: the
central claim is about what a *conformant* verifier does not check, and asserting it in code of
our own proves nothing. Added after the build, on the question being asked directly.

Three walt.id services now do all the protocol work, and none of it is ours:

| Service | Role |
|---|---|
| `issuer-api2` | issues over OpenID4VCI 1.0 |
| `wallet-api2` | holds the key, the DID and the credentials; receives and presents |
| `verifier-api2` | verifies over OpenID4VP 1.0 with DCQL |

`src/holder/wallet.py` is a 300-line HTTP client that drives them. It replaced a hand-rolled
OpenID4VCI and OpenID4VP implementation of about the same size, which was the right call for
the same reason: a demonstration about interoperability should not depend on our reading of
the specifications.

`did-x509-policy` is therefore not a credential verifier and should not be read as one. It is the
**PKI policy layer**: path validation to the national root, the SPKI-to-JWK binding, the SAN
URI rule, accreditation, revocation, and the offline cache. Those are the checks the
specifications require someone to add and do not define.

The two are run against the same credentials, and disagree exactly where the source document
says they will:

|  | walt.id `verifier-api2` | PKI policy layer |
|---|---|---|
| accredited issuer | `SUCCESSFUL` | ACCEPTED |
| impostor with a borrowed chain | `SUCCESSFUL` | REJECTED `spki_jwk_mismatch` |

`scripts/95-impostor.sh` builds the second row. Nothing in it is forged: the chain is the real
issuer A certificate and the real Issuing CA, and it validates to the National Root CA. It
simply does not certify the key published beside it. `verifier-api2` accepts it because
validating `x5c` is not its job, and `tests/integration/test_waltid_verifier.py` asserts that
no policy it runs mentions `x5c`, `x5u`, `chain`, `x509` or `pkix` -- so the premise is checked
against the implementation rather than believed.

Two consequences worth recording:

- **A real verifier resolves `did:web` over real DNS and real TLS.** The first attempt failed
  on the signature policy because it fetched the public `jacarandapropaganda.com`, which serves
  unrelated content. `images/verifier-api/Dockerfile` adds the demonstration's Web-TLS root to
  the JVM trust store, keeping resolution over HTTPS instead of downgrading it to plain HTTP.
  The public profile needs no such layer.
- **A wallet that discards its holder key cannot present anything.** Issuance now writes
  `<credential>.holder.json` beside each credential.

## 17. Where the build departed from the original plan

These departures are recorded here because no other file records them.

| The plan said | The code does |
|---|---|
| verification method fragment `nrca-sig-<serial>` | the RFC 7638 thumbprint, to match the `kid` `issuer-api2` emits (recorded in README and NOTES) |
| Web-TLS hierarchy on EC P-256 | RSA 4096 root, RSA 2048 server certificates |
| OCSP nonce sent when online | as planned. A 16-byte nonce is sent per request and the responder echoes it; a response echoing a different nonce is rejected as `revocation_response_nonce_mismatch`. A response with no nonce is accepted, because responders that pre-sign answers cannot echo one, and a cached response carries the nonce of a request no longer held. |
| revocation checked for every non-root certificate | only the leaf. Coherent here, because the Issuing CA carries no AIA or CDP and so publishes no status of its own, but it means a compromised Issuing CA would not be detected by this verifier. Not fixed; it needs the root to publish CRLs. |
| path validation checks AKI against SKI | name chaining and signatures only. Sound, but a certificate re-keyed under the same subject name would not be distinguished by AKI; it would still fail on the signature. Not fixed. |
| `--explain` for the camera, `--json` for tests | the text report is the default; `--json` for tests |
| exit 0 accept, 1 reject | plus exit 2 when the check could not run |
| cache files `cache/ocsp/<ca>-<serial>.der`, `cache/crl/<ca>.crl` | JSON wrappers with base64 DER and a `storedAt` stamp, keyed by digest |
| seven policy settings | eighteen. `require_x5c` was declared but read by nothing, and was in any case `allow_x5u` inverted, so it has been removed: a JWK with no chain is rejected unconditionally, because with no chain there is nothing to validate. |
| `demo/part0-setup` | as planned, and it runs `10-offline-root.sh` first so the offline machine is on camera |
| all verification done by our own code | walt.id `verifier-api2` does the conformant half; `did-x509-policy` is the PKI policy layer. See section 16a -- this was the plan's most substantive weakness. |
| our own holder client | walt.id `wallet-api2`. The hand-rolled OpenID4VCI/OpenID4VP client is gone; `src/holder/wallet.py` is now an HTTP client of three real services. |
| reason code `privilegeWithdrawn` | `cessationOfOperation`, which stock `openssl ca` can express, so brief steps 16 and 18 are literal. `REVOCATION_REASON` changes it. The bespoke responder that could emit `privilegeWithdrawn` was removed once that trade was accepted. |
| `src/verifier/cache`, `src/issuer/export_issuer_jwk.py`, `scripts/25-waltid-profiles` | the policy layer became the `did-x509-policy` package; `jwkexport.py`; `25-waltid-config.sh` |
| an `offline-ca` image and a `verifier` service | neither; both are `docker run` invocations |
| two credentials per issuer | one; see section 7 |
| part 4 ends with an expired cache rejecting as `unknown` | it rejects as `revocation_expired` or `revocation_stale` under the strict policy |

## 18. What went wrong during the build

The reusable lessons, each fixed in the code named:

- **Docker creates a missing bind-mount source directory as root.** It is then unwritable by
  the unprivileged user the containers run as. `scripts/lib/common.sh` pre-creates every state
  directory before any container starts.
- **`rm -rf` on a directory a running container bind-mounts** leaves that container holding a
  deleted inode. It showed up later as an OCSP responder that could not find any certificate
  it had issued. `00-reset.sh` empties contents with `find -mindepth 1 -delete`, and stops the
  dependent services first.
- **A key written at mode 400 cannot be overwritten.** Every generation step removes the
  previous file before `openssl genrsa` or `ecparam`.
- **Session-scoped pytest certificate fixtures go stale** after a test runs a full reset. The
  integration fixtures are per-test now; only the unit `world` stays session-scoped, and
  nothing resets it.
- **`tr` works on bytes and shreds a multibyte character.** The demo's rule lines are built by
  repetition in `demo/lib/present.sh`.
- **`set -o pipefail` ends a demo script on the verifier's exit 1**, which is an answer, not a
  failure. `verdict` captures the report with `|| true` before rendering it.
- **pytest's `tmp_path` is inside the test runner's filesystem**, which the Docker daemon does
  not share, so bind-mounting it writes nowhere. `test_domain2_serves_the_crl_over_http` uses
  `state/tmp` instead.
- **A 30-second clock-skew tolerance makes short expiry windows unobservable.** Three attempts
  at the freshness scenes failed before `config/verifier-policy-strict.json` was introduced;
  `expire-crl.sh` dates the CRL in the past for the same reason.
- **A responder wired in before it had a test** cost three debugging rounds: a method that does
  not exist in this version of `cryptography` (`add_response_by_hash`), a flag OpenSSL 3.3
  rejects (`-nrequest 0`), and a stand-in object where a real certificate was required. Each
  surfaced as an unexplained HTTP 502 rather than a test failure.
  `tests/unit/test_revocation_service.py` now covers the responder directly.
- **A setting that nothing reads is worse than no setting**, because a reader believes it. A
  review found `require_x5c` declared, documented as "brief rule 2", unit-tested for
  round-tripping, and consulted by no check.
- **One time check read the clock itself** while every other honoured the `at` argument and the
  policy's skew. It could not be driven deterministically from a test and silently ignored the
  strict policy. `credential.check_validity_window` now takes both.
- **A pinned image tag that exists only on the machine that built it.** `scripts/pytest.sh`
  defaulted to `pki-in-did/verifier:dev`, which `make images` does not build, so unit tests
  would have failed on any other host.
- **An OCSP responder may ship several certificates, in any order.** Taking
  `certificates[0]` as the delegated signer worked against our own responder and would break
  against a real one; the signer is now searched for.

## 19. Open question

The brief's step 10 assumes public Let's Encrypt certificates on `adamndegwa.com`,
`jacarandapropaganda.com` and `lawnbull.com`. Those names are Cloudflare-proxied and serve
unrelated content. The self-contained stack is what is recorded. A public overlay through the existing Caddy would
need Cloudflare set to DNS-only, or Full-strict with origin certificates, for those hostnames;
it has not been built.
