# PKI in Decentralised Identifiers — a working demonstration

> Looking for the reusable part? The PKI policy layer is published on its own:
> **[adammwaniki/did-x509-policy](https://github.com/adammwaniki/did-x509-policy)**. This
> repository is the demonstration it was extracted from, and it installs that package rather
> than keeping a copy.

A `did:web` issuer publishes a signing key that a **National Root CA** certified, issues a
Verifiable Credential with it over **OpenID4VCI**, and a verifier whose only trust anchor is
that root certificate decides accept or reject — **with or without a network**.

Then the Issuing CA withdraws the accreditation, twice: once with OCSP, once with a CRL. The
DID documents never change.

And the part that makes the case: the same credential goes through **walt.id `verifier-api2`**,
a production OpenID4VP 1.0 verifier. It returns `SUCCESSFUL` for a credential whose national
certificate chain is **genuine but certifies a different key** — correctly, because validating
`x5c` is not part of `did:web` or DID Core. The policy layer rejects it.

|  | walt.id `verifier-api2` | PKI policy layer |
|---|---|---|
| accredited issuer | `SUCCESSFUL` | ACCEPTED |
| impostor, borrowed chain | `SUCCESSFUL` | REJECTED `spki_jwk_mismatch` |

That is the source document's *"the chain is decorative"*, shown against a third-party
implementation rather than asserted. Twenty-four seconds:

![Part 5 — the same credential through walt.id verifier-api2 and through the PKI policy layer](docs/media/part5-the-gap.gif)

### The policy layer is published on its own

The part of this that is ours — the PKI policy layer — is packaged separately, because it is
the reusable half:

**[adammwaniki/did-x509-policy](https://github.com/adammwaniki/did-x509-policy) · [`ghcr.io/adammwaniki/did-x509-policy`](https://github.com/adammwaniki/did-x509-policy/pkgs/container/did-x509-policy)**

```bash
docker run --rm -p 8080:8080 \
  -e DID_X509_TRUST_ANCHOR_PEM="$(cat your-root.pem)" \
  ghcr.io/adammwaniki/did-x509-policy:1.0.1

curl -sS -X POST localhost:8080/verify -H 'Content-Type: application/json' \
  -d "{\"credential\": \"$(cat credential.jwt)\"}"
```

A library, a CLI and an HTTP service, with pluggable cache and transport backends so it fits
whatever you already run. 201 tests of its own. This demonstration installs it by pinned tag
(`images/verifier/Dockerfile`), so the two cannot drift.

### What is off-the-shelf, and what is not

| Component | What it is |
|---|---|
| Issuance | **walt.id `issuer-api2`** — a real OpenID4VCI 1.0 issuer, unmodified |
| Holder | **walt.id `wallet-api2`** — a real wallet. It generates and holds the holder key, creates the DID, proves possession, stores credentials, and presents them over OpenID4VP |
| Standards-conformant verification | **walt.id `verifier-api2`** — a real OpenID4VP 1.0 verifier with DCQL, unmodified except one root added to its JVM trust store |
| The CA | stock `openssl ca` and `openssl ocsp` |
| **The PKI policy layer** | [`did-x509-policy`](https://github.com/adammwaniki/did-x509-policy) — ours, published separately, installed here by pinned tag. Path validation to the national root, the SPKI-to-JWK binding, SAN URI, accreditation, revocation, and the offline cache |
| Glue | `src/holder/wallet.py` — an HTTP client that drives the three services; it implements no protocol itself |

So the credential is issued, held, presented and verified by production walt.id services
throughout. The only code of ours in the trust decision is [`did-x509-policy`](https://github.com/adammwaniki/did-x509-policy), and it is
deliberately **not** a reimplementation of a credential verifier: it is the policy layer the
specifications say you must add and do not define. That is why the demonstration runs both.

```
did:web resolution
  → DID document
    → verificationMethod.publicKeyJwk
      → RFC 7517 x5c
        → X.509 certificate chain
          → National Root CA        ← the verifier's only trust anchor
```

Built from `PKI in DID.md` (tabs **K** and **C**) and the demonstration script in `PLAN.md`.

---

## Run it

```bash
make setup     # build the PKI, start the stack, issue the credentials  (~5 min)
make demo      # the four recorded parts, in order
make test      # 180 unit tests, then 66 integration tests
make record    # write recordings/ (five .cast + .gif + .mp4)
```

`make setup` needs Docker and about 5 minutes. It binds no host ports.

## What is running

| Brief | Real domain | Container | Serves |
|---|---|---|---|
| NRCA, public | `adamndegwa.com` | `nrca-web` | `/nrca.pem` over HTTPS |
| NRCA, private | — | *(not a service)* | the root private key, `--network none` |
| Issuing CA | `mwaniki.dev` | `issuing-ca`, `ocsp-responder` | `/ocsp`, `/issuing-ca.crl` over HTTP |
| Credential issuer A | `jacarandapropaganda.com` | `issuer-a-web`, `issuer-a-api` | `did.json`; OpenID4VCI |
| Credential issuer B | `lawnbull.com` | `issuer-b-web`, `issuer-b-api` | `did.json`; OpenID4VCI |
| Verifier | — | *(run on demand)* | the root certificate and a cache |

Issuer A's certificate carries an **AIA OCSP** URI. Issuer B's carries a **CRL distribution
point**. That is the only difference between them — the controlled variable of the experiment.

The four domain names are Docker-network DNS aliases, so `did:web:jacarandapropaganda.com`
resolves inside the network exactly as it would on the internet. See
[Why it is self-contained](#why-it-is-self-contained).

### Two PKI layers, kept apart

The source document is blunt that these are different problems — *"Don't assume one cert does
both"* — so the demonstration keeps two separate trust stores and a test asserts they are not
interchangeable.

| | Certifies | In the laptop's | Root |
|---|---|---|---|
| **Web-TLS CA** | the HTTPS endpoints, so `did:web` can be resolved at all | TLS trust store | `DemoWebTLS Root` |
| **National Root CA** | the credential-signing keys | credential trust anchor store | `Demo National Root CA` |

## The verifier

Fifteen checks, in order. Exit 0 accepted, 1 rejected, 2 could not run.

```bash
docker run --rm --network pki-in-did_demo \
  -v "$PWD/state/laptop:/laptop" -v "$PWD/state/credentials:/credentials:ro" \
  pki-in-did/verifier verify --credential /credentials/issuer-a-vc-jose.jwt
```

| # | Check | Source |
|---|---|---|
| 1 | Credential parses and is inside its validity window | — |
| 2 | Algorithm is allow-listed (`ES256`; never `none`) | policy |
| 3 | Issuer and key reference name the same DID | DID Core |
| 4 | `did:web` resolves to a DID document | `did:web` Read |
| 5 | The document's `id` equals the DID resolved | `did:web` Read step 2 |
| 6 | The verification method is listed under `assertionMethod` | DID Core §5.3.2 |
| 7 | **`publicKeyJwk` carries `x5c`** | brief rule 2 — unconditional |
| 8 | `x5t#S256` matches the leaf, when present | RFC 7517 |
| 9 | **Leaf SubjectPublicKeyInfo equals the JWK** | policy — see below |
| 10 | The credential signature verifies under that key | DID Core |
| 11 | The leaf names the DID in a SAN URI | policy — profile rule |
| 12 | Leaf `keyUsage` includes `digitalSignature` | policy |
| 13 | Path validates to the National Root CA, and only it | RFC 5280 |
| 14 | The certificate accredits this credential *type* | policy |
| 15 | **Revocation is good and fresh** | policy — brief rule 3 |

Checks 1–6 and 10 are what the specifications give you. Everything in bold is *verifier
policy*: a conformant DID resolver treats `x5c` as opaque metadata, and that gap is the whole
point of the exercise.

Check 9 is the one people leave out. Tab C: *"Confirm the leaf certificate's
SubjectPublicKeyInfo matches the `x`/`y` in the JWK. Without this binding check the chain is
decorative."* Anyone can paste a national CA chain into their own `did.json`;
`tests/unit/test_x5c_and_binding.py::test_a_decorative_chain_is_rejected` is that attack.

Almost every rule is a setting in [`config/verifier-policy.json`](config/verifier-policy.json)
rather than a constant in the code, because that is what "verifier policy" means. Check 7 is
the exception: with no chain in the JWK there is nothing to validate against the root, so it
is a premise rather than a choice. What *is* a choice there is whether a chain held by
reference will do — `allow_x5u`, which defaults to false and is why offline works.

OCSP requests carry a nonce (RFC 6960 §4.4.1), so a captured `good` response cannot be
replayed. A responder that omits the nonce is still accepted — many pre-sign their answers —
and freshness then rests on `thisUpdate` and `nextUpdate`.

### Offline

```bash
docker run --rm --network none \
  -v "$PWD/state/laptop:/laptop" -v "$PWD/state/credentials:/credentials:ro" \
  pki-in-did/verifier verify --offline --credential /credentials/issuer-a-vc-jose.jwt
```

Docker enforces the isolation, not our code: `tests/integration/test_offline_isolation.py`
asserts that nothing resolves and there is no route off `lo`, and that verification still
succeeds.

Everything the laptop needs is in `state/laptop/` — the root certificate, the policy, and a
cache of DID documents, OCSP responses and CRLs filled while it was online. A cached document
is a **copy of evidence, never a stored verdict**: all fifteen checks run again against it.

This works because the chain travels *inside* the key material. `x5c` holds certificates;
`x5u` holds only a URL. The same key is published both ways so the difference can be shown:

```
$ verify --offline   # the x5c document
ACCEPTED
$ verify --offline   # the x5u variant
REJECTED   x5u_fetch_failed
```

## Credential issuance: walt.id `issuer-api2`

Credentials are issued by [walt.id `issuer-api2`](https://github.com/walt-id/waltid-identity/tree/main/waltid-services/waltid-issuer-api2)
(`waltid/issuer-api2:1.0.0`), a real OpenID4VCI 1.0 issuer — not a signing script.

```
EC P-256 key + CSR (ours)
  → the Issuing CA signs the leaf                → scripts/20-issuer-certs.sh
  → private JWK (with d)                         → issuer-api2 profile `issuerKey`
  → leaf + Issuing CA PEM                        → issuer-api2 profile `x5Chain`
  → public JWK + x5c + x5t#S256                  → our did.json
```

walt.id `wallet-api2` is the holder. It generates the holder key, creates the `did:jwk`, runs
the pre-authorized-code flow with DPoP-bound access tokens, proves possession and stores the
credential. `src/holder/wallet.py` only asks it to.

The join between the two halves is the `kid`. `issuer-api2` emits
`<issuerDid>#<RFC 7638 thumbprint of the public JWK>`, so `30-did-documents.sh` computes the
same thumbprint for the verification method fragment. They agree by construction, not by
convention — and DID Core recommends exactly that. Every observed detail is recorded in
[`record/NOTES-waltid.md`](record/NOTES-waltid.md), including two mistakes that cost time.

`issuer-api2` also puts `x5c` in the JOSE header. The verifier deliberately takes the chain
from the **DID document** instead, because taking it from the header is the *other* design the
source document describes (*"Skip the DID. Put `x5c` directly in the JOSE header"*) and is not
what is being demonstrated.

## The recordings

Six parts, all watchable here. The GIFs in [`docs/media/`](docs/media) are committed for
exactly that reason; the `.cast` and `.mp4` files are not, because
[`record/record.sh`](record/record.sh) regenerates them:

```bash
record/record.sh all          # re-record everything, ~12 minutes including rendering
record/publish-media.sh       # re-render the GIFs below from the casts
```

The narration is **in the scripts** (`narrate "..."`), printed in quotes as it comes up, so what
is said and what is run cannot drift apart. [`record/RECORDING.md`](record/RECORDING.md) is the
shot list: what to point at, the lines to say aloud, and how to reset between takes
(`scripts/90-restore-revocations.sh`, ~25 s, rather than a full rebuild).

---

### Part 1 — the happy path, online · 20s

`did:web` resolving by textual rule, the `x5c` chain decoded into certificate names rather than
kilobytes of base64, then fifteen checks passing twice: issuer A via OCSP `good`, issuer B with
its serial absent from the CRL.

![Part 1](docs/media/part1-happy-online.gif)

### Part 2 — the happy path with no network · 17s

Opens by *proving* the isolation rather than claiming it: nothing resolves, and `/proc/net/route`
holds nothing but `lo`. Both credentials verify anyway. Closes with the three lines that show why
— `x5c` by value against `x5u` by reference.

![Part 2](docs/media/part2-happy-offline.gif)

### Part 3 — revocation, online · 46s

The Issuing CA acts alone, twice. OCSP first: the DID document's hash is printed before and
after, identical. Then the CRL, where the verifier **accepts and is right to** until a new CRL is
published — that gap is the revocation window. Finally an expired CRL, rejected *for being
expired* even though it lists the serial.

![Part 3](docs/media/part3-revocation-online.gif)

### Part 4 — revocation, offline · 2m35s

What a disconnected verifier can and cannot honestly know. It still accepts, because it has not
been told and cannot ask; refuse the cached answer and it reports `unknown`; one reconnection
makes the rejection persist. Ends with a cached answer going stale under a narrower policy while
the default still accepts the same cache.

![Part 4](docs/media/part4-revocation-offline.gif)

### Part 5 — what a conformant verifier does not check · 24s

**The argument.** walt.id `verifier-api2` and the PKI policy layer on the same two credentials.
If you watch one, watch this.

![Part 5](docs/media/part5-the-gap.gif)

### Part 0 — building it · 1m40s, shown at 3x

<details>
<summary>The offline machine, then the whole PKI, the DID documents and OpenID4VCI issuance</summary>

The root key directory and the container's interface count come first, because where the root
private key lives is the thing a viewer needs to see before anything else. Then the CSR crossing
to the offline machine and the certificate coming back, the Web-TLS CA, the two issuer
certificates with their different revocation pointers, the walt.id profiles, the DID documents,
the CRL, issuance, and the laptop's trust store.

![Part 0](docs/media/part0-setup.gif)

</details>

---

Each recording also produces an `.mp4` and a `.cast` in `recordings/`. The `.cast` is the most
useful of the three: exact, a few kilobytes, replayable and copy-pasteable as text —
`asciinema play recordings/part5-the-gap.cast`. `asciinema`, `agg` and `ffmpeg` all live in the
`recorder` image, so the host needs nothing installed, and the terminal is fixed at 104x34 so
the reports lay out identically every time.

Run any part by hand for a live audience and it pauses between scenes:

```bash
demo/part5-the-gap.sh            # [enter to continue] between scenes
PAUSE=0 demo/part5-the-gap.sh    # straight through, as the recorder runs it
```

## OCSP versus CRL, as the demonstration shows it

| | OCSP | CRL |
|---|---|---|
| When a verifier learns | at the next verification, unless a cached response is still fresh | when it next fetches a CRL |
| Network | needed for every check | needed only to fetch a new CRL |
| Work for the authority | a responder that must always answer | a file republished on a schedule |
| Revocation window | none, beyond the response life you choose (here **5 minutes**) | up to the CRL's `nextUpdate` (here **1 hour**) |

Part 3 shows the CRL window as a real window: revoke, publish nothing, and the verifier
**accepts — correctly**. Then publish, and it rejects.

## Deliberate deviations, and why

| The brief says | This does | Why |
|---|---|---|
| Let's Encrypt on three real domains | a Web-TLS CA inside the stack | see below |
| an offline machine or VM for the root | a container run with `--network none`, its key mounted nowhere else | the same isolation property, reproducible on camera, enforced by Docker |
| reason code `privilegeWithdrawn` | `cessationOfOperation` | `openssl ca` cannot express `privilegeWithdrawn`, in either direction, and that is still true of **OpenSSL 3.5.8 LTS** — measured, not assumed. Taking the nearest reason it does support keeps brief steps 16 and 18 literal: stock `openssl ocsp` behind nginx, and `openssl ca -gencrl`. Set `REVOCATION_REASON` in `config/domains.env` to use another. Evidence in [`record/NOTES-waltid.md`](record/NOTES-waltid.md). |
| one credential per issuer | one per issuer, `vc+jwt` | `issuer-api2` is OpenID4VCI/JOSE only. The verifier also supports the source document's §4 Data Integrity shape, covered by unit tests. |
| `x5c` | `x5c`, plus an `x5u` variant | needed to *demonstrate* why `x5c` is the offline-capable choice |
| three verifier rules | fifteen checks | the brief's three, plus everything tab C §5 requires |

Two smaller ones worth stating plainly:

- **Data Integrity canonicalisation is JCS (RFC 8785), not URDNA2015.** The demonstration
  carries no JSON-LD processor. Both ends agree on it, and it is the same choice the
  `*-jcs-*` cryptosuites make, but a `JsonWebSignature2020` proof from here will not verify
  against a URDNA2015 implementation.
- **The accreditation policy OID `1.3.6.1.4.1.99999.1.1` is invented** for this
  demonstration, under a private-enterprise arc. It backs check 14.

### Why it is self-contained

Two things about the host this was built on:

- **Ports 80 and 443 belong to another service**, so the demonstration must not take them, and
  it binds no host port at all.
- **The four bare domains are proxied and already serve unrelated content**, so they cannot
  resolve to this stack. Public certificates for them, as brief step 10 assumes, is not the
  current state of the world.

So the stack uses those exact domain names as Docker-network aliases with its own Web-TLS CA.
This is not a compromise: it is what makes the run reproducible, `--network none` meaningful,
and the recording re-shootable. Publishing to the real domains would additionally need
Cloudflare set to DNS-only (or Full-strict with origin certificates) for those hostnames.

## Layout

```
PLAN.md                  the plan, and the environment findings that shaped it
PKI in DID.md            the source document (tabs K and C)
config/                  domains.env · verifier-policy*.json · openssl/ · nginx/ · waltid-*/
(the policy layer lives in its own repository and is installed by pinned tag)
src/issuer/              JWK export, DID document builder, walt.id profile renderer
src/holder/wallet.py     an HTTP client driving walt.id issuer-api2, wallet-api2 and verifier-api2
scripts/                 the build, in the order the brief describes
demo/                    the four recorded parts, with their narration
tests/unit/              180 hermetic tests: every reject path, no Docker, no network
tests/integration/       66 tests against the live stack, including --network none
record/                  record.sh · publish-media.sh · RECORDING.md · NOTES-waltid.md
docs/media/              the GIFs embedded above; committed so the README plays
recordings/              .cast and .mp4, generated by record/record.sh; not committed
state/                   generated; state/offline holds the root key and is mounted nowhere else
```

### Scripts, in order

| Script | Does |
|---|---|
| `10-offline-root.sh` | root key and certificate, on the offline machine |
| `11-issuing-ca-csr.sh` | Issuing CA key and CSR, on the server |
| `12-offline-sign-ca.sh` | the root signs the Issuing CA; the CSR crosses as a file |
| `05-publish-root.sh` | publish the root **certificate** on domain1 |
| `15-web-tls.sh` | the separate Web-TLS CA and its server certificates |
| `20-issuer-certs.sh` | issuer A (AIA OCSP), issuer B (CRL DP), the OCSP signer (EKU OCSPSigning) |
| `25-waltid-config.sh` | render the `issuer-api2` profiles and metadata |
| `30-did-documents.sh` | build and publish both `did.json`, plus the `x5u` variant |
| `40-issue-credentials.sh` | issue over OpenID4VCI |
| `50-publish-crl.sh` | publish a CRL — a deliberate, separate act |
| `60-revoke.sh a\|b` | withdraw an accreditation, reason `$REVOCATION_REASON` |
| `95-impostor.sh` | publish a DID document pasting a genuine chain beside an uncertified key |
| `70-fingerprint.sh` | fetch the root, compare fingerprints, install the trust anchor |
| `80-seed-offline-cache.sh` | prime the cache so the laptop can work disconnected |
| `expire-crl.sh` | publish an already-expired CRL |
| `responder.sh stop\|start` | stop and start the OCSP responder |
| `00-reset.sh` | reissue everything; the root is kept |
| `90-restore-revocations.sh` | undo revocations without reissuing (~25 s) |

## Tests

```bash
make test-unit          # hermetic; no Docker, no network
make test-integration   # against the running stack
```

Unit tests build their own PKI in process, so every adverse case is reachable: a decorative
chain, an expired leaf, a rogue OCSP signer, a responder without `OCSPSigning`, a CRL signed
by the wrong CA, `alg: none`, a key listed only under `authentication`, a relative DID URL, a
JWK carrying `d`, a chain that reaches an untrusted root, a `pathlen:0` violation.

Integration tests assert the things that only a live stack can show: that domain1 serves no
private key, that the root fingerprint matches the offline machine, that an isolated container
has no routes, that `/issuer2/` is not reachable through nginx (it returns the issuer's private
key), and that no private key exists anywhere under a web root.

## Things worth saying out loud

1. **The root private key is not on the network.** It is in `state/offline/`, mounted into one
   container that has no interfaces but loopback.
2. **The DID documents never changed.** Only the Issuing CA acted. `60-revoke.sh` prints the
   document's hash before and after.
3. **A valid chain proves who certified the key, not what it may issue.** That is check 14,
   and it is why the brief's model needs an accreditation policy as well as a certificate.
