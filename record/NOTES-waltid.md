# walt.id `issuer-api2` — observed behaviour

Everything below was measured against `waltid/issuer-api2:1.0.0` (Docker Hub, pushed
2026-08-24) on 2026-09-26, with a throwaway three-tier PKI and a `did:web` issuer DID.
None of it is inferred from reading the source. `record/spike-wallet.py` is the client
used to establish it, kept so the measurements can be repeated.

## What a profile needs

```hocon
accreditedOperatorCredential = {
  name = "AccreditedOperatorCredential"
  credentialConfigurationId = "AccreditedOperatorCredential_jwt_vc_json"
  issuerKey = { type = "jwk", jwk = { kty="EC", crv="P-256", d="…", x="…", y="…" } }
  issuerDid = "did:web:jacarandapropaganda.com"
  x5Chain   = [ """<leaf PEM>""", """<Issuing CA PEM>""" ]
  credentialData = { … }
  mapping = { "id"="<uuid>", "issuer"={"id"="<issuerDid>"},
              "credentialSubject"={"id"="<subjectDid>"}, "validFrom"="<timestamp>" }
}
```

`credentialConfigurationId` must also exist under `credentialConfigurations` in
`credential-issuer-metadata.conf`, or the offer cannot be redeemed:

```hocon
"AccreditedOperatorCredential_jwt_vc_json" = {
  format = "jwt_vc_json"
  scope = "AccreditedOperatorCredential_jwt_vc_json"
  credential_signing_alg_values_supported = ["ES256"]
  cryptographic_binding_methods_supported = ["jwk", "did:key", "did:web", "did:jwk"]
  proof_types_supported = { jwt = { proof_signing_alg_values_supported = ["ES256"] } }
  credential_definition = { type = ["VerifiableCredential", "AccreditedOperatorCredential"] }
}
```

`issuer2-profiles.conf` states the trust model this demonstration depends on, in its own
words: *"Test-only leaf chains. The external trust anchor is configured separately and MUST
NOT be embedded here."*

## The issued credential

Header of a `jwt_vc_json` credential from a profile carrying both `issuerDid` and `x5Chain`:

```json
{
  "alg": "ES256",
  "kid": "did:web:jacarandapropaganda.com#e_cur7Otp54RYZPNrblDY3ki7MP9flHjWVWQvj3G51w",
  "typ": "vc+jwt",
  "x5c": ["<leaf DER, standard base64>", "<Issuing CA DER, standard base64>"]
}
```

Measured facts:

1. **`kid` = `<issuerDid>#<RFC 7638 thumbprint of the public JWK>`.** Verified by computing
   the thumbprint independently; it matched exactly. It is deterministic, so
   `scripts/30-did-documents.sh` computes the same value rather than guessing, and the DID
   document's verification method fragment is that thumbprint. This is also what DID Core
   recommends (fragment = JWK `kid` = RFC 7638 thumbprint).
2. **`x5c` is standard base64, leaf first, root omitted** — re-encoding each entry with
   standard base64 reproduced the string exactly. Same profile as RFC 7517 §4.7.
3. **The credential signature verifies against the leaf certificate's public key**, so the
   SPKI-to-JWK binding the verifier checks holds by construction.
4. **Issuance never resolves `did:web`.** Re-run with `--add-host
   jacarandapropaganda.com:127.0.0.1` so any resolution would fail: issuance still returned
   200, and the logs contain no resolution attempt. Consequence: no need to put the demo
   Web-TLS root into the JVM truststore, and the issuer works on an isolated network.
5. Payload carries `iss` (the DID) **and** a `issuer` object whose `id` is the DID, plus
   `jti`, `sub`, `iat`, `nbf`, `validFrom`, `id`, `type`.
6. `validFrom` is emitted with **nanosecond** precision
   (`2026-09-26T12:26:57.207818928Z`), which `datetime.fromisoformat` rejects. The verifier
   truncates the fraction to microseconds.

## Driving the flow (what the holder client must do)

1. `POST /issuer2/credential-offers` → `201` with `credentialOffer` =
   `openid-credential-offer://?credential_offer_uri=…`.
2. `GET /openid4vci/credential-offer?id=<offerId>` → `grants
   ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]`.
   No `tx_code` for an anonymous pre-authorized offer.
3. `POST /openid4vci/token`, **form-encoded**, `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`
   and `pre-authorized_code=…` → `access_token`.
4. `POST /openid4vci/nonce` → `c_nonce` (itself a JWT).
5. `POST /openid4vci/credential` with `Authorization: Bearer <access_token>` and
   `{"credential_configuration_id": "...", "proofs": {"jwt": ["<proof>"]}}`
   → `{"credentials":[{"credential":"<compact JWS>"}]}`.

### Two things that cost time, recorded so they do not again

- The holder proof JWT must bind through a **`kid` holding a DID** (`did:jwk:<b64u>#0`).
  A proof carrying a bare `jwk` header instead fails the profile's `<subjectDid>` mapping
  with `400 invalid_credential_request: Cannot find in context: subjectDid`.
- The proof's `aud` is the `credential_issuer` value from the issuer metadata
  (`<baseUrl>/openid4vci`), not `baseUrl`.

## Operational notes

- `GET /issuer2/profiles` returns each profile's `issuerKey` **including the private `d`**.
  The management API must never be published. In this stack it is reachable only on the
  internal Docker network, and nginx does not proxy `/issuer2/`.
- Startup takes ~21 s before the port answers; scripts must poll rather than sleep.
- `baseUrl` in `issuer-service.conf` must be the externally reachable URL, because it is
  echoed into the metadata, the offer URI and the proof `aud`.

## What issuer-api2 does not do

It is OpenID4VCI 1.0 only: `jwt_vc_json`, SD-JWT VC and mdoc. It does **not** produce a
Data Integrity / `JsonWebSignature2020` proof, which is the shape in the source document's
§4 example. The verifier still supports that shape and it is covered by unit tests; the
live stack issues VC-JOSE-COSE (`typ: vc+jwt`) only, because that is what a real issuer
emits here.

---

# OpenSSL and the `privilegeWithdrawn` reason code

The brief asks for the RFC 5280 reason `privilegeWithdrawn`, which is the right reason when
an authority withdraws an accreditation and the key itself is not suspect. The `openssl ca`
application cannot express it, and moving to a newer OpenSSL does not help.

Measured on 2026-09-26 against **OpenSSL 3.5.8 LTS** (Alpine 3.22), with a throwaway CA:

| reason passed to `openssl ca -revoke -crl_reason` | result |
|---|---|
| `unspecified`, `keyCompromise`, `CACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL` | accepted |
| `privilegeWithdrawn` | **rejected** — `Unknown CRL reason privilegeWithdrawn` |
| `aACompromise` | **rejected** |

Writing the reason into `index.txt` by hand does not get round it either, because the same
table is used when reading:

```
$ openssl ca -config ca.cnf -gencrl -out crl.pem
invalid reason code privilegeWithdrawn
 in entry 1
```

The limitation is a hard-coded list in the `ca` **application**. libcrypto itself supports
the full RFC 5280 set — `CRLReason` / `ReasonFlags` includes `privilege_withdrawn` — which is
why `src/ca/revocation_service.py` can emit it while `openssl ca` cannot.

**Consequence for this demonstration.** `openssl ca -revoke` still maintains the certificate
database, exactly as brief step 16's design intends, and the responder still sits behind nginx
on domain2 with a response life we choose. Only the two artefacts that must *carry* the reason
code — the OCSP response and the CRL — are produced by `src/ca/revocation_service.py`, which
reads that same `index.txt`. The reason per serial lives in `revocations.json` beside it,
because `index.txt` cannot hold it.

The demonstration runs OpenSSL 3.5.8 LTS regardless, since it is the current LTS.
