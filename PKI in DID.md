# **K**

Q. 

Can DID Core implementations such as did:webvh, did:web etc. make use of keys from a national Root CA's PKI for issuers who are signing verifiable credentials?

Ref:

* [https://github.com/w3c-ccg/did-method-web/blob/main/index.html](https://github.com/w3c-ccg/did-method-web/blob/main/index.html)  
* [https://www.w3.org/TR/did/\#ref-for-dfn-verification-method-14](https://github.com/w3c-ccg/did-method-web/blob/main/index.html)

Ans.

**Yes — but through the issuer’s X.509 certificate chain represented inside a DID verification method, not because `did:web` itself defines national-PKI validation for credential-signing keys.**

The specification chain is:

```
did:web resolution
    → DID document
    → verificationMethod with publicKeyJwk
    → JWK x5c or x5u
    → X.509 certificate chain
    → national Root CA trust anchor
```

There are two distinct PKI layers to keep separate:

1. **TLS PKI for resolving the DID document.**  
2. **Document-signing PKI for verifying VCs.**

They may use the same national Root CA, but they do not have to.

---

## **1\. What `did:web` itself provides**

The `did:web` specification says that the method-specific identifier is a fully qualified domain name “secured by a TLS/SSL certificate.” Resolution transforms the DID into an HTTPS URL, performs a secure HTTPS `GET`, and checks that the resolved DID document’s `id` matches the DID being resolved.

For example:

```
did:web:issuer.gov.example
```

resolves to:

```
https://issuer.gov.example/.well-known/did.json
```

Therefore, if the issuer’s HTTPS certificate chains to the national Root CA **and the DID resolver’s TLS trust store contains that Root CA**, national PKI already participates in `did:web` resolution.

However, that TLS certificate proves control of the HTTPS endpoint used to retrieve `did.json`. It does **not**, by itself, prove that a VC-signing key in the DID document was certified by the national PKI. For that, use the DID Core verification-method mechanism below.

---

## **2\. Put the national-PKI-certified public key in the DID document**

DID Core requires each verification method to contain:

- `id`  
- `type`  
- `controller`  
- verification material appropriate to its `type`

DID Core defines `publicKeyJwk` as one such verification-material property. Its value must be an RFC 7517 JSON Web Key and must not contain private-key material such as `"d"`.

RFC 7517, which DID Core references for JWKs, defines:

- **`x5u`**: an HTTPS URL pointing to an X.509 certificate or certificate chain.  
- **`x5c`**: the X.509 certificate chain embedded directly in the JWK.

In both cases, the first certificate must contain the same public key represented by the other JWK members, such as `n`/`e` for RSA or `x`/`y` for an EC key.

That is the normative bridge between a DID verification method and a national Root CA.

---

## **3\. Example `did:web` issuer document**

Assume:

- Issuer DID: `did:web:issuer.gov.example`  
- Signing key: RSA key from an end-entity certificate  
- Certificate chain: issuer certificate → intermediate CA → national Root CA  
- Signature algorithm: PS256

Publish this as:

```
https://issuer.gov.example/.well-known/did.json
```

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:issuer.gov.example",
  "verificationMethod": [
    {
      "id": "did:web:issuer.gov.example#issuer-signing-key-2026-01",
      "type": "JsonWebKey2020",
      "controller": "did:web:issuer.gov.example",
      "publicKeyJwk": {
        "kty": "RSA",
        "use": "sig",
        "kid": "issuer-signing-key-2026-01",
        "alg": "PS256",
        "n": "base64url-encoded-RSA-modulus-from-the-certificate",
        "e": "AQAB",
        "x5u": "https://issuer.gov.example/.well-known/pki/issuer-chain.pem"
      }
    }
  ],
  "assertionMethod": [
    "did:web:issuer.gov.example#issuer-signing-key-2026-01"
  ]
}
```

The `assertionMethod` entry is essential. DID Core defines it as the verification relationship used when the DID subject expresses claims, including when issuing a Verifiable Credential. A verifier checks that the verification method referenced by the credential proof is associated with `assertionMethod` in the issuer’s DID document.

The `did:web` method also requires DID URLs inside the DID document, including embedded key references, to be absolute, which the example follows.

### Inline-chain alternative

Instead of `x5u`, the certificate chain can be embedded directly:

```json
{
  "id": "did:web:issuer.gov.example#issuer-signing-key-2026-01",
  "type": "JsonWebKey2020",
  "controller": "did:web:issuer.gov.example",
  "publicKeyJwk": {
    "kty": "RSA",
    "use": "sig",
    "kid": "issuer-signing-key-2026-01",
    "alg": "PS256",
    "n": "base64url-encoded-RSA-modulus-from-the-certificate",
    "e": "AQAB",
    "x5c": [
      "base64-DER-issuer-certificate",
      "base64-DER-intermediate-ca-certificate",
      "base64-DER-national-root-ca-certificate"
    ]
  }
}
```

For `x5c`, the first entry must be the issuer/end-entity certificate containing the JWK public key. The root certificate may be omitted when the verifier already has the national Root CA configured as a trust anchor.

Using `x5c` or `x5u` does not introduce a second DID verification-material property: both are members **inside** the single `publicKeyJwk` map.

---

## **4\. Example VC proof**

The issuer signs the VC with the private key corresponding to the certified public key:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "type": ["VerifiableCredential"],
  "issuer": "did:web:issuer.gov.example",
  "issuanceDate": "2026-09-19T10:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "license": "Example Licence"
  },
  "proof": {
    "type": "JsonWebSignature2020",
    "created": "2026-09-19T10:00:00Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:web:issuer.gov.example#issuer-signing-key-2026-01",
    "jws": "eyJhbGciOiJQUzI1NiIs..signature"
  }
}
```

The important linkage is:

```
issuer
  = did:web:issuer.gov.example

proof.verificationMethod
  = did:web:issuer.gov.example#issuer-signing-key-2026-01

DID document assertionMethod
  contains that exact verification method

JWK public key
  = public key in the first X.509 certificate

certificate chain
  → national Root CA
```

---

## **5\. What a verifier must do**

A verifier supporting this model should perform all of these checks:

1. **Resolve the DID**

   - Transform `did:web:issuer.gov.example` into `https://issuer.gov.example/.well-known/did.json`.  
   - Retrieve it over authenticated HTTPS.  
   - Confirm that the document’s top-level `id` equals the DID being resolved.  
2. **Check the VC authorization relationship**

   - Locate `proof.verificationMethod`.  
   - Confirm that the method appears under the issuer DID document’s `assertionMethod`.  
3. **Verify the VC signature**

   - Use the JWK public key and the proof’s algorithm.  
   - Ensure that the algorithm is compatible with the certificate and the VC securing mechanism.  
4. **Validate the national-PKI chain**

   - Retrieve `x5u` or decode `x5c`.  
   - Confirm that the first certificate’s public key exactly equals the JWK public key.  
   - Build a certification path to a configured national Root CA trust anchor.  
   - Check certificate validity periods, key usage, certificate policies, and revocation status through CRL, OCSP, or the applicable national mechanism.  
5. **Apply issuer-authorization policy**

   - Determine whether the certificate subject is actually authorized to issue that credential type.  
   - A valid chain proves who certified the key; it does not automatically prove authorization to issue every kind of VC.

---

## **6\. Important limitations**

- **The Root CA does not sign the VC.** The issuer signs with its own end-entity private key. The Root CA anchors the chain that certifies the issuer’s public key.  
- **Never publish the private key.** The DID document contains only public JWK and certificate material.  
- **TLS key and VC-signing key can be different.** In fact, separating them is generally preferable. Reusing a TLS certificate key for VC signing requires the certificate’s key usage and organizational policy to permit it.  
- **The national Root CA must be configured as a verifier trust anchor.** An ordinary public Web PKI resolver will not automatically trust a national signing-only Root CA.  
- **DID Core/`did:web` do not define the national-PKI policy checks.** Chain construction, revocation, qualified-certificate status, authorized credential types, and similar rules belong to the ecosystem profile.  
- For a stronger binding, the ecosystem can require the certificate’s Subject Alternative Name `uniformResourceIdentifier` to contain the issuer’s DID, such as `did:web:issuer.gov.example`. That is a sensible profile rule, but it is not mandated by `did:web` or DID Core.

This pattern is used in practice: the Gaia-X profile, for example, uses `did:web` with a JWK verification method and requires either RFC 7517 `x5c` or `x5u` so that the issuer’s key can be chained to an approved trust service provider.

So the accurate formulation is:

> `did:web` can publish and resolve an issuer’s national-PKI-certified signing key as a DID verification method. DID Core makes that key usable for VC issuance through `assertionMethod`, while RFC 7517’s `x5c`/`x5u` members carry the X.509 chain. The national Root CA becomes the external trust anchor through verifier policy; `did:web` itself does not replace PKIX path validation.

# **C**

Q. 

Can DID Core implementations such as did:webvh, did:web etc. make use of keys from a national Root CA's PKI for issuers who are signing verifiable credentials?

Ref:

* [https://github.com/w3c-ccg/did-method-web/blob/main/index.html](https://github.com/w3c-ccg/did-method-web/blob/main/index.html)  
* [https://www.w3.org/TR/did/\#ref-for-dfn-verification-method-14](https://github.com/w3c-ccg/did-method-web/blob/main/index.html)

Ans.

In short, Yes.  Nothing in either spec forbids it, and DID Core explicitly anticipates it. But the two specs only give you the *container*; the PKI validation semantics are yours to add. Here's the walk-through.

## **Where the specs permit it**

**did:web says nothing about key provenance.** Read the method spec's Create section: step 3 is just "creating the DID document JSON-LD file including a suitable keypair, e.g. using the Koblitz Curve." The `e.g.` is illustrative, not normative. The only hard constraints the method imposes are on the *identifier* (must match the CN in the TLS cert, no IP addresses) and on *transport* (NIST SP 800-52 Rev. 2, TLS 1.2+). Key origin is unconstrained — an HSM-held key certified under a national root CA is as valid as a freshly generated Ed25519 key.

**DID Core's Introduction endorses the bridge directly.** Section 1 states that implementers can create DIDs based on identifiers registered in federated or centralized identity management systems, and calls this an interoperability bridge between centralized, federated and decentralized identifiers. Note the tension though: the Abstract says DIDs are designed to be decoupled from centralized registries, identity providers *and certificate authorities*. You're deliberately re-coupling. That's allowed, it just means the decentralization design goal isn't what you're buying.

## **The mechanism: `x5c` inside `publicKeyJwk`**

This is the part people miss. DID Core §5.2.1 deliberately limits verification material to two properties — `publicKeyJwk` and `publicKeyMultibase`. There's no `publicKeyPem` or X.509 property in core. So how do you carry a chain?

`publicKeyJwk` must be a map that conforms to RFC 7517\. RFC 7517 §4.6–4.9 defines `x5c`, `x5u`, `x5t` and `x5t#S256` as JWK members. So the certificate chain rides *inside* the JWK, and stays spec-conformant. The only exclusion DID Core states is `d` and other private-class members.

A verification method for an issuer would look like this:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:health.gov.example",
  "verificationMethod": [{
    "id": "did:web:health.gov.example#nrca-sig-2026",
    "type": "JsonWebKey2020",
    "controller": "did:web:health.gov.example",
    "publicKeyJwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
      "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
      "alg": "ES256",
      "kid": "nrca-sig-2026",
      "x5c": [
        "MIIDxTCCAq2gAwIBAgIQ...",   // leaf: CN=Ministry of Health VC Issuer
        "MIIEFzCCAv+gAwIBAgIQ...",   // National Intermediate CA
        "MIIDdTCCAl2gAwIBAgIL..."    // National Root CA
      ],
      "x5t#S256": "n4BQvP0kCk5NkGXn8sO5Yc2zVv9wFq0fW0lM7bH9r2Q"
    }
  }],
  "assertionMethod": [
    "did:web:health.gov.example#nrca-sig-2026"
  ]
}
```

Three spec details doing work here:

* **`assertionMethod`, not `authentication`.** DID Core §5.3.2 is explicit that `assertionMethod` is the relationship for expressing claims "such as for the purposes of issuing a Verifiable Credential," and that the verifier checks the VM used to assert the proof is associated with `assertionMethod`. A key listed only under `authentication` is not valid for signing a VC.  
* **Absolute DID URLs.** did:web's Key Material section requires every DID URL inside the document to be absolute — the spec notes this includes URLs inside embedded key material, and that it prevents key confusion attacks. So `#nrca-sig-2026` as a relative reference is legal in DID Core §3.2.2 but *not* in did:web.  
* **`kid`.** DID Core recommends the fragment equal the JWK `kid`, and that `kid` be the RFC 7638 thumbprint. With an X.509-anchored key you'll often want a human-meaningful `kid` tied to the cert serial instead. Both are RECOMMENDED, not MUST.

The credential proof then points at the fragment:

```json
"proof": {
  "type": "JsonWebSignature2020",
  "proofPurpose": "assertionMethod",
  "verificationMethod": "did:web:health.gov.example#nrca-sig-2026",
  "created": "2026-09-14T09:12:00Z",
  "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.."
}
```

For VC-JOSE-COSE / SD-JWT VC, the same absolute DID URL goes in the JOSE `kid` header instead.

## **What the specs do *not* give you**

This is the gap that matters for a national ID deployment. Following DID Core §7.1 and did:web's Read algorithm, a verifier does:

1. Replace `:` with `/`, prepend `https://`, append `/.well-known/did.json`, GET over TLS.  
2. Verify the resolved document's `id` matches the DID being resolved.  
3. Dereference the fragment, confirm it appears in `assertionMethod`.  
4. Verify the signature against `x` and `y`.

**Step 4 never touches `x5c`.** A conformant DID resolver treats the chain as opaque metadata. Which means: as written, that DID document proves only that whoever controls `health.gov.example`'s web root asserted this key. Anyone can paste a national CA chain into their own `did.json`. You must add, as policy outside both specs:

* Build and validate the `x5c` chain to your national root trust anchor (RFC 5280 path validation).  
* **Confirm the leaf certificate's SubjectPublicKeyInfo matches the `x`/`y` in the JWK.** Without this binding check the chain is decorative.  
* Check `keyUsage` (digitalSignature) / `extendedKeyUsage`, validity window, and name constraints.  
* Check CRL or OCSP.

## **Two revocation systems that can disagree**

DID Core §5.3 states that a DID document does not express revoked keys via verification relationships — if a referenced VM is absent from the latest DID document, it's considered invalid or revoked. So at the DID layer, revocation means deleting the entry from `did.json`. At the PKI layer, revocation means an OCSP response. These are independent and will drift. You need a policy rule: does a valid-in-`did.json` but OCSP-revoked key verify? (It should not.) Pin that rule in your issuer trust framework, because neither spec resolves it.

## **Two deployment traps specific to national PKI**

**The TLS cert and the signing cert are different problems.** did:web's Read step requires an agent that can successfully negotiate a secure HTTPS connection. If your national root isn't in the resolver's trust store, resolution fails before anyone sees the DID document. So in practice you need a publicly-trusted commercial/ACME cert for the domain's TLS, and the national-CA cert for the issuing key inside the document. Don't assume one cert does both.

**Path-based DIDs weaken the binding.** did:web's Optional Path Considerations section is blunt: with `did:web:example.gov:agency:health`, proofs demonstrate control of the file at that path, not control of the domain. For a national issuer registry where sub-agencies get paths, that's a meaningful downgrade — combine it with per-agency certs and treat the path segment as untrusted.

## **Whether you should**

Honest framing: if all the trust flows from the national root CA, the DID layer is adding a DNS \+ TLS \+ web-server-integrity dependency (the method spec's own security section flags DNS spoofing and MITM, and recommends DNSSEC and DNS-over-HTTPS) without adding trust. Two alternatives worth weighing:

* **Skip the DID.** Put `x5c` directly in the JOSE header per VC-JOSE-COSE. Same trust, fewer moving parts. This is broadly what the EUDI wallet ecosystem does.  
* **Split the roles.** Use `did:web` purely as a stable, rotatable key-discovery endpoint with plain JWKs, and put accreditation in a separate CA-anchored trusted issuer registry (eIDAS trusted lists, EBSI TIR). The verifier then asks two questions independently: "is this signature valid for this DID?" and "is this DID an accredited issuer?" Cleaner separation, and key rotation stops requiring re-issuance of certificates.

The `x5c`\-in-`did.json` approach is best when you specifically need one artifact to carry both discovery and accreditation — for example where relying parties are offline-capable and can't reach a trust list.

