#!/usr/bin/env bash
# Build the impostor: a DID document that pastes a real national certificate chain beside a
# key that chain does not certify, and a credential signed with that key.
#
# This exists to show what a conformant verifier does not check. walt.id verifier-api2 accepts
# the result, correctly, because validating x5c is not part of did:web or DID Core. Only the
# PKI policy layer rejects it, on the SPKI-to-JWK binding.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[[ -f "$STATE/ca/certs/issuer-a.pem" ]] || die "issue the real certificates first (make setup)"

step "Build an impostor at $IMPOSTOR_DID"
mkdir -p "$STATE/web/impostor/.well-known" "$STATE/credentials"

run docker run --rm --network none -u "$(id -u):$(id -g)" \
  -v "$REPO:/app" -w /app -e PYTHONPATH=/app/src/issuer \
  --entrypoint python "$VERIFIER_IMAGE" \
  src/issuer/make_impostor.py \
    --did "$IMPOSTOR_DID" \
    --borrowed-leaf state/ca/certs/issuer-a.pem \
    --borrowed-issuing-ca state/ca/issuing-ca.pem \
    --did-out "state/web/impostor/.well-known/did.json" \
    --credential-out "state/credentials/impostor-vc-jose.jwt" \
    --credential-type "$ACCREDITED_CREDENTIAL_TYPE"

step "Put it in a wallet, so it can be presented like any other credential"
wait_for_port "wallet-api" 7006 120 || die "wallet-api did not come up"
run docker run --rm --network "$DEMO_NETWORK" -u "$(id -u):$(id -g)" \
  -v "$REPO:/app" -w /app --entrypoint python "$VERIFIER_IMAGE" \
  src/holder/wallet.py --wallet http://wallet-api:7006 import \
    --credential state/credentials/impostor-vc-jose.jwt

step "What the impostor published"
jq '{id, assertionMethod,
     verificationMethod: [.verificationMethod[] | {id, controller,
       publicKeyJwk: (.publicKeyJwk | {kty, crv, x, kid,
         x5c: ["\(.x5c | length) certificate(s), borrowed and genuine"]})}]}' \
  "$STATE/web/impostor/.well-known/did.json" | sed 's/^/      /'

ok "state/credentials/impostor-vc-jose.jwt is signed by a key nobody certified"
