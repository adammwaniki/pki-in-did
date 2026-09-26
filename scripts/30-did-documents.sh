#!/usr/bin/env bash
# Publish a did.json for each credential issuer.
#
# The verification method fragment is the RFC 7638 thumbprint of the public JWK, which is
# exactly what walt.id issuer-api2 puts after the '#' in the credential's kid. Both are
# computed the same way from the same key, so they agree by construction.
#
# Usage:
#   30-did-documents.sh              build and publish both documents
#   30-did-documents.sh --print a    print issuer A's published document (used by tests)
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

if [[ "${1:-}" == "--print" ]]; then
  cat "$STATE/web/issuer-${2:-a}/.well-known/did.json"
  exit 0
fi

build_one() {
  local which="$1" did="$2" domain="$3"
  step "DID document for $did"
  mkdir -p "$STATE/web/issuer-$which/.well-known/pki"

  local fragment
  fragment=$(docker run --rm --network none -u "$(id -u):$(id -g)" \
    -v "$REPO:/app" -w /app -e PYTHONPATH=/app/src/issuer \
    --entrypoint python "$VERIFIER_IMAGE" \
    src/issuer/build_did_document.py \
      --did "$did" \
      --key "state/issuers/issuer-$which/private/issuer-$which.key" \
      --leaf "state/ca/certs/issuer-$which.pem" \
      --issuing-ca "state/ca/issuing-ca.pem" \
      --out "state/web/issuer-$which/.well-known/did.json" \
      --x5u "state/web/issuer-$which/.well-known/did.x5u.json" \
      --x5u-url "https://$domain/.well-known/pki/issuer-chain.pem")

  note "verification method: $did#$fragment"
  note "resolves from:       https://$domain/.well-known/did.json"
  jq '{id, assertionMethod,
       verificationMethod: [.verificationMethod[] | {id, type, controller,
         publicKeyJwk: (.publicKeyJwk | {kty, crv, alg, kid,
           x5c: ["\(.x5c | length) certificate(s)"], "x5t#S256"})}]}' \
    "$STATE/web/issuer-$which/.well-known/did.json" 2>/dev/null \
    | sed 's/^/      /' || cat "$STATE/web/issuer-$which/.well-known/did.json"
  ok "issuer $which"
}

build_one a "$ISSUER_A_DID" "$ISSUER_A_DOMAIN"
build_one b "$ISSUER_B_DID" "$ISSUER_B_DOMAIN"

if grep -rqI 'PRIVATE KEY\|"d"' "$STATE/web"/*/.well-known/did*.json 2>/dev/null; then
  die "a DID document contains private key material -- refusing to publish"
fi
ok "neither document contains private key material"
