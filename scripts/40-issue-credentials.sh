#!/usr/bin/env bash
# Issue one credential from each issuer, through walt.id issuer-api2 over OpenID4VCI 1.0.
#
# The holder client performs the whole pre-authorized-code flow: offer, token, nonce, proof,
# credential. Nothing here signs anything; the issuer does, with its nationally certified key.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

mkdir -p "$STATE/credentials"

issue_one() {
  local which="$1" name="$2" licence="$3"
  step "Credential issuer ${which^^} issues over OpenID4VCI"

  wait_for_port "issuer-$which-api" 7005 90 \
    || die "issuer-$which-api did not come up; try: docker compose logs issuer-$which-api"

  run docker run --rm --network "$DEMO_NETWORK" -u "$(id -u):$(id -g)" \
    -v "$REPO:/app" -w /app --entrypoint python "$VERIFIER_IMAGE" \
    src/holder/wallet.py \
      --issuer "http://issuer-$which-api:7005" \
      --profile accreditedOperatorCredential \
      --operator-name "$name" \
      --licence "$licence" \
      --out "state/credentials/issuer-$which-vc-jose.jwt"
  ok "state/credentials/issuer-$which-vc-jose.jwt"
}

issue_one a "Jacaranda Field Operator" "OP-2026-0001"
issue_one b "Lawnbull Field Operator" "OP-2026-0002"

step "The key identifier and issuer inside each credential"
for which in a b; do
  docker run --rm --network none -u "$(id -u):$(id -g)" \
    -v "$REPO:/app" -w /app -e PYTHONPATH=/app/src \
    --entrypoint python "$VERIFIER_IMAGE" -m verifier.cli inspect \
      --credential "state/credentials/issuer-$which-vc-jose.jwt" \
    | jq -r '"      issuer  \(.issuer)\n      kid     \(.header.kid)\n      typ     \(.header.typ)   alg \(.header.alg)   x5c \(.header.x5c | length) cert(s)\n      type    \(.types | join(", "))"'
done

ok "both credentials issued by a real OpenID4VCI issuer"
