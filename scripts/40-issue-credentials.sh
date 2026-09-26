#!/usr/bin/env bash
# Issue one credential from each issuer, through walt.id issuer-api2 over OpenID4VCI 1.0,
# into walt.id wallet-api2.
#
# Three real services and none of our own protocol code: the issuer signs with its nationally
# certified key, the wallet generates the holder key, creates the DID, proves possession and
# stores the result. src/holder/wallet.py only drives them over HTTP.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

mkdir -p "$STATE/credentials"

issue_one() {
  local which="$1" name="$2" licence="$3"
  step "Credential issuer ${which^^} issues over OpenID4VCI"

  wait_for_port "issuer-$which-api" 7005 120 \
    || die "issuer-$which-api did not come up; try: docker compose logs issuer-$which-api"
  wait_for_port "wallet-api" 7006 120 \
    || die "wallet-api did not come up; try: docker compose logs wallet-api"

  run docker run --rm --network "$DEMO_NETWORK" -u "$(id -u):$(id -g)" \
    -v "$REPO:/app" -w /app --entrypoint python "$VERIFIER_IMAGE" \
    src/holder/wallet.py \
      --wallet http://wallet-api:7006 \
      collect \
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
    --entrypoint python "$VERIFIER_IMAGE" -m did_x509_policy.cli inspect \
      --credential "state/credentials/issuer-$which-vc-jose.jwt" \
    | jq -r '"      issuer  \(.issuer)\n      kid     \(.header.kid)\n      typ     \(.header.typ)   alg \(.header.alg)   x5c \(.header.x5c | length) cert(s)\n      type    \(.types | join(", "))"'
done

ok "both credentials issued by a real OpenID4VCI issuer"
