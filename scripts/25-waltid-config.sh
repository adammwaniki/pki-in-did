#!/usr/bin/env bash
# Render walt.id issuer-api2 configuration for both credential issuers.
#
# The private JWK handed to issuer-api2 is the very key the Issuing CA certified, and the
# x5Chain is that certificate plus the Issuing CA. The root is not included: it is the
# verifier's trust anchor. walt.id's own shipped config says the same.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

step "walt.id issuer-api2 configuration"

render_one() {
  local which="$1" did="$2"
  mkdir -p "$STATE/waltid/issuer-$which"
  run docker run --rm --network none -u "$(id -u):$(id -g)" \
    -v "$REPO:/app" -w /app \
    -e PYTHONPATH=/app/src/issuer \
    --entrypoint python "$VERIFIER_IMAGE" \
    src/issuer/render_profile.py \
      --did "$did" \
      --key "state/issuers/issuer-$which/private/issuer-$which.key" \
      --leaf "state/ca/certs/issuer-$which.pem" \
      --issuing-ca "state/ca/issuing-ca.pem" \
      --out "state/waltid/issuer-$which" \
      --base-url "http://issuer-$which-api:7005" \
      --credential-type "$ACCREDITED_CREDENTIAL_TYPE"
}

render_one a "$ISSUER_A_DID"
render_one b "$ISSUER_B_DID"

step "What the profile tells the issuer"
grep -E '^(issuerDid|  *name|  *credentialConfigurationId) ' "$STATE/waltid/issuer-a/issuer2-profiles.conf" \
  | sed 's/^/      /'
note "x5Chain carries $(grep -c 'BEGIN CERTIFICATE' "$STATE/waltid/issuer-a/issuer2-profiles.conf") certificates (leaf + Issuing CA; the root is a trust anchor, not a chain link)"

# The profile contains the issuer's private key, so it must not be world-readable and must
# never be served by a web server.
chmod -R go-rwx "$STATE/waltid"
ok "configuration written to state/waltid; it holds private keys and is never published"
