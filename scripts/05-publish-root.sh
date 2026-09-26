#!/usr/bin/env bash
# Publish the root CERTIFICATE (never the key) at https://domain1/nrca.pem.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

step "Publish the root certificate on $NRCA_DOMAIN"
mkdir -p "$STATE/web/nrca"
run cp "$STATE/offline/nrca/nrca.pem" "$STATE/web/nrca/nrca.pem"

# A web root that contains a private key is a private key on the internet.
if grep -rqI 'PRIVATE KEY' "$STATE/web" 2>/dev/null; then
  die "private key material found under state/web -- refusing to publish"
fi
ok "state/web/nrca/nrca.pem contains only the certificate"
