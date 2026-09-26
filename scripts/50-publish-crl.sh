#!/usr/bin/env bash
# Generate a CRL from the Issuing CA's database and publish it on domain2.
#
# `openssl ca -gencrl`, as brief step 18 intends. This is a deliberate, separate act: the brief
# is explicit that a new CRL must NOT appear automatically after a revocation, because the gap
# between revoking and publishing is the revocation window that part 3 demonstrates.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

HOURS="${CRL_NEXTUPDATE_HOURS:-1}"
step "Publish a CRL valid for ${HOURS}h"

mkdir -p "$STATE/ca/crl" "$STATE/web/issuing-ca"

run ca openssl ca -config /config/openssl/issuing-ca.cnf -gencrl \
      -crlhours "$HOURS" -crlexts crl_ext -out /ca/crl/issuing-ca.crl.pem
run ca openssl crl -in /ca/crl/issuing-ca.crl.pem -outform DER -out /ca/crl/issuing-ca.crl
run cp "$STATE/ca/crl/issuing-ca.crl" "$STATE/web/issuing-ca/issuing-ca.crl"
cp "$STATE/ca/issuing-ca.pem" "$STATE/web/issuing-ca/issuing-ca.pem"

step "What the published CRL says"
ca openssl crl -in /ca/crl/issuing-ca.crl -inform DER -noout -text \
  | sed -n '1,/Signature Value/p' | grep -v 'Signature Value' | sed 's/^/      /'

ok "http://$ISSUING_CA_DOMAIN/issuing-ca.crl updated"
