#!/usr/bin/env bash
# On the offline machine: sign the Issuing CA certificate, then send it back.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[[ -f "$STATE/transfer/issuing-ca.csr" ]] || die "no CSR in state/transfer; run 11-issuing-ca-csr.sh first"

step "The National Root CA signs the Issuing CA certificate"
note "still no network in this container; the CSR arrived as a file"

run offline openssl ca -config /config/openssl/nrca.cnf -batch \
      -extensions v3_issuing_ca -days 3650 -notext -md sha384 \
      -in /transfer/issuing-ca.csr -out /transfer/issuing-ca.pem

step "What the root certified"
offline openssl x509 -in /transfer/issuing-ca.pem -noout -subject -issuer -serial -dates
echo
offline openssl x509 -in /transfer/issuing-ca.pem -noout -text \
  | sed -n '/X509v3 extensions/,/Signature Algorithm/p' | head -16

step "Install the Issuing CA certificate on the server"
run cp "$STATE/transfer/issuing-ca.pem" "$STATE/ca/issuing-ca.pem"

# The root certificate also crosses on the sneakernet: it is public, unlike the key.
run cp "$STATE/offline/nrca/nrca.pem" "$STATE/transfer/nrca.pem"
run ca openssl verify -CAfile /transfer/nrca.pem /ca/issuing-ca.pem

ok "the Issuing CA is certified by the National Root CA"
