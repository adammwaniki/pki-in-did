#!/usr/bin/env bash
# The Issuing CA certifies the two credential issuers and its own OCSP responder.
#
# Issuer A gets an AIA OCSP URI. Issuer B gets a CRL distribution point. That difference is
# the controlled variable of the whole demonstration; everything else about them matches.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[[ -f "$STATE/ca/issuing-ca.pem" ]] || die "the Issuing CA is not certified yet; run 12-offline-sign-ca.sh"

issue_leaf() {
  local which="$1" domain="$2" cn="$3" did="$4" template="$5"
  step "Credential issuer ${which^^}: $cn"

  mkdir -p "$STATE/issuers/issuer-$which/private"
  rm -f "$STATE/issuers/issuer-$which/private/issuer-$which.key"
  run ca openssl ecparam -name prime256v1 -genkey -noout \
        -out "/issuers/issuer-$which/private/issuer-$which.key"
  run ca chmod 400 "/issuers/issuer-$which/private/issuer-$which.key"
  run ca openssl req -new -sha256 \
        -key "/issuers/issuer-$which/private/issuer-$which.key" \
        -subj "/C=$DN_C/O=$DN_O/CN=$cn" \
        -out "/ca/issuer-$which.csr"

  render_ext "$CONFIG/openssl/ext/$template" "$STATE/ca/issuer-$which.ext" \
    DID "$did" POLICY_OID "$ACCREDITATION_POLICY_OID" \
    OCSP_URL "$OCSP_URL" CRL_URL "$CRL_URL"

  run ca openssl ca -config /config/openssl/issuing-ca.cnf -batch -notext -md sha384 \
        -days 730 -extfile "/ca/issuer-$which.ext" \
        -in "/ca/issuer-$which.csr" -out "/ca/certs/issuer-$which.pem"
  rm -f "$STATE/ca/issuer-$which.csr" "$STATE/ca/issuer-$which.ext"

  note "what the Issuing CA certified:"
  ca openssl x509 -in "/ca/certs/issuer-$which.pem" -noout -subject -serial
  ca openssl x509 -in "/ca/certs/issuer-$which.pem" -noout -ext \
      subjectAltName,keyUsage,certificatePolicies,authorityInfoAccess,crlDistributionPoints \
      2>/dev/null | sed 's/^/      /'
  ok "issuer $which"
}

issue_leaf a "$ISSUER_A_DOMAIN" "$ISSUER_A_DN_CN" "$ISSUER_A_DID" issuer-a.ext
issue_leaf b "$ISSUER_B_DOMAIN" "$ISSUER_B_DN_CN" "$ISSUER_B_DID" issuer-b.ext

step "OCSP responder signing certificate"
rm -f "$STATE/ca/private/ocsp-signer.key"
run ca openssl genrsa -out /ca/private/ocsp-signer.key 2048
run ca chmod 400 /ca/private/ocsp-signer.key
run ca openssl req -new -sha256 -key /ca/private/ocsp-signer.key \
      -subj "/C=$DN_C/O=$DN_O/CN=$OCSP_SIGNER_DN_CN" -out /ca/ocsp-signer.csr
run ca openssl ca -config /config/openssl/issuing-ca.cnf -batch -notext -md sha384 \
      -days 365 -extfile /config/openssl/ext/ocsp-signer.ext \
      -in /ca/ocsp-signer.csr -out /ca/certs/ocsp-signer.pem
rm -f "$STATE/ca/ocsp-signer.csr"
ca openssl x509 -in /ca/certs/ocsp-signer.pem -noout -ext extendedKeyUsage | sed 's/^/      /'

step "Publish the chain for the x5u variant"
mkdir -p "$STATE/web/issuer-a/.well-known/pki"
cat "$STATE/ca/certs/issuer-a.pem" "$STATE/ca/issuing-ca.pem" \
  > "$STATE/web/issuer-a/.well-known/pki/issuer-chain.pem"

step "The Issuing CA's database"
cat "$STATE/ca/index.txt" | sed 's/^/      /'
ok "three certificates issued; V means valid, R would mean revoked"
