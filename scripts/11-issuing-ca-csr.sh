#!/usr/bin/env bash
# On the server: create the Issuing CA private key and a certificate signing request.
#
# The key never leaves the server; only the CSR travels to the offline machine.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

step "Issuing CA key and CSR, on the server"

mkdir -p "$STATE/ca"/{private,certs,newcerts,crl} "$STATE/transfer" \
         "$STATE/issuers/issuer-a/private" "$STATE/issuers/issuer-b/private"
chmod 700 "$STATE/ca/private"
[[ -f "$STATE/ca/index.txt" ]] || : > "$STATE/ca/index.txt"
[[ -f "$STATE/ca/serial" ]] || echo 2000 > "$STATE/ca/serial"
[[ -f "$STATE/ca/crlnumber" ]] || echo 1000 > "$STATE/ca/crlnumber"

rm -f "$STATE/ca/private/issuing-ca.key"
run ca openssl genrsa -out /ca/private/issuing-ca.key 4096
run ca chmod 400 /ca/private/issuing-ca.key
run ca openssl req -config /config/openssl/issuing-ca.cnf \
      -key /ca/private/issuing-ca.key -new -sha384 \
      -subj "/C=$DN_C/O=$DN_O/CN=$ISSUING_CA_DN_CN" \
      -out /transfer/issuing-ca.csr

step "The request that will cross to the offline machine"
ca openssl req -in /transfer/issuing-ca.csr -noout -subject -verify 2>&1 | head -3
ok "state/transfer/issuing-ca.csr is ready; carry it to the offline machine"
