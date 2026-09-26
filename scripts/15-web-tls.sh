#!/usr/bin/env bash
# The OTHER PKI layer: a Web-TLS CA so that did:web resolution can negotiate HTTPS.
#
# This hierarchy is entirely separate from the National Root CA. It is in the laptop's TLS
# trust store and never in its credential trust anchor store. The source document is blunt
# about why both are needed: "Don't assume one cert does both."
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

step "Web-TLS CA (the transport layer, not the credential layer)"

mkdir -p "$STATE/tls"/{root,private,certs}
chmod 700 "$STATE/tls/private"

if [[ -f "$STATE/tls/root/webtls-root.pem" ]]; then
  note "the Web-TLS root already exists"
else
  rm -f "$STATE/tls/private/webtls-root.key"
  run ca openssl req -x509 -newkey rsa:4096 -noenc -sha384 -days 3650 \
        -subj "/C=$DN_C/O=Demo Web TLS/CN=DemoWebTLS Root" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -keyout /tls/private/webtls-root.key -out /tls/root/webtls-root.pem
  run ca chmod 400 /tls/private/webtls-root.key
fi

for domain in "$NRCA_DOMAIN" "$ISSUER_A_DOMAIN" "$ISSUER_B_DOMAIN" "$IMPOSTOR_DOMAIN"; do
  if [[ -f "$STATE/tls/certs/$domain.pem" ]]; then
    note "$domain already has a TLS certificate"
    continue
  fi
  step "TLS certificate for $domain"
  render_ext "$CONFIG/openssl/ext/webtls-server.ext" "$STATE/tls/$domain.ext" DOMAIN "$domain"
  rm -f "$STATE/tls/private/$domain.key"
  run ca openssl req -newkey rsa:2048 -noenc -sha256 \
        -subj "/C=$DN_C/O=Demo Web TLS/CN=$domain" \
        -keyout "/tls/private/$domain.key" -out "/tls/$domain.csr"
  run ca openssl x509 -req -in "/tls/$domain.csr" \
        -CA /tls/root/webtls-root.pem -CAkey /tls/private/webtls-root.key \
        -CAcreateserial -days 825 -sha256 \
        -extfile "/tls/$domain.ext" -out "/tls/certs/$domain.pem"
  rm -f "$STATE/tls/$domain.csr" "$STATE/tls/$domain.ext"
  ok "$domain"
done

ok "the Web-TLS root is a different key from the National Root CA, on purpose"
