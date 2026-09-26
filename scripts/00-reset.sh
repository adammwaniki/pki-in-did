#!/usr/bin/env bash
# Reissue every certificate, DID document and credential, and republish a clean CRL.
#
# Brief, tests and alternative procedure step 1. The National Root CA is NOT re-keyed: a
# national root is not regenerated on a whim, and keeping it means the fingerprint a person
# wrote down stays correct across resets.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

step "Reset the demonstration"

[[ -f "$STATE/offline/nrca/nrca.pem" ]] || die "no root yet; run 'make setup' rather than a reset"

step "Stop the services that read the state about to be replaced"
# The OCSP responder loads its certificates at startup, and walt.id loads its profile at
# startup. Emptying their directories underneath them leaves both crash-looping until they
# are recreated, which is noise at best and a confusing failure at worst.
run compose stop ocsp-responder issuer-a-api issuer-b-api issuing-ca

step "Clear the Issuing CA, the issuers and the laptop (the root stays)"

# Empty these directories rather than removing them. Several are bind-mounted into
# running containers, and deleting the host directory leaves those containers holding a
# mount of a deleted inode -- which shows up much later as an OCSP responder that cannot
# find any certificate it issued.
clear_contents() {
  local dir="$1"
  mkdir -p "$dir"
  find "$dir" -mindepth 1 -delete
}

for dir in "$STATE/ca" "$STATE/issuers" "$STATE/waltid" "$STATE/credentials" \
           "$STATE/web/issuer-a" "$STATE/web/issuer-b" "$STATE/web/issuing-ca" \
           "$STATE/laptop/cache"; do
  run clear_contents "$dir"
done
run rm -f "$STATE/transfer/issuing-ca.csr" "$STATE/transfer/issuing-ca.pem"

# Scratch left by an integration test and by part 2's x5u scene. Both are harmless, but
# tests/integration walks the whole of state/ looking for stray key material, so nothing
# should be allowed to accumulate there unnoticed.
run rm -rf "$STATE/tmp" "$STATE/laptop-x5u"

"$REPO/scripts/11-issuing-ca-csr.sh"
"$REPO/scripts/12-offline-sign-ca.sh"
"$REPO/scripts/05-publish-root.sh"
"$REPO/scripts/15-web-tls.sh"
"$REPO/scripts/20-issuer-certs.sh"
"$REPO/scripts/25-waltid-config.sh"
"$REPO/scripts/30-did-documents.sh"
"$REPO/scripts/50-publish-crl.sh"

step "Restart the services so they pick up the new material"
run compose up -d --force-recreate ocsp-responder issuing-ca \
      issuer-a-api issuer-b-api nrca-web issuer-a-web issuer-b-web
wait_for_port "$ISSUING_CA_DOMAIN" 80 60 || die "the Issuing CA did not come up"

"$REPO/scripts/40-issue-credentials.sh"
"$REPO/scripts/70-fingerprint.sh"
"$REPO/scripts/80-seed-offline-cache.sh"

ok "reset complete; every certificate and credential is new"
