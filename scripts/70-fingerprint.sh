#!/usr/bin/env bash
# Provision the laptop's trust store, and compare fingerprints as a person would.
#
# Brief steps 24-26: fetch the root certificate over HTTPS, compare its fingerprint with the
# one held on the offline machine, and configure it as the only credential trust anchor.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

TRUST="$STATE/laptop/trust"
mkdir -p "$TRUST" "$STATE/laptop/cache"/{did,ocsp,crl}

step "The transport trust store comes first, and is a separate store"
run cp "$STATE/tls/root/webtls-root.pem" "$TRUST/webtls-root.pem"
note "this root is for TLS only; it is never a credential trust anchor"

step "Fetch the root certificate from https://$NRCA_DOMAIN/nrca.pem"
wait_for_url "https://$NRCA_DOMAIN/nrca.pem" || die "domain1 is not serving the root certificate"

run docker run --rm --network "$DEMO_NETWORK" -u "$(id -u):$(id -g)" \
  -v "$TRUST:/trust" "$CA_TOOLS_IMAGE" \
  curl -sS --fail --cacert /trust/webtls-root.pem \
    "https://$NRCA_DOMAIN/nrca.pem" -o /trust/fetched.pem

if grep -q 'PRIVATE KEY' "$TRUST/fetched.pem"; then
  die "domain1 served private key material"
fi
note "$(wc -l < "$TRUST/fetched.pem") lines, no private key"

step "Compare the fingerprint with the one on the offline machine"
served=$(docker run --rm --network none -v "$TRUST:/trust:ro" "$CA_TOOLS_IMAGE" \
           openssl x509 -in /trust/fetched.pem -noout -fingerprint -sha256 | cut -d= -f2)
held=$(offline openssl x509 -in /offline/nrca/nrca.pem -noout -fingerprint -sha256 | cut -d= -f2)

printf '      fetched over the network : %s\n' "$served"
printf '      held on the offline box  : %s\n' "$held"

[[ "$served" == "$held" ]] || die "the fingerprints differ -- do not trust this certificate"
ok "the fingerprints match"

step "Install it as the only credential trust anchor"
run mv "$TRUST/fetched.pem" "$TRUST/nrca.pem"
run cp "$CONFIG/verifier-policy.json" "$STATE/laptop/policy.json"
# A second policy with no clock-skew tolerance, for the scenes about freshness.
run cp "$CONFIG/verifier-policy-strict.json" "$STATE/laptop/policy-strict.json"

note "the laptop's trust stores:"
ls -1 "$TRUST" | sed 's/^/      /'
note "credential trust anchor:"
laptop fingerprint | sed 's/^/      /'
ok "one credential trust anchor, and a separate TLS store"
