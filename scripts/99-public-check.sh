#!/usr/bin/env bash
# Check the public deployment the way a stranger would: over the internet, with no special
# trust configured for transport, and then with no network at all.
#
# Run after Caddy has the four hostnames (deploy/README.md step 2).
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[[ "$DEMO_PROFILE" == "public" ]] || die "run with DOMAINS_FILE=config/domains.public.env"

failures=0
check() {
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  %sok%s   %s\n' "$C_GREEN" "$C_OFF" "$what"
  else
    printf '  %sFAIL%s %s\n' "$C_RED" "$C_OFF" "$what"
    failures=$((failures + 1))
  fi
}

# A container with only the public CA bundle: no demo trust material of any kind.
stranger() { docker run --rm --network bridge "$CA_TOOLS_IMAGE" "$@"; }

step "Public TLS, using only the public Web PKI"
for host in "$NRCA_DOMAIN" "$ISSUER_A_DOMAIN" "$ISSUER_B_DOMAIN"; do
  check "https://$host presents a publicly trusted certificate" \
    stranger curl -sSf --max-time 15 -o /dev/null "https://$host/healthz"
done

step "What each domain serves"
check "https://$NRCA_DOMAIN/nrca.pem is the root certificate" \
  sh -c "stranger curl -sSf --max-time 15 'https://$NRCA_DOMAIN/nrca.pem' | grep -q 'BEGIN CERTIFICATE'"
check "https://$NRCA_DOMAIN/nrca.pem carries no private key" \
  sh -c "! stranger curl -sSf --max-time 15 'https://$NRCA_DOMAIN/nrca.pem' | grep -q 'PRIVATE KEY'"

for entry in "$ISSUER_A_DOMAIN:$ISSUER_A_DID" "$ISSUER_B_DOMAIN:$ISSUER_B_DID"; do
  host="${entry%%:did:*}"; did="${entry#*:}"
  check "did:web resolution at $host returns a document whose id is $did" \
    sh -c "stranger curl -sSf --max-time 15 'https://$host/.well-known/did.json' | grep -q '\"$did\"'"
done

check "http://$ISSUING_CA_DOMAIN/issuing-ca.crl is served over plain HTTP" \
  stranger curl -sSf --max-time 15 -o /dev/null "http://$ISSUING_CA_DOMAIN/issuing-ca.crl"
check "the management API is not reachable on any public hostname" \
  sh -c "! stranger curl -sSf --max-time 10 -o /dev/null 'https://$ISSUER_A_DOMAIN/issuer2/profiles'"

step "The root certificate matches the offline machine"
served=$(stranger curl -sSf --max-time 15 "https://$NRCA_DOMAIN/nrca.pem" 2>/dev/null \
         | docker run --rm -i --network none --entrypoint openssl "$CA_TOOLS_IMAGE" \
             x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
held=$(offline openssl x509 -in /offline/nrca/nrca.pem -noout -fingerprint -sha256 | cut -d= -f2)
printf '      fetched over the internet : %s\n' "${served:-<none>}"
printf '      held on the offline box   : %s\n' "$held"
if [[ -n "$served" && "$served" == "$held" ]]; then
  printf '  %sok%s   the fingerprints match\n' "$C_GREEN" "$C_OFF"
else
  printf '  %sFAIL%s the fingerprints differ\n' "$C_RED" "$C_OFF"; failures=$((failures + 1))
fi

step "Verify both credentials over the internet"
for which in a b; do
  # The laptop joins the default bridge, not the demo network: resolution is real DNS.
  verdict=$(docker run --rm --network bridge -u "$(id -u):$(id -g)" \
    -v "$STATE/laptop:/laptop" -v "$STATE/credentials:/credentials:ro" \
    "$VERIFIER_IMAGE" verify --json \
    --credential "/credentials/issuer-$which-vc-jose.jwt" 2>/dev/null \
    | jq -r '"\(if .accepted then "ACCEPTED" else "REJECTED " + .reason end)  \(.revocation.method // "-") \(.revocation.status // "-")"' || echo "REJECTED no-report")
  printf '      issuer %s  %s\n' "$which" "$verdict"
  [[ "$verdict" == ACCEPTED* ]] || failures=$((failures + 1))
done

step "And with no network at all"
for which in a b; do
  verdict=$(laptop_offline verify --offline --json \
    --credential "/credentials/issuer-$which-vc-jose.jwt" 2>/dev/null \
    | jq -r '"\(if .accepted then "ACCEPTED" else "REJECTED " + .reason end)  from \(.revocation.source // "-")"' || echo "REJECTED no-report")
  printf '      issuer %s  %s\n' "$which" "$verdict"
  [[ "$verdict" == ACCEPTED* ]] || failures=$((failures + 1))
done

echo
if (( failures )); then
  die "$failures check(s) failed"
fi
ok "the public deployment answers correctly from outside, and offline"
