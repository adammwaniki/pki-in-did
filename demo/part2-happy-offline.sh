#!/usr/bin/env bash
# Part 2 -- the happy path, with no network at all.
. "$(dirname "${BASH_SOURCE[0]}")/lib/present.sh"

title "Part 2 - the same two credentials, with no network" \
      "docker run --network none. Docker enforces the isolation, not our code."

scene "First, prove the isolation" \
      "Nothing resolves, and there is no route off the loopback interface."
for d in "$NRCA_DOMAIN" "$ISSUING_CA_DOMAIN" "$ISSUER_A_DOMAIN" "$ISSUER_B_DOMAIN"; do
  printf '     %-30s ' "$d"
  if docker run --rm --network none --entrypoint getent "$VERIFIER_IMAGE" hosts "$d" >/dev/null 2>&1
  then printf '%sRESOLVED%s\n' "$C_RED" "$C_OFF"
  else printf '%sdoes not resolve%s\n' "$C_GREEN" "$C_OFF"; fi
done
printf '     %-30s ' "routing table"
routes=$(docker run --rm --network none --entrypoint cat "$VERIFIER_IMAGE" /proc/net/route \
         | tail -n +2 | awk '{print $1}' | sort -u | tr '\n' ' ')
printf '%s%s%s\n' "$C_GREEN" "${routes:-loopback only}" "$C_OFF"
narrate "No DNS, no routes. Whatever happens next happens without a network."

hold

scene "What the laptop is carrying" \
      "One trust anchor, one policy, and a cache filled while it was online."
find "$STATE/laptop" -type f | sed "s|$STATE/laptop|     laptop|" | sort
echo
printf '     %strust anchor fingerprint%s\n' "$C_DIM" "$C_OFF"
laptop_offline fingerprint | sed 's/^/     /'

hold

scene "Verify credential issuer A offline"
show_offline issuer-a-vc-jose.jwt
result "$(verdict issuer-a-vc-jose.jwt --offline)"
narrate "The DID document came from the cache, and so did the OCSP response."

hold

scene "Verify credential issuer B offline"
result "$(verdict issuer-b-vc-jose.jwt --offline)"
narrate "Same again, from the cached CRL, which has not reached its nextUpdate."

hold

scene "Why this works: the chain travels inside the credential's own key material" \
      "x5c holds the certificates. x5u holds only a URL."
printf '     %sthe same key, published the other way:%s\n' "$C_DIM" "$C_OFF"
jq -r '.verificationMethod[0].publicKeyJwk | {x5u, x5c: (.x5c // "absent")}' \
  "$STATE/web/issuer-a/.well-known/did.x5u.json" | sed 's/^/     /'

# A throwaway copy of the laptop, handed the x5u document instead of the x5c one. The real
# store is left alone.
scratch="$STATE/laptop-x5u"
rm -rf "$scratch"; cp -r "$STATE/laptop" "$scratch"
trap 'rm -rf "$scratch"' EXIT

x5u_laptop() {
  docker run --rm --network none -u "$(id -u):$(id -g)" \
    -v "$scratch:/laptop" -v "$STATE/credentials:/credentials:ro" \
    -v "$STATE/web:/web:ro" "$VERIFIER_IMAGE" "$@"
}

x5u_laptop cache-document --did "$ISSUER_A_DID" \
  --file "/web/issuer-a/.well-known/did.x5u.json" | sed 's/^/     /'

echo
printf '     %swith policy refusing x5u, which is the default:%s\n' "$C_DIM" "$C_OFF"
x5u_laptop verify --offline --json --credential /credentials/issuer-a-vc-jose.jwt \
  | jq -r '"     REJECTED   \(.reason)"' || true
printf '     %sand with policy allowing it, offline:%s\n' "$C_DIM" "$C_OFF"
x5u_laptop verify --offline --allow-x5u --json --credential /credentials/issuer-a-vc-jose.jwt \
  | jq -r '"     REJECTED   \(.reason)"' || true
printf '     %sthe same document, allowing x5u, with a network:%s\n' "$C_DIM" "$C_OFF"
docker run --rm --network "$DEMO_NETWORK" -u "$(id -u):$(id -g)" \
  -v "$scratch:/laptop" -v "$STATE/credentials:/credentials:ro" \
  "$VERIFIER_IMAGE" verify --allow-x5u --json \
  --credential /credentials/issuer-a-vc-jose.jwt \
  | jq -r 'if .accepted then "     ACCEPTED   the chain was fetched over the network"
           else "     REJECTED   \(.reason)" end' || true

rm -rf "$scratch"; trap - EXIT
narrate "A chain held by reference cannot be followed with no network. A chain held by value can."
narrate "That is why this demonstration puts x5c in the DID document."

closing "Offline verification is not a fallback here. It is the default capability."
