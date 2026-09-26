#!/usr/bin/env bash
# Part 4 -- revocation, offline: what a disconnected verifier can and cannot know.
. "$(dirname "${BASH_SOURCE[0]}")/lib/present.sh"

title "Part 4 - withdrawing accreditation, offline" \
      "A disconnected verifier is honest about the limits of what it holds."

scene "Start from a clean stack and a freshly primed cache"
"$REPO/scripts/00-reset.sh" >/dev/null 2>&1 || die "reset failed; run scripts/00-reset.sh to see why"
printf '     issuer A offline   %s\n' "$(verdict issuer-a-vc-jose.jwt --offline)"
printf '     issuer B offline   %s\n' "$(verdict issuer-b-vc-jose.jwt --offline)"
narrate "Both accepted, with no network, from the cache."

hold

scene "Revoke credential issuer A while the laptop is disconnected"
"$REPO/scripts/60-revoke.sh" a >/dev/null
printf '     %sthe Issuing CA database now says:%s\n' "$C_DIM" "$C_OFF"
grep '^R' "$STATE/ca/index.txt" | cut -f1,3,4 | sed 's/^/     /'

hold

scene "The disconnected laptop verifies again" \
      "It has not been told, and it cannot ask."
result "$(verdict issuer-a-vc-jose.jwt --offline)"
narrate "Still accepted. The cached response is inside its own validity, so the laptop cannot know yet."
narrate "That is the honest answer, and the reason the response life is a policy decision."

hold

scene "Refuse the cached answer instead" \
      "The same laptop, asked not to rely on anything it cannot currently confirm."
result "$(verdict issuer-a-vc-jose.jwt --offline --no-cached-revocation)"
narrate "With no cache to lean on and no network to ask, the status is unknown, so it rejects."

hold

scene "Reconnect once, then disconnect again" \
      "One online verification is all it takes to learn."
printf '     %sonline:  %s%s\n' "$C_DIM" "$(verdict issuer-a-vc-jose.jwt)" "$C_OFF"
printf '     %soffline: %s%s\n' "$C_DIM" "$(verdict issuer-a-vc-jose.jwt --offline)" "$C_OFF"
narrate "The rejection persists offline, because the revoked response is now what is cached."

hold

scene "The same story with a CRL" \
      "Revoke credential issuer B and publish the new CRL, with the laptop disconnected."
"$REPO/scripts/60-revoke.sh" b >/dev/null 2>&1
printf '     %soffline, with the old cached CRL: %s%s\n' "$C_DIM" "$(verdict issuer-b-vc-jose.jwt --offline)" "$C_OFF"
narrate "The cached CRL predates the revocation and has not expired, so the laptop still accepts."
echo
printf '     %sfetch the new CRL once:%s\n' "$C_DIM" "$C_OFF"
"$REPO/scripts/80-seed-offline-cache.sh" >/dev/null 2>&1 || true
printf '     %soffline, with the new cached CRL: %s%s\n' "$C_DIM" "$(verdict issuer-b-vc-jose.jwt --offline)" "$C_OFF"
narrate "Once a newer CRL is in hand, the rejection holds offline for as long as that CRL is valid."

hold

scene "A cached answer that goes stale" \
      "A verifier stops standing behind an answer it can no longer date."
# Put every certificate back to valid first, so this scene is about freshness alone and not
# about a revocation. Then verify under a policy whose freshness window is 30 seconds
# instead of the default hour, and let it lapse.
"$REPO/scripts/90-restore-revocations.sh" >/dev/null 2>&1 \
  || die "could not restore the stack; run scripts/00-reset.sh"
"$REPO/scripts/80-seed-offline-cache.sh" >/dev/null 2>&1 || true

printf '     %sthis laptop will trust a cached answer for 30 seconds, not an hour:%s\n' \
  "$C_DIM" "$C_OFF"
jq -c '{clock_skew_seconds, ocsp_max_age_seconds, crl_max_age_seconds}' \
  "$STATE/laptop/policy-strict.json" | sed 's/^/     /'
echo
printf '     %sjust cached:  %s%s\n' "$C_DIM" \
  "$(verdict issuer-b-vc-jose.jwt --offline --policy /laptop/policy-strict.json)" "$C_OFF"
printf '     %swaiting for that window to lapse%s\n' "$C_DIM" "$C_OFF"
sleep 33
result "$(verdict issuer-b-vc-jose.jwt --offline --policy /laptop/policy-strict.json)"
narrate "Nothing was revoked. The answer simply got too old for this verifier to rely on, and it says so rather than guessing."
printf '     %sunder the default policy, the same cache is still fine: %s%s\n' "$C_DIM" \
  "$(verdict issuer-b-vc-jose.jwt --offline)" "$C_OFF"
narrate "How long a cached answer counts is a policy decision, not a property of the credential."

closing "Offline, a verifier can be certain, stale, or unsure - and it always says which."
