#!/usr/bin/env bash
# Part 5 -- the gap the specifications leave, shown with a third-party verifier.
#
# Everything in this part is run twice: once through walt.id verifier-api2, a production
# OpenID4VP 1.0 verifier, and once through the PKI policy layer in src/verifier. The point is
# not that one is better. It is that they answer different questions, and that a national PKI
# deployment needs both answers.
. "$(dirname "${BASH_SOURCE[0]}")/lib/present.sh"

waltid() {
  docker run --rm --network "$DEMO_NETWORK" -u "$(id -u):$(id -g)" \
    -v "$REPO:/app" -w /app --entrypoint python "$VERIFIER_IMAGE" \
    src/holder/wallet.py present --verifier http://verifier-api:7004 \
    --credential "state/credentials/$1" --quiet --json 2>/dev/null \
    | jq -r '.status // "NO VERDICT"' || echo "NO VERDICT"
}

waltid_policies() {
  docker run --rm --network "$DEMO_NETWORK" -u "$(id -u):$(id -g)" \
    -v "$REPO:/app" -w /app --entrypoint python "$VERIFIER_IMAGE" \
    src/holder/wallet.py present --verifier http://verifier-api:7004 \
    --credential "state/credentials/$1" 2>/dev/null | grep -E '^\s+(pass|FAIL)' || true
}

title "Part 5 - what a conformant verifier does not check" \
      "walt.id verifier-api2 and the PKI policy layer, on the same two credentials."

scene "Start from a known state" \
      "This part is about the binding check, so nothing here should be revoked."
"$REPO/scripts/90-restore-revocations.sh" >/dev/null 2>&1 \
  || die "could not restore the stack; run scripts/00-reset.sh"
printf '     %severy certificate valid, a clean CRL published, the cache reprimed%s\n' \
  "$C_DIM" "$C_OFF"

hold

scene "A genuine credential, through a real OpenID4VP verifier" \
      "Session, authorization request, vp_token, verdict. A wallet's whole job."
docker run --rm --network "$DEMO_NETWORK" -u "$(id -u):$(id -g)" \
  -v "$REPO:/app" -w /app --entrypoint python "$VERIFIER_IMAGE" \
  src/holder/wallet.py present --verifier http://verifier-api:7004 \
  --credential state/credentials/issuer-a-vc-jose.jwt || true
narrate "That is walt.id's verifier, not ours. It resolved the DID and checked the signatures."
narrate "Notice which policies ran. Not one of them is about the certificate chain."

hold

scene "Now an impostor" \
      "Its own key, and somebody else's genuine national certificate chain beside it."
"$REPO/scripts/95-impostor.sh"
narrate "Nothing here is forged. That chain is real, issued by the real Issuing CA."
narrate "It simply does not certify the key sitting next to it in the document."

hold

scene "The same real verifier, on the impostor's credential"
result "walt.id verifier-api2 says: $(waltid impostor-vc-jose.jwt)"
waltid_policies impostor-vc-jose.jwt | sed 's/^/     /'
narrate "Successful. And that is correct behaviour, not a bug."
narrate "did:web resolution ends at the JWK. DID Core never says to look at x5c."

hold

scene "The PKI policy layer, on the same credential"
show_online impostor-vc-jose.jwt
result "$(verdict impostor-vc-jose.jwt)"
narrate "Check nine. The JWK is not the public key in that certificate."
narrate "The source document calls this the check without which the chain is decorative."

hold

scene "Both verifiers, both credentials, side by side"
printf '     %-34s %-22s %s\n' "" "walt.id verifier-api2" "PKI policy layer"
printf '     %s\n' "$(printf '%.0s-' {1..78})"
for entry in "issuer-a-vc-jose.jwt:accredited issuer" \
             "impostor-vc-jose.jwt:impostor, borrowed chain"; do
  file="${entry%%:*}"; label="${entry##*:}"
  printf '     %-34s %-22s %s\n' "$label" "$(waltid "$file")" "$(verdict "$file" | cut -d' ' -f1)"
done
echo
narrate "The specifications give you the left-hand column. The right-hand column is policy."
narrate "A national PKI deployment needs both, and only one of them is standardised."

closing "x5c is opaque metadata to a conformant verifier. Someone has to validate it."
