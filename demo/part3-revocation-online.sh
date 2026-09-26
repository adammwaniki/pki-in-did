#!/usr/bin/env bash
# Part 3 -- revocation, online: OCSP, then the CRL revocation window.
. "$(dirname "${BASH_SOURCE[0]}")/lib/present.sh"

title "Part 3 - withdrawing accreditation, online" \
      "The Issuing CA acts alone. No DID document changes."

scene "Both credentials verify right now"
printf '     issuer A   %s\n' "$(verdict issuer-a-vc-jose.jwt)"
printf '     issuer B   %s\n' "$(verdict issuer-b-vc-jose.jwt)"

hold

scene "Revoke credential issuer A, reason $REVOCATION_REASON" \
      "This touches the Issuing CA's certificate database, and nothing else."
printf '     %sthe DID document before:%s\n' "$C_DIM" "$C_OFF"
show_did_unchanged a
echo
"$REPO/scripts/60-revoke.sh" a
echo
printf '     %sthe DID document after:%s\n' "$C_DIM" "$C_OFF"
show_did_unchanged a
narrate "The DID document did not change. The key is still published. Only its status changed."

hold

scene "Verify credential issuer A again" \
      "Nothing was republished. OCSP is asked at every verification."
show_online issuer-a-vc-jose.jwt
result "$(verdict issuer-a-vc-jose.jwt)"
narrate "OCSP now says revoked, and gives the reason. The verifier rejects."
narrate "privilegeWithdrawn would say it better, but openssl cannot express it -- so this says cessationOfOperation."

hold

scene "Stop the OCSP responder" \
      "A verifier with nothing to fall back on cannot establish a status at all."
"$REPO/scripts/responder.sh" stop
echo
printf '     %sa verifier that has never seen this certificate before:%s\n' "$C_DIM" "$C_OFF"
printf '     %s\n' "$(verdict issuer-a-vc-jose.jwt --no-cached-revocation)"
printf '     %sa verifier holding a cached answer uses it, and says so:%s\n' "$C_DIM" "$C_OFF"
printf '     %s\n' "$(verdict issuer-a-vc-jose.jwt)"
"$REPO/scripts/responder.sh" start
narrate "Unknown is a rejection. A verifier never treats silence as good news."

hold

scene "Now the CRL, which behaves differently" \
      "Revoke credential issuer B, and publish nothing."
"$REPO/scripts/60-revoke.sh" b --no-publish

hold

scene "Verify credential issuer B during the revocation window"
result "$(verdict issuer-b-vc-jose.jwt)"
narrate "The verifier accepts, and it is right to. The published CRL is still inside its own nextUpdate."
narrate "This gap is the revocation window. With a one-hour CRL, it can last an hour."

hold

scene "Publish the new CRL"
"$REPO/scripts/50-publish-crl.sh"
result "$(verdict issuer-b-vc-jose.jwt)"
narrate "Now the serial number is on the list, and the verifier rejects."

hold

scene "An expired CRL" \
      "An expired CRL is not evidence about anything, whatever it lists."
"$REPO/scripts/expire-crl.sh"
result "$(verdict issuer-b-vc-jose.jwt)"
narrate "Expired, so rejected - and rejected for being expired, not for what it contains."

closing "The Issuing CA withdrew both accreditations. Neither DID document was touched."
