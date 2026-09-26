#!/usr/bin/env bash
# Part 1 -- the happy path, online.
. "$(dirname "${BASH_SOURCE[0]}")/lib/present.sh"

title "Part 1 - credentials the verifier accepts, online" \
      "A did:web issuer whose signing key was certified by a National Root CA."

scene "The National Root CA, published at https://$NRCA_DOMAIN/nrca.pem" \
      "One file. The root private key is not on this network at all."
on_network curl -sS --cacert /trust/webtls-root.pem "https://$NRCA_DOMAIN/nrca.pem" | head -4
echo "      ..."
narrate "The root private key is on an offline machine. What you can reach is only the certificate."

scene "Where the root private key actually is" \
      "One directory, mounted into one container, and that container has no network."
run ls -l "$STATE/offline/nrca/private/"
printf '     %sinterfaces in that container: %s, loopback only%s\n' \
  "$C_DIM" "$(offline sh -c 'ip -o link show | wc -l')" "$C_OFF"

hold

scene "did:web:$ISSUER_A_DOMAIN resolves to a URL" \
      "Replace the colons with slashes, prepend https, append /.well-known/did.json."
printf '     %s%s%s\n' "$C_BOLD" "did:web:$ISSUER_A_DOMAIN" "$C_OFF"
printf '     %s   becomes%s\n' "$C_DIM" "$C_OFF"
printf '     %shttps://%s/.well-known/did.json%s\n' "$C_BOLD" "$ISSUER_A_DOMAIN" "$C_OFF"
echo
show_did_document "$ISSUER_A_DOMAIN"
narrate "The JWK carries x5c: the issuer's certificate, and the Issuing CA that certified it."
narrate "assertionMethod is what makes this key usable for issuing a credential."
narrate "The root is deliberately absent from x5c. The verifier already holds it."

hold

scene "The credential, as walt.id issuer-api2 issued it" \
      "Its kid is the absolute DID URL of that verification method."
docker run --rm --network none -u "$(id -u):$(id -g)" \
  -v "$STATE:/state:ro" -e PYTHONPATH=/app/src --entrypoint python "$VERIFIER_IMAGE" \
  -m did_x509_policy.cli inspect --credential /state/credentials/issuer-a-vc-jose.jwt \
  | jq '{typ: .header.typ, alg: .header.alg, kid: .header.kid,
         x5cInHeader: (.header.x5c | length), issuer, types}'
narrate "The kid in the credential and the verification method id in the DID document are the same string."

hold

scene "Verify credential issuer A - revocation checked by OCSP"
show_online issuer-a-vc-jose.jwt
result "$(verdict issuer-a-vc-jose.jwt)"
narrate "Fifteen checks. The chain ends at the National Root CA, and OCSP says good."

hold

scene "Verify credential issuer B - revocation checked by a CRL" \
      "The revocation mechanism is the only difference between the two issuers."
show_online issuer-b-vc-jose.jwt
result "$(verdict issuer-b-vc-jose.jwt)"
narrate "The serial number is not on the CRL, and the CRL has not expired."

closing "Both accepted. One trust anchor: the National Root CA."
