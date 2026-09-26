#!/usr/bin/env bash
# Withdraw an issuer's accreditation, at the Issuing CA and nowhere else.
#
#   60-revoke.sh a                revoke issuer A (OCSP sees it at the next verification)
#
# The reason code comes from REVOCATION_REASON in config/domains.env.
#   60-revoke.sh b                revoke issuer B and publish a new CRL
#   60-revoke.sh b --no-publish   revoke issuer B and publish nothing: the revocation window
#
# Note what this does NOT touch: the DID document. The key stays published; only the
# certificate's status changes. That is the point of the whole demonstration.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

which="${1:-}"
[[ "$which" == "a" || "$which" == "b" ]] || die "usage: 60-revoke.sh <a|b> [--no-publish]"
publish=yes
[[ "${2:-}" == "--no-publish" ]] && publish=no

cert="$STATE/ca/certs/issuer-$which.pem"
[[ -f "$cert" ]] || die "no certificate at $cert"

step "Revoke credential issuer ${which^^}, reason $REVOCATION_REASON"
note "serial $(serial_of "/ca/certs/issuer-$which.pem")"

serial="$(serial_of "/ca/certs/issuer-$which.pem")"

if grep -qi "^R.*$serial" "$STATE/ca/index.txt"; then
  note "already revoked in the Issuing CA database"
else
  run ca openssl ca -config /config/openssl/issuing-ca.cnf \
        -revoke "/ca/certs/issuer-$which.pem" -crl_reason "$REVOCATION_REASON"
fi

step "The Issuing CA's database now"
sed 's/^/      /' "$STATE/ca/index.txt"
note "R in the first column means revoked; the reason follows the revocation date"

step "The DID document is untouched"
note "$(ls -l --time-style=+%H:%M:%S "$STATE/web/issuer-$which/.well-known/did.json" | awk '{print $6, $7}')"

if [[ "$which" == "a" ]]; then
  note "issuer A is checked by OCSP; the responder reads the database on every request,"
  note "so the next verification already sees this -- nothing was republished"
elif [[ "$publish" == "yes" ]]; then
  "$REPO/scripts/50-publish-crl.sh"
else
  warn "no new CRL published -- this is the revocation window"
fi

ok "accreditation withdrawn by the Issuing CA alone"
