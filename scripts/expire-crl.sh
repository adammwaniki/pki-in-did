#!/usr/bin/env bash
# Publish a CRL that is past its nextUpdate (brief, part 3, optional step 5).
#
# `openssl ca -gencrl` can only date a CRL from now, so the CRL is given a short life and
# waited out. No clock is faked.
#
# The wait must exceed the life PLUS the verifier's clock-skew tolerance, which is 30 seconds
# under the default policy. Rather than wait 40 seconds on camera, verify this scene with
# config/verifier-policy-strict.json, whose tolerance is zero:
#
#     verify --policy /laptop/policy-strict.json ...
#
# A verifier must reject on an expired CRL whatever the list contains, because an expired CRL
# is not evidence about anything.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

SECONDS_VALID="${1:-5}"
step "Publish a CRL with a ${SECONDS_VALID}-second life, then let it lapse"
mkdir -p "$STATE/ca/crl" "$STATE/web/issuing-ca"

run ca openssl ca -config /config/openssl/issuing-ca.cnf -gencrl \
      -crlsec "$SECONDS_VALID" -crlexts crl_ext -out /ca/crl/short.crl.pem
run ca openssl crl -in /ca/crl/short.crl.pem -outform DER -out /ca/crl/short.crl
run cp "$STATE/ca/crl/short.crl" "$STATE/web/issuing-ca/issuing-ca.crl"

ca openssl crl -in /ca/crl/short.crl -inform DER -noout -lastupdate -nextupdate \
  | sed 's/^/      /'

note "waiting $((SECONDS_VALID + 2))s for it to lapse"
sleep "$((SECONDS_VALID + 2))"
ok "the published CRL is past its nextUpdate; verify with the strict policy to see it"
