#!/usr/bin/env bash
# Part 0 -- building the PKI, the DID documents and the credentials.
#
# This is the recorded build. It begins with the offline machine, because the first thing a
# viewer needs to see is where the root private key lives and what it is isolated from.
#
# 10-offline-root.sh is safe to run again: a national root is not re-keyed on a whim, so it
# reports the existing root and shows its certificate rather than generating a new one.
# 00-reset.sh then rebuilds everything below it.
. "$(dirname "${BASH_SOURCE[0]}")/lib/present.sh"

title "Part 0 - building the demonstration" \
      "A two-tier PKI, two did:web issuers, and two credentials issued over OpenID4VCI."

scene "The offline machine, and the root it holds" \
      "No network in this container: the root private key cannot leave it over a wire."
"$REPO/scripts/10-offline-root.sh"
narrate "That key is mounted into this one container and into nothing else. It is not a service."

hold

scene "Everything below the root, rebuilt from scratch" \
      "The CSR crosses to the offline machine as a file, and the certificate comes back."
"$REPO/scripts/00-reset.sh"

hold

scene "What was built"
printf '     %scertificates the Issuing CA now holds:%s\n' "$C_DIM" "$C_OFF"
# Paths are given as the ca-tools container sees them, which is where openssl runs.
for cert in issuing-ca.pem certs/issuer-a.pem certs/issuer-b.pem certs/ocsp-signer.pem; do
  printf '       %-26s %s\n' "$cert" \
    "$(ca openssl x509 -in "/ca/$cert" -noout -subject | cut -d= -f2-)"
done
echo
printf '     %sthe Issuing CA'"'"'s database:%s\n' "$C_DIM" "$C_OFF"
cut -f1,4,6 "$STATE/ca/index.txt" | sed 's/^/       /'
echo
printf '     %scredentials on the laptop:%s\n' "$C_DIM" "$C_OFF"
ls -1 "$STATE/credentials" | sed 's/^/       /'

closing "Built. The root private key never touched the network."
