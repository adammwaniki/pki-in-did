#!/usr/bin/env bash
# The offline machine: create the National Root CA private key and certificate.
#
# Runs in a container with `--network none`. The root private key is written into
# state/offline, which is mounted into no other container in this demonstration.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

step "National Root CA, on the offline machine"

mkdir -p "$STATE/offline/nrca"/{private,certs,newcerts} "$STATE/transfer"
chmod 700 "$STATE/offline/nrca/private"
[[ -f "$STATE/offline/nrca/index.txt" ]] || : > "$STATE/offline/nrca/index.txt"
[[ -f "$STATE/offline/nrca/serial" ]] || echo 1000 > "$STATE/offline/nrca/serial"

# Always show the isolation, whether or not a key is generated. It is the first thing a
# viewer needs to see, and it used to be printed only on the generating path -- so a
# re-run, which is what the recorded build does, never showed it.
step "What this container can reach"
note "network interfaces: $(offline sh -c 'ip -o link show | wc -l') (loopback only)"
note "routes off loopback: $(offline sh -c 'cat /proc/net/route | tail -n +2 | wc -l')"
note "mounted here: /offline (the root key) and /transfer (the sneakernet), nothing else"

if [[ -f "$STATE/offline/nrca/nrca.pem" ]]; then
  note "the root already exists; a national root is not re-keyed on a whim"
else
  run offline openssl genrsa -out /offline/nrca/private/nrca.key 4096
  run offline chmod 400 /offline/nrca/private/nrca.key
  run offline openssl req -config /config/openssl/nrca.cnf \
        -key /offline/nrca/private/nrca.key \
        -new -x509 -days 7300 -sha384 -extensions v3_root_ca \
        -out /offline/nrca/nrca.pem
fi

step "The root certificate"
offline openssl x509 -in /offline/nrca/nrca.pem -noout \
  -subject -issuer -serial -dates -fingerprint -sha256
echo
offline openssl x509 -in /offline/nrca/nrca.pem -noout -text \
  | sed -n '/X509v3 extensions/,/Signature Algorithm/p' | head -20

ok "root private key is at state/offline/nrca/private/nrca.key and goes nowhere else"
