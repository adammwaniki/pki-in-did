#!/usr/bin/env bash
# The OCSP responder: `openssl ocsp`, as brief step 16 specifies.
#
# `openssl ocsp` reads index.txt once at startup, so a revocation would otherwise stay
# invisible until someone restarted it. Watching the file is what makes "revoke, then verify
# again" work with nothing republished and nobody restarting anything.
#
# Two flags worth knowing:
#   -nmin N      how long each response is valid: the value the brief asks us to select.
#   no -nrequest serve until killed. OpenSSL rejects `-nrequest 0` ("Non-positive number").
set -euo pipefail

CA_DIR=${CA_DIR:-/ca}
PORT=${OCSP_PORT:-2560}
INDEX="$CA_DIR/index.txt"
RESPONSE_MINUTES=${OCSP_RESPONSE_MINUTES:-5}

log() { printf '[ocsp] %s\n' "$*" >&2; }

start_responder() {
  openssl ocsp \
    -index "$INDEX" \
    -CA "$CA_DIR/issuing-ca.pem" \
    -rsigner "$CA_DIR/certs/ocsp-signer.pem" \
    -rkey "$CA_DIR/private/ocsp-signer.key" \
    -port "$PORT" \
    -nmin "$RESPONSE_MINUTES" \
    -ignore_err \
    -text &
  responder=$!
  log "listening on $PORT, responses valid for ${RESPONSE_MINUTES}m (pid $responder)"
}

for _ in $(seq 1 60); do
  [[ -f "$INDEX" && -f "$CA_DIR/certs/ocsp-signer.pem" ]] && break
  log "waiting for the Issuing CA's database and responder certificate"
  sleep 2
done

signature_of_index() { stat -c '%Y %s' "$INDEX" 2>/dev/null || echo missing; }

start_responder
seen=$(signature_of_index)
trap 'kill "$responder" 2>/dev/null || true; exit 0' TERM INT

while true; do
  sleep 2
  current=$(signature_of_index)
  if [[ "$current" != "$seen" ]]; then
    log "the Issuing CA database changed; reloading so the next answer reflects it"
    kill "$responder" 2>/dev/null || true
    wait "$responder" 2>/dev/null || true
    start_responder
    seen="$current"
  elif ! kill -0 "$responder" 2>/dev/null; then
    log "responder exited; restarting"
    start_responder
  fi
done
