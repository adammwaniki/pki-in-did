#!/usr/bin/env bash
# Stop and start the OCSP responder, to show what "status unknown" looks like.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

case "${1:-}" in
  stop)
    step "Stop the OCSP responder on $ISSUING_CA_DOMAIN"
    run compose stop issuing-ca
    ok "nothing is answering at $OCSP_URL"
    ;;
  start)
    step "Start the OCSP responder on $ISSUING_CA_DOMAIN"
    run compose up -d issuing-ca
    wait_for_port "$ISSUING_CA_DOMAIN" 80 60 || die "the responder did not come back"
    ok "$OCSP_URL is answering again"
    ;;
  *)
    die "usage: responder.sh <stop|start>"
    ;;
esac
