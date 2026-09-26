#!/usr/bin/env bash
# Default to running whatever command was asked for; `serve` starts the domain2 services.
set -euo pipefail

# `serve` runs domain2's web server. The OCSP responder is a separate service, because
# it needs a CRL reason code that OpenSSL's command line cannot express.
if [[ "${1:-}" == "serve" ]]; then
  shift
  exec nginx -c /etc/nginx/nginx.conf -g 'daemon off;'
fi

exec "$@"
