# The certificate authority toolbox, and the server side of domain2.
#
# Used three ways:
#   * as the offline machine, run with `--network none`, holding the root private key
#   * as the Issuing CA workspace on the server
#   * as domain2's web server, publishing the CRL
#   * as the OCSP responder itself: `openssl ocsp`, per brief step 16
# Alpine 3.22 ships OpenSSL 3.5.8, the current LTS.
FROM alpine:3.22

RUN apk add --no-cache openssl nginx curl netcat-openbsd tini bash jq \
 && mkdir -p /run/nginx

COPY images/ca-tools/ocsp-responder.sh /usr/local/bin/ocsp-responder
COPY images/ca-tools/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/ocsp-responder /usr/local/bin/entrypoint

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint"]
