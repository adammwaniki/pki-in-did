#!/usr/bin/env bash
# Bring the current profile's stack up (or down with --down), and wait for it to answer.
#
# Which stack depends on DOMAINS_FILE: the local profile uses docker-compose.yml alone, the
# public profile adds docker-compose.public.yml and its own project name and state directory.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

if [[ "${1:-}" == "--down" ]]; then
  step "Stop the $DEMO_PROFILE stack"
  run compose down
  ok "stopped"
  exit 0
fi

step "Start the $DEMO_PROFILE stack"
note "project $COMPOSE_PROJECT, state ${STATE#"$REPO/"}"
run compose up -d --force-recreate

if [[ "$DEMO_PROFILE" == "public" ]]; then
  step "Wait for each web server on its loopback port"
  for entry in "nrca:$NRCA_PORT" "issuing-ca:$ISSUING_CA_PORT" \
               "issuer-a:$ISSUER_A_PORT" "issuer-b:$ISSUER_B_PORT"; do
    name="${entry%%:*}"; port="${entry##*:}"
    for _ in $(seq 1 40); do
      curl -sf --max-time 2 -o /dev/null "http://127.0.0.1:$port/healthz" && break
      sleep 1
    done
    printf '      %-12s 127.0.0.1:%-6s %s\n' "$name" "$port" \
      "$(curl -sf --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/healthz" \
         || echo 'not answering')"
  done
else
  wait_for_port "$ISSUING_CA_DOMAIN" 80 60 || die "the Issuing CA did not come up"
fi

step "Wait for the walt.id services"
for which in a b; do
  wait_for_port "issuer-$which-api" 7005 120 \
    || die "issuer-$which-api did not come up; try: compose logs issuer-$which-api"
  note "issuer-$which-api ready"
done
for entry in "wallet-api:7006" "verifier-api:7004"; do
  wait_for_port "${entry%%:*}" "${entry##*:}" 120 \
    || die "${entry%%:*} did not come up; try: compose logs ${entry%%:*}"
  note "${entry%%:*} ready"
done

ok "the $DEMO_PROFILE stack is up"
