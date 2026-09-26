#!/usr/bin/env bash
# Run the test suite.
#
# Unit tests run in the verifier image: hermetic, no Docker, no network.
#
# Integration tests (PKI_DEMO_STACK=1) run in the tester image, which has a Docker client
# and the socket, because those tests drive the demonstration exactly as a person does.
# The repository is mounted at ITS OWN ABSOLUTE HOST PATH so that a path computed inside the
# container is the same string on the host -- otherwise every `-v "$STATE/..."` the tests
# build would name a directory that does not exist on the host.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${PKI_DEMO_STACK:-0}" == "1" ]]; then
  docker_gid="$(stat -c %g /var/run/docker.sock)"
  exec docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$REPO:$REPO" -w "$REPO" \
    -u "$(id -u):$(id -g)" --group-add "$docker_gid" \
    -e PYTHONPATH="$REPO/src" \
    -e PKI_DEMO_STACK=1 \
    -e PKI_DEMO_NETWORK="${PKI_DEMO_NETWORK:-pki-in-did_demo}" \
    -e PKI_DEMO_VERIFIER_IMAGE="${PKI_DEMO_VERIFIER_IMAGE:-pki-in-did/verifier}" \
    -e HOME=/tmp \
    "${PKI_DEMO_TESTER_IMAGE:-pki-in-did/tester}" -m pytest "$@"
fi

exec docker run --rm \
  -v "$REPO:/app" -w /app \
  -e PYTHONPATH=/app/src \
  -e PKI_DEMO_STACK=0 \
  --entrypoint python \
  "${PKI_DEMO_VERIFIER_IMAGE:-pki-in-did/verifier}" -m pytest "$@"
