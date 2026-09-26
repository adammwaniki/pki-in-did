# The test runner.
#
# Integration tests drive the demonstration the way a person does -- `docker run`, `docker
# compose`, the scripts in scripts/ -- so the runner needs a Docker client and the socket.
#
# The repository is mounted at its own absolute host path (see scripts/pytest.sh), so a path
# computed inside this container is the same string on the host. Without that, every
# `-v "$STATE/..."` the tests build would point at a directory that does not exist.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl openssl jq docker-cli netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

# On Debian 13 the Docker client is docker-cli; docker.io is only the runtime.
# Debian carries no compose plugin package; the scripts under test call `docker compose`.
ARG COMPOSE_VERSION=v2.29.7
RUN mkdir -p /usr/libexec/docker/cli-plugins \
 && curl -fsSL -o /usr/libexec/docker/cli-plugins/docker-compose \
      "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
 && chmod +x /usr/libexec/docker/cli-plugins/docker-compose

COPY images/verifier/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python"]
