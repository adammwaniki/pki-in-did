# did-x509-policy — the PKI policy layer, as a service.
#
# Two stages so the runtime image carries no build tooling. It runs as an unprivileged user
# with a read-only root filesystem in mind: nothing is written outside the cache directory,
# and with the default in-memory cache nothing is written at all.
FROM python:3.12-slim AS build

WORKDIR /src
RUN pip install --no-cache-dir hatchling
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip wheel --no-cache-dir --no-deps -w /wheels . \
 && pip download --no-cache-dir -d /wheels \
      "cryptography>=42,<45" "requests>=2.31,<3" "starlette>=0.37,<1" "uvicorn>=0.30,<1"

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="did-x509-policy" \
      org.opencontainers.image.description="Validate the x5c chain behind a did:web verification method against your own trust anchors, online or offline." \
      org.opencontainers.image.source="https://github.com/adammwaniki/pki-in-did" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 policy

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels \
      did-x509-policy requests starlette uvicorn \
 && rm -rf /wheels

USER policy
WORKDIR /home/policy

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DID_X509_PORT=8080

EXPOSE 8080

# A verifier with no trust anchor can only reject, so /healthz reports 503 until one is set.
HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=3 \
  CMD curl -fsS -o /dev/null "http://127.0.0.1:${DID_X509_PORT}/healthz"

ENTRYPOINT ["sh", "-c", "exec uvicorn did_x509_policy.api:create_app --factory \
  --host 0.0.0.0 --port ${DID_X509_PORT} --no-server-header --log-level info"]
