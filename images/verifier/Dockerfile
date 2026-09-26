# The verifier — stands in for "your laptop".
# Holds the National Root CA certificate and a local cache, nothing else.
# Runs online on the demo network, and offline under `docker run --network none`.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl curl dnsutils jq \
 && rm -rf /var/lib/apt/lists/*

COPY images/verifier/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LAPTOP_STORE=/laptop

WORKDIR /app
COPY src/ /app/src/
COPY config/ /app/config/
COPY tests/ /app/tests/
COPY pytest.ini /app/pytest.ini

ENTRYPOINT ["python", "-m", "verifier.cli"]
