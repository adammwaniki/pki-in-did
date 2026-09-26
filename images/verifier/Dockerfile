# The verifier — stands in for "your laptop".
# Holds the National Root CA certificate and a local cache, nothing else.
# Runs online on the demo network, and offline under `docker run --network none`.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl curl dnsutils jq git \
 && rm -rf /var/lib/apt/lists/*

COPY images/verifier/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# The policy layer is did-x509-policy, which lives in its own repository and is pinned here by
# tag. The demonstration therefore exercises exactly the released code, and there is no second
# copy to drift. Bump DID_X509_POLICY_VERSION to move.
ARG DID_X509_POLICY_VERSION=v1.0.1
RUN pip install --no-cache-dir \
      "did-x509-policy[http,service] @ git+https://github.com/adammwaniki/did-x509-policy@${DID_X509_POLICY_VERSION}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LAPTOP_STORE=/laptop

WORKDIR /app
# The demonstration's own helpers: the DID document builder, the walt.id profile renderer, the
# impostor, and the wallet client. The policy layer itself comes from the installed package.
COPY src/ /app/src/
COPY config/ /app/config/
COPY tests/ /app/tests/
COPY pytest.ini /app/pytest.ini

ENTRYPOINT ["python", "-m", "did_x509_policy.cli"]
