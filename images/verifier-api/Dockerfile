# walt.id verifier-api2, with the demonstration's Web-TLS root added to the JVM truststore.
#
# Why this layer exists
# ---------------------
# A real verifier resolves `did:web` over HTTPS, using its own trust store. On the
# self-contained profile the issuer hostnames are Docker-network aliases served by the
# demonstration's own Web-TLS CA, which no public trust store knows about, so resolution
# would fail with a TLS error -- which is exactly what happened the first time.
#
# Adding that one root here is the honest fix. It preserves the `did:web` requirement that
# resolution happen over authenticated HTTPS, rather than switching the resolver to plain
# HTTP through dev-mode. It also mirrors what a national deployment does: put your root in
# your relying parties' trust stores.
#
# On the public profile this layer changes nothing that matters: those hostnames carry real
# Let's Encrypt certificates, which the stock cacerts already trusts.
#
# NOTE the layering: this root is for TRANSPORT only. The National Root CA that certifies
# credential-signing keys is never added to a TLS trust store, and the Web-TLS root is never
# a credential trust anchor. tests/unit/test_chain_validation.py asserts that separation.
ARG VERIFIER_API_VERSION=1.0.0
FROM waltid/verifier-api2:${VERIFIER_API_VERSION}

USER root
COPY state/tls/root/webtls-root.pem /tmp/webtls-root.pem
RUN /opt/java/openjdk/bin/keytool -importcert -noprompt \
      -alias demo-webtls-root \
      -file /tmp/webtls-root.pem \
      -keystore /opt/java/openjdk/lib/security/cacerts \
      -storepass changeit \
 && rm /tmp/webtls-root.pem \
 && /opt/java/openjdk/bin/keytool -list -alias demo-webtls-root \
      -keystore /opt/java/openjdk/lib/security/cacerts -storepass changeit
