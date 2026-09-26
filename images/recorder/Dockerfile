# Terminal recording, containerised so the host needs nothing installed.
#
# Built on the tester image, which already carries the Docker client, the compose plugin and
# jq -- all of which the demo scripts use, because what is being recorded is a sequence of
# docker commands. Duplicating that setup here would only invite the two to drift apart.
#
# Build order: pki-in-did/tester, then this. `make images` does both.
FROM pki-in-did/tester

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg ncurses-bin fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir asciinema==2.4.0

# agg renders an asciinema cast to a GIF. Shipped as a static binary.
ARG AGG_VERSION=1.5.0
RUN curl -fsSL -o /usr/local/bin/agg \
      "https://github.com/asciinema/agg/releases/download/v${AGG_VERSION}/agg-x86_64-unknown-linux-gnu" \
 && chmod +x /usr/local/bin/agg

ENV TERM=xterm-256color LANG=C.UTF-8
WORKDIR /app
ENTRYPOINT ["/bin/bash"]
