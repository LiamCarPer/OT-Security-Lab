# MITRE/Apache Caldera, built from a pinned release tag.
#
# The pre-built ghcr.io/apache/caldera image is convenient but the registry
# access is not guaranteed in CI and the project recommends building locally.
# The build is intentionally outside the default lab profile: `make caldera`
# builds this image only when it is missing.
ARG CALDERA_VERSION=5.3.0

FROM node:23-bookworm-slim AS ui-build
ARG CALDERA_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${CALDERA_VERSION}" --recursive \
        https://github.com/apache/caldera.git .
RUN cd plugins/magma && npm install && npm run build

FROM debian:bookworm-slim AS runtime
ARG CALDERA_VERSION
ARG GO_VERSION=1.25.0
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl git python3 python3-dev python3-pip \
        gcc zlib1g mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /usr/src/app
RUN git clone --depth 1 --branch "${CALDERA_VERSION}" --recursive \
        https://github.com/apache/caldera.git .
COPY --from=ui-build /src/plugins/magma/dist /usr/src/app/plugins/magma/dist

RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt
RUN cd plugins/sandcat && ./update-agents.sh

COPY entrypoint.py /opt/caldera-entrypoint.py

EXPOSE 8888
ENTRYPOINT ["python3", "/opt/caldera-entrypoint.py"]
