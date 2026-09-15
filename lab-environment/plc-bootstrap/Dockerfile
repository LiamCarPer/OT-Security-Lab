# OpenPLC v4 program deployer - uploads committed bundles over the runtime API
#
# checkov:skip=CKV_DOCKER_3:Root is required to install the Control-zone route
#   via the gateway (CAP_NET_ADMIN); a non-root process cannot use container
#   capabilities. The deployer itself only makes outbound HTTPS calls.
FROM python:3.12-slim

# iproute2 provides `ip`: the EWS routes Control-zone traffic through the zone
# gateway so conduit C5 is enforced (a direct path would bypass the firewall).
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir requests==2.32.3

WORKDIR /app
COPY deploy.py /app/deploy.py

# Healthy once at least the deployment attempt completed (sentinel written)
HEALTHCHECK CMD ["python3", "-c", "import pathlib,sys; sys.exit(0 if pathlib.Path('/tmp/deploy.ok').exists() else 1)"]

CMD ["python3", "-u", "/app/deploy.py"]
