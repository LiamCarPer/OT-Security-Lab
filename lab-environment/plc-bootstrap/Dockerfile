# OpenPLC v4 program deployer - uploads committed bundles over the runtime API
#
# checkov:skip=CKV_DOCKER_3:Root is required to install the Control-zone route
#   via the gateway (CAP_NET_ADMIN); a non-root process cannot use container
#   capabilities. The deployer itself only makes outbound HTTPS calls.
FROM python:3.14-slim

# iproute2 provides `ip`: the EWS routes Control-zone traffic through the zone
# gateway so conduit C5 is enforced (a direct path would bypass the firewall).
# openssh-server exposes the DMZ->EWS engineering endpoint (conduit C11).
# checkov:skip=CKV_DOCKER_1:the EWS sshd is the endpoint of the source-restricted
#   DMZ conduit C11 and is key-only; exposing 22 is intentional.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir requests==2.32.3 \
    && ssh-keygen -A \
    && useradd -m -s /bin/bash -p '*' engineer

COPY sshd_config /etc/ssh/sshd_config
COPY start-sshd.sh /usr/local/bin/start-sshd.sh
RUN chmod +x /usr/local/bin/start-sshd.sh

EXPOSE 22

WORKDIR /app
COPY deploy.py /app/deploy.py

# Healthy once at least the deployment attempt completed (sentinel written)
HEALTHCHECK CMD ["python3", "-c", "import pathlib,sys; sys.exit(0 if pathlib.Path('/tmp/deploy.ok').exists() else 1)"]

CMD ["python3", "-u", "/app/deploy.py"]
