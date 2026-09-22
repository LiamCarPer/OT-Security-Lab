# Compromised engineering workstation (Operations zone).
#
# Represents the classic OT attack path: the adversary pivots to the EWS and
# uses its legitimate conduits to reach the controllers. It runs the real
# protocol client libraries and routes Control-zone traffic through the gateway
# so the zone firewall applies and the IDS observes the sessions.
#
# checkov:skip=CKV_DOCKER_3:Root is required to install the Control-zone route
#   (CAP_NET_ADMIN); the container drops all other capabilities.
FROM python:3.10-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --pre dnp3-python==0.3.0b2 asyncua==2.0.1 python-snap7==3.1.2

WORKDIR /app

HEALTHCHECK CMD ["sh", "-c", "ip route | grep -q '172.21.0.0/24'"]

CMD ["sh", "-c", "for net in 172.21.0.0/24 172.24.0.0/24; do until ip route replace $net via 172.23.0.2 2>/dev/null; do sleep 2; done; done; exec tail -f /dev/null"]
