# OPC UA server endpoint (real asyncua server, plaintext None security policy)
#
# checkov:skip=CKV_DOCKER_3:Root is required to install the Control-zone default
#   route via the gateway (CAP_NET_ADMIN); only that capability is retained.
FROM python:3.14-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir asyncua==2.0.1

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 4840
HEALTHCHECK CMD ["python3", "-c", "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',4840))==0 else 1)"]
CMD ["python3", "-u", "/app/server.py"]
