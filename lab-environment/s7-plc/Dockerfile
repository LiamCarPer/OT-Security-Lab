# S7comm server endpoint (pure-Python S7 server from python-snap7)
#
# checkov:skip=CKV_DOCKER_3:Port 102 is privileged and the Control-zone default
#   route needs CAP_NET_ADMIN, so the server runs as root. Only NET_BIND_SERVICE
#   and NET_ADMIN are retained; no-new-privileges is enforced.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir python-snap7==3.1.2

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 102
HEALTHCHECK CMD ["python3", "-c", "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',102))==0 else 1)"]
CMD ["python3", "-u", "/app/server.py"]
