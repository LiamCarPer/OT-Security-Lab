# Modbus process stand-in (historian data source until OpenPLC bundles exist)
#
# checkov:skip=CKV_DOCKER_3:Port 502 is privileged; the server binds it as root.
#   Only NET_BIND_SERVICE is retained and no-new-privileges is enforced.
FROM python:3.14-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir pymodbus==3.6.9

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 502
HEALTHCHECK CMD ["python3", "-c", "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',502))==0 else 1)"]
CMD ["python3", "-u", "/app/server.py"]
