# Historian collector: Modbus/OpenPLC -> InfluxDB (Level 3)
#
# checkov:skip=CKV_DOCKER_3:Root is required to install the Control/Ops routes
#   via the gateway (CAP_NET_ADMIN); only that capability is retained.
FROM python:3.14-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir pymodbus==3.6.9

WORKDIR /app
COPY poller.py /app/poller.py
COPY historian.py /app/historian.py

HEALTHCHECK CMD ["python3", "-c", "import os,time,sys; p='/tmp/poller.ok'; sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p)<30 else 1)"]
CMD ["python3", "-u", "/app/poller.py"]
