# DNP3 outstation endpoint (real opendnp3 via dnp3-python bindings)
#
# Python 3.10 is required: dnp3-python publishes x86_64 wheels only for
# cp38-cp310, so newer interpreters have no installable distribution.
#
# checkov:skip=CKV_DOCKER_3:Root is required to install the Control-zone default
#   route via the gateway (CAP_NET_ADMIN); only that capability is retained.
FROM python:3.14-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --pre dnp3-python==0.3.0b2

WORKDIR /app
COPY outstation.py /app/outstation.py

EXPOSE 20000
HEALTHCHECK CMD ["python3", "-c", "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',20000))==0 else 1)"]
CMD ["python3", "-u", "/app/outstation.py"]
