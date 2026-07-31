# Attacker simulation host - pre-baked tooling (no runtime apt/pip installs)
FROM kalilinux/kali-rolling

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-scapy \
        iputils-ping \
        iproute2 \
        nmap \
    && rm -rf /var/lib/apt/lists/*

# Simulation scripts are bind-mounted at /attacker
