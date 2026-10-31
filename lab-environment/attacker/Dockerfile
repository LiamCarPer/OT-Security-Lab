# Attacker simulation host - pre-baked tooling (no runtime apt/pip installs)
# Base pinned by digest (kali publishes only rolling tags; digest pinning
# keeps the build reproducible - re-pin deliberately on image refresh).
FROM kalilinux/kali-rolling@sha256:ea20024e16833dab1a5337f5998602f3b81f8a38f3b0995dda272c83a1b0c1b9

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-scapy \
        iputils-ping \
        iproute2 \
        nmap \
    && rm -rf /var/lib/apt/lists/*

# checkov:skip=CKV_DOCKER_3:Attacker needs NET_ADMIN/NET_RAW (pivot routes,
#   raw packet injection) which Docker grants only to root; lab-only role.

# Minimal kali images lack procps (pgrep); health reflects the pivot routes
HEALTHCHECK CMD ip route | grep -q 172.21.0.0/24 || exit 1

# Simulation scripts are bind-mounted at /attacker
