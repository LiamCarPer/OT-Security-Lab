# Attacker simulation host - pre-baked tooling (no runtime apt/pip installs)
# Base pinned by digest (kali publishes only rolling tags; digest pinning
# keeps the build reproducible - re-pin deliberately on image refresh).
FROM kalilinux/kali-rolling@sha256:4be87f78671419c13dcf4f207ead1cfc0de178ea281b3f69c0f49b69ba4e79b1

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
