# PowerShell 7 operator workstation (Supervisory / L2).
# checkov:skip=CKV_DOCKER_3: Root is required to install the Control-zone route with NET_ADMIN; all other capabilities are dropped.
#
# The image is pinned by digest. The host is deliberately placed in L2 rather
# than L3: conduit C1 permits Supervisory -> Control Modbus/502, while C5
# explicitly denies the EWS Modbus access. That makes a normal TcpClient write
# a realistic test of the source-allowlist detection instead of a SYN that the
# firewall drops before a PDU is sent.
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04@sha256:62300a213a9293916333df2b014cd3a8f22fb0b0b65f2bb446aaf436bcf8c868

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/otsec

HEALTHCHECK --interval=10s --timeout=5s --retries=12 --start-period=10s \
    CMD ip route | grep -q 172.21.0.0/24 && pwsh -NoProfile -Command 'exit 0' || exit 1

CMD ["pwsh", "-NoProfile", "-Command", "Start-Sleep -Seconds 2147483647"]
