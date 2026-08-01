# Zone gateway / IDS host - pre-baked dependencies (no runtime package installs)
FROM alpine:3.19

RUN apk add --no-cache iptables iproute2 python3 py3-pip libpcap \
    && pip3 install --no-cache-dir --break-system-packages scapy

# checkov:skip=CKV_DOCKER_3:Zone gateway requires root for iptables/NET_ADMIN
#   and AF_PACKET capture; compensating controls: default-deny conduits,
#   no-new-privileges, dropped capabilities, and rate-limited log output.

# start_ids.sh exits after launching the rules; health reflects the rules
# ([d] bracket avoids pgrep matching the healthcheck's own command line)
HEALTHCHECK CMD pgrep -f "[d]etection/rules/" || exit 1

# Runtime config is bind-mounted:
#   /network-config/firewall-rules.sh  (zone firewall, applied on boot)
#   /scripts/start_ids.sh              (persistent detection rules)
#   /detection/rules                   (Scapy detection rules)
#   /detection/logs                    (centralized alert output)
