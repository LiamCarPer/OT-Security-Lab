# Zone gateway / IDS host - pre-baked dependencies (no runtime package installs)
FROM alpine:3.19

RUN apk add --no-cache iptables iproute2 python3 py3-pip libpcap \
    && pip3 install --no-cache-dir --break-system-packages scapy

# Runtime config is bind-mounted:
#   /network-config/firewall-rules.sh  (zone firewall, applied on boot)
#   /scripts/start_ids.sh              (persistent detection rules)
#   /detection/rules                   (Scapy detection rules)
#   /detection/logs                    (centralized alert output)
