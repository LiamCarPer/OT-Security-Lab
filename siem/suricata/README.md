# Suricata Integration (Optional Add-On)

The default lab detection stack uses the custom Scapy rules (`detection/rules/`)
which already cover the lab scenarios. This directory adds a **signature-based
alternative** that mirrors the same detections, plus the deployment path for
scale-out: Suricata is the industry-standard NIDS, ships with protocol parsers
(including Modbus), and supports the ET ICS open ruleset.

## Why run it in the gateway container?

Docker bridge networks isolate containers at L2: a separate Suricata container
would only see its own traffic. The `ot_gateway` is the router between zones, so
it is the only container with visibility of all inter-zone traffic. In a
production deployment this role maps to an industrial firewall/IDS appliance at
the zone boundary (e.g., Nozomi, Claroty, or a TAP-fed Suricata/Zeek sensor).

## Deployment (gateway container)

```bash
docker exec -it ot_gateway /bin/sh
apk add --no-cache suricata
mkdir -p /etc/suricata/rules
cp /network-config/../suricata/* /etc/suricata/  # rules + config
suricata -c /etc/suricata/suricata.yaml -i eth0 -i eth1 -i eth2 -i eth3
# Detections: /var/log/suricata/fast.log
```

Alternatively, install Suricata on a Linux host and feed it a mirrored/TAP
interface on the zone boundary.

## Rules

`ot-security.rules` mirrors the Scapy rules:

| SID | Detection | MITRE |
| :--- | :--- | :--- |
| 2000001 | Unauthorized Modbus write (FC 6) | T0831 |
| 2000002 | Unauthorized Modbus write (FC 16) | T0831 |
| 2000003 | Cross-zone violation (IT -> Control) | T0886 |
| 2000004 | Modbus exception flood (threshold-based) | T0846 |
| 2000005 | Unsafe inlet-valve open command (correlation) | T0836 |

## Engineering judgment

Signature matching (Suricata) is complementary to the custom stateful rules
(Scapy): signatures scale and reuse community rulesets, while the physics-aware
shadow monitor catches protocol-valid commands that no signature can express.
Both feed the same SIEM pipeline (fast.log via Promtail, or the custom rules'
`alerts.json`).
