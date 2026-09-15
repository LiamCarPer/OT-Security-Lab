#!/bin/sh
# Route Supervisory <-> Control and Supervisory <-> DMZ traffic through the zone
# gateway (172.22.0.2).
#
# The Scada-LTS HMI sits in Level 2 and must reach Level 1 only through the
# IEC 62443 conduit (C1), and serve the DMZ reverse proxy via C10. Routing via
# the gateway also means the gateway's protocol-aware IDS observes the real
# Modbus reads/writes and can shadow the live process - a dual-homed HMI would
# bypass the chokepoint entirely.
set -e

for net in 172.21.0.0/24 172.25.0.0/24; do
    until ip route replace "$net" via 172.22.0.2 2>/dev/null; do
        sleep 2
    done
done

exec "$@"
