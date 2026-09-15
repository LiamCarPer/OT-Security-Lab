#!/bin/sh
# Corporate workstation: route DMZ traffic through the zone gateway so the
# conduit policy applies and the IDS observes corporate -> DMZ flows.
set -e

until ip route replace 172.25.0.0/24 via 172.24.0.2 2>/dev/null; do
    sleep 2
done

exec tail -f /dev/null
