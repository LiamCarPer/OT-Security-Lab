#!/bin/sh
# Deploy the Caldera Sandcat agent inside the existing attacker container.
# The agent is only started when CALDERA_URL is set (the optional profile).
set -eu

[ -n "${CALDERA_URL:-}" ] || exit 0

echo "[caldera] waiting for ${CALDERA_URL}"
until curl -fsS "${CALDERA_URL}/" >/dev/null 2>&1; do
    sleep 2
done

echo "[caldera] downloading the Linux Sandcat agent"
curl -fsS -X POST \
    -H "file:sandcat.go" \
    -H "platform:linux" \
    "${CALDERA_URL}/file/download" \
    -o /tmp/sandcat
chmod +x /tmp/sandcat

exec /tmp/sandcat -server "${CALDERA_URL}" -group red
