#!/bin/sh

# Launches all custom detection rules as persistent background services
# inside the gateway container (the L3/L4 chokepoint that sees all
# inter-zone traffic). Rules write JSON alerts to /detection/logs.

RULE_DIR="/detection/rules"
LOG_DIR="/detection/logs"
mkdir -p "$LOG_DIR"

echo "[IDS] Starting persistent detection rules..."
for rule in "$RULE_DIR"/*.py; do
    [ -f "$rule" ] || continue
    name=$(basename "$rule" .py)
    if pgrep -f "$rule" >/dev/null 2>&1; then
        echo "[IDS] $name already running"
        continue
    fi
    nohup python3 "$rule" > "$LOG_DIR/$name.out" 2>&1 &
    echo "[IDS] Started $name (pid $!)"
done
echo "[IDS] Done."
