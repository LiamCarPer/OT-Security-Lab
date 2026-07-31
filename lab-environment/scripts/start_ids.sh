#!/bin/sh

# Launches all custom detection rules as persistent background services
# inside the gateway container (the L3/L4 chokepoint that sees all
# inter-zone traffic). Rules write JSON alerts to /detection/logs.
# Rules are verified alive after startup; failures are reported loudly.

RULE_DIR="/detection/rules"
LOG_DIR="/detection/logs"
mkdir -p "$LOG_DIR"

echo "[IDS] Starting persistent detection rules..."
started=0
for rule in "$RULE_DIR"/*.py; do
    [ -f "$rule" ] || continue
    name=$(basename "$rule" .py)
    if pgrep -f "$rule" >/dev/null 2>&1; then
        echo "[IDS] $name already running"
        continue
    fi
    nohup python3 -u "$rule" > "$LOG_DIR/$name.out" 2>&1 &
    echo "[IDS] Started $name (pid $!)"
    started=$((started + 1))
done

sleep 3
alive=0
for rule in "$RULE_DIR"/*.py; do
    [ -f "$rule" ] || continue
    name=$(basename "$rule" .py)
    if pgrep -f "$rule" >/dev/null 2>&1; then
        alive=$((alive + 1))
    else
        echo "[IDS][ERROR] $name exited immediately. Output:"
        cat "$LOG_DIR/$name.out" 2>/dev/null || echo "(no output file)"
    fi
done
echo "[IDS] $alive/$started rules verified running."
