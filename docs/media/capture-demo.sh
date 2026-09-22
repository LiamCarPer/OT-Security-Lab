#!/usr/bin/env bash
# Reproduce evidence/demo.gif and evidence/demo.mp4.
#
# Requires: docker (the lab), xterm, Xvfb, google-chrome, ffmpeg and
# ImageMagick (`convert`). Run from anywhere; outputs land in evidence/.
#
# The demo is composed of three segments: a title card, a headless screenshot
# of the Grafana SOC dashboard (slow zoom), and a real `make compliance` run
# recorded in a terminal. Nothing is mocked - the dashboard shows live lab data
# and the terminal shows the suite's own output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
DISPLAY_NUM="${DEMO_DISPLAY:-:95}"
SCREEN="1280x720x24"
FPS=12
DASH_URL="http://localhost:3000/d/ot_security_overview/ot-security-lab-soc-overview?kiosk&from=now-30m&to=now"

cleanup() {
    if [ -n "${XPID:-}" ]; then kill "$XPID" 2>/dev/null || true; fi
    if [ -n "${TPID:-}" ]; then kill "$TPID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap 'cleanup' EXIT

echo "[demo] ensuring the lab is up and populated..."
(cd "$ROOT/lab-environment" && docker compose up -d --wait --wait-timeout 600)
(cd "$ROOT" && make compliance >/dev/null)

echo "[demo] capturing the Grafana dashboard (headless)..."
google-chrome --headless=new --no-sandbox --disable-gpu --hide-scrollbars \
    --window-size=1600,900 --virtual-time-budget=20000 \
    --screenshot="$WORK/dashboard.png" "$DASH_URL"

echo "[demo] recording the compliance run in a terminal..."
Xvfb "$DISPLAY_NUM" -screen 0 "$SCREEN" >"$WORK/xvfb.log" 2>&1 &
XPID=$!
sleep 2
DISPLAY="$DISPLAY_NUM" xterm -fa Monospace -fs 15 -bg '#0b0f14' -fg '#e6e6e6' \
    -geometry 130x36 -e bash -lc "cd '$ROOT' && make compliance 2>&1; sleep 6" \
    >"$WORK/xterm.log" 2>&1 &
TPID=$!
sleep 1
DISPLAY="$DISPLAY_NUM" ffmpeg -y -f x11grab -video_size 1280x720 -framerate "$FPS" \
    -i "$DISPLAY_NUM" -t 175 -c:v libx264 -preset ultrafast -crf 23 \
    "$WORK/terminal.mp4" >"$WORK/ffmpeg.log" 2>&1
kill "$TPID" 2>/dev/null || true
TPID=""
kill "$XPID" 2>/dev/null || true
XPID=""

echo "[demo] composing title + dashboard + terminal..."
convert -size 1280x720 xc:'#0b0f14' -gravity center \
    -pointsize 62 -fill '#e6e6e6' -annotate +0-70 'OT-Security-Lab' \
    -pointsize 32 -fill '#33ff66' -annotate +0+10 'make compliance  ->  11/11 checks' \
    -pointsize 20 -fill '#8aa0b4' \
    -annotate +0+80 'real IEC 61131-3 PLCs  -  Modbus / DNP3 / OPC UA / S7comm  -  protocol-aware detection' \
    "$WORK/title.png"

ffmpeg -y -loop 1 -i "$WORK/title.png" -t 2.6 -r "$FPS" -pix_fmt yuv420p \
    -c:v libx264 -crf 20 "$WORK/title.mp4" >/dev/null 2>&1
ffmpeg -y -loop 1 -i "$WORK/dashboard.png" \
    -vf "scale=1600:900,zoompan=z='min(zoom+0.0007,1.12)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1280x720:fps=$FPS,format=yuv420p" \
    -t 6 -c:v libx264 -crf 20 "$WORK/dash.mp4" >/dev/null 2>&1
ffmpeg -y -ss 100 -i "$WORK/terminal.mp4" -t 12 -an -c:v libx264 -crf 20 \
    -pix_fmt yuv420p "$WORK/term.mp4" >/dev/null 2>&1

ffmpeg -y -i "$WORK/title.mp4" -i "$WORK/dash.mp4" -i "$WORK/term.mp4" \
    -filter_complex "[0:v]fps=$FPS,format=yuv420p[a];[1:v]fps=$FPS,format=yuv420p[b];[2:v]fps=$FPS,format=yuv420p[c];[a][b][c]concat=n=3:v=1:a=0[out]" \
    -map "[out]" -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p \
    "$ROOT/evidence/demo.mp4" >/dev/null 2>&1
ffmpeg -y -i "$ROOT/evidence/demo.mp4" \
    -vf "fps=$FPS,scale=1280:-1:flags=lanczos,palettegen=stats_mode=diff" \
    "$WORK/palette.png" >/dev/null 2>&1
ffmpeg -y -i "$ROOT/evidence/demo.mp4" -i "$WORK/palette.png" \
    -lavfi "fps=$FPS,scale=1280:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3" \
    "$ROOT/evidence/demo.gif" >/dev/null 2>&1

cp "$WORK/dashboard.png" "$ROOT/evidence/SOC_Overview_Dashboard.png"
echo "[demo] wrote evidence/demo.gif, evidence/demo.mp4 and evidence/SOC_Overview_Dashboard.png"
