#!/bin/sh
# Build OpenPLC Runtime v4 program bundles from the Structured Text sources.
#
# OpenPLC v4 is headless: it only accepts an editor-built program.zip and
# compiles it on-device. This script produces those bundles without the desktop
# editor by running the STruC++ toolchain (the same codegen the editor uses)
# and assembling the layout the runtime expects:
#
#   generated.hpp, generated.cpp, defines.h, generated_debug.cpp,
#   strucpp_runtime/include/*.hpp, conf/modbus_slave.json
#
# Output: plc/programs/<name>/program.zip (one per plc/<name>.st).
# The zips are committed; CI rebuilds and diffs them to catch drift.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ARCH="${OT_STRUCPP_ARCH:-x64}"
VERSION="${OT_STRUCPP_VERSION:-v0.6.6}"
CACHE="$ROOT/.toolchain"
STRUCPP="${OT_STRUCPP:-$CACHE/strucpp/strucpp}"
# Fixed timestamp so the committed zips are byte-reproducible.
FIXED_TS="202601010000.00"

ensure_toolchain() {
    [ -x "$STRUCPP" ] && return 0
    mkdir -p "$CACHE"
    url="https://github.com/Autonomy-Logic/STruCpp/releases/download/${VERSION}/strucpp-linux-${ARCH}.tar.gz"
    echo "[plc-build] fetching STruC++ ${VERSION} (${ARCH})"
    curl -fsSL -o "$CACHE/strucpp.tar.gz" "$url"
    tar -xzf "$CACHE/strucpp.tar.gz" -C "$CACHE"
    if [ ! -x "$STRUCPP" ]; then
        echo "[plc-build] ERROR: strucpp binary not found at $STRUCPP" >&2
        exit 1
    fi
}

write_debug_table() {
    cat > "$1/generated_debug.cpp" <<'EOF'
// Minimal debug table (debugger metadata only). The PLC logic and the
// located-variable / Modbus binding do not depend on it.
#include "generated.hpp"
#include "debug_table.hpp"

namespace strucpp { namespace debug {
const Entry* const debug_arrays[1] = { nullptr };
const uint16_t debug_array_counts[1] = { 0 };
const uint8_t debug_array_count = 0;
const RetainVar retain_vars[1] = { {0, 0} };
const uint16_t retain_var_count = 0;
const uint32_t retain_layout_hash = 0;
}}  // namespace strucpp::debug
EOF
}

write_modbus_config() {
    cat > "$1/conf/modbus_slave.json" <<'EOF'
{
  "network_configuration": { "host": "0.0.0.0", "port": 502 },
  "buffer_mapping": {
    "max_coils": 16,
    "max_discrete_inputs": 16,
    "max_holding_registers": 8,
    "max_input_registers": 8
  }
}
EOF
}

build_program() {
    src="$1"
    name=$(basename "$src" .st)
    out="$ROOT/programs/$name"
    work=$(mktemp -d)

    "$STRUCPP" "$src" -o "$work/generated.cpp" >/dev/null

    mkdir -p "$work/strucpp_runtime"
    cp -r "$CACHE/strucpp/runtime/include" "$work/strucpp_runtime/include"

    md5=$(md5sum "$src" | awk '{print $1}')
    printf '#pragma once\n// Program MD5\n#define PROGRAM_MD5 "%s"\n' "$md5" > "$work/defines.h"

    write_debug_table "$work"
    mkdir -p "$work/conf"
    write_modbus_config "$work"

    rm -rf "$out"
    mkdir -p "$out"
    ( cd "$work" && find . -exec touch -t "$FIXED_TS" {} + && zip -qrX "$out/program.zip" . )
    rm -rf "$work"
    echo "[plc-build] $name -> programs/$name/program.zip"
}

ensure_toolchain
for src in "$ROOT"/*.st; do
    [ -f "$src" ] || continue
    build_program "$src"
done
echo "[plc-build] done"
