# PLC Program Bundles (OpenPLC Editor v4)

The OpenPLC Runtime v4 is **headless**: it does not load `.st` files directly.
It accepts an editor-built `program.zip`, compiles it on-device into
`libplc_*.so`, and starts the PLC.

This directory holds the committed, reproducible bundles for the three
controllers, **built automatically by `plc/build.sh`** (no desktop editor
required):

```
plc/
├── intake.st                 STATUS project source (STruC++ compiles it)
├── treatment.st
├── distribution.st
├── build.sh                  builds the bundles below
└── programs/
    ├── intake/program.zip        -> 172.21.0.10 (plc_intake)
    ├── treatment/program.zip     -> 172.21.0.11 (plc_treatment)
    └── distribution/program.zip  -> 172.21.0.12 (plc_distribution)
```

## Building

```bash
plc/build.sh      # downloads STruC++ v0.6.6, compiles each plc/*.st, zips the bundle
```

`build.sh` runs the same STruC++ codegen the editor uses and assembles the
layout the runtime expects:

| File | Source |
| :--- | :--- |
| `generated.hpp`, `generated.cpp` | `strucpp plc/<name>.st -o generated.cpp` |
| `strucpp_runtime/include/*.hpp` | STruC++ release runtime headers |
| `defines.h` | `PROGRAM_MD5` of the source |
| `generated_debug.cpp` | minimal debug table (debugger metadata only) |
| `conf/modbus_slave.json` | Modbus/TCP server on `0.0.0.0:502` |

The bundles are committed. CI rebuilds them and compares the bundle *contents*
(entry names + per-file SHA-256 via `plc/check_bundles.py`) to catch drift — the
`.zip` container itself is not asserted byte-identical across `zip` builds.

## Deploying

`lab-environment/plc-bootstrap/` (the EWS, Operations zone) uploads each
committed bundle over the runtime REST API at boot — `create-user → login →
upload-file → compile → start-plc` — and asserts `RUNNING`. The controllers
reach it through conduit C5 (source-restricted to the EWS).

The OpenPLC Modbus server is enabled by `conf/modbus_slave.json` inside the
bundle, exposing the canonical register map (`plc/register-map.md`): `%QWn` →
holding register `n`.
