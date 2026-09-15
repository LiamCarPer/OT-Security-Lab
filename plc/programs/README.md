# PLC Program Bundles (OpenPLC Editor v4)

The OpenPLC Runtime v4 is **headless**: it does not load `.st` files directly.
It accepts an editor-built `program.zip` over its REST API, then compiles it
on-device into `libplc_*.so`.

This directory holds the committed, reproducible program bundles that
`lab-environment/plc-bootstrap/` uploads to each runtime at boot:

```
plc/programs/
├── intake/program.zip        -> 172.21.0.10 (plc_intake)
├── treatment/program.zip     -> 172.21.0.11 (plc_treatment)
└── distribution/program.zip  -> 172.21.0.12 (plc_distribution)
```

If a `program.zip` is absent, the bootstrap logs a warning and leaves that PLC
program in the `EMPTY` state. The lab still boots and the rest of the detection
suite still runs; the physics-aware test then falls back to its simulated
stimulus (see `governance/testing/run_security_tests.py`).

## Building a bundle (one-time, per PLC)

Prerequisite: [OpenPLC Editor v4](https://github.com/Autonomy-Logic/openplc-editor/releases)
(a desktop AppImage/EXE/DMG). Record the editor version you used — the
committed bundle is cryptographically tied to the STruC++ headers it shipped
with, and the runtime image must be pinned to a compatible version.

1. **Create the project** for one PLC (e.g. intake):
   - New project, ST language.
   - Create a `PROGRAM` POU and paste the POU body from `plc/intake.st`. Keep the
     located variables exactly as declared in `plc/register-map.md`
     (`%QW0`, `%QW1`, `%QW5`, `%QW6`) so detection and the HMI stay aligned.
   - Add a **CONFIGURATION / RESOURCE / TASK** and schedule the program POU on a
     periodic task (e.g. `T#50ms`).
2. **Enable the Modbus server** for the project (Project Explorer → Server →
   Modbus/TCP). Listen on `0.0.0.0:502`, slave id `1`, and size the `%QW`
   holding-register area to at least `7` words so HR 0–6 are exposed. This
   writes `modbus_slave.json` into the bundle.
3. **Build and upload once** (Configuration → connect to the runtime, or
   Build → Compile) to confirm it runs (`Compilation complete`, PLC `RUNNING`).
4. **Export the bundle**: everything under the project's
   `build/OpenPLC Runtime v4/src` becomes the zip *contents* (do not include a
   `src/` folder level). For example:
   ```bash
   cd "<project>/build/OpenPLC Runtime v4/src"
   zip -r ../../../../program.zip .
   ```
   The archive must contain `generated.hpp`, `defines.h`, `configuration.cpp`,
   `pou_*.cpp`, `program.st`, `debug-map.json`, `plc.xml`, `strucpp_runtime/include/`
   and `modbus_slave.json`.
5. Copy the zip to `plc/programs/<name>/program.zip` and repeat for treatment
   and distribution.

## Verifying the committed bundles

```bash
# Structural sanity (must not contain the MatIEC-era files the v4 compiler rejects)
unzip -l plc/programs/intake/program.zip | grep -E 'Config0.c|glueVars.c' && echo "BAD: MatIEC bundle"
```

The Compliance Gate does not regenerate these bundles (it cannot run a desktop
editor). It validates whatever is committed: the bootstrap uploads them, the
plc-bootstrap healthcheck fails if a committed bundle fails to compile, and the
runtime `/api/status` must read `RUNNING`.

## Regeneration / version changes

When the OpenPLC Runtime image is bumped, rebuild the bundles with a matching
Editor version, re-run `make up`, and confirm `/api/status` reports `RUNNING`
for all three PLCs before committing. Update `OT_OPENPLC_VERSION` in
`.env`/`docker-compose.yml` and the versions table in `README.md`.
