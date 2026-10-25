# Optional Caldera Adversary-Emulation Profile

This directory adds an **optional** MITRE/Apache Caldera control plane to the
lab. It is not part of `make up` or `make compliance`; the deterministic Python
compliance gate remains the regression test. Caldera is used to demonstrate the
same scenarios through a recognised BAS/emulation platform.

## Topology

- **Caldera server:** Enterprise zone, `172.24.0.40`, host UI on `:8888`.
- **Sandcat agent:** runs inside the existing `ot_attacker` container. The
  attacker is already single-homed in the Enterprise zone and has the pivot
  routes to OT via the gateway. This preserves the single-chokepoint invariant
  (`tests/test_zone_isolation.py`).
- **Plugin:** `plugins/ot-lab` supplies four abilities and the
  `OT External Adversary` profile.

## Build and run

The image is built from the pinned Caldera release tag (default `5.3.0`). It is
built on demand because it is large and is not part of the default CI image
build.

```bash
# Build the image once (or after changing the Caldera version)
make caldera-image

# Start Caldera + the attacker agent
make caldera

# UI: http://localhost:8888
# Lab credentials (override with env vars):
#   username: red
#   password: ot-lab-caldera
#   API key:  ot-lab-caldera-api

# Stop the profile
make caldera-down
```

The `make caldera` target exports `CALDERA_URL=http://caldera:8888` to the
attacker service. Without that variable the attacker does not start an agent.

## Run an operation

From the UI, create an operation against the `red` group with the
**OT External Adversary** profile. Or use the PowerShell runner:

```bash
export CALDERA_API_KEY=ot-lab-caldera-api
pwsh -File powershell/Invoke-OTCalderaOperation.ps1 \
    -CalderaUrl http://localhost:8888 \
    -AdversaryName 'OT External Adversary' \
    -EvidencePath evidence/caldera_operation.json
```

The runner starts the operation, polls it to completion, retrieves the link
results and attaches the last 15 minutes of Loki alerts. The evidence file is
machine-generated; do not hand-edit it.

## Abilities

| Ability | Tactic | Technique | Expected lab detection |
| :--- | :--- | :--- | :--- |
| OT Service Discovery | Discovery | T0846 | `CROSS_ZONE_VIOLATION`; `OT_PORT_SCAN` after the detection-gap fix |
| Unauthorized Modbus Write | Impact | T0831 | `CROSS_ZONE_VIOLATION`, `UNAUTHORIZED_MODBUS_WRITE`, `OT_BRUTE_FORCE_SCAN` |
| OT Lateral Movement | Lateral Movement | T0886 | `CROSS_ZONE_VIOLATION` |
| Process Safety Interlock Stimulus | Impact | T0836 | `PROCESS_SAFETY_VIOLATION` |

The safety ability uses the deterministic spoofed-precondition stimulus
(`simulate_process_violation_spoof.py`) so the operation does not depend on the
live tank level being in the unsafe band. The detector still evaluates the
process logic; only the precondition is injected.

## Safety and scope

- Caldera is reachable only from the lab's Enterprise zone and the host.
- The plugin abilities call the same scripts used by the compliance gate; no
  new attack surface is added.
- The default credentials are lab-only and are generated from environment
  variables. Do not reuse them outside the lab.
- The profile is intentionally excluded from `make compliance` so a Caldera
  build or UI change cannot make the deterministic gate flaky.
