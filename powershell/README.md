# PowerShell Toolkit (`OTSec`)

PowerShell 7 module and scripts for OT adversary emulation, detection
validation and SIEM reporting. The module is cross-platform; the lab runs it in
the `ot_powershell` operator workstation (Supervisory zone) and the optional
Caldera operation runner runs on the host.

## Why a PowerShell host in the Supervisory zone?

The lab's conduit design matters here:

- **C1** permits Supervisory (L2) → Control (L1) Modbus/TCP 502.
- **C5** explicitly denies the Engineering Workstation (L3) Modbus access.

A normal `TcpClient` write from the EWS would be dropped at the SYN and never
produce a Modbus PDU. The PowerShell workstation therefore sits in L2, where a
real FC6 write reaches PLC-01. The write comes from `172.22.0.30`, which is not
in the Modbus write allow-list (HMI `172.22.0.10` and EWS `172.23.0.4`), so the
gateway raises `UNAUTHORIZED_MODBUS_WRITE`.

The scenario reads the original pump-speed register, writes a test value and
restores the original value. PLC-01's ST logic does not use HR1, so the process
is left unchanged.

## Module functions

| Function | Purpose |
| :--- | :--- |
| `ConvertTo-OTModbusFrame` | Encode FC3/FC6/FC16 frames (MBAP + PDU) |
| `ConvertFrom-OTModbusResponse` | Parse normal and exception responses |
| `Invoke-OTModbusRequest` | Send a raw frame over TCP and return a typed result |
| `Invoke-OTModbusWrite` | FC6 write with `ShouldProcess` support |
| `Get-OTProcessState` | Read the canonical intake register map |
| `Test-OTConduit` | TCP reachability probe |
| `Invoke-OTAdversaryScenario` | Bounded `UnauthorizedWrite` / `Recon` scenarios |
| `ConvertFrom-OTLokiResponse` | Parse a Loki `query_range` response |
| `Get-OTAlertSummary` | Query Loki and group alerts by type/source |
| `ConvertTo-OTCalderaOperationBody` | Build the Caldera v2 operation payload |
| `Invoke-OTCalderaOperation` | Start/poll a Caldera operation and capture evidence |
| `Get-OTDetectionCoverage` | Summarise Sigma rules and ATT&CK for ICS techniques |

## Usage

```powershell
# Import the module
Import-Module ./powershell/OTSec/OTSec.psd1 -Force

# Read the process image
Get-OTProcessState -Target 172.21.0.10

# Run the live adversary scenario (inside the lab)
./powershell/Invoke-OTAdversaryEmulation.ps1 `
    -Scenario UnauthorizedWrite -Target 172.21.0.10 -AllowLab

# Report Sigma coverage
./powershell/Get-OTDetectionReport.ps1 -AsMarkdown
```

## Safety

- `Invoke-OTAdversaryScenario` refuses to run without `-AllowLab`.
- The target must be in `172.21.0.0/24`; public addresses are rejected even
  with `-AllowLab`.
- The write scenario only targets HR1 and restores the original value.
- The module is for the isolated lab, not production OT.

## Tests and CI

```bash
make powershell-lint
make powershell-test
```

The `PowerShell Lint & Tests` CI job runs PSScriptAnalyzer and Pester 5+ on
`ubuntu-latest` (PowerShell 7 is preinstalled). The tests cover frame encoding,
response parsing, the safety guard, Loki parsing, the Caldera body schema and
the committed Sigma coverage.

## Windows telemetry note

The lab runs PowerShell 7 on Linux, not a Windows VM. The Sigma rules in
`detection/sigma/powershell_*.yml` target Windows PowerShell Script Block
Logging (event 4104) and are statically validated in CI. Live 4104 validation
requires a Windows endpoint with Script Block Logging and a forwarder; that is
tracked as a known gap in `CLAIMS.md`.
