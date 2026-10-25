#Requires -Version 7.2
<#
.SYNOPSIS
    Start a Caldera operation, wait for it and capture detection evidence.

.DESCRIPTION
    Requires a running Caldera server with the ot-lab plugin loaded. The
    operation is scoped to the isolated lab; the script records the operation
    id, link results and the Loki alert summary in evidence/caldera_operation.json.
#>
[CmdletBinding()]
param(
    [string]$CalderaUrl = 'http://localhost:8888',
    [string]$ApiKey = $env:CALDERA_API_KEY,
    [string]$AdversaryName = 'OT External Adversary',
    [string]$AdversaryId,
    [string]$Group = 'red',
    [string]$Name = "OT Caldera Operation $(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [ValidateRange(1, 120)]
    [int]$TimeoutMinutes = 10,
    [string]$LokiUrl = 'http://localhost:3100',
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
if (-not $EvidencePath) {
    $EvidencePath = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'evidence/caldera_operation.json'
}
Import-Module (Join-Path $PSScriptRoot 'OTSec/OTSec.psd1') -Force

$result = Invoke-OTCalderaOperation -CalderaUrl $CalderaUrl -ApiKey $ApiKey `
    -AdversaryName $AdversaryName -AdversaryId $AdversaryId -Group $Group -Name $Name `
    -TimeoutMinutes $TimeoutMinutes -LokiUrl $LokiUrl -EvidencePath $EvidencePath

$result | ConvertTo-Json -Depth 10
if ($result.State -notin @('finished', 'cleanup', 'out_of_time')) {
    exit 1
}
